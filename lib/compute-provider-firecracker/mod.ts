import { Hono } from "@hono/hono";
import { parse as yamlParse, stringify as yamlStringify } from "npm:yaml@^2.7.0";
import { acceptBundleModule, buildUserData, getUserDataModules, injectJsrUrl } from "@publicdomainrelay/cloud-init-common";
import type {
  CloudInitContext,
  UserDataModule,
  UserDataPatch,
  WriteFileEntry,
} from "@publicdomainrelay/cloud-init-common";
import type {
  ComputeAtproto,
  ComputeProvider,
  ComputeProviderCtx,
  DropletSpec,
  ProvisionResult,
  StrongRef,
  VM,
} from "@publicdomainrelay/compute-provider-abc";
import type { NodeImageStore } from "@publicdomainrelay/node-image-abc";
import type { Microvm } from "@publicdomainrelay/microvm-firecracker";
import type { OidcProvisioningEnricher } from "@publicdomainrelay/oidc-issuer-abc";
import { createOidcIssuer, OIDCToken } from "@publicdomainrelay/oidc-issuer-hono";
import { parseAtUri } from "@publicdomainrelay/atproto-helpers";
import { DEFAULT_ACCEPT_PATH_VM } from "@publicdomainrelay/secrets-common";
import { createPackageRegistryFactory } from "@publicdomainrelay/hono-factory-package-registry";
import { createLocalFsStore } from "@publicdomainrelay/package-store-local-fs";
import { createServe } from "@publicdomainrelay/serve";

export const WIF_SIMPLE_NSID = "com.publicdomainrelay.temp.compute.config.wif.simple";

export const ON_NETWORK_NSID = "com.publicdomainrelay.temp.compute.events.vm.onNetwork";

export const EVENT_NSID = "com.publicdomainrelay.temp.market.event";

export const SUBMIT_EVENT_NSID = "com.publicdomainrelay.temp.market.submitEvent";

export const SECRETS_PREFIX = "/root/secrets/digitalocean.com/serviceaccount";

export interface GuestContractEntry {
  receiptKey: string;
  receiptUri: string;
  receiptCid: string;
  submitEventUrl?: string;
}

export interface ComputeProviderFirecrackerCtx extends ComputeProviderCtx {
  image: NodeImageStore;
  microvm: Microvm;
  workRoot: string;
  getIssuerUrl: () => string;
  acceptPathVm?: string;
  rangeBase?: string;
  reuseStale?: boolean;
  guestTlsPort?: number;
  jsrBaseDir?: string;
  oidcProvisioner?: OidcProvisioningEnricher;
  acceptToContract?: Map<string, GuestContractEntry>;
  createSignedRepoRecord?: (
    collection: string,
    record: Record<string, unknown>,
    issuer?: string,
  ) => Promise<{ uri: string; cid: string; record: Record<string, unknown> }>;
  callService?: (
    endpointUrl: string,
    nsid: string,
    lxm: string,
    body: Record<string, unknown>,
  ) => Promise<{ status: number; ok: boolean; body: unknown }>;
  rbacProvisioner?: {
    provision(
      vm: { role: string },
      requesterDid: string,
      ctx: {
        getAgentDid: () => string;
        getIssuerUrl: () => string;
        createRecord: (collection: string, record: Record<string, unknown>) => Promise<{ uri: string }>;
        parseAtUri: (uri: string) => { repo: string; collection: string; rkey: string };
        actx?: string;
      },
    ): Promise<{ uri: string } | undefined>;
  };
  serve: {
    readonly app: Hono;
    onConnected(cb: (ingressRef: string) => void | Promise<void>): void;
  };
}

interface Guest {
  name: string;
  workDir: string;
  network: { guestIp: string; gateway: string; pastaIp: string; prefix: number; guestMac: string };
  userDataFile: string;
  /**
   * The requester's PLC and the role it asked for, kept because the issuer's
   * prove handler reads them back off the droplet to rebuild the subject the
   * guest's provisioning token carries. A guest whose droplet has neither is a
   * guest the issuer cannot name, and its token exchange is refused.
   */
  requesterPlc: string;
  role: string;
}

function didWebToHttps(didOrUrl: string): string {
  return didOrUrl.startsWith("did:web:") ? "https://" + didOrUrl.slice("did:web:".length) : didOrUrl;
}

const PREFIX_BITS = 30;

const DEFAULT_RANGE_BASE = "172.30.0.0";

const GUEST_SSH_PORT = 22;

const GUEST_SSH_BIND = "0.0.0.0";

function octets(address: string): [number, number, number, number] {
  const parts = address.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    throw new Error(`${address} is not an IPv4 address, and a guest's address and its MAC are derived from it`);
  }
  return parts as [number, number, number, number];
}

export function guestMacFor(address: string): string {
  const [a, b, c, d] = octets(address);
  const hex = (n: number) => n.toString(16).padStart(2, "0");
  return `06:00:${hex(a)}:${hex(b)}:${hex(c)}:${hex(d)}`;
}

export function networkFor(base: string, index: number): Guest["network"] {
  const [a, b, c] = octets(base);
  if (index < 0 || index > 16383) {
    throw new Error(
      `guest index ${index} is outside the 16384 /30 blocks a range based at ${base} holds. The ` +
        `addresses a host hands out are a bounded pool and the pool is exhausted rather than ` +
        `wrapped: two guests sharing one range are two guests whose packets arrive at whichever ` +
        `the host routes to.`,
    );
  }
  const block = index * 4;
  const third = c + Math.floor(block / 256);
  const fourth = block % 256;
  const pastaIp = `${a}.${b}.${third}.${fourth}`;
  const gateway = `${a}.${b}.${third}.${fourth + 1}`;
  const guestIp = `${a}.${b}.${third}.${fourth + 2}`;
  return { guestIp, gateway, pastaIp, prefix: PREFIX_BITS, guestMac: guestMacFor(guestIp) };
}

function shortId(value: string): string {
  let h1 = 0xdeadbeef ^ value.length;
  let h2 = 0x41c6ce57 ^ value.length;
  for (let i = 0; i < value.length; i++) {
    const ch = value.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (h1 >>> 0).toString(16).padStart(8, "0") + (h2 >>> 0).toString(16).padStart(8, "0").slice(0, 4);
}

export function injectAcceptBundle(
  userData: string,
  bundle: Record<string, unknown>,
  acceptPathVm: string = DEFAULT_ACCEPT_PATH_VM,
): string {
  return buildUserData({ base: userData, modules: [acceptBundleModule(acceptPathVm, bundle)] });
}

/**
 * The URL a guest reports its tunnel FQDN to, read out of the accept bundle the
 * bidder injected. The bidder is the only party that knows its own relay URL,
 * and it is the bidder's `/v1/on-network` that holds the accept-to-receipt map
 * and submits the wrapped event to the requester. When the bundle carries none
 * (an older bidder), this provider's own endpoint is used.
 */
export function onNetworkUrlFromBundle(userData: string, fallback: string): string {
  const match = /"guest_onnetwork_url"\s*:\s*"([^"]+)"/.exec(userData);
  return match ? match[1] : `${fallback.replace(/\/+$/, "")}/v1/on-network`;
}

export interface OnNetworkTarget {
  url: string;
  resolve?: string;
}

/**
 * Where a guest can actually deliver its report. The first target is the URL as
 * written. The second, when the guest's cloud-config names the host it reaches
 * the relay dispatcher at (`<ip> relay.localhost`), pins that same address for
 * the relay's own name: a guest's route to the host is the one pasta hands it,
 * and the address in /etc/hosts for a relay name is the microVM's own gateway,
 * which carries no arbitrary port.
 */
export function onNetworkTargets(userData: string, fallbackUrl: string): OnNetworkTarget[] {
  const url = onNetworkUrlFromBundle(userData, fallbackUrl);
  const targets: OnNetworkTarget[] = [{ url }];
  const relayIp = /(\d+\.\d+\.\d+\.\d+)\s+relay\.localhost/.exec(userData)?.[1];
  if (!relayIp) return targets;
  try {
    const parsed = new URL(url);
    if (parsed.hostname.endsWith(".localhost")) {
      targets.push({ url, resolve: `${parsed.hostname}:${parsed.port || "80"}:${relayIp}` });
    }
  } catch {
    /* the URL as written is the only target */
  }
  return targets;
}

/**
 * guest-onnetwork -- report the dispatcher FQDN the tunnel subscriber wrote to
 * /run/guest-fqdn back to the market, so the requester learns the one address it
 * can open an SSH session to. Nothing else reports it: the guest is born from
 * this user_data, and without this module the requester waits until its FQDN
 * timeout while only the bidder-side onNetwork (the guest's raw, unroutable IP)
 * is ever published.
 *
 * Composed into user_data, never baked into the image: curl and jq are already
 * in the node image, and what the script says is a property of the contract
 * (which accept, which endpoint), not of the disk.
 */
export function onNetworkReporterModule(
  targets: OnNetworkTarget[],
  acceptPathVm: string = DEFAULT_ACCEPT_PATH_VM,
): UserDataModule {
  const attempts: string[] = [];
  let index = 0;
  for (const target of targets) {
    index += 1;
    const name = `CODE${index}`;
    const resolve = target.resolve ? `--resolve "${target.resolve}" ` : "";
    attempts.push(
      `  ${name}="$(curl -sS -m 20 -o /tmp/guest-onnetwork.out -w '%{http_code}' ${resolve}\\`,
      `    -X POST "${target.url}" -H 'Content-Type: application/json' -d "\${PAYLOAD}" \\`,
      "    2>>/tmp/guest-onnetwork.err || echo 000)\"",
      `  echo "guest-onnetwork: http \${${name}} ${target.url}"`,
      `  if [ "\${${name}}" = "200" ]; then echo "guest-onnetwork: reported \${FQDN}"; exit 0; fi`,
    );
  }

  const script = [
    "#!/usr/bin/env bash",
    "set -uo pipefail",
    `ACCEPT_JSON="${acceptPathVm}"`,
    'if [ ! -f "${ACCEPT_JSON}" ]; then echo "guest-onnetwork: no ${ACCEPT_JSON}"; exit 0; fi',
    'FQDN=""',
    "for _ in $(seq 1 90); do",
    '  FQDN="$(cat /run/guest-fqdn 2>/dev/null || true)"',
    '  [ -n "${FQDN}" ] && break',
    "  sleep 2",
    "done",
    "if [ -z \"${FQDN}\" ]; then",
    '  echo "guest-onnetwork: no /run/guest-fqdn after 180s"',
    '  echo "guest-onnetwork: tunnel-subscriber is $(systemctl is-active tunnel-subscriber.service 2>&1), restarts=$(systemctl show -p NRestarts --value tunnel-subscriber.service 2>&1)"',
    "  journalctl -u tunnel-subscriber.service --no-pager -n 40 2>&1 | tail -40",
    "  exit 0",
    "fi",
    'ACCEPT_URI="$(jq -r \'.accept.uri // empty\' "${ACCEPT_JSON}")"',
    'ACCEPT_CID="$(jq -r \'.accept.cid // empty\' "${ACCEPT_JSON}")"',
    'if [ -z "${ACCEPT_URI}" ] || [ -z "${ACCEPT_CID}" ]; then echo "guest-onnetwork: accept.json has no accept ref"; exit 0; fi',
    'PAYLOAD="$(jq -nc --arg au "${ACCEPT_URI}" --arg ac "${ACCEPT_CID}" --arg addr "${FQDN}" \\',
    "  '{acceptUri: $au, acceptCid: $ac, address: $addr}')" + '"',
    'echo "guest-onnetwork: reporting ${FQDN}"',
    "for _ in 1 2 3 4 5; do",
    ...attempts,
    "  sleep 6",
    "done",
    'echo "guest-onnetwork: gave up; last response: $(cat /tmp/guest-onnetwork.out 2>/dev/null)"',
    "",
  ].join("\n");

  const unit = [
    "[Unit]",
    "Description=Report the guest tunnel FQDN to the market",
    "After=network-online.target tunnel-subscriber.service",
    "Wants=network-online.target tunnel-subscriber.service",
    "",
    "[Service]",
    "Type=oneshot",
    "RemainAfterExit=yes",
    "ExecStart=/usr/local/bin/send-onnetwork.sh",
    "StandardOutput=journal+console",
    "StandardError=journal+console",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n");

  return () => ({
    write_files: [
      { path: "/usr/local/bin/send-onnetwork.sh", owner: "root:root", permissions: "0700", content: script },
      { path: "/etc/systemd/system/guest-onnetwork.service", owner: "root:root", permissions: "0644", content: unit },
    ],
    runcmdPrepend: [
      "systemctl daemon-reload",
      "systemctl enable --no-block guest-onnetwork.service",
      "systemctl start --no-block guest-onnetwork.service",
    ],
  });
}

/**
 * Compose the FQDN reporter into a guest's user_data. A user_data that already
 * carries a guest-onnetwork unit (an `oidcProvisioner` composed one) is left
 * alone: two reporters would race to publish the same event.
 */
/**
 * What the guest's on-network reporter reads to learn where to post.
 *
 * The reporter the OIDC enricher composes gets its URL from
 * /root/secrets/digitalocean.com/serviceaccount/base_url, and the only writer of
 * that file is the provisioning-token script, which writes it only when its token
 * exchange succeeds. A provider with no issuer therefore leaves the guest with no
 * base_url, the reporter falls back to the public dispatcher, and its POST answers
 * 404 - the service fails and the requester never learns the guest's tunnel
 * address. This provider already knows the URL, so it writes it.
 */
export function withOnNetworkBaseUrl(
  userData: string,
  fallbackUrl: string,
): string {
  const path = "/root/secrets/digitalocean.com/serviceaccount/base_url";
  if (userData.includes(path)) return userData;
  const origin = new URL(onNetworkUrlFromBundle(userData, fallbackUrl)).origin;
  return buildUserData({
    base: userData,
    modules: [() => ({
      write_files: [{ path, owner: "root:root", permissions: "0600", content: `${origin}\n` }],
      runcmdPrepend: [["sh", "-c", `install -d -m 0700 -o root -g root ${path.split("/").slice(0, -1).join("/")}`]],
    })],
  });
}

export function withOnNetworkReporter(
  userData: string,
  fallbackUrl: string,
  acceptPathVm: string = DEFAULT_ACCEPT_PATH_VM,
): string {
  if (userData.includes("guest-onnetwork.service")) return userData;
  return buildUserData({
    base: userData,
    modules: [onNetworkReporterModule(onNetworkTargets(userData, fallbackUrl), acceptPathVm)],
  });
}

export interface PreinstallFile {
  path: string;
  mode?: string;
  content?: string;
  source?: string;
}

export interface PreinstallManifest {
  packages: string[];
  files: PreinstallFile[];
  runs: string[];
  leftToBoot: { packages: string[]; files: string[]; runs: string[] };
}

export interface PreinstallManifestInput {
  modules: string[];
  ctx?: Partial<CloudInitContext>;
  base?: Partial<Omit<PreinstallManifest, "leftToBoot">>;
}

export function shellCommandLine(entry: unknown, moduleId: string): string {
  if (typeof entry === "string") return entry;
  if (Array.isArray(entry)) {
    if (entry.some((part) => typeof part !== "string")) {
      throw new Error(
        `the user-data module ${moduleId} prepends a command whose arguments are not all strings: ${
          JSON.stringify(entry)
        }. The preinstall runs these during the build, and a build step that is not a string is one ` +
          `this cannot render as the shell command the manifest carries.`,
      );
    }
    return entry.map((part) => `'${String(part).replaceAll("'", `'\\''`)}'`).join(" ");
  }
  throw new Error(
    `the user-data module ${moduleId} prepends a runcmd entry that is neither a string nor an argv ` +
      `array: ${JSON.stringify(entry)}. Both spellings are commands the guest would run at boot, and ` +
      `a third spelling is one this would bake as nothing while the boot-time copy still ran.`,
  );
}

function preinstallFileFor(moduleId: string, entry: WriteFileEntry): PreinstallFile {
  if (typeof entry.path !== "string" || !entry.path.startsWith("/")) {
    throw new Error(
      `the user-data module ${moduleId} writes ${JSON.stringify(entry.path)}, which is not an ` +
        `absolute path inside the guest. The build writes preinstalled files into the staged rootfs ` +
        `at that path, so a relative one would land wherever the build was running.`,
    );
  }
  const owner = entry.owner === undefined ? "root:root" : String(entry.owner);
  if (owner !== "root:root" && owner !== "root") {
    throw new Error(
      `the user-data module ${moduleId} writes ${entry.path} owned by ${owner}, and the preinstall ` +
        `manifest has no owner: the build writes these files as root, so baking this one would bake ` +
        `a file whose owner is not the one the module asked for, and the difference would show up ` +
        `only inside a guest as a service that cannot read its own config.`,
    );
  }
  if (typeof entry.content !== "string") {
    throw new Error(
      `the user-data module ${moduleId} writes ${entry.path} with no content in the user_data, so ` +
        `there is nothing to bake there. The preinstall carries content or a source, and the source ` +
        `spelling exists for a file too large to sit in a JSON manifest.`,
    );
  }
  return {
    path: entry.path,
    mode: entry.permissions === undefined ? undefined : String(entry.permissions),
    content: entry.content,
  };
}

interface ModuleContribution {
  packages: string[];
  files: Map<string, PreinstallFile>;
  runs: string[];
}

function contributionOf(ids: string[], ctx: Partial<CloudInitContext>): ModuleContribution {
  const packages: string[] = [];
  const files = new Map<string, PreinstallFile>();
  const runs: string[] = [];
  for (const id of ids) {
    const patch: UserDataPatch = getUserDataModules([id])[0](ctx);
    const apt = patch.apt as Record<string, unknown> | undefined;
    if (apt !== undefined && apt.sources !== undefined) {
      throw new Error(
        `the user-data module ${id} adds apt sources, and the preinstall has none: the image ` +
          `carries no repository of its own, so a package from that source cannot be baked and the ` +
          `guest would reach the network for it at first boot -- which is the boot this manifest ` +
          `exists to make unnecessary. Bake the package into the base image instead.`,
      );
    }
    for (const name of patch.packages ?? []) {
      if (!packages.includes(name)) packages.push(name);
    }
    for (const entry of patch.write_files ?? []) {
      const file = preinstallFileFor(id, entry);
      files.set(file.path, file);
    }
    for (const entry of patch.runcmdPrepend ?? []) {
      runs.unshift(shellCommandLine(entry, id));
    }
  }
  return { packages, files, runs };
}

export function preinstallManifest(input: PreinstallManifestInput): PreinstallManifest {
  for (const module of input.modules) {
    if (typeof module !== "string") {
      throw new Error(
        `preinstallManifest was given a module function rather than the id of a registered one, and ` +
          `a function closes over whatever it was built for: acceptBundleModule carries one ` +
          `contract's bundle inside it, so a derivation that accepted functions could bake one ` +
          `guest's accept.json into every guest's image. Derive from ids, which name modules the ` +
          `image can carry, and leave per-contract values to the boot-time user_data.`,
      );
    }
  }
  const ctx = input.ctx ?? {};
  const wanted = contributionOf(input.modules, ctx);
  const withoutInstanceValues = contributionOf(input.modules, {});

  const packages = [...(input.base?.packages ?? [])];
  const leftPackages: string[] = [];
  for (const name of wanted.packages) {
    if (withoutInstanceValues.packages.includes(name)) {
      if (!packages.includes(name)) packages.push(name);
    } else {
      leftPackages.push(name);
    }
  }

  const files = [...(input.base?.files ?? [])];
  const leftFiles: string[] = [];
  for (const [path, file] of wanted.files) {
    const same = withoutInstanceValues.files.get(path);
    if (same !== undefined && same.content === file.content && same.mode === file.mode) {
      const at = files.findIndex((existing) => existing.path === path);
      if (at >= 0) files[at] = file;
      else files.push(file);
    } else {
      leftFiles.push(path);
    }
  }

  const runs = [...(input.base?.runs ?? [])];
  const leftRuns: string[] = [];
  for (const [index, run] of wanted.runs.entries()) {
    if (withoutInstanceValues.runs[index] === run) runs.push(run);
    else leftRuns.push(run);
  }

  return {
    packages,
    files,
    runs,
    leftToBoot: { packages: leftPackages, files: leftFiles, runs: leftRuns },
  };
}

/**
 * The address a requester already named for this host, if it named one.
 *
 * A requester can put the host in the guest's /etc/hosts itself -- the market
 * harness passes `guestHostAliases` as `<address> relay.localhost` and does so
 * precisely because a NodeClaim carries no such thing. When it has, that line is
 * in the document the guest boots with, and cloud-init resolves a name before
 * the step below can append a line for it, so a second line is a line that never
 * wins: the requester's address has to be the one this provider names too.
 */
export function addressTheRequesterNamed(userData: string): string | undefined {
  return /(\d+\.\d+\.\d+\.\d+)\s+relay\.localhost/.exec(userData)?.[1];
}

function pointGuestAtHost(userData: string, gateway: string, guestTlsPort?: number): string {
  const patched = guestTlsPort
    ? userData.replace(/https:\/\/([a-z0-9.-]+\.localhost)(?![:.\w-])/gi, `https://$1:${guestTlsPort}`)
    : userData;
  const hosts = new Set<string>();
  for (const m of patched.matchAll(/https?:\/\/([a-z0-9.-]+\.localhost)/gi)) hosts.add(m[1]);
  if (hosts.size === 0) return patched;
  let obj: Record<string, unknown> | null = null;
  try {
    obj = yamlParse(patched.replace(/^#cloud-config\s*/i, "")) as Record<string, unknown> | null;
  } catch {
    obj = null;
  }
  if (!obj || typeof obj !== "object") {
    throw new Error(
      "the cloud-init document this guest was given is not the YAML this reads, so the names it " +
        "resolves to the host cannot be added to it. A guest whose relay name resolves nowhere " +
        "installs its services and then cannot reach the thing that makes it reachable, and the " +
        "failure reads as a tunnel that never appears rather than as a host that was never named.",
    );
  }
  const runcmd = (obj["runcmd"] as unknown[]) ?? [];
  for (const host of hosts) runcmd.unshift(["sh", "-c", `echo ${gateway} ${host} >> /etc/hosts`]);
  obj["runcmd"] = runcmd;
  if (guestTlsPort) {
    const writeFiles = (obj["write_files"] as unknown[]) ?? [];
    writeFiles.push({
      path: "/root/.curlrc",
      owner: "root:root",
      permissions: "0644",
      content: `resolve = *:${guestTlsPort}:${gateway}\n`,
    });
    obj["write_files"] = writeFiles;
  }
  return "#cloud-config\n" + yamlStringify(obj, { lineWidth: 0 });
}

export function createComputeProviderFirecracker(ctx: ComputeProviderFirecrackerCtx) {
  const { logger, atproto, image, microvm, workRoot } = ctx;
  const acceptPathVm = ctx.acceptPathVm ?? DEFAULT_ACCEPT_PATH_VM;
  const rangeBase = ctx.rangeBase ?? DEFAULT_RANGE_BASE;

  const guests = new Map<string, Guest>();
  const rbacByProvider = new Map<string | number, StrongRef>();
  let nextIndex = 0;
  let imageDir: string | undefined;
  let imageRootfsMiB: number | undefined;

  // The packages these guests run (the tunnel subscriber above all) are
  // workspace members that are not published to jsr.io, so a guest that fetches
  // them from the public registry gets a 404 and its tunnel never comes up.
  // Serve them from this host, exactly as the container provider does, and point
  // the guest at it.
  const jsrBaseDir = ctx.jsrBaseDir ?? new URL("../../..", import.meta.url).pathname;
  let jsrPort = 0;
  const jsrRegistryReady = (async () => {
    const store = createLocalFsStore({ baseDir: jsrBaseDir, fallbackVersion: "0.0.0" });
    const factory = createPackageRegistryFactory({ store });
    const jsrServe = createServe({ logger, tcp: { addr: "0.0.0.0", port: 0 } });
    jsrServe.app.route("/", factory as never);
    await jsrServe.beginServe();
    jsrPort = jsrServe.tcpPort;
    logger.info("jsr registry mounted on TCP", { jsrBaseDir, port: jsrPort });
  })();

  /**
   * The address a guest dials this host on. The relay name the requester put in
   * the cloud-config is the host's own address as the guest sees it; a guest
   * whose packets reach the gateway address instead can dial that.
   */

  async function ensureImage(): Promise<string> {
    const status = await image.ensure({ reuseStale: ctx.reuseStale });
    imageDir = status.dir;
    imageRootfsMiB = status.rootfsMiB;
    if (status.state === "reused") {
      logger.warn("node_image_reused", {
        askedFor: status.fingerprint,
        using: status.reusedFrom,
        dir: status.dir,
      });
      return status.dir;
    }
    logger.info("node_image_ready", { state: status.state, fingerprint: status.fingerprint, dir: status.dir });
    return status.dir;
  }

  function diskTheGuestIsAskedFor(disk: string): number | undefined {
    return parseMemMiB(disk);
  }

  async function createBidConfig(nowIso: string): Promise<StrongRef> {
    const agentDid = atproto.getAgentDid();
    return await atproto.createRecord(WIF_SIMPLE_NSID, {
      $type: WIF_SIMPLE_NSID,
      accept_path: acceptPathVm,
      issuer_uri: ctx.getIssuerUrl(),
      to_issue: "exchange-firecracker-oidc",
      actx: agentDid.split(":").slice(-1)[0],
      actx_path: `${SECRETS_PREFIX}/team_uuid`,
      token_path: `${SECRETS_PREFIX}/token`,
      url_path: `${SECRETS_PREFIX}/base_url`,
      url_route: "/v1/oidc/issue",
      subject: "actx:{actx}:plc:{did-plc-key}:role:{role}",
      createdAt: nowIso,
    });
  }

  async function provision(
    vm: VM,
    requesterDid: string,
    _spec?: DropletSpec,
  ): Promise<{ result: ProvisionResult; rbacRef?: StrongRef }> {
    if (!vm.user_data) {
      throw new Error(
        `an RFP for ${vm.role} arrived with no user_data. On this provider the user_data IS the ` +
          `guest: nothing else is baked into it at boot, so a guest started without one comes up ` +
          `with no sshd, no tunnel and no secrets, and reaches Running while being unreachable.`,
      );
    }
    const name = `fc-${shortId(requesterDid)}-${crypto.randomUUID().slice(0, 8)}`;
    const workDir = `${workRoot}/${name}`;
    const network = networkFor(rangeBase, nextIndex++);
    const userDataFile = `${workDir}/user-data.yaml`;
    await Deno.mkdir(workDir, { recursive: true });

    const enriched = ctx.oidcProvisioner
      ? await ctx.oidcProvisioner.enrich(vm.user_data, atproto.getAgentDid().split(":").slice(-1)[0], ctx.getIssuerUrl())
      : { userData: vm.user_data, nonce: "", associateWithDroplet: (_id: string) => {} };
    const reported = withOnNetworkBaseUrl(
      withOnNetworkReporter(enriched.userData, ctx.getIssuerUrl(), acceptPathVm),
      ctx.getIssuerUrl(),
    );
    await jsrRegistryReady;
    // Every name the guest resolves to this host is written against one address.
    // A requester that already named one (the harness passes `guestHostAliases`)
    // is kept: its line is in the document the guest boots with, and cloud-init
    // resolves a name before this step's runcmd can append a second line for it,
    // so the later line would be the one that never wins. With no such line, the
    // host is at the container's own gateway, which is where a guest that leaves
    // through pasta actually arrives -- see Microvm.hostAddressForGuest.
    const hostAddress = addressTheRequesterNamed(reported) ?? await ctx.microvm.hostAddressForGuest();
    const withJsr = injectJsrUrl(reported, `http://${hostAddress}:${jsrPort}`);
    const userData = pointGuestAtHost(withJsr, hostAddress, ctx.guestTlsPort);
    logger.info("guest_host_address", { name, hostAddress, jsrPort });
    await Deno.writeTextFile(userDataFile, userData);

    logger.info("provisioning microvm", { name, guestIp: network.guestIp, cpus: vm.cpus, mem: vm.mem });
    const dir = imageDir ?? (await ensureImage());
    const diskMib = diskTheGuestIsAskedFor(vm.disk);
    let booted;
    try {
      booted = await microvm.boot({
        name,
        imageDir: dir,
        workDir,
        userDataFile,
        vcpu: typeof vm.cpus === "number" && vm.cpus > 0 ? vm.cpus : undefined,
        memMib: parseMemMiB(vm.mem),
        diskMib,
        pastaArgs: ["-t", `${GUEST_SSH_BIND}/${GUEST_SSH_PORT}:${network.guestIp}`],
        network,
      });
    } catch (cause) {
      await Deno.remove(workDir, { recursive: true }).catch(() => {});
      throw cause;
    }
    enriched.associateWithDroplet(name);
    const guest: Guest = {
      name,
      workDir,
      network,
      userDataFile,
      requesterPlc: requesterDid.split(":").pop() ?? "",
      role: vm.role,
    };
    guests.set(name, guest);

    let rbacRef: StrongRef | undefined;
    if (ctx.rbacProvisioner) {
      const created = await ctx.rbacProvisioner.provision({ role: vm.role }, requesterDid, {
        getAgentDid: () => atproto.getAgentDid(),
        getIssuerUrl: () => ctx.getIssuerUrl(),
        createRecord: async (collection, record) => await atproto.createRecord(collection, record),
        parseAtUri,
      });
      if (created) rbacRef = { $type: "com.atproto.repo.strongRef", uri: created.uri, cid: "" };
    }
    if (rbacRef) rbacByProvider.set(name, rbacRef);

    logger.info("microvm provisioned", {
      name,
      guestIp: booted.guestIp,
      vmmPid: booted.vmmPid,
      fingerprint: booted.fingerprint,
    });
    return {
      result: {
        providerId: name,
        metadata: {
          name,
          ip: booted.guestIp,
          mode: "firecracker",
          sshReady: true,
          vmmPid: booted.vmmPid,
          console: booted.console,
          imageFingerprint: booted.fingerprint,
        },
      },
      rbacRef,
    };
  }

  async function destroy(id: string | number): Promise<void> {
    const name = String(id);
    const rbacRef = rbacByProvider.get(name);
    if (rbacRef) {
      const { collection, rkey } = parseAtUri(rbacRef.uri);
      await atproto.deleteRecord(collection, rkey).catch(() => {});
      rbacByProvider.delete(name);
    }
    const guest = guests.get(name);
    if (guest) {
      await microvm.stop(guest.workDir).catch((err: unknown) =>
        logger.warn("microvm_stop_failed", { name, error: String(err) })
      );
      guests.delete(name);
    }
  }

  function onConnected(app: Hono): void {
    const events = new Hono();
    events.post("/v1/on-network", async (c) => {
      const authHeader = c.req.header("Authorization");
      const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;
      if (!token) return c.json({ error: "AuthenticationRequired" }, 401);
      const validated = await OIDCToken.validate(token).catch(() => null);
      if (!validated) return c.json({ error: "InvalidToken" }, 401);
      let body: Record<string, unknown>;
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "InvalidRequest" }, 400);
      }
      const acceptUri = body.acceptUri as string | undefined;
      const acceptCid = body.acceptCid as string | undefined;
      if (!acceptUri || !acceptCid) {
        return c.json({ error: "InvalidRequest", message: "missing acceptUri or acceptCid" }, 400);
      }
      const acceptKey = `${acceptUri}#${acceptCid}`;
      const entry = ctx.acceptToContract?.get(acceptKey);
      if (!entry) {
        logger.warn("guest.onNetwork: unknown accept ref", { acceptKey });
        return c.json({ error: "UnknownAccept" }, 404);
      }
      const nowIso = (body.createdAt as string) ?? new Date().toISOString();
      const ref = await atproto.createRecord(ON_NETWORK_NSID, {
        $type: ON_NETWORK_NSID,
        address: body.address,
        createdAt: nowIso,
      });
      if (ctx.createSignedRepoRecord) {
        const { uri: eventUri, cid: eventCid, record: eventRecord } = await ctx.createSignedRepoRecord(
          EVENT_NSID,
          {
            $type: EVENT_NSID,
            receipt: { $type: "com.atproto.repo.strongRef", uri: entry.receiptUri, cid: entry.receiptCid },
            payload: { $type: "com.atproto.repo.strongRef", uri: ref.uri, cid: ref.cid },
          },
          atproto.getAgentDid(),
        );
        if (entry.submitEventUrl && ctx.callService) {
          ctx.callService(entry.submitEventUrl, SUBMIT_EVENT_NSID, SUBMIT_EVENT_NSID, {
            uri: eventUri,
            cid: eventCid,
            record: eventRecord,
          }).catch((err: unknown) => logger.warn("guest.onNetwork submitEvent failed", { error: String(err) }));
        }
        logger.info("guest.onNetwork recorded with event", { receiptKey: entry.receiptKey, uri: ref.uri });
      } else {
        logger.info("guest.onNetwork recorded (no event wrapper)", { uri: ref.uri, address: body.address });
      }
      return c.json({ ok: true, uri: ref.uri, cid: ref.cid });
    });
    app.route("/", events as never);
    logger.info("firecracker guest event routes mounted", {});
  }

  return { ensureImage, createBidConfig, provision, destroy, onConnected, guests };
}

export function parseMemMiB(mem: unknown): number | undefined {
  if (typeof mem !== "string") return undefined;
  const m = /^\s*(\d+)\s*([KMGT])?i?B?\s*$/i.exec(mem);
  if (!m) return undefined;
  const value = Number(m[1]);
  switch ((m[2] ?? "M").toUpperCase()) {
    case "K":
      return Math.max(1, Math.round(value / 1024));
    case "G":
      return value * 1024;
    case "T":
      return value * 1024 * 1024;
    default:
      return value;
  }
}

export function createFirecrackerComputeProvider(ctx: ComputeProviderFirecrackerCtx) {
  const inner = createComputeProviderFirecracker(ctx);

  // The droplet the issuer sees, which is not the droplet the market sees: the
  // prove handler resolves the guest's ssh host key by scanning it from inside
  // the container the guest runs in, so it needs that container's name, and it
  // rebuilds the subject of the token it issues out of the oidc-sub tags. Both
  // are properties of the guest this provider already holds.
  const dropletForIssuer = (id: string): Record<string, unknown> | undefined => {
    const guest = inner.guests.get(id);
    if (!guest) return undefined;
    return {
      id,
      containerName: guest.name,
      tags: [`oidc-sub:plc:${guest.requesterPlc}`, `oidc-sub:role:${guest.role}`],
      networks: { v4: [{ ip_address: guest.network.guestIp, type: "public" }] },
    };
  };

  ctx.serve.onConnected((ingressRef) => {
    inner.onConnected(ctx.serve.app);

    // The guest's user_data carries provisioning-token.service, which exchanges
    // the token it is handed at <issuer>/v1/oidc/prove for one that names the
    // requester's PLC and the role, and setup-secrets.service fetches the
    // accept bundle with it. The other providers that compose that same
    // user_data -- local and digitalocean -- each mount this issuer on their own
    // serve; without it here the route the guest is told to call answers 404,
    // the token exchange fails, no accept bundle is ever written, and the guest
    // reports no tunnel address, which reads as a guest that never joined
    // rather than as an issuer that was never mounted.
    const oidcIssuer = createOidcIssuer({
      getIssuerUrl: ctx.getIssuerUrl,
      getDroplet: dropletForIssuer,
      serviceUrl: didWebToHttps(ingressRef),
      log: (level: string, msg: string, extra?: Record<string, unknown>) => {
        const at = level as "info" | "warn" | "error" | "debug";
        if (typeof ctx.logger?.[at] === "function") ctx.logger[at](msg, extra);
      },
    });
    ctx.serve.app.route("/", oidcIssuer.app as never);
    ctx.logger?.info("firecracker oidc issuer mounted", { serviceUrl: didWebToHttps(ingressRef) });
  });
  const provider: ComputeProvider = {
    name: "firecracker",
    async provision(vm: VM, requesterDid: string, spec?: DropletSpec): Promise<ProvisionResult> {
      const { result } = await inner.provision(vm, requesterDid, spec);
      return result;
    },
    destroy: inner.destroy,
    createBidConfig: inner.createBidConfig,
    injectAcceptBundle: (userData: string, bundle: Record<string, unknown>) =>
      injectAcceptBundle(userData, bundle, ctx.acceptPathVm ?? DEFAULT_ACCEPT_PATH_VM),
    getDroplet: dropletForIssuer,
    setup: async () => {
      await inner.ensureImage();
    },
  };
  return { provider, ensureImage: inner.ensureImage, onConnected: inner.onConnected };
}
