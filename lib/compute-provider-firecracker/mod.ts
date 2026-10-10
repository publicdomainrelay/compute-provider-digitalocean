import { Hono } from "@hono/hono";
import { parse as yamlParse, stringify as yamlStringify } from "npm:yaml@^2.7.0";
import { acceptBundleModule, buildUserData, getUserDataModules } from "@publicdomainrelay/cloud-init-common";
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
import { OIDCToken } from "@publicdomainrelay/oidc-issuer-hono";
import { parseAtUri } from "@publicdomainrelay/atproto-helpers";
import { DEFAULT_ACCEPT_PATH_VM } from "@publicdomainrelay/secrets-common";

export const WIF_SIMPLE_NSID = "com.publicdomainrelay.temp.compute.config.wif.simple";

export const ON_NETWORK_NSID = "com.publicdomainrelay.temp.compute.events.vm.onNetwork";

export const EVENT_NSID = "com.publicdomainrelay.temp.market.event";

export const SUBMIT_EVENT_NSID = "com.publicdomainrelay.temp.market.submitEvent";

export const SECRETS_PREFIX = "/root/secrets/firecracker/serviceaccount";

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
    const userData = pointGuestAtHost(enriched.userData, network.gateway, ctx.guestTlsPort);
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
    const guest: Guest = { name, workDir, network, userDataFile };
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
  ctx.serve.onConnected(() => {
    inner.onConnected(ctx.serve.app);
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
    getDroplet: (id: string) => {
      const guest = inner.guests.get(id);
      return guest ? { id, networks: { v4: [{ ip_address: guest.network.guestIp, type: "public" }] } } : undefined;
    },
    setup: async () => {
      await inner.ensureImage();
    },
  };
  return { provider, ensureImage: inner.ensureImage, onConnected: inner.onConnected };
}
