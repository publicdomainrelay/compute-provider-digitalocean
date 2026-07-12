import { parse as yamlParse, stringify as yamlStringify } from "npm:yaml@^2.7.0";
import type { Logger, LoggerInterface, StructuredLoggerInterface } from "@publicdomainrelay/logger";
import type {
  ComputeAtproto,
  ComputeProvider,
  ComputeProviderCtx,
  DropletSpec,
  ProvisionResult,
  RbacProvisioner,
  StrongRef,
  VM,
} from "@publicdomainrelay/compute-provider-abc";
import { parseAtUri } from "@publicdomainrelay/atproto-helpers";
import type { ContainerBackend } from "@publicdomainrelay/container-backend-abc";
import type { OidcProvisioningEnricher } from "@publicdomainrelay/oidc-issuer-abc";
import { createOidcIssuer } from "@publicdomainrelay/oidc-issuer-hono";
import { createPackageRegistryFactory } from "@publicdomainrelay/hono-factory-package-registry";
import { Hono } from "@hono/hono";
import { createLocalFsStore } from "@publicdomainrelay/package-store-local-fs";
import type { ServeHandle } from "@publicdomainrelay/serve";

// Direct import needed for internal QEMU VM provisioning path.
// This is not an ABC violation: VM provisioning (QEMU + KVM) fundamentally
// requires Docker. It is separate from the container management abstraction.
import { createDockerBackend } from "@publicdomainrelay/container-backend-docker";
import { createContainerBackend } from "@publicdomainrelay/container-backend-container";

function didWebToHttps(didOrUrl: string): string {
  return didOrUrl.startsWith("did:web:") ? "https://" + didOrUrl.slice("did:web:".length) : didOrUrl;
}

export interface ComputeProviderLocalCtx extends ComputeProviderCtx {
  serve: ServeHandle;
  getIssuerUrl: () => string;
  acceptPathVm?: string;
  containerMode?: "vm" | "container";
  vmImage?: string;
  containerImage?: string;
  cacheDir?: string;
  containerBackend?: ContainerBackend;
  oidcProvisioner?: OidcProvisioningEnricher;
  rbacProvisioner?: RbacProvisioner;
  /** Base directory for the ephemeral JSR package registry. Defaults to org root. */
  jsrBaseDir?: string;
  /** Bidder-side PDS operations for guest event record creation. */
  createSignedRepoRecord?: (collection: string, record: Record<string, unknown>, issuer?: string) => Promise<{ uri: string; cid: string; record: Record<string, unknown> }>;
  callService?: (endpointUrl: string, nsid: string, lxm: string, body: Record<string, unknown>) => Promise<{ status: number; ok: boolean; body: unknown }>;
  acceptToContract?: Map<string, { receiptKey: string; receiptUri: string; receiptCid: string; submitEventUrl?: string }>;
}

type Distro = "fedora" | "ubuntu";

export interface ContainerOptions {
  distro?: Distro;
  memory?: string;
  imageTag?: string;
  containerName?: string;
  onIp?: (ip: string, containerName: string) => void | Promise<void>;
}

export interface ContainerInfo {
  ip: string;
  containerName: string;
  gateway: string;
}

const COMPUTE_CONFIG_WIF_SIMPLE_NSID =
  "com.publicdomainrelay.temp.compute.config.wif.simple";

const DEFAULT_ACCEPT_PATH_VM =
  "/root/secrets/publicdomainrelay.com/market/accept.json";

function getHomeDir(): string {
  const home = Deno.env.get("HOME");
  if (!home) throw new Error("HOME environment variable is not set.");
  return home;
}

const POLL_TIMEOUT_MS = 300_000;
const SSH_DEFAULT_PORT = 22;
const MEMORY_DEFAULT = "512m";

export const DEFAULT_USER_DATA = `#cloud-config
users:
  - name: agent
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
chpasswd:
  expire: False
  users:
  - name: agent
    password: agent
    type: text
ssh_pwauth: true
`;

function dropletSpecFromEnv(): {
  region?: string;
  size?: string;
  image?: string;
} {
  return {
    region: Deno.env.get("COMPUTE_PROVIDER_REGION") ?? "sfo3",
    size: Deno.env.get("COMPUTE_PROVIDER_SIZE") ?? "s-1vcpu-512mb-10gb",
    image: Deno.env.get("COMPUTE_PROVIDER_IMAGE") ?? "ubuntu",
  };
}

export function defaultCacheDir(): string {
  return `${getHomeDir()}/.cache/pdr-local`;
}

function shortUuid(): string {
  return crypto.randomUUID().slice(0, 8);
}

/**
 * Short, filesystem/container-name-safe id derived from an arbitrary string.
 * did:plc keys are already short (~24 chars); did:web hostnames can be
 * arbitrarily long (e.g. a did:key-derived subdomain), which overflows the
 * container runtime's 64-char name limit. Hash down to a fixed 12 hex chars.
 */
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

export async function pollSsh(
  host: string,
  port: number = SSH_DEFAULT_PORT,
  timeoutMs: number = POLL_TIMEOUT_MS,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const conn = await Deno.connect({ hostname: host, port });
      conn.close();
      return true;
    } catch {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  return false;
}

/**
 * Readiness probe that runs INSIDE the guest via `backend.exec`, checking that
 * sshd is listening on `port`. Unlike pollSsh, this never opens a host->guest
 * TCP socket, so it works on backends whose guest network the host cannot route
 * to from Deno.connect (e.g. macOS Apple `container` vmnet, which returns
 * "No route to host").
 */
export async function pollSshExec(
  backend: ContainerBackend,
  containerName: string,
  port: number = SSH_DEFAULT_PORT,
  timeoutMs: number = POLL_TIMEOUT_MS,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  const probe = `ss -H -tln 2>/dev/null | grep -q ':${port} ' || pgrep -x sshd >/dev/null 2>&1`;
  while (Date.now() < deadline) {
    try {
      const { code } = await backend.exec(containerName, ["bash", "-c", probe]);
      if (code === 0) return true;
    } catch {
      // container not up yet; keep polling
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

function imageTag(distro: Distro): string {
  return `container-runner-${distro}:latest`;
}

function generateEntrypoint(_distro: Distro): string {
  return `#!/bin/bash
set -e
echo "[container-entrypoint] Launching systemctl-shim as PID 1"

if [ -f /usr/local/bin/systemctl-shim.ts ]; then
  cat > /usr/local/bin/systemctl << 'SHEOF'
#!/bin/bash
exec deno run -A /usr/local/bin/systemctl-shim.ts "$@"
SHEOF
  chmod +x /usr/local/bin/systemctl
fi

exec deno run -A /usr/local/bin/systemctl-shim.ts --init
`;
}

function generateDockerfile(distro: Distro): string {
  const base = distro === "fedora"
    ? `FROM fedora:latest
RUN dnf install -y \\
    cloud-init openssh-server sudo curl jq util-linux rsyslog vim tmux git unzip python3 \\
  && dnf clean all`
    : `FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \\
    cloud-init openssh-server sudo curl jq util-linux rsyslog vim tmux git unzip ca-certificates locales python3 \\
  && rm -rf /var/lib/apt/lists/*`;

  return `${base}
RUN curl -fsSL https://deno.land/install.sh | DENO_INSTALL=/usr/local sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
`;
}

export async function buildContainerImage(
  backend: ContainerBackend,
  distro: Distro = "ubuntu",
): Promise<string> {
  const tag = imageTag(distro);

  if (await backend.imageExists(tag)) {
    console.log(`==> Image ${tag} already exists. Skipping build.`);
    return tag;
  }

  console.log(`==> Building container image for ${distro}...`);

  const buildDir = await Deno.makeTempDir({ prefix: "container-build-" });
  try {
    await Deno.writeTextFile(
      `${buildDir}/entrypoint.sh`,
      generateEntrypoint(distro),
    );
    await Deno.chmod(`${buildDir}/entrypoint.sh`, 0o755);

    await Deno.writeTextFile(
      `${buildDir}/Dockerfile`,
      generateDockerfile(distro),
    );

    const { code } = await backend.command([
      "build",
      "--pull",
      "--progress", "plain",
      "-t", tag,
      buildDir,
    ], { inherit: true });

    if (code !== 0) {
      throw new Error(`container build failed for ${tag}`);
    }

    console.log(`==> Built container image: ${tag}`);
    return tag;
  } finally {
    await Deno.remove(buildDir, { recursive: true }).catch(() => {});
  }
}

async function copySystemctlShim(
  distro: Distro,
  cacheDir: string,
): Promise<string> {
  const dst = `${cacheDir}/systemctl-shim-${distro}.ts`;
  // Check cache first — the caller may have pre-seeded the file to avoid
  // a runtime fetch (e.g. in compiled apps where fetch(file://…) may fail).
  try {
    const existing = await Deno.readTextFile(dst);
    if (existing.length > 0) return dst;
  } catch { /* not cached yet */ }
  const systemctlShimSrc = new URL(
    "./systemctl-shim.ts",
    import.meta.url,
  );
  const resp = await fetch(systemctlShimSrc);
  if (!resp.ok) throw new Error(`Failed to load systemctl-shim: ${resp.status}`);
  const content = await resp.text();
  await Deno.writeTextFile(dst, content);
  return dst;
}

export async function runContainer(
  backend: ContainerBackend,
  userData: string,
  opts: ContainerOptions = {},
): Promise<ContainerInfo> {
  const distro = opts.distro ?? "ubuntu";
  const tag = opts.imageTag ?? imageTag(distro);
  const memory = opts.memory ?? MEMORY_DEFAULT;
  const containerName = opts.containerName ??
    `container-${crypto.randomUUID().slice(0, 8)}`;

  console.log(`==> Starting container (${distro}, tag=${tag})`);

  if (!(await backend.imageExists(tag))) {
    console.log(`==> Image ${tag} not found. Building...`);
    await buildContainerImage(backend, distro);
  }

  const cacheDir = defaultCacheDir();
  await Deno.mkdir(cacheDir, { recursive: true });

  const udFile = await Deno.makeTempFile({
    dir: cacheDir,
    prefix: "container-ud-",
    suffix: ".yaml",
  });
  await Deno.writeTextFile(udFile, userData);

  const entrypointScript = generateEntrypoint(distro);
  const epFile = await Deno.makeTempFile({
    dir: cacheDir,
    prefix: "container-ep-",
    suffix: ".sh",
  });
  await Deno.writeTextFile(epFile, entrypointScript);
  await Deno.chmod(epFile, 0o755);

  const systemctlShimTag = await copySystemctlShim(distro, cacheDir);

  await backend.rm(containerName).catch(() => {});

  const runArgs: string[] = [
    "run", "-d",
    "--name", containerName,
    "--memory", memory,
  ];
  // --memory-swap is docker-only; container backend sets memory as VM limit
  if (backend.type === "docker") runArgs.push("--memory-swap", memory);
  runArgs.push(
    "-v", `${udFile}:/tmp/user-data:ro`,
    "-v", `${epFile}:/entrypoint.sh:ro`,
    "-v", `${systemctlShimTag}:/usr/local/bin/systemctl-shim.ts:ro`,
    "-e", "USER_DATA_FILE=/tmp/user-data",
    tag,
  );

  const { code, stderr } = await backend.command(runArgs);

  if (code !== 0) {
    await Deno.remove(udFile).catch(() => {});
    await Deno.remove(epFile).catch(() => {});
    throw new Error(
      `container run failed for ${containerName} (exit ${code}): ${stderr}`,
    );
  }

  await new Promise((r) => setTimeout(r, 1_000));
  const ip = await backend.inspectIp(containerName);
  console.log(`==> Container IP: ${ip}`);

  let gateway = ip;
  try {
    gateway = await backend.inspectGateway(containerName);
    console.log(`==> Container gateway: ${gateway}`);
  } catch {
    console.log(`==> Container gateway: (unavailable, using ip=${ip})`);
  }

  if (opts.onIp) await opts.onIp(ip, containerName);

  console.log("==> Waiting for SSH...");
  const ready = await pollSshExec(backend, containerName, 22);
  if (!ready) {
    await Deno.remove(udFile).catch(() => {});
    await Deno.remove(epFile).catch(() => {});
    await backend.rm(containerName).catch(() => {});
    throw new Error(
      `SSH not ready within timeout for ${containerName} (ip=${ip})`,
    );
  }

  console.log(`==> SSH ready! ssh agent@${ip}`);
  console.log(`    Container: ${containerName}`);

  await Deno.remove(udFile).catch(() => {});
  await Deno.remove(epFile).catch(() => {});

  return { ip, containerName, gateway };
}

async function provisionVM(
  vm: VM,
  containerName: string,
  user_data: string,
  ds: DropletSpec,
  cacheDir: string,
  vmImage: string,
  log: Logger,
): Promise<{ ip: string; sshReady: boolean }> {
  const docker = createDockerBackend();
  log("info", "provisioning VM", { containerName, image: vmImage });

  await docker.pullImage(vmImage);

  const udFile = `${cacheDir}/ud-${containerName}.yaml`;
  await Deno.writeTextFile(udFile, user_data);

  await docker.rm(containerName).catch(() => {});

  const { code, stderr } = await docker.command([
    "run", "-d",
    "--name", containerName,
    "--privileged",
    "--memory", "6g",
    "--memory-swap", "6g",
    "--device", "/dev/kvm",
    "-v", `${cacheDir}:/root/.cache/simple-qemu`,
    "-v", `${udFile}:/tmp/user-data:ro`,
    "-e", "USER_DATA_FILE=/tmp/user-data",
    vmImage,
    `--distro=${ds.image ?? "ubuntu"}`,
  ]);

  if (code !== 0) {
    throw new Error(`docker run failed for ${containerName}: ${stderr}`);
  }

  await new Promise((r) => setTimeout(r, 2_000));

  let ip = "0.0.0.0";
  try {
    ip = await docker.inspectIp(containerName);
    log("info", "VM container IP", { containerName, ip });
  } catch {
    log("warn", "could not get VM container IP", { containerName });
  }

  const sshReady = await pollSsh(ip, 22, POLL_TIMEOUT_MS);
  if (!sshReady) {
    log("warn", "SSH not ready within timeout", { containerName, ip });
  }

  return { ip, sshReady };
}

export interface SpawnVMOpts {
  droplet: Record<string, unknown>;
  userData: string;
  vmImage: string;
  containerMode: boolean;
  containerImage: string;
  cacheDir: string;
  log: LoggerInterface;
  backend: ContainerBackend;
  distro?: Distro;
}

export async function spawnVM(opts: SpawnVMOpts): Promise<void> {
  const { droplet, userData, vmImage, containerMode, containerImage, cacheDir, log, backend } = opts;
  const containerName = `droplet-${droplet["id"]}`;

  if (containerMode) {
    try {
      const distro = (droplet["image"] as Record<string, string>)?.slug ?? opts.distro ?? "ubuntu";
      const info = await runContainer(backend, userData, {
        distro: distro as Distro,
        containerName,
        imageTag: containerImage,
        onIp(ip: string, name: string) {
          droplet["networks"] = { v4: [{ ip_address: ip, type: "public" }] };
          droplet["containerName"] = name;
        },
      });
      droplet["networks"] = { v4: [{ ip_address: info.ip, type: "public" }] };
      droplet["containerName"] = info.containerName;
      droplet["status"] = "active";
      log.info("container droplet ready", { droplet_id: droplet["id"], ip: info.ip });
    } catch (err) {
      droplet["status"] = "off";
      log.error("container spawn failed", { droplet_id: droplet["id"], error: String(err) });
    }
    return;
  }

  await Deno.mkdir(cacheDir, { recursive: true });
  const udFile = await Deno.makeTempFile({ dir: cacheDir, prefix: "userdata-", suffix: ".yaml" });
  await Deno.writeTextFile(udFile, userData);

  const docker = createDockerBackend();
  await docker.rm(containerName).catch(() => {});

  const distro = (droplet["image"] as Record<string, string>)?.slug ?? "ubuntu";

  const { code } = await docker.command([
    "run", "-d",
    "--name", containerName,
    "--memory", "6g",
    "--memory-swap", "6g",
    "--device", "/dev/kvm",
    "-v", `${cacheDir}:/root/.cache/simple-qemu`,
    "-v", `${udFile}:/tmp/user-data:ro`,
    "-e", "USER_DATA_FILE=/tmp/user-data",
    vmImage,
    `--distro=${distro}`,
  ], { inherit: true });

  if (code !== 0) {
    droplet["status"] = "off";
    await Deno.remove(udFile).catch(() => {});
    return;
  }

  (async () => {
    try {
      await new Promise((r) => setTimeout(r, 2_000));
      const ip = await docker.inspectIp(containerName);
      log.info("container IP assigned", { droplet_id: droplet["id"], ip });
      const up = await pollSsh(ip);
      if (up) {
        droplet["networks"] = { v4: [{ ip_address: ip, type: "public" }] };
        droplet["containerName"] = containerName;
        droplet["status"] = "active";
        log.info("SSH ready", { droplet_id: droplet["id"], ip });
      } else {
        log.warn("SSH timeout", { droplet_id: droplet["id"], ip });
      }
    } catch (err) {
      log.error("IP/SSH probe failed", { droplet_id: droplet["id"], error: String(err) });
    } finally {
      await Deno.remove(udFile).catch(() => {});
    }
  })();
}

export function injectAcceptBundle(
  userData: string,
  bundle: Record<string, unknown>,
  acceptPathVm: string = DEFAULT_ACCEPT_PATH_VM,
): string {
  let obj: Record<string, unknown> = {};
  try {
    const parsed = userData
      ? yamlParse(userData.replace(/^#cloud-config\s*/i, ""))
      : null;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      obj = parsed as Record<string, unknown>;
    }
  } catch {
    /* fall through with empty obj */
  }

  const writeFiles = (obj["write_files"] as unknown[]) ?? (obj["write_files"] = []) as unknown[];
  writeFiles.push({
    path: acceptPathVm,
    owner: "root:root",
    permissions: "0600",
    content: JSON.stringify(bundle, null, 2),
  });

  const runcmd = (obj["runcmd"] as unknown[]) ?? (obj["runcmd"] = []) as unknown[];
  const parent = acceptPathVm.split("/").slice(0, -1).join("/");
  runcmd.unshift([
    "sh",
    "-c",
    `install -d -m 0700 -o root -g root ${parent}`,
  ]);

  return "#cloud-config\n" + yamlStringify(obj, { lineWidth: 0 });
}

interface LocalDroplet {
  id: string;
  name: string;
  networks: { v4: { ip_address: string; type: string }[] };
  tags: string[];
  containerName?: string;
}

export function createComputeProviderLocal(ctx: ComputeProviderLocalCtx) {
  const { atproto, getIssuerUrl, logger, oidcProvisioner, rbacProvisioner, serve } = ctx;
  const log: Logger = (level, message, meta) => {
    logger[level as "info" | "warn" | "error" | "debug"]?.(message, meta);
  };
  const backend: ContainerBackend = ctx.containerBackend ??
    (Deno.build.os === "darwin" ? createContainerBackend() : createDockerBackend());
  const acceptPathVm = ctx.acceptPathVm ?? DEFAULT_ACCEPT_PATH_VM;
  const containerMode = ctx.containerMode ??
    (Deno.env.get("CONTAINER_MODE") === "true" ? "container" : undefined) ??
    "container";
  const vmImage = ctx.vmImage ??
    Deno.env.get("VM_IMAGE") ??
    "atcr.io/johnandersen777.bsky.social/ccripoc-qemu-runner";
  const containerImage = ctx.containerImage ??
    Deno.env.get("CONTAINER_IMAGE") ??
    "container-runner-ubuntu:latest";
  const cacheDir = ctx.cacheDir ??
    Deno.env.get("CACHE_DIR") ??
    defaultCacheDir();

  serve.onConnected((ingressRef) => {
    const serviceUrl = didWebToHttps(ingressRef);
    const oidcIssuer = createOidcIssuer({
      getIssuerUrl,
      getDroplet: (id: string) => droplets.get(id) as Record<string, unknown> | undefined,
      serviceUrl,
      log: (level: string, msg: string, extra?: Record<string, unknown>) => {
        logger[level as "info" | "warn" | "error" | "debug"]?.(msg, extra);
      },
    });
    serve.app.route("/", oidcIssuer.app as never);
    logger.info("local oidc issuer mounted", { serviceUrl });

    // Ephemeral JSR registry — serves workspace packages to guest containers
    // over the same relay subdomain (reachable at https://<subdomain>.<host>/jsr/).
    const jsrBaseDir = ctx.jsrBaseDir ?? "../..";
    const jsrStore = createLocalFsStore({ baseDir: jsrBaseDir, fallbackVersion: "0.0.0" });
    const jsrFactory = createPackageRegistryFactory({ store: jsrStore, passthrough: false });
    serve.app.route("/", jsrFactory as never);
    logger.info("ephemeral jsr registry mounted", { jsrBaseDir, serviceUrl });

    // Guest onNetwork endpoint — VM calls back at boot with accept ref + FQDN.
    // Protected by OIDC Bearer token (same workload identity as /v1/oidc/issue).
    const eventsApp = new Hono();
    eventsApp.post("/v1/on-network", async (c) => {
      // Validate OIDC Bearer token
      const authHeader = c.req.header("Authorization");
      const token = (authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null);
      if (!token) return c.json({ error: "AuthenticationRequired" }, 401);
      try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        if (typeof payload.exp === "number" && payload.exp * 1000 < Date.now()) {
          return c.json({ error: "TokenExpired" }, 401);
        }
      } catch { return c.json({ error: "InvalidToken" }, 401); }
      let body: Record<string, unknown>;
      try { body = await c.req.json(); } catch {
        return c.json({ error: "InvalidRequest" }, 400);
      }
      const acceptUri = body.acceptUri as string | undefined;
      const acceptCid = body.acceptCid as string | undefined;
      if (!acceptUri || !acceptCid) {
        return c.json({ error: "InvalidRequest", message: "missing acceptUri or acceptCid" }, 400);
      }
      // Look up receipt via acceptToContract map
      const acceptKey = `${acceptUri}#${acceptCid}`;
      const guestEntry = ctx.acceptToContract?.get(acceptKey);
      if (!guestEntry) {
        logger.warn("guest.onNetwork: unknown accept ref", { acceptKey });
        return c.json({ error: "UnknownAccept" }, 404);
      }
      const nowIso = (body.createdAt as string) ?? new Date().toISOString();
      const ref = await atproto.createRecord(
        "com.publicdomainrelay.temp.compute.events.vm.onNetwork",
        { $type: "com.publicdomainrelay.temp.compute.events.vm.onNetwork", address: body.address, createdAt: nowIso },
      );
      // Wrap in market.event with receipt strongRef
      if (ctx.createSignedRepoRecord) {
        const { uri: eventUri, cid: eventCid, record: eventRecord } = await ctx.createSignedRepoRecord(
          "com.publicdomainrelay.temp.market.event", {
            $type: "com.publicdomainrelay.temp.market.event",
            receipt: { $type: "com.atproto.repo.strongRef", uri: guestEntry.receiptUri, cid: guestEntry.receiptCid },
            payload: { $type: "com.atproto.repo.strongRef", uri: ref.uri, cid: ref.cid },
          }, "");
        // Push to requester if submitEventUrl exists
        if (guestEntry.submitEventUrl && ctx.callService) {
          ctx.callService(guestEntry.submitEventUrl, "com.publicdomainrelay.temp.market.submitEvent", "com.publicdomainrelay.temp.market.submitEvent", {
            uri: eventUri, cid: eventCid, record: eventRecord,
          }).catch((err: unknown) => logger.warn("guest.onNetwork submitEvent failed", { error: String(err) }));
        }
        logger.info("guest.onNetwork recorded with event", { receiptKey: guestEntry.receiptKey, uri: ref.uri, eventUri });
      } else {
        logger.info("guest.onNetwork recorded (no event wrapper)", { uri: ref.uri, address: body.address });
      }
      return c.json({ ok: true, uri: ref.uri, cid: ref.cid });
    });
    serve.app.route("/", eventsApp as never);
    logger.info("guest event routes mounted", { serviceUrl });
  });

  const droplets = new Map<string, LocalDroplet>();

  async function provisionLocal(
    vm: VM,
    requesterDid: string,
    spec?: DropletSpec,
  ): Promise<{ result: ProvisionResult; rbacRef?: StrongRef }> {
    const ds = spec ?? dropletSpecFromEnv();
    const agentDid = atproto.getAgentDid();
    const agentDidPlc = agentDid.split(":").pop() ?? "unknown";
    // did:plc keys are short and stay human-legible in the container name;
    // did:web (e.g. a did:key-derived subdomain) can be arbitrarily long, so
    // it gets hashed down instead of overflowing the container name limit.
    // Full value: used for RBAC/OIDC subject matching, must stay exactly
    // what rbacProvisioner.provision() derives from requesterDid elsewhere.
    const requesterPlc = requesterDid.split(":").pop() ?? "unknown";
    // Shortened: container-name-safe only. did:plc keys are short and stay
    // human-legible; did:web (e.g. a did:key-derived subdomain) can be
    // arbitrarily long and overflows the container runtime's 64-char limit.
    const containerRequesterPlc = requesterPlc.length > 20 ? shortId(requesterPlc) : requesterPlc;
    const rfpRkey = (vm._uri ?? "").split("/")[4] ?? "unknown";
    const containerName = `pdr-${containerRequesterPlc}-${rfpRkey}-${shortUuid()}`;

    await Deno.mkdir(cacheDir, { recursive: true });

    let rbacRef: StrongRef | undefined;
    if (rbacProvisioner) {
      logger.info("provision rbac write", {
        repo: agentDid,
        actx: agentDidPlc,
        requesterPlc,
        role: vm.role,
        service: getIssuerUrl(),
      });
      rbacRef = await rbacProvisioner.provision(vm, requesterDid, {
        getAgentDid: () => atproto.getAgentDid(),
        getIssuerUrl,
        createRecord: (collection: string, record: Record<string, unknown>) =>
          atproto.createRecord(collection, record),
        parseAtUri,
      }) as StrongRef | undefined;
      logger.info("provision rbac written", { uri: rbacRef?.uri });
    } else {
      logger.warn("provision rbac skipped", { reason: "no rbacProvisioner" });
    }

    const droplet: LocalDroplet = {
      id: containerName,
      name: containerName,
      networks: { v4: [] },
      tags: [`oidc-sub:plc:${requesterPlc}`, `oidc-sub:role:${vm.role}`],
    };
    droplets.set(containerName, droplet);

    const user_data = vm.user_data ?? DEFAULT_USER_DATA;

    logger.info("provision token config", {
      teamUuid: agentDidPlc,
      issuerUrl: getIssuerUrl(),
      containerName,
    });
    const enriched = oidcProvisioner
      ? await oidcProvisioner.enrich(user_data, agentDidPlc, getIssuerUrl())
      : { userData: user_data, nonce: "", associateWithDroplet: () => {} };
    let enrichedUserData = enriched.userData;
    // Inject JSR_URL — points to provider's serve root where JSR is mounted.
    const jsrUrl = getIssuerUrl();
    enrichedUserData = enrichedUserData.replace(
      /(ExecStart=deno run .*tunnel-subscriber)/,
      `Environment="JSR_URL=${jsrUrl}"\n      $1`,
    );
    enriched.associateWithDroplet(containerName);

    if (containerMode === "container") {
      logger.info("provisioning container", {
        containerName,
        image: containerImage,
      });

      const info = await runContainer(backend, enrichedUserData, {
        distro: (ds.image as Distro | undefined) ?? "ubuntu",
        containerName,
        imageTag: containerImage,
        onIp: (ip, name) => {
          droplet.networks.v4 = [{ ip_address: ip, type: "public" }];
          droplet.containerName = name;
        },
      });

      droplet.networks.v4 = [{ ip_address: info.ip, type: "public" }];
      droplet.containerName = info.containerName;

      return {
        result: {
          providerId: containerName,
          metadata: {
            containerName,
            ip: info.ip,
            mode: "container",
            sshReady: true,
          },
        },
        rbacRef,
      };
    }

    const { ip, sshReady } = await provisionVM(
      vm,
      containerName,
      enrichedUserData,
      ds,
      cacheDir,
      vmImage,
      log,
    );

    droplet.networks.v4 = [{ ip_address: ip, type: "public" }];
    droplet.containerName = containerName;

    return {
      result: {
        providerId: containerName,
        metadata: {
          containerName,
          ip,
          mode: "vm",
          sshReady,
        },
      },
      rbacRef,
    };
  }

  async function destroyLocal(id: string | number): Promise<void> {
    const name = String(id);
    logger.info("destroying container", { containerName: name });
    await backend.kill(name).catch(() => {});
    await backend.rm(name).catch(() => {});
    droplets.delete(name);
  }

  async function createBidConfig(nowIso: string): Promise<StrongRef> {
    const agentDid = atproto.getAgentDid();
    return await atproto.createRecord(COMPUTE_CONFIG_WIF_SIMPLE_NSID, {
      $type: COMPUTE_CONFIG_WIF_SIMPLE_NSID,
      accept_path: acceptPathVm,
      issuer_uri: getIssuerUrl(),
      to_issue: "exchange-custom-droplet-oidc-poc",
      actx: agentDid.split(":").slice(-1)[0],
      actx_path: "/root/secrets/digitalocean.com/serviceaccount/team_uuid",
      token_path: "/root/secrets/digitalocean.com/serviceaccount/token",
      url_path: "/root/secrets/digitalocean.com/serviceaccount/base_url",
      url_route: "/v1/oidc/issue",
      subject: "actx:{actx}:plc:{did-plc-key}:role:{role}",
      createdAt: nowIso,
    });
  }

  async function ensureImage(distro: Distro = "ubuntu"): Promise<void> {
    if (containerMode !== "container") return;
    await buildContainerImage(backend, distro);
  }

  return {
    provisionLocal,
    destroyLocal,
    createBidConfig,
    injectAcceptBundle: (userData: string, bundle: Record<string, unknown>) =>
      injectAcceptBundle(userData, bundle, acceptPathVm),
    getDroplet: (id: string): Record<string, unknown> | undefined =>
      droplets.get(id) as Record<string, unknown> | undefined,
    ensureImage,
  };
}

export function createLocalComputeProvider(
  ctx: ComputeProviderLocalCtx,
): ComputeProvider {
  const {
    provisionLocal,
    destroyLocal,
    createBidConfig,
    injectAcceptBundle: injectBundle,
    getDroplet,
    ensureImage,
  } = createComputeProviderLocal(ctx);

  const rbacByProvider = new Map<string | number, StrongRef>();

  return {
    name: "local",

    async provision(
      vm: VM,
      requesterDid: string,
      spec?: DropletSpec,
    ): Promise<ProvisionResult> {
      const { result, rbacRef } = await provisionLocal(vm, requesterDid, spec);
      if (rbacRef) rbacByProvider.set(result.providerId, rbacRef);
      return result;
    },

    async destroy(id: string | number): Promise<void> {
      const rbacRef = rbacByProvider.get(id);
      if (rbacRef) {
        const { collection, rkey } = parseAtUri(rbacRef.uri);
        await ctx.atproto.deleteRecord(collection, rkey).catch(() => {});
        rbacByProvider.delete(id);
      }
      await destroyLocal(id);
    },

    createBidConfig,
    injectAcceptBundle: injectBundle,
    getDroplet,
    ensureImage,
  } as ComputeProvider & { ensureImage(): Promise<void> };
}
