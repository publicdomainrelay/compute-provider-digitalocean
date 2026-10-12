import { Hono } from "@hono/hono";
import {
  addressTheRequesterNamed,
  DEFAULT_GUEST_RANGE_BASE,
  EVENT_NSID,
  type GuestNetwork,
  injectAcceptBundle,
  networkFor,
  ON_NETWORK_NSID,
  parseMemMiB,
  pointGuestAtHost,
  SECRETS_PREFIX,
  shortId,
  SUBMIT_EVENT_NSID,
  WIF_SIMPLE_NSID,
  withOnNetworkBaseUrl,
  withOnNetworkReporter,
} from "@publicdomainrelay/compute-provider-common";
import type {
  AdoptResult,
  ComputeAtproto,
  ComputeProvider,
  ComputeProviderCtx,
  DropletSpec,
  GuestGone,
  GuestHostKeysAck,
  GuestHostKeysHandler,
  ProvisionResult,
  StrongRef,
  VM,
} from "@publicdomainrelay/compute-provider-abc";
import { GuestHostKeysRelay } from "@publicdomainrelay/compute-provider-abc";
import type { NodeImageStore } from "@publicdomainrelay/node-image-abc";
import type { Microvm, MicrovmExit } from "@publicdomainrelay/microvm-firecracker";
import {
  createOidcIssuer,
  type HostKeysReported,
  type JwkStore,
  type NonceStore,
} from "@publicdomainrelay/oidc-issuer-hono";
import { parseAtUri } from "@publicdomainrelay/atproto-helpers";
import { DEFAULT_ACCEPT_PATH_VM } from "@publicdomainrelay/secrets-common";

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
  oidcProvisioning?: boolean;
  oidcJwkStore?: JwkStore;
  oidcNonceStore?: NonceStore;
  hostBootId?: () => Promise<string>;
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
  network: GuestNetwork;
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

const GUEST_NAME = /^fc-[0-9a-f]+-[0-9a-f]+$/;

const GUEST_RECORD = "guest.json";

const BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id";

interface GuestRecord {
  version: 1;
  guest: Guest;
  index: number;
  hostBootId: string;
}

export async function readHostBootId(): Promise<string> {
  try {
    return (await Deno.readTextFile(BOOT_ID_PATH)).trim();
  } catch {
    return "";
  }
}

async function readGuestRecord(workDir: string): Promise<GuestRecord | undefined> {
  let raw: string;
  try {
    raw = await Deno.readTextFile(`${workDir}/${GUEST_RECORD}`);
  } catch {
    return undefined;
  }
  try {
    const parsed = JSON.parse(raw) as GuestRecord;
    if (parsed?.version !== 1 || typeof parsed.guest?.name !== "string" || typeof parsed.index !== "number") {
      return undefined;
    }
    return parsed;
  } catch {
    return undefined;
  }
}

export function createComputeProviderFirecracker(ctx: ComputeProviderFirecrackerCtx) {
  const { logger, atproto, image, microvm, workRoot } = ctx;
  const acceptPathVm = ctx.acceptPathVm ?? DEFAULT_ACCEPT_PATH_VM;
  const rangeBase = ctx.rangeBase ?? DEFAULT_GUEST_RANGE_BASE;
  const hostBootId = ctx.hostBootId ?? readHostBootId;

  const guests = new Map<string, Guest>();

  const dropletForIssuer = (id: string): Record<string, unknown> | undefined => {
    const guest = guests.get(id);
    if (!guest) return undefined;
    return {
      id,
      tags: [`oidc-sub:plc:${guest.requesterPlc}`, `oidc-sub:role:${guest.role}`],
    };
  };

  const hostKeys = new GuestHostKeysRelay();
  const onHostKeys = (handler: GuestHostKeysHandler): () => void => hostKeys.onHostKeys(handler);
  const dropNonces = (name: string): void => hostKeys.forget(name);

  const forwardHostKeys = async (report: HostKeysReported): Promise<GuestHostKeysAck> => {
    const ack = await hostKeys.forward(report, new Date().toISOString());
    if (ack.id === undefined) logger.warn("guest_hostkeys_unknown_guest", {});
    else if (ack.status === 503) logger.warn("guest_hostkeys_no_listener", { name: ack.id });
    else logger.info("guest_hostkeys_forwarded", { name: ack.id, ok: ack.ok, status: ack.status, reason: ack.reason });
    return ack;
  };

  const oidcIssuer = createOidcIssuer({
    getIssuerUrl: ctx.getIssuerUrl,
    getDroplet: dropletForIssuer,
    onHostKeys: forwardHostKeys,
    store: ctx.oidcJwkStore,
    nonceStore: ctx.oidcNonceStore,
    log: (level: string, msg: string, extra?: Record<string, unknown>) => {
      const at = level as "info" | "warn" | "error" | "debug";
      if (typeof ctx.logger?.[at] === "function") ctx.logger[at](msg, extra);
    },
  });
  const rbacByProvider = new Map<string | number, StrongRef>();
  const watches = new Map<string, () => void>();
  const goneListeners = new Set<(gone: GuestGone) => void>();
  let nextIndex = 0;
  let imageDir: string | undefined;
  let imageRootfsMiB: number | undefined;

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
          `with no sshd, no iroh listener and no secrets, and reaches Running while being unreachable.`,
      );
    }
    const name = `fc-${shortId(requesterDid)}-${crypto.randomUUID().slice(0, 8)}`;
    const workDir = `${workRoot}/${name}`;
    const index = nextIndex++;
    const network = networkFor(rangeBase, index);
    const userDataFile = `${workDir}/user-data.yaml`;
    await Deno.mkdir(workDir, { recursive: true });
    const guest: Guest = {
      name,
      workDir,
      network,
      userDataFile,
      requesterPlc: requesterDid.split(":").pop() ?? "",
      role: vm.role,
    };
    const record: GuestRecord = { version: 1, guest, index, hostBootId: await hostBootId() };
    await Deno.writeTextFile(`${workDir}/${GUEST_RECORD}`, JSON.stringify(record, null, 2));

    const enriched = ctx.oidcProvisioning
      ? await oidcIssuer.provisioningEnricher.enrich(vm.user_data, atproto.getAgentDid().split(":").slice(-1)[0])
      : { userData: vm.user_data, nonce: "", associateWithDroplet: (_id: string) => {} };
    hostKeys.bindNonce(enriched.nonce, name);
    const reported = withOnNetworkBaseUrl(
      withOnNetworkReporter(enriched.userData, ctx.getIssuerUrl(), acceptPathVm),
      ctx.getIssuerUrl(),
    );
    // Every name the guest resolves to this host is written against one address.
    // A requester that already named one (the harness passes `guestHostAliases`)
    // is kept: its line is in the document the guest boots with, and cloud-init
    // resolves a name before this step's runcmd can append a second line for it,
    // so the later line would be the one that never wins. With no such line, the
    // host is at the container's own gateway, which is where a guest that leaves
    // through pasta actually arrives -- see Microvm.hostAddressForGuest.
    const hostAddress = addressTheRequesterNamed(reported) ?? await ctx.microvm.hostAddressForGuest();
    const userData = pointGuestAtHost(reported, hostAddress, ctx.guestTlsPort);
    logger.info("guest_host_address", { name, hostAddress });
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
        network,
      });
    } catch (cause) {
      await microvm.stop(workDir).catch((err: unknown) =>
        logger.warn("microvm_stop_failed", { name, error: String(err) })
      );
      throw cause;
    }
    enriched.associateWithDroplet(name);
    guests.set(name, guest);
    watchGuest(name, booted.container);

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

  async function releaseRbac(name: string): Promise<void> {
    const rbacRef = rbacByProvider.get(name);
    if (!rbacRef) return;
    rbacByProvider.delete(name);
    const { collection, rkey } = parseAtUri(rbacRef.uri);
    await atproto.deleteRecord(collection, rkey).catch(() => {});
  }

  function workDirOf(name: string): string | undefined {
    return guests.get(name)?.workDir ?? (GUEST_NAME.test(name) ? `${workRoot}/${name}` : undefined);
  }

  function watchGuest(name: string, container: string): void {
    watches.set(
      name,
      microvm.watch(container, (exit) => {
        guestExited(name, exit).catch((err: unknown) =>
          logger.warn("microvm_exit_handling_failed", { name, error: String(err) })
        );
      }),
    );
  }

  async function adopt(id: string | number): Promise<AdoptResult> {
    const name = String(id);
    const workDir = workDirOf(name);
    if (!workDir) {
      logger.warn("microvm_adopt_unknown", { name });
      return { state: "gone", gone: { id, reason: "vmm_exited" } };
    }
    if (watches.has(name)) return { state: "running" };
    const record = await readGuestRecord(workDir);
    const state = microvm.inspect ? await microvm.inspect(name) : { exists: true, running: true };
    if (state.running) {
      if (record) {
        guests.set(name, { ...record.guest, workDir });
        nextIndex = Math.max(nextIndex, record.index + 1);
      }
      watchGuest(name, name);
      logger.info("microvm_adopted", { name, workDir, guestIp: record?.guest.network.guestIp });
      return { state: "running" };
    }
    const bootNow = await hostBootId();
    const reason = record?.hostBootId && bootNow && record.hostBootId !== bootNow ? "host_reboot" : "vmm_exited";
    guests.delete(name);
    dropNonces(name);
    await releaseRbac(name);
    await microvm.stop(workDir).catch((err: unknown) =>
      logger.warn("microvm_stop_failed", { name, error: String(err) })
    );
    logger.warn("microvm_gone_at_adopt", {
      name,
      reason,
      containerExists: state.exists,
      exitCode: state.exitCode,
      bootIdThen: record?.hostBootId,
      bootIdNow: bootNow,
    });
    const gone: GuestGone = state.exitCode === undefined
      ? { id: name, reason }
      : { id: name, reason, exitCode: state.exitCode };
    return { state: "gone", gone };
  }

  async function guestExited(name: string, exit: MicrovmExit): Promise<void> {
    watches.delete(name);
    const workDir = guests.get(name)?.workDir ?? workDirOf(name);
    guests.delete(name);
    dropNonces(name);
    if (!workDir) return;
    logger.warn("microvm_exited", {
      name,
      reason: exit.reason,
      exitCode: exit.exitCode,
      logs: exit.logs.slice(-2000),
    });
    await releaseRbac(name);
    await microvm.stop(workDir).catch((err: unknown) =>
      logger.warn("microvm_stop_failed", { name, error: String(err) })
    );
    const gone: GuestGone = { id: name, reason: `runner container ${exit.reason}`, exitCode: exit.exitCode };
    for (const listener of goneListeners) {
      try {
        listener(gone);
      } catch (err) {
        logger.warn("guest_gone_listener_failed", { name, error: String(err) });
      }
    }
  }

  function onGuestGone(listener: (gone: GuestGone) => void): () => void {
    goneListeners.add(listener);
    return () => goneListeners.delete(listener);
  }

  async function destroy(id: string | number): Promise<void> {
    const name = String(id);
    watches.get(name)?.();
    watches.delete(name);
    await releaseRbac(name);
    const workDir = workDirOf(name);
    guests.delete(name);
    dropNonces(name);
    if (!workDir) {
      logger.warn("microvm_destroy_unknown", { name });
      return;
    }
    await microvm.stop(workDir).catch((err: unknown) =>
      logger.warn("microvm_stop_failed", { name, error: String(err) })
    );
  }

  function onConnected(app: Hono): void {
    const events = new Hono();
    events.post("/v1/on-network", async (c) => {
      const authHeader = c.req.header("Authorization");
      const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;
      if (!token) return c.json({ error: "AuthenticationRequired" }, 401);
      const validated = await oidcIssuer.validateToken(token).catch(() => null);
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

  return {
    ensureImage,
    createBidConfig,
    provision,
    destroy,
    adopt,
    onConnected,
    onGuestGone,
    onHostKeys,
    guests,
    dropletForIssuer,
    oidcIssuer,
  };
}

export function createFirecrackerComputeProvider(ctx: ComputeProviderFirecrackerCtx) {
  const inner = createComputeProviderFirecracker(ctx);

  ctx.serve.onConnected((ingressRef) => {
    inner.onConnected(ctx.serve.app);
    ctx.serve.app.route("/", inner.oidcIssuer.app as never);
    ctx.logger?.info("firecracker oidc issuer mounted", { serviceUrl: didWebToHttps(ingressRef) });
  });
  const provider: ComputeProvider = {
    name: "firecracker",
    async provision(vm: VM, requesterDid: string, spec?: DropletSpec): Promise<ProvisionResult> {
      const { result } = await inner.provision(vm, requesterDid, spec);
      return result;
    },
    destroy: inner.destroy,
    adopt: inner.adopt,
    onGuestGone: inner.onGuestGone,
    onHostKeys: inner.onHostKeys,
    createBidConfig: inner.createBidConfig,
    injectAcceptBundle: (userData: string, bundle: Record<string, unknown>) =>
      injectAcceptBundle(userData, bundle, ctx.acceptPathVm ?? DEFAULT_ACCEPT_PATH_VM),
    getDroplet: inner.dropletForIssuer,
    setup: async () => {
      await inner.ensureImage();
    },
  };
  return { provider, ensureImage: inner.ensureImage, onConnected: inner.onConnected, oidcIssuer: inner.oidcIssuer };
}
