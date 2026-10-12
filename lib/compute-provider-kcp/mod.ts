import {
  injectAcceptBundle,
  pointGuestAtHost,
  SECRETS_PREFIX,
  shortId,
  WIF_SIMPLE_NSID,
  withOnNetworkBaseUrl,
  withOnNetworkReporter,
} from "@publicdomainrelay/compute-provider-common";
import type {
  AdoptResult,
  ComputeProvider,
  ComputeProviderCtx,
  GuestGone,
  GuestHostKeysHandler,
  GuestHostKeysRelay,
  ProvisionResult,
  RbacProvisioner,
  StrongRef,
  VM,
} from "@publicdomainrelay/compute-provider-abc";
import {
  ComputeVMCache,
  type ComputeVMChange,
  computeVMFor,
  dropletOf,
  endedMessage,
  goneOf,
  hasEnded,
  isReleasing,
  phaseOf,
  type UserDataSecret,
  userDataSecretFor,
  userDataSecretName,
} from "@publicdomainrelay/compute-provider-kcp-abc";
import {
  assertComputeVM,
  COMPUTE_VM_RESOURCE,
  type ComputeVM,
  FIELD_MANAGER_COMPUTE_VM_PROVIDER,
  parseComputeVM,
  USER_DATA_SECRET_NAMESPACE,
} from "@publicdomainrelay/compute-provider-kcp-common";
import type { OidcProvisioningEnricher } from "@publicdomainrelay/oidc-issuer-abc";
import { parseAtUri } from "@publicdomainrelay/atproto-helpers";
import { DEFAULT_ACCEPT_PATH_VM } from "@publicdomainrelay/secrets-common";

export interface KcpCredentials {
  server: string;
  workspace: string;
  token?: string;
  tokenFile?: string;
  caFile?: string;
}

export interface KcpComputeVMClientOptions {
  credentials: KcpCredentials;
  fetch?: typeof fetch;
  timeoutMs?: number;
  watchTimeoutSeconds?: number;
}

export class KcpRequestError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = "KcpRequestError";
  }
}

export interface ComputeVMWatchEvent {
  type: "ADDED" | "MODIFIED" | "DELETED" | "BOOKMARK" | "ERROR";
  object: unknown;
}

export interface ComputeVMList {
  items: ComputeVM[];
  resourceVersion: string;
}

export interface KcpComputeVMClient {
  apply(vm: ComputeVM): Promise<ComputeVM>;
  get(name: string): Promise<ComputeVM | null>;
  list(): Promise<ComputeVMList>;
  watch(resourceVersion: string, signal: AbortSignal): AsyncGenerator<ComputeVMWatchEvent>;
  delete(name: string): Promise<boolean>;
  applySecret(secret: UserDataSecret): Promise<void>;
  deleteSecret(name: string): Promise<boolean>;
}

const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
const DEFAULT_WATCH_TIMEOUT_SECONDS = 300;

export function createKcpComputeVMClient(opts: KcpComputeVMClientOptions): KcpComputeVMClient {
  const creds = opts.credentials;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  const watchTimeoutSeconds = opts.watchTimeoutSeconds ?? DEFAULT_WATCH_TIMEOUT_SECONDS;
  const baseFetch = opts.fetch ?? fetch;
  const server = creds.server.replace(/\/+$/, "");
  const { group, version, plural } = COMPUTE_VM_RESOURCE;
  const vmBase = `${server}/clusters/${creds.workspace}/apis/${group}/${version}/${plural}`;
  const secretBase = `${server}/clusters/${creds.workspace}/api/v1/namespaces/${USER_DATA_SECRET_NAMESPACE}/secrets`;
  const applyQuery = `?fieldManager=${encodeURIComponent(FIELD_MANAGER_COMPUTE_VM_PROVIDER)}&force=true`;
  let httpClient: Promise<Deno.HttpClient | undefined> | undefined;

  function clientForCa(): Promise<Deno.HttpClient | undefined> {
    if (!creds.caFile || opts.fetch) return Promise.resolve(undefined);
    httpClient ??= Deno.readTextFile(creds.caFile).then((ca) => Deno.createHttpClient({ caCerts: [ca] }));
    return httpClient;
  }

  async function bearer(): Promise<string | undefined> {
    if (creds.tokenFile) {
      const token = (await Deno.readTextFile(creds.tokenFile)).trim();
      if (token) return token;
    }
    return creds.token;
  }

  async function send(url: string, init: RequestInit): Promise<Response> {
    const headers = new Headers(init.headers);
    headers.set("accept", "application/json");
    const token = await bearer();
    if (token) headers.set("authorization", `Bearer ${token}`);
    const client = await clientForCa();
    return await baseFetch(url, { ...init, headers, ...(client ? { client } : {}) } as RequestInit);
  }

  async function request(url: string, init: RequestInit = {}): Promise<unknown> {
    const res = await send(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    const text = await res.text();
    if (!res.ok) {
      throw new KcpRequestError(
        res.status,
        `${init.method ?? "GET"} ${new URL(url).pathname}: ${res.status} ${text.slice(0, 300)}`,
      );
    }
    return text ? JSON.parse(text) : null;
  }

  async function absentOn404<T>(work: Promise<T>): Promise<T | null> {
    try {
      return await work;
    } catch (err) {
      if (err instanceof KcpRequestError && err.status === 404) return null;
      throw err;
    }
  }

  function applyInit(body: unknown): RequestInit {
    return {
      method: "PATCH",
      headers: { "content-type": "application/apply-patch+yaml" },
      body: JSON.stringify(body),
    };
  }

  const item = (name: string) => `${vmBase}/${encodeURIComponent(name)}`;
  const secretItem = (name: string) => `${secretBase}/${encodeURIComponent(name)}`;

  async function* watch(resourceVersion: string, signal: AbortSignal): AsyncGenerator<ComputeVMWatchEvent> {
    const query = new URLSearchParams({
      watch: "true",
      resourceVersion,
      allowWatchBookmarks: "true",
      timeoutSeconds: String(watchTimeoutSeconds),
    });
    const res = await send(`${vmBase}?${query}`, { signal });
    if (!res.ok || !res.body) {
      const text = await res.text().catch(() => "");
      throw new KcpRequestError(res.status, `watch ${new URL(vmBase).pathname}: ${res.status} ${text.slice(0, 300)}`);
    }
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
    let buffered = "";
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffered += value;
        let newline = buffered.indexOf("\n");
        while (newline >= 0) {
          const line = buffered.slice(0, newline).trim();
          buffered = buffered.slice(newline + 1);
          if (line) yield JSON.parse(line) as ComputeVMWatchEvent;
          newline = buffered.indexOf("\n");
        }
      }
      if (buffered.trim()) yield JSON.parse(buffered) as ComputeVMWatchEvent;
    } finally {
      await reader.cancel().catch(() => {});
    }
  }

  return {
    async apply(vm) {
      assertComputeVM(vm);
      return parseComputeVM(await request(`${item(vm.metadata!.name!)}${applyQuery}`, applyInit(vm)));
    },
    async get(name) {
      const raw = await absentOn404(request(item(name)));
      return raw === null ? null : parseComputeVM(raw);
    },
    async list() {
      const out = await request(vmBase) as { metadata?: { resourceVersion?: string }; items?: unknown[] };
      return {
        items: (out.items ?? []).map((raw) => parseComputeVM(raw)),
        resourceVersion: out.metadata?.resourceVersion ?? "",
      };
    },
    watch,
    async delete(name) {
      return (await absentOn404(request(item(name), { method: "DELETE" }))) !== null;
    },
    async applySecret(secret) {
      await request(`${secretItem(secret.metadata.name)}${applyQuery}`, applyInit(secret));
    },
    async deleteSecret(name) {
      return (await absentOn404(request(secretItem(name), { method: "DELETE" }))) !== null;
    },
  };
}

export interface ComputeProviderKcpCtx extends ComputeProviderCtx {
  client: KcpComputeVMClient;
  handle: string;
  guestHostAddress: string;
  getIssuerUrl: () => string;
  acceptPathVm?: string;
  guestTlsPort?: number;
  reuseStale?: boolean;
  stopGraceSeconds?: number;
  bootTimeoutMs?: number;
  releaseTimeoutMs?: number;
  pollIntervalMs?: number;
  resyncBackoffMs?: number;
  provisioningEnricher?: OidcProvisioningEnricher;
  hostKeys?: GuestHostKeysRelay;
  rbacProvisioner?: RbacProvisioner;
}

const DEFAULT_BOOT_TIMEOUT_MS = 300_000;
const DEFAULT_RELEASE_TIMEOUT_MS = 300_000;
const DEFAULT_POLL_INTERVAL_MS = 2_000;
const DEFAULT_RESYNC_BACKOFF_MS = 2_000;

function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const done = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal?.addEventListener("abort", done, { once: true });
  });
}

export function createComputeProviderKcp(ctx: ComputeProviderKcpCtx): ComputeProvider {
  const { logger, atproto, client, handle } = ctx;
  const acceptPathVm = ctx.acceptPathVm ?? DEFAULT_ACCEPT_PATH_VM;
  const bootTimeoutMs = ctx.bootTimeoutMs ?? DEFAULT_BOOT_TIMEOUT_MS;
  const releaseTimeoutMs = ctx.releaseTimeoutMs ?? DEFAULT_RELEASE_TIMEOUT_MS;
  const pollIntervalMs = ctx.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const resyncBackoffMs = ctx.resyncBackoffMs ?? DEFAULT_RESYNC_BACKOFF_MS;

  const cache = new ComputeVMCache(handle);
  const provisioning = new Set<string>();
  const releasing = new Set<string>();
  const reportedGone = new Set<string>();
  const goneListeners = new Set<(gone: GuestGone) => void>();
  const rbacByGuest = new Map<string, StrongRef>();
  let syncStarted: Promise<void> | undefined;
  let syncAbort: AbortController | undefined;
  let syncLoop: Promise<void> | undefined;

  async function releaseRbac(name: string): Promise<void> {
    const ref = rbacByGuest.get(name);
    if (!ref) return;
    rbacByGuest.delete(name);
    const { collection, rkey } = parseAtUri(ref.uri);
    await atproto.deleteRecord(collection, rkey).catch(() => {});
  }

  async function releaseGone(name: string, vm: ComputeVM | undefined): Promise<void> {
    ctx.hostKeys?.forget(name);
    await releaseRbac(name);
    if (vm && vm.metadata?.deletionTimestamp === undefined) {
      await client.delete(name).catch((err: unknown) =>
        logger.warn("computevm_release_failed", { name, error: String(err) })
      );
    }
    await client.deleteSecret(userDataSecretName(name)).catch((err: unknown) =>
      logger.warn("computevm_user_data_release_failed", { name, error: String(err) })
    );
  }

  function reportGone(name: string, vm: ComputeVM | undefined): void {
    reportedGone.add(name);
    const gone = goneOf(name, vm);
    logger.warn("computevm_guest_gone", {
      name,
      reason: gone.reason,
      phase: phaseOf(vm),
      lostReason: vm?.status?.lostReason,
      message: vm?.status?.message,
    });
    for (const listener of goneListeners) {
      try {
        listener(gone);
      } catch (err) {
        logger.warn("guest_gone_listener_failed", { name, error: String(err) });
      }
    }
    void releaseGone(name, vm);
  }

  function observe(change: ComputeVMChange): void {
    const { name, before, after } = change;
    if (!after) {
      const ours = provisioning.has(name) || releasing.has(name) || reportedGone.has(name);
      releasing.delete(name);
      reportedGone.delete(name);
      if (ours || hasEnded(before)) return;
      reportGone(name, before);
      return;
    }
    if (provisioning.has(name) || releasing.has(name) || reportedGone.has(name)) return;
    if (hasEnded(before) || !hasEnded(after)) return;
    reportGone(name, after);
  }

  function applyEvent(event: ComputeVMWatchEvent): string | undefined {
    const raw = event.object as ComputeVM | undefined;
    const resourceVersion = raw?.metadata?.resourceVersion;
    if (event.type === "BOOKMARK") return resourceVersion;
    let vm: ComputeVM;
    try {
      vm = parseComputeVM(raw);
    } catch (err) {
      logger.warn("computevm_watch_object_refused", { error: String(err) });
      return resourceVersion;
    }
    const name = vm.metadata?.name;
    if (!name) return resourceVersion;
    const change = event.type === "DELETED" ? cache.remove(name) : cache.upsert(vm);
    if (change) observe(change);
    return resourceVersion;
  }

  async function runSync(signal: AbortSignal, listedAt: string): Promise<void> {
    let resourceVersion: string | undefined = listedAt;
    let mode: "watch" | "relist" | undefined;
    while (!signal.aborted) {
      try {
        if (resourceVersion === undefined) {
          const listed = await client.list();
          for (const change of cache.replace(listed.items)) observe(change);
          resourceVersion = listed.resourceVersion;
        }
        let events = 0;
        for await (const event of client.watch(resourceVersion, signal)) {
          events++;
          if (mode !== "watch") {
            mode = "watch";
            logger.info("computevm_sync_mode", { mode, handle });
          }
          if (event.type === "ERROR") {
            resourceVersion = undefined;
            break;
          }
          resourceVersion = applyEvent(event) ?? resourceVersion;
        }
        if (events === 0) await delay(resyncBackoffMs, signal);
      } catch (err) {
        if (signal.aborted) break;
        if (mode !== "relist") {
          mode = "relist";
          logger.warn("computevm_sync_mode", { mode, handle, everyMs: resyncBackoffMs, error: String(err) });
        }
        resourceVersion = undefined;
        await delay(resyncBackoffMs, signal);
      }
    }
  }

  async function startSync(): Promise<void> {
    const listed = await client.list();
    cache.replace(listed.items);
    syncAbort = new AbortController();
    syncLoop = runSync(syncAbort.signal, listed.resourceVersion);
    logger.info("computevm_cache_filled", { handle, guests: cache.names().length });
  }

  function ensureSync(): Promise<void> {
    syncStarted ??= startSync().catch((err) => {
      syncStarted = undefined;
      throw err;
    });
    return syncStarted;
  }

  async function stopSync(): Promise<void> {
    syncAbort?.abort();
    await syncLoop;
    syncAbort = undefined;
    syncLoop = undefined;
    syncStarted = undefined;
  }

  async function nextChangeWithin(name: string, ms: number): Promise<void> {
    const abort = new AbortController();
    await Promise.race([cache.nextChange(name, abort.signal), delay(ms, abort.signal)]);
    abort.abort();
  }

  async function untilRunning(name: string): Promise<ComputeVM> {
    const deadline = Date.now() + bootTimeoutMs;
    let seen = false;
    while (true) {
      const vm = cache.get(name);
      if (vm) seen = true;
      if (phaseOf(vm) === "Running") return vm!;
      if (vm && hasEnded(vm)) throw new Error(endedMessage(name, vm));
      if (vm && isReleasing(vm)) throw new Error(`ComputeVM ${name} was deleted before it was Running`);
      if (!vm && seen) throw new Error(`ComputeVM ${name} disappeared from kcp before it was Running`);
      const left = deadline - Date.now();
      if (left <= 0) {
        throw new Error(
          `ComputeVM ${name} was not Running within ${bootTimeoutMs} ms (phase ${phaseOf(vm) ?? "none yet"}); ` +
            `the ComputeVM controller of this bidder's kcp boots it, so a phase that never moves means no controller is reconciling it`,
        );
      }
      await nextChangeWithin(name, Math.min(left, pollIntervalMs));
    }
  }

  async function untilAbsent(name: string): Promise<void> {
    const deadline = Date.now() + releaseTimeoutMs;
    while ((await client.get(name)) !== null) {
      const left = deadline - Date.now();
      if (left <= 0) {
        throw new Error(
          `ComputeVM ${name} still exists ${releaseTimeoutMs} ms after its delete; the controller holds its ` +
            `finalizer until the VM is stopped and its work dir is removed`,
        );
      }
      await nextChangeWithin(name, Math.min(left, pollIntervalMs));
    }
  }

  async function abandon(name: string): Promise<void> {
    releasing.add(name);
    ctx.hostKeys?.forget(name);
    await client.delete(name).catch((err: unknown) =>
      logger.warn("computevm_release_failed", { name, error: String(err) })
    );
    await client.deleteSecret(userDataSecretName(name)).catch(() => false);
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

  async function provision(vm: VM, requesterDid: string): Promise<ProvisionResult> {
    if (!vm.user_data) {
      throw new Error(
        `an RFP for ${vm.role} arrived with no user_data. On this provider the user_data IS the ` +
          `guest: nothing else is baked into it at boot, so a guest started without one comes up ` +
          `with no sshd, no iroh listener and no secrets, and reaches Running while being unreachable.`,
      );
    }
    await ensureSync();
    const name = `fc-${shortId(requesterDid)}-${crypto.randomUUID().slice(0, 8)}`;
    const teamUuid = atproto.getAgentDid().split(":").slice(-1)[0];
    const enriched = ctx.provisioningEnricher
      ? await ctx.provisioningEnricher.enrich(vm.user_data, teamUuid)
      : { userData: vm.user_data, nonce: "", associateWithDroplet: (_id: string) => {} };
    ctx.hostKeys?.bindNonce(enriched.nonce, name);
    const issuerUrl = ctx.getIssuerUrl();
    const reported = withOnNetworkBaseUrl(withOnNetworkReporter(enriched.userData, issuerUrl, acceptPathVm), issuerUrl);
    const userData = pointGuestAtHost(reported, ctx.guestHostAddress, ctx.guestTlsPort);
    const desired = computeVMFor({
      name,
      handle,
      vm,
      requesterDid,
      reuseStale: ctx.reuseStale,
      stopGraceSeconds: ctx.stopGraceSeconds,
    });

    provisioning.add(name);
    let applied: ComputeVM | undefined;
    try {
      applied = await client.apply(desired);
      cache.upsert(applied);
      await client.applySecret(userDataSecretFor(applied, userData));
      enriched.associateWithDroplet(name);
      logger.info("computevm_applied", { name, handle, guestHostAddress: ctx.guestHostAddress, cpus: vm.cpus, mem: vm.mem });
      const running = await untilRunning(name);
      provisioning.delete(name);

      if (ctx.rbacProvisioner) {
        const created = await ctx.rbacProvisioner.provision({ role: vm.role }, requesterDid, {
          getAgentDid: () => atproto.getAgentDid(),
          getIssuerUrl: () => ctx.getIssuerUrl(),
          createRecord: async (collection, record) => await atproto.createRecord(collection, record),
          parseAtUri,
        });
        if (created) rbacByGuest.set(name, { $type: "com.atproto.repo.strongRef", uri: created.uri, cid: "" });
      }

      const status = running.status ?? {};
      logger.info("computevm_running", { name, guestIp: status.network?.guestIP, image: status.image?.ref });
      return {
        providerId: name,
        metadata: {
          name,
          ip: status.network?.guestIP,
          hostAddress: status.network?.hostAddress,
          mode: "kcp",
          sshReady: true,
          imageRef: status.image?.ref,
          imageSha256: status.image?.sha256,
        },
      };
    } catch (err) {
      provisioning.delete(name);
      if (applied) await abandon(name);
      else ctx.hostKeys?.forget(name);
      logger.warn("computevm_provision_failed", { name, error: String(err) });
      throw err;
    }
  }

  async function destroy(id: string | number): Promise<void> {
    const name = String(id);
    releasing.add(name);
    ctx.hostKeys?.forget(name);
    await releaseRbac(name);
    if (await client.delete(name)) await untilAbsent(name);
    await client.deleteSecret(userDataSecretName(name)).catch((err: unknown) =>
      logger.warn("computevm_user_data_release_failed", { name, error: String(err) })
    );
    logger.info("computevm_released", { name });
  }

  async function adopt(id: string | number): Promise<AdoptResult> {
    const name = String(id);
    await ensureSync();
    const fetched = cache.get(name) ?? (await client.get(name)) ?? undefined;
    const vm = cache.owns(fetched) ? fetched : undefined;
    if (vm && !hasEnded(vm) && !isReleasing(vm)) {
      logger.info("computevm_adopted", { name, phase: phaseOf(vm) });
      return { state: "running" };
    }
    reportedGone.add(name);
    const gone = goneOf(name, vm);
    logger.warn("computevm_gone_at_adopt", { name, reason: gone.reason, phase: phaseOf(vm), lostReason: vm?.status?.lostReason });
    if (vm) void releaseGone(name, vm);
    return { state: "gone", gone };
  }

  function getDroplet(id: string): Record<string, unknown> | undefined {
    const vm = cache.get(id);
    if (!vm || hasEnded(vm) || isReleasing(vm)) return undefined;
    return dropletOf(vm);
  }

  function onGuestGone(listener: (gone: GuestGone) => void): () => void {
    goneListeners.add(listener);
    return () => goneListeners.delete(listener);
  }

  const provider: ComputeProvider = {
    name: "kcp",
    provision,
    destroy,
    adopt,
    createBidConfig,
    injectAcceptBundle: (userData: string, bundle: Record<string, unknown>) =>
      injectAcceptBundle(userData, bundle, acceptPathVm),
    getDroplet,
    onGuestGone,
    setup: ensureSync,
    teardown: stopSync,
  };
  if (ctx.hostKeys) {
    const relay = ctx.hostKeys;
    provider.onHostKeys = (handler: GuestHostKeysHandler) => relay.onHostKeys(handler);
  }
  return provider;
}
