import { Hono } from "@hono/hono";
import { createFactory } from "@hono/hono/factory";
import { EVENT_NSID, ON_NETWORK_NSID, SUBMIT_EVENT_NSID } from "@publicdomainrelay/compute-provider-common";
import {
  type ComputeAtproto,
  type ComputeProvider,
  type ComputeProviderCtx,
  type GuestHostKeysAck,
  GuestHostKeysRelay,
  type RbacProvisioner,
} from "@publicdomainrelay/compute-provider-abc";
import {
  createComputeProviderKcp,
  createKcpComputeVMClient,
  type KcpCredentials,
} from "@publicdomainrelay/compute-provider-kcp";
import type { JwkStore, NonceStore, OidcIssuer } from "@publicdomainrelay/oidc-issuer-abc";
import { createOidcIssuer, type HostKeysReported } from "@publicdomainrelay/oidc-issuer-hono";

export interface GuestContractEntry {
  receiptKey: string;
  receiptUri: string;
  receiptCid: string;
  submitEventUrl?: string;
}

export interface ComputeProviderKcpServe {
  readonly app: Hono;
  onConnected(cb: (ingressRef: string) => void | Promise<void>): void;
}

export interface ComputeProviderKcpFactoryOptions extends ComputeProviderCtx {
  atproto: ComputeAtproto;
  serve?: ComputeProviderKcpServe;
  credentials: KcpCredentials;
  fetch?: typeof fetch;
  handle: string;
  guestHostAddress: string;
  getIssuerUrl: () => string;
  acceptPathVm?: string;
  guestTlsPort?: number;
  reuseStale?: boolean;
  stopGraceSeconds?: number;
  bootTimeoutMs?: number;
  releaseTimeoutMs?: number;
  oidcProvisioning?: boolean;
  oidcJwkStore?: JwkStore;
  oidcNonceStore?: NonceStore;
  rbacProvisioner?: RbacProvisioner;
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
}

export interface ComputeProviderKcpFactory {
  provider: ComputeProvider;
  oidcIssuer: OidcIssuer;
  createApp(): Hono;
}

export function createComputeProviderKcpFactory(opts: ComputeProviderKcpFactoryOptions): ComputeProviderKcpFactory {
  const { logger, atproto } = opts;
  const hostKeys = new GuestHostKeysRelay();

  const provider = createComputeProviderKcp({
    logger,
    atproto,
    client: createKcpComputeVMClient({ credentials: opts.credentials, fetch: opts.fetch }),
    handle: opts.handle,
    guestHostAddress: opts.guestHostAddress,
    getIssuerUrl: opts.getIssuerUrl,
    acceptPathVm: opts.acceptPathVm,
    guestTlsPort: opts.guestTlsPort,
    reuseStale: opts.reuseStale,
    stopGraceSeconds: opts.stopGraceSeconds,
    bootTimeoutMs: opts.bootTimeoutMs,
    releaseTimeoutMs: opts.releaseTimeoutMs,
    provisioningEnricher: opts.oidcProvisioning
      ? { enrich: (userData, teamUuid) => oidcIssuer.provisioningEnricher.enrich(userData, teamUuid) }
      : undefined,
    hostKeys,
    rbacProvisioner: opts.rbacProvisioner,
  });

  const forwardHostKeys = async (report: HostKeysReported): Promise<GuestHostKeysAck> => {
    const ack = await hostKeys.forward(report, new Date().toISOString());
    if (ack.id === undefined) logger.warn("guest_hostkeys_unknown_guest", {});
    else if (ack.status === 503) logger.warn("guest_hostkeys_no_listener", { name: ack.id });
    else logger.info("guest_hostkeys_forwarded", { name: ack.id, ok: ack.ok, status: ack.status, reason: ack.reason });
    return ack;
  };

  const oidcIssuer = createOidcIssuer({
    getIssuerUrl: opts.getIssuerUrl,
    getDroplet: (id: string) => provider.getDroplet?.(id),
    onHostKeys: forwardHostKeys,
    store: opts.oidcJwkStore,
    nonceStore: opts.oidcNonceStore,
    log: (level: string, msg: string, extra?: Record<string, unknown>) => {
      const at = level as "info" | "warn" | "error" | "debug";
      if (typeof logger?.[at] === "function") logger[at](msg, extra);
    },
  });

  function onNetworkRoutes(): Hono {
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
      const entry = opts.acceptToContract?.get(acceptKey);
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
      if (opts.createSignedRepoRecord) {
        const { uri: eventUri, cid: eventCid, record: eventRecord } = await opts.createSignedRepoRecord(
          EVENT_NSID,
          {
            $type: EVENT_NSID,
            receipt: { $type: "com.atproto.repo.strongRef", uri: entry.receiptUri, cid: entry.receiptCid },
            payload: { $type: "com.atproto.repo.strongRef", uri: ref.uri, cid: ref.cid },
          },
          atproto.getAgentDid(),
        );
        if (entry.submitEventUrl && opts.callService) {
          opts.callService(entry.submitEventUrl, SUBMIT_EVENT_NSID, SUBMIT_EVENT_NSID, {
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
    return events;
  }

  const factory = createFactory({
    initApp: (app) => {
      app.route("/", oidcIssuer.app as never);
      app.route("/", onNetworkRoutes());
    },
  });

  const createApp = (): Hono => factory.createApp() as unknown as Hono;

  opts.serve?.onConnected((ingressRef) => {
    opts.serve!.app.route("/", createApp());
    logger.info("compute-provider-kcp guest routes mounted", { ingressRef, handle: opts.handle });
  });

  return { provider, oidcIssuer, createApp };
}
