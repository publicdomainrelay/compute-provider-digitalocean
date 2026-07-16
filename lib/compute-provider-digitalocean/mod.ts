import { parse as yamlParse, stringify as yamlStringify } from "npm:yaml@^2.7.0";
import { ON_BEHALF_OF_HEADER } from "@publicdomainrelay/compute-provider-common";
import type { StructuredLoggerInterface } from "@publicdomainrelay/logger";
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
import type { OidcProvisioningEnricher } from "@publicdomainrelay/oidc-issuer-abc";
import { createOidcIssuer, OIDCToken } from "@publicdomainrelay/oidc-issuer-hono";
import { createPackageRegistryFactory } from "@publicdomainrelay/hono-factory-package-registry";
import { createLocalFsStore } from "@publicdomainrelay/package-store-local-fs";
import type { ServeHandle } from "@publicdomainrelay/serve";

export interface ComputeProviderDigitalOceanCtx extends ComputeProviderCtx {
  serve: ServeHandle;
  getIssuerUrl: () => string;
  acceptPathVm?: string;
  digitaloceanBaseUrl?: string;
  doToken: string;
  rbacProvisioner?: RbacProvisioner;
  oidcProvisioner?: OidcProvisioningEnricher;
  acceptToContract?: Map<string, {
    receiptKey: string;
    receiptUri: string;
    receiptCid: string;
    submitEventUrl?: string;
  }>;
  createSignedRepoRecord?: (
    collection: string,
    record: Record<string, unknown>,
  ) => Promise<StrongRef>;
  callService?: (
    url: string,
    body: Record<string, unknown>,
  ) => Promise<Response>;
  jsrBaseDir?: string;
}

const COMPUTE_CONFIG_WIF_SIMPLE_NSID =
  "com.publicdomainrelay.temp.compute.config.wif.simple";
const DEFAULT_DIGITALOCEAN_BASE_URL = "https://droplet-oidc.its1337.com";
const DEFAULT_ACCEPT_PATH_VM =
  "/root/secrets/publicdomainrelay.com/market/accept.json";

function parseAtUri(uri: string): { repo: string; collection: string; rkey: string } {
  const parts = uri.slice("at://".length).split("/");
  return { repo: parts[0], collection: parts[1], rkey: parts[2] };
}

interface LocalDroplet {
  id: number;
  name: string;
  networks?: { v4?: { ip_address: string }[] };
  tags?: string[];
}

function didWebToHttps(didOrUrl: string): string {
  return didOrUrl.startsWith("did:web:") ? "https://" + didOrUrl.slice("did:web:".length) : didOrUrl;
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
  } catch { /* fall through with empty obj */ }
  const writeFiles = (obj["write_files"] as unknown[]) ??
    (obj["write_files"] = []) as unknown[];
  writeFiles.push({
    path: acceptPathVm,
    owner: "root:root",
    permissions: "0600",
    content: JSON.stringify(bundle, null, 2),
  });
  const runcmd = (obj["runcmd"] as unknown[]) ?? (obj["runcmd"] = []) as unknown[];
  const parent = acceptPathVm.split("/").slice(0, -1).join("/");
  runcmd.unshift(["sh", "-c", `install -d -m 0700 -o root -g root ${parent}`]);
  return "#cloud-config\n" + yamlStringify(obj, { lineWidth: 0 });
}

export function createComputeProviderDigitalOcean(ctx: ComputeProviderDigitalOceanCtx) {
  const {
    atproto,
    getIssuerUrl,
    logger,
    acceptPathVm = DEFAULT_ACCEPT_PATH_VM,
    digitaloceanBaseUrl = DEFAULT_DIGITALOCEAN_BASE_URL,
    doToken,
    rbacProvisioner,
    oidcProvisioner,
    acceptToContract,
    createSignedRepoRecord,
    callService,
    serve,
  } = ctx;

  const droplets = new Map<string, LocalDroplet>();

  let doctxPromise: Promise<{ teamUuid: string }> | null = null;
  let _serviceUrl = "";

  async function makeDoctx(): Promise<{ teamUuid: string }> {
    const res = await fetch(`${digitaloceanBaseUrl}/v2/account`, {
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${doToken}`,
      },
    });
    const json = await res.json();
    logger.debug("DO /v2/account response", { account: json });
    if (res.status >= 400) {
      throw new Error(
        `DO /v2/account ${res.status}: ${JSON.stringify(json)}`,
      );
    }
    const uuid = json.account.team.uuid;
    return { teamUuid: uuid };
  }

  async function cachedDoctx(): Promise<{ teamUuid: string }> {
    doctxPromise ??= makeDoctx();
    return doctxPromise;
  }

  serve.onConnected((ingressRef) => {
    const serviceUrl = didWebToHttps(ingressRef);
    _serviceUrl = serviceUrl;
    const oidcIssuer = createOidcIssuer({
      getIssuerUrl,
      getDroplet: async (id: string) => {
        try {
          const res = await fetch(`${digitaloceanBaseUrl}/v2/droplets/${id}`, {
            headers: { "Authorization": `Bearer ${doToken}` },
          });
          if (!res.ok) return undefined;
          const json = await res.json() as { droplet: Record<string, unknown> };
          return json.droplet;
        } catch {
          return droplets.get(id) as Record<string, unknown> | undefined;
        }
      },
      serviceUrl,
      log: (
        level: string,
        msg: string,
        extra?: Record<string, unknown>,
      ) => {
        logger[level as "info" | "warn" | "error" | "debug"]?.(msg, extra);
      },
    });
    serve.app.route("/", oidcIssuer.app as never);
    logger.info("do oidc issuer mounted", { serviceUrl });

    const jsrBaseDir = ctx.jsrBaseDir ??
      new URL("../../..", import.meta.url).pathname;
    const jsrStore = createLocalFsStore({
      baseDir: jsrBaseDir,
      fallbackVersion: "0.0.0",
    });
    const jsrFactory = createPackageRegistryFactory({
      store: jsrStore,
      passthrough: true,
    });
    serve.app.route("/", jsrFactory as never);
    logger.info("ephemeral jsr registry mounted", { serviceUrl });

    // Guest on-network endpoint — VM reports tunnel FQDN after boot.
    if (acceptToContract && createSignedRepoRecord) {
      const COMPUTE_EVENTS_VM_ON_NETWORK_NSID =
        "com.publicdomainrelay.temp.compute.events.vm.onNetwork";
      const MARKET_EVENT_NSID = "com.publicdomainrelay.temp.market.event";

      serve.app.post("/v1/on-network", async (c) => {
        try {
          const authHeader = c.req.header("Authorization");
          if (!authHeader) {
            return c.json({ error: "missing Authorization header" }, 401);
          }
          const token = authHeader.startsWith("Bearer ")
            ? authHeader.slice("Bearer ".length)
            : authHeader;
          const validated = await OIDCToken.validate(token).catch(() => null);
          if (!validated) {
            return c.json({ error: "invalid or expired token" }, 401);
          }

          const body = await c.req.json().catch(() => ({}));
          const { acceptUri, acceptCid, address, createdAt } = body as Record<
            string,
            unknown
          >;
          if (!acceptUri || !acceptCid) {
            return c.json(
              { error: "missing acceptUri or acceptCid" },
              400,
            );
          }

          const refKey = `${acceptUri}#${acceptCid}`;
          const contract = acceptToContract.get(refKey as string);
          if (!contract) {
            return c.json({ error: "contract not found" }, 404);
          }

          const onNetworkRecord = {
            $type: COMPUTE_EVENTS_VM_ON_NETWORK_NSID,
            address,
            createdAt: createdAt ?? new Date().toISOString(),
          };
          const onNetworkRef = await createSignedRepoRecord(
            COMPUTE_EVENTS_VM_ON_NETWORK_NSID,
            onNetworkRecord,
          );

          const eventRecord = {
            $type: MARKET_EVENT_NSID,
            receipt: {
              $type: "com.atproto.repo.strongRef",
              uri: contract.receiptUri,
              cid: contract.receiptCid,
            },
            payload: {
              $type: "com.atproto.repo.strongRef",
              uri: onNetworkRef.uri,
              cid: onNetworkRef.cid,
            },
            createdAt: new Date().toISOString(),
          };
          await createSignedRepoRecord(MARKET_EVENT_NSID, eventRecord);

          if (contract.submitEventUrl && callService) {
            callService(contract.submitEventUrl, eventRecord).catch((e) =>
              logger.warn("onNetwork submitEvent push failed", {
                error: String(e),
              })
            );
          }

          return c.json({ ok: true });
        } catch (e) {
          logger.error("onNetwork handler error", { error: String(e) });
          return c.json({ error: "internal error" }, 500);
        }
      });
      logger.info("guest on-network endpoint mounted", { serviceUrl });
    }
  });

  async function createBidConfig(nowIso: string): Promise<StrongRef> {
    const doctx = await cachedDoctx();
    return atproto.createRecord(COMPUTE_CONFIG_WIF_SIMPLE_NSID, {
      $type: COMPUTE_CONFIG_WIF_SIMPLE_NSID,
      accept_path: acceptPathVm,
      issuer_uri: getIssuerUrl(),
      to_issue: "exchange-custom-droplet-oidc-poc",
      actx: doctx.teamUuid,
      actx_path: "/root/secrets/digitalocean.com/serviceaccount/team_uuid",
      token_path: "/root/secrets/digitalocean.com/serviceaccount/token",
      url_path: "/root/secrets/digitalocean.com/serviceaccount/base_url",
      url_route: "/v1/oidc/issue",
      subject: "actx:{actx}:plc:{did-plc-key}:role:{role}",
      createdAt: nowIso,
    });
  }

  async function createDroplet(
    vm: VM,
    requesterDid: string,
    spec?: DropletSpec,
  ): Promise<{ json: unknown; rbacRef?: StrongRef }> {
    const requesterPlc = requesterDid.split(":").slice(-1)[0];
    const rfpRkey = (vm._uri ?? "").split("/")[4] ?? "unknown";
    const name = `${requesterPlc}-${rfpRkey}-${vm._cid ?? ""}`;
    const user_data = vm.user_data ?? "";

    const finalRegion = "sfo3";
    const finalSize = spec?.size ?? "s-1vcpu-512mb-10gb";
    const finalImage = "ubuntu-24-04-x64";

    // OIDC enrichment
    const enriched = oidcProvisioner
      ? await oidcProvisioner.enrich(user_data, requesterDid, getIssuerUrl())
      : { userData: user_data, nonce: "", associateWithDroplet: (_id: string) => {} };

    let enrichedUserData = enriched.userData;
    if (_serviceUrl) {
      enrichedUserData = enrichedUserData.replace(
        /(ExecStart=deno run .*tunnel-subscriber)/,
        `Environment="JSR_URL=${_serviceUrl}"\n      $1`,
      );
    }

    const body = {
      name,
      region: finalRegion,
      size: finalSize,
      image: finalImage,
      user_data: enrichedUserData,
      with_droplet_agent: true,
      tags: [`oidc-sub:plc:${requesterPlc}`, `oidc-sub:role:${vm.role}`],
    };
    logger.info("droplet request", { name, requesterDid, droplet: body });

    let rbacRef: StrongRef | undefined;
    if (rbacProvisioner) {
      rbacRef = await rbacProvisioner.provision(vm, requesterDid, {
        getAgentDid: () => atproto.getAgentDid(),
        getIssuerUrl,
        createRecord: (
          collection: string,
          record: Record<string, unknown>,
        ) => atproto.createRecord(collection, record),
        parseAtUri,
      }) as StrongRef | undefined;
    }

    const res = await fetch(`${digitaloceanBaseUrl}/v2/droplets`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${doToken}`,
        [ON_BEHALF_OF_HEADER]: requesterDid,
      },
      body: JSON.stringify(body),
    });
    const json = await res.json();
    logger.info("droplet created", {
      name,
      requesterDid,
      status: res.status,
    });
    if (res.status >= 400) {
      throw new Error(
        `DO /v2/droplets ${res.status}: ${JSON.stringify(json)}`,
      );
    }

    // Track droplet for OIDC issuer getDroplet lookup
    const droplet = (json as Record<string, unknown>)?.droplet as
      | Record<string, unknown>
      | undefined;
    const providerId: number = (droplet?.id as number) ?? 0;
    if (providerId) {
      droplets.set(String(providerId), {
        id: providerId,
        name,
        networks: droplet?.networks as LocalDroplet["networks"],
        tags: body.tags,
      });
    }
    // Associate nonce with droplet ID (not name) for getDroplet lookup
    enriched.associateWithDroplet(String(providerId));

    return { json, rbacRef };
  }

  async function deleteDroplet(dropletId: number | string, reason: string): Promise<void> {
    logger.info("deleting droplet", { dropletId, reason });
    const res = await fetch(`${digitaloceanBaseUrl}/v2/droplets/${dropletId}`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${doToken}` },
    });
    if (res.status >= 400 && res.status !== 404) {
      const body = await res.text();
      logger.error("DO delete droplet failed", { dropletId, status: res.status, body });
      return;
    }
    logger.info("droplet deleted", { dropletId, reason });
  }

  return {
    createBidConfig,
    createDroplet,
    deleteDroplet,
    injectAcceptBundle,
    getDroplet: (id: string) => droplets.get(id),
  };
}

export function createDigitalOceanComputeProvider(
  ctx: ComputeProviderDigitalOceanCtx,
): ComputeProvider {
  const {
    createBidConfig,
    createDroplet,
    deleteDroplet,
    injectAcceptBundle,
    getDroplet: lookupDroplet,
  } = createComputeProviderDigitalOcean(ctx);

  const rbacByProvider = new Map<string | number, StrongRef>();

  return {
    name: "digitalocean",

    async provision(
      vm: VM,
      requesterDid: string,
      spec?: DropletSpec,
    ): Promise<ProvisionResult> {
      const { json, rbacRef } = await createDroplet(vm, requesterDid, spec);
      const droplet = (json as Record<string, unknown>)?.droplet as
        | Record<string, unknown>
        | undefined;
      const providerId: string | number = (droplet?.id as string | number) ?? 0;
      if (rbacRef) rbacByProvider.set(providerId, rbacRef);
      return { providerId, metadata: json as Record<string, unknown> };
    },

    async destroy(id: string | number): Promise<void> {
      const rbacRef = rbacByProvider.get(id);
      if (rbacRef) {
        const { collection, rkey } = parseAtUri(rbacRef.uri);
        await ctx.atproto.deleteRecord(collection, rkey).catch(() => {});
        rbacByProvider.delete(id);
      }
      await deleteDroplet(id, "vm.delete event");
    },

    getDroplet(id: string): Record<string, unknown> | undefined {
      return lookupDroplet(id) as Record<string, unknown> | undefined;
    },

    createBidConfig,
    injectAcceptBundle,
  };
}
