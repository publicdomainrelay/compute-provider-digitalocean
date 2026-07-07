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
import { parseAtUri } from "@publicdomainrelay/atproto-helpers";
import { createOidcIssuer } from "@publicdomainrelay/oidc-issuer-hono";
import type { ServeHandle } from "@publicdomainrelay/serve";

export interface ComputeProviderDigitalOceanCtx extends ComputeProviderCtx {
  serve: ServeHandle;
  getIssuerUrl: () => string;
  acceptPathVm?: string;
  digitaloceanBaseUrl?: string;
  doToken: string;
  rbacProvisioner?: RbacProvisioner;
}

const COMPUTE_CONFIG_WIF_SIMPLE_NSID =
  "com.publicdomainrelay.temp.compute.config.wif.simple";
const DEFAULT_DIGITALOCEAN_BASE_URL = "https://droplet-oidc.its1337.com";
const DEFAULT_ACCEPT_PATH_VM =
  "/root/secrets/publicdomainrelay.com/market/accept.json";

function didWebToHttps(didOrUrl: string): string {
  return didOrUrl.startsWith("did:web:") ? "https://" + didOrUrl.slice("did:web:".length) : didOrUrl;
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
    serve,
  } = ctx;

  serve.onConnected((proxyRef) => {
    const serviceUrl = didWebToHttps(proxyRef);
    const oidcIssuer = createOidcIssuer({
      getIssuerUrl,
      getDroplet: (_id: string) => undefined,
      serviceUrl,
      log: (level: string, msg: string, extra?: Record<string, unknown>) => {
        logger[level as "info" | "warn" | "error" | "debug"]?.(msg, extra);
      },
    });
    serve.app.route("/", oidcIssuer.app as never);
    logger.info("do oidc issuer mounted", { serviceUrl });
  });

  async function makeDoctx(): Promise<{ teamUuid: string }> {
    const res = await fetch(`${digitaloceanBaseUrl}/v2/account`, {
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${doToken}` },
    });
    const json = await res.json();
    logger.debug("DO /v2/account response", { account: json });
    if (res.status >= 400) throw new Error(`DO /v2/account ${res.status}: ${JSON.stringify(json)}`);
    const uuid = json.account.team.uuid;
    return { teamUuid: uuid };
  }

  function injectAcceptBundle(userData: string, bundle: Record<string, unknown>): string {
    let obj: Record<string, unknown> = {};
    try {
      const parsed = userData ? yamlParse(userData.replace(/^#cloud-config\s*/i, "")) : null;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        obj = parsed as Record<string, unknown>;
      }
    } catch { /* fall through with empty obj */ }
    const writeFiles = (obj["write_files"] as unknown[]) ?? (obj["write_files"] = []) as unknown[];
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

  async function createBidConfig(nowIso: string): Promise<StrongRef> {
    const doctx = await makeDoctx();
    const agentDid = atproto.getAgentDid();
    try {
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
    } catch {
      /* fallback no-op ref */
    }
    return {
      $type: "com.atproto.repo.strongRef",
      uri: `at://${agentDid}/${COMPUTE_CONFIG_WIF_SIMPLE_NSID}/self`,
      cid: "do-noop",
    };
  }

  async function createDroplet(
    vm: VM,
    requesterDid: string,
  ): Promise<{ json: unknown; rbacRef?: StrongRef }> {
    const requesterPlc = requesterDid.split(":").slice(-1)[0];
    const rfpRkey = (vm._uri ?? "").split("/")[4] ?? "unknown";
    const name = `${requesterPlc}-${rfpRkey}-${vm._cid ?? ""}`;
    const body = {
      name,
      region: "sfo3",
      size: "s-1vcpu-512mb-10gb",
      image: "ubuntu",
      user_data: vm.user_data,
      with_droplet_agent: true,
      tags: [`oidc-sub:plc:${requesterPlc}`, `oidc-sub:role:${vm.role}`],
    };
    logger.info("droplet request", { name, requesterDid, droplet: body });

    const doctx = await makeDoctx();

    let rbacRef: StrongRef | undefined;
    if (rbacProvisioner) {
      rbacRef = await rbacProvisioner.provision(vm, requesterDid, {
        getAgentDid: () => atproto.getAgentDid(),
        getIssuerUrl,
        createRecord: (collection: string, record: Record<string, unknown>) =>
          atproto.createRecord(collection, record),
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
    logger.info("droplet created", { name, requesterDid, status: res.status });
    if (res.status >= 400) throw new Error(`DO /v2/droplets ${res.status}: ${JSON.stringify(json)}`);
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
  } = createComputeProviderDigitalOcean(ctx);

  const rbacByProvider = new Map<string | number, StrongRef>();

  return {
    name: "digitalocean",

    async provision(
      vm: VM,
      requesterDid: string,
      _spec?: DropletSpec,
    ): Promise<ProvisionResult> {
      const { json, rbacRef } = await createDroplet(vm, requesterDid);
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

    createBidConfig,
    injectAcceptBundle,
    setup: undefined,
    teardown: undefined,
  };
}
