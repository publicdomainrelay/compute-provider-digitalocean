import { createFactory } from "hono/factory";
import { cors } from "hono/cors";
import { registerErrorMiddleware } from "@publicdomainrelay/hono-error-middleware";
import type { LoggerInterface } from "@publicdomainrelay/logger";
import type { VM, ProvisionResult } from "@publicdomainrelay/compute-provider-abc";
import { spawnVM, defaultCacheDir } from "@publicdomainrelay/compute-provider-local";
import { createOidcIssuer, ProvisioningData } from "@publicdomainrelay/oidc-issuer";

export interface DropletCreateRequest {
  name: string;
  region?: string;
  size?: string;
  image?: string;
  user_data?: string;
  ssh_keys?: string[];
  tags?: string[];
}

export interface Droplet {
  id: string;
  name: string;
  status: "new" | "active" | "off" | "archive";
  created_at: string;
  region: { slug: string; name: string };
  size_slug: string;
  image: { slug: string };
  networks: { v4: { ip_address: string; type: string }[] };
  tags: string[];
}

export type ComputeProviderLocalEnv = {
  Variables: {
    actx: string;
  };
};

export interface ComputeProviderLocalFactoryOptions {
  operatorHandle: string | (() => string);
  selfDid: string;
  issuerUrl: string | (() => string);
  vmImage: string;
  containerMode: boolean;
  containerImage: string;
  cacheDir?: string;
  log: LoggerInterface;
  getDroplet?: (id: string) => Record<string, unknown> | undefined;
  rbac?: {
    getAgentDid: () => string;
    createRecord: (collection: string, record: Record<string, unknown>) => Promise<{ $type: string; uri: string; cid: string }>;
    deleteRecord?: (collection: string, rkey: string) => Promise<void>;
    parseAtUri: (uri: string) => { repo: string; collection: string; rkey: string };
    log?: (level: string, msg: string, meta?: Record<string, unknown>) => void;
  };
}

function extractBearer(authHeader: string | undefined): string {
  if (!authHeader) throw new Error("Missing Authorization header");
  const parts = authHeader.split(" ");
  const token = parts[parts.length - 1];
  if (!token || token === "0") throw new Error("Missing bearer token");
  return token;
}

function makeDroplet(req: DropletCreateRequest): Droplet {
  const id = crypto.randomUUID();
  return {
    id,
    name: req.name,
    status: "new",
    created_at: new Date().toISOString(),
    region: { slug: req.region ?? "homelab-1", name: "Homelab Region 1" },
    size_slug: req.size ?? "s-1vcpu-1gb",
    image: { slug: typeof req.image === "string" ? req.image : "fedora-latest" },
    networks: { v4: [] },
    tags: req.tags ?? [],
  };
}

export interface ComputeProviderLocalFactory {
  createApp(): ReturnType<ReturnType<typeof createFactory<ComputeProviderLocalEnv>>["createApp"]>;
  state: ComputeProviderLocalFactoryState;
  killAllDroplets(): Promise<void>;
  provisionDroplet(
    vm: VM,
    actx: string,
    opts?: { image?: string; region?: string; size?: string; tags?: string[] },
  ): Promise<ProvisionResult>;
}

export interface ComputeProviderLocalFactoryState {
  dropletsByActx: Map<string, Map<string, Droplet>>;
}

export function createComputeProviderLocalFactory(
  opts: ComputeProviderLocalFactoryOptions,
): ComputeProviderLocalFactory {
  const { operatorHandle: _operatorHandle, issuerUrl: _issuerUrl, log } = opts;
  const getIssuerUrl = (): string =>
    typeof _issuerUrl === "function" ? _issuerUrl() : _issuerUrl;
  const getOperatorHandle = (): string =>
    typeof _operatorHandle === "function" ? _operatorHandle() : _operatorHandle;

  const dropletsByActx = new Map<string, Map<string, Droplet>>();

  function getDropletsMap(actx: string): Map<string, Droplet> {
    let m = dropletsByActx.get(actx);
    if (!m) { m = new Map(); dropletsByActx.set(actx, m); }
    return m;
  }

  function getDropletById(id: string): Record<string, unknown> | undefined {
    if (opts.getDroplet) return opts.getDroplet(id);
    for (const m of dropletsByActx.values()) {
      const d = m.get(id);
      if (d) return d as unknown as Record<string, unknown>;
    }
    return undefined;
  }

  const oidcIssuer = createOidcIssuer({
    getIssuerUrl,
    getDroplet: getDropletById,
    log: (level, msg, extra) => {
      if (level === "info") log.info(msg, extra);
      else if (level === "warn") log.warn(msg, extra);
      else if (level === "error") log.error(msg, extra);
      else log.info(msg, extra);
    },
  });

  const factory = createFactory<ComputeProviderLocalEnv>({
    initApp: (app) => {
      app.use("*", cors());
      registerErrorMiddleware(app, log);

      app.use("*", async (c, next) => {
        log.info("request", { method: c.req.method, path: c.req.path });
        await next();
      });

      app.route("/", oidcIssuer.app);

      app.use("/v2/account", async (c, next) => {
        try {
          const token = extractBearer(c.req.header("Authorization"));
          c.set("actx", token);
          await next();
        } catch (err) {
          return c.json({ id: "unauthorized", message: String(err) }, 401);
        }
      });

      app.use("/v2/droplets", async (c, next) => {
        try {
          const token = extractBearer(c.req.header("Authorization"));
          c.set("actx", token);
          await next();
        } catch (err) {
          return c.json({ id: "unauthorized", message: String(err) }, 401);
        }
      });

      app.use("/v2/droplets/*", async (c, next) => {
        try {
          const token = extractBearer(c.req.header("Authorization"));
          c.set("actx", token);
          await next();
        } catch (err) {
          return c.json({ id: "unauthorized", message: String(err) }, 401);
        }
      });

      app.get("/v2/account", (c) => {
        const actx = c.get("actx");
        return c.json({ account: { team: { uuid: actx } } });
      });

      app.post("/v2/droplets", async (c) => {
        let body: DropletCreateRequest;
        try {
          body = await c.req.json<DropletCreateRequest>();
        } catch {
          return c.json({ id: "unprocessable_entity", message: "Invalid JSON body" }, 422);
        }

        if (!body.name) {
          return c.json({ id: "unprocessable_entity", message: "'name' is required" }, 422);
        }

        if (body.region === "invalid-region-for-auth-check") {
          return c.json({ id: "unprocessable_entity", message: "invalid region" }, 422);
        }

        try {
          const actx = c.get("actx");
          const droplet = makeDroplet(body);
          getDropletsMap(actx).set(droplet.id, droplet);

          const provisioningData = await ProvisioningData.create(actx, body.user_data ?? null, getIssuerUrl());
          body.user_data = provisioningData.userData;
          provisioningData.associateWithDroplet(droplet.id);

          log.info("droplets.create -> local VM", { name: body.name, actx });
          spawnVM({
            droplet: droplet as unknown as Record<string, unknown>,
            userData: provisioningData.userData,
            vmImage: opts.vmImage,
            containerMode: opts.containerMode,
            containerImage: opts.containerImage,
            cacheDir: opts.cacheDir ?? defaultCacheDir(),
            log,
          });
          return c.json({ droplet }, 202);
        } catch (err) {
          log.error("droplets create failed", { error: String(err) });
          return c.json({ id: "server_error", message: String(err) }, 500);
        }
      });

      app.get("/v2/droplets", (c) => {
        const actx = c.get("actx");
        return c.json({ droplets: [...getDropletsMap(actx).values()] });
      });

      app.get("/v2/droplets/:id", (c) => {
        const actx = c.get("actx");
        const id = c.req.param("id");
        const droplet = getDropletsMap(actx).get(id);
        if (!droplet) return c.json({ id: "not_found", message: "Droplet not found" }, 404);
        return c.json({ droplet });
      });

      app.delete("/v2/droplets/:id", async (c) => {
        const actx = c.get("actx");
        const id = c.req.param("id");
        const dm = getDropletsMap(actx);
        if (!dm.has(id)) return c.json({ id: "not_found", message: "Droplet not found" }, 404);
        dm.delete(id);
        await new Deno.Command("docker", { args: ["kill", `droplet-${id}`] }).output().catch(() => {});
        await new Deno.Command("docker", { args: ["rm", "-f", `droplet-${id}`] }).output().catch(() => {});
        return new Response(null, { status: 204 });
      });
    },
  });

  return {
    createApp: () => factory.createApp(),
    state: { dropletsByActx },
    async killAllDroplets() {
      const ids = [...dropletsByActx.values()].flatMap((m) => [...m.keys()]);
      if (ids.length === 0) return;
      log.info("shutdown: killing droplets", { ids });
      await Promise.all(
        ids.map((id) =>
          new Deno.Command("docker", { args: ["rm", "-f", `droplet-${id}`] })
            .output()
            .catch(() => {})
        ),
      );
    },

    async provisionDroplet(
      vm: VM,
      actx: string,
      provOpts?: { image?: string; region?: string; size?: string; tags?: string[] },
    ): Promise<ProvisionResult> {
      const droplet = makeDroplet({
        name: `vm-${crypto.randomUUID().slice(0, 8)}`,
        region: provOpts?.region,
        size: provOpts?.size,
        image: provOpts?.image,
        user_data: vm.user_data,
        tags: provOpts?.tags,
      });
      getDropletsMap(actx).set(droplet.id, droplet);

      const provisioningData = await ProvisioningData.create(actx, vm.user_data, getIssuerUrl());
      provisioningData.associateWithDroplet(droplet.id);

      log.info("provisionDroplet -> local container", {
        name: droplet.name,
        actx,
        image: droplet.image?.slug,
      });

      await spawnVM({
        droplet: droplet as unknown as Record<string, unknown>,
        userData: provisioningData.userData,
        vmImage: opts.vmImage,
        containerMode: opts.containerMode,
        containerImage: opts.containerImage,
        cacheDir: opts.cacheDir ?? defaultCacheDir(),
        log,
      });

      return {
        providerId: droplet.id,
        metadata: {
          dropletId: droplet.id,
          containerName: (droplet as unknown as Record<string, unknown>)["containerName"] ?? null,
          ip: droplet.networks?.v4?.[0]?.ip_address ?? "",
          mode: opts.containerMode ? "container" : "vm",
        },
      };
    },
  };
}
