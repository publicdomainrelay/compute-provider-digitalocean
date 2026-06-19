import { createFactory } from "hono/factory";
import { cors } from "hono/cors";
import type { Hono } from "hono";
import { registerErrorMiddleware } from "@publicdomainrelay/hono-error-middleware";
import { ON_BEHALF_OF_HEADER } from "@publicdomainrelay/compute-provider-common";
import type { LoggerInterface } from "@publicdomainrelay/logger";
import { createOidcIssuer, createOidcProvisioningEnricher } from "@publicdomainrelay/oidc-issuer-hono";

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
  id: number;
  name: string;
  status: "new" | "active" | "off" | "archive";
  created_at: string;
  region: { slug: string; name: string };
  size_slug: string;
  image: { slug: string };
  networks: { v4: { ip_address: string; type: string }[] };
  tags: string[];
}

export type ComputeProviderDigitalOceanEnv = {
  Variables: {
    actx: string;
  };
};

export interface ComputeProviderDigitalOceanFactoryOptions {
  operatorHandle: string | (() => string);
  selfDid: string;
  issuerUrl: string | (() => string);
  digitaloceanBaseUrl: string;
  doToken: string;
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

export interface ComputeProviderDigitalOceanFactory {
  createApp(): ReturnType<ReturnType<typeof createFactory<ComputeProviderDigitalOceanEnv>>["createApp"]>;
  state: ComputeProviderDigitalOceanFactoryState;
}

export interface ComputeProviderDigitalOceanFactoryState {
  dropletsByActx: Map<string, Map<number, Droplet>>;
}

export function createComputeProviderDigitalOceanFactory(
  opts: ComputeProviderDigitalOceanFactoryOptions,
): ComputeProviderDigitalOceanFactory {
  const { operatorHandle: _operatorHandle, issuerUrl: _issuerUrl, log, digitaloceanBaseUrl, doToken } = opts;
  const getIssuerUrl = (): string =>
    typeof _issuerUrl === "function" ? _issuerUrl() : _issuerUrl;
  const getOperatorHandle = (): string =>
    typeof _operatorHandle === "function" ? _operatorHandle() : _operatorHandle;

  const dropletsByActx = new Map<string, Map<number, Droplet>>();

  const oidcProvisioningEnricher = createOidcProvisioningEnricher(getIssuerUrl);

  function getDropletsMap(actx: string): Map<number, Droplet> {
    let m = dropletsByActx.get(actx);
    if (!m) { m = new Map(); dropletsByActx.set(actx, m); }
    return m;
  }

  function getDropletById(id: string): Record<string, unknown> | undefined {
    if (opts.getDroplet) return opts.getDroplet(id);
    for (const m of dropletsByActx.values()) {
      const d = m.get(Number(id));
      if (d) return d as unknown as Record<string, unknown>;
    }
    return undefined;
  }

  const oidcIssuer = createOidcIssuer({
    getIssuerUrl,
    getDroplet: getDropletById,
    serviceUrl: getIssuerUrl(),
    log: (level, msg, extra) => {
      if (level === "info") log.info(msg, extra);
      else if (level === "warn") log.warn(msg, extra);
      else if (level === "error") log.error(msg, extra);
      else log.info(msg, extra);
    },
  });

  const factory = createFactory<ComputeProviderDigitalOceanEnv>({
    initApp: (app) => {
      app.use("*", cors());
      registerErrorMiddleware(app, log);

      app.use("*", async (c, next) => {
        log.info("request", { method: c.req.method, path: c.req.path });
        await next();
      });

      app.route("/", oidcIssuer.app as unknown as Hono);

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

      app.get("/v2/account", async (c) => {
        const res = await fetch(`${digitaloceanBaseUrl}/v2/account`, {
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${doToken}`,
            [ON_BEHALF_OF_HEADER]: c.get("actx"),
          },
        });
        const json = await res.json();
        return c.json(json);
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

        try {
          const actx = c.get("actx");
          log.info("droplets.create -> DO proxy", { name: body.name, actx });

          const enriched = await oidcProvisioningEnricher.enrich(body.user_data ?? "", actx, getIssuerUrl());
          body.user_data = enriched.userData;
          enriched.associateWithDroplet(body.name);

          const res = await fetch(`${digitaloceanBaseUrl}/v2/droplets`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${doToken}`,
              [ON_BEHALF_OF_HEADER]: actx,
            },
            body: JSON.stringify(body),
          });
          const json = await res.json();
          if (res.status >= 400) {
            return c.json(json, res.status as 400);
          }
          return c.json(json, 202);
        } catch (err) {
          log.error("droplets create failed", { error: String(err) });
          return c.json({ id: "server_error", message: String(err) }, 500);
        }
      });

      app.get("/v2/droplets", async (c) => {
        const actx = c.get("actx");
        const res = await fetch(`${digitaloceanBaseUrl}/v2/droplets`, {
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${doToken}`,
            [ON_BEHALF_OF_HEADER]: actx,
          },
        });
        const json = await res.json();
        return c.json(json);
      });

      app.get("/v2/droplets/:id", async (c) => {
        const actx = c.get("actx");
        const id = c.req.param("id");
        const res = await fetch(`${digitaloceanBaseUrl}/v2/droplets/${id}`, {
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${doToken}`,
            [ON_BEHALF_OF_HEADER]: actx,
          },
        });
        const json = await res.json();
        if (res.status === 404) return c.json({ id: "not_found", message: "Droplet not found" }, 404);
        return c.json(json);
      });

      app.delete("/v2/droplets/:id", async (c) => {
        const actx = c.get("actx");
        const id = c.req.param("id");
        const res = await fetch(`${digitaloceanBaseUrl}/v2/droplets/${id}`, {
          method: "DELETE",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${doToken}`,
            [ON_BEHALF_OF_HEADER]: actx,
          },
        });
        if (res.status >= 400 && res.status !== 404) {
          const body = await res.text();
          log.error("DO delete droplet failed", { dropletId: id, status: res.status, body });
          return c.json({ id: "server_error", message: body }, res.status as 400);
        }
        return new Response(null, { status: 204 });
      });
    },
  });

  return {
    createApp: () => factory.createApp(),
    state: { dropletsByActx },
  };
}
