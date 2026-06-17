import { Hono } from "hono";

export interface PlcDirectory {
  app: Hono;
  registerDid: (did: string, pdsUrl: string) => void;
}

export function createPlcDirectory(): PlcDirectory {
  const docs = new Map<string, object>();

  const app = new Hono();

  app.get("/*", (c) => {
    const path = c.req.path;
    const raw = decodeURIComponent(path);
    const did = raw.startsWith("/") ? raw.slice(1) : raw;
    const doc = docs.get(did);
    if (!doc) return c.json({ error: "not_found", message: `DID not found: ${did}` }, 404);
    return c.json(doc);
  });

  function registerDid(did: string, pdsUrl: string): void {
    docs.set(did, {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: did,
      service: [
        {
          id: "#atproto_pds",
          type: "AtprotoPersonalDataServer",
          serviceEndpoint: pdsUrl,
        },
      ],
    });
  }

  return { app, registerDid };
}
