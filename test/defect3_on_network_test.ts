import { assert, assertEquals } from "@std/assert";
import { Hono } from "@hono/hono";
import { ProvisioningData } from "@publicdomainrelay/oidc-issuer-hono";
import { createComputeProviderLocal, type ComputeProviderLocalCtx } from "@publicdomainrelay/compute-provider-local";
import type { ServeHandle } from "@publicdomainrelay/serve";

const ISSUER = "http://127.0.0.1:9977";

function b64url(s: string): string {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function forgedToken(): string {
  const now = Math.floor(Date.now() / 1000);
  return `${b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }))}.${
    b64url(JSON.stringify({ iss: ISSUER, aud: "api://DigitalOcean?actx:attacker:role:admin", sub: "actx:attacker:role:admin", iat: now, exp: now + 3600 }))
  }.not-a-signature`;
}

Deno.test("defect3: /v1/on-network must verify the token signature, not just exp", async () => {
  const app = new Hono();
  const callbacks: Array<(ref: string) => void | Promise<void>> = [];
  const serve = {
    app,
    addRelay: () => {},
    onConnected: (cb: (ref: string) => void | Promise<void>) => { callbacks.push(cb); },
    beginServe: async () => {},
    shutdown: () => {},
    tcpPort: 0,
  } as unknown as ServeHandle;

  const ctx = {
    serve,
    atproto: { createRecord: async () => ({ uri: "at://x/y", cid: "b" }) },
    getIssuerUrl: () => ISSUER,
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    acceptToContract: new Map(),
    jsrBaseDir: new URL("../../..", import.meta.url).pathname,
  } as unknown as ComputeProviderLocalCtx;

  createComputeProviderLocal(ctx);
  await callbacks[0]("did:web:onnetwork.test");

  const post = (token: string) =>
    app.request("/v1/on-network", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ acceptUri: "at://did:plc:x/com.publicdomainrelay.temp.market.accept/y", acceptCid: "bafyreiexample" }),
    });

  const forged = await post(forgedToken());
  console.log("[defect3] forged token ->", forged.status, JSON.stringify(await forged.json()));

  const provisioning = await ProvisioningData.create("defect3team", null, ISSUER);
  const legit = await post(provisioning.token.asString);
  console.log("[defect3] issuer-minted token ->", legit.status, JSON.stringify(await legit.json()));

  assertEquals(forged.status, 401);
  assertEquals(legit.status, 404);
  assert(true);
});
