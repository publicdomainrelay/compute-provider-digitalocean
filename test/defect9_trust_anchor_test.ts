import { assertEquals, assertExists, assertRejects } from "@std/assert";
import { Hono } from "hono";
import {
  configureOidc,
  createOidcIssuer,
  OIDCToken,
} from "@publicdomainrelay/oidc-issuer-hono";
import { createPlcDirectory } from "./plc_directory.ts";

const RBAC_NSID = "com.fedproxy.rbac";

async function serve(
  handler: (req: Request) => Response | Promise<Response>,
): Promise<{ url: string; abort: () => void }> {
  const ac = new AbortController();
  const { promise, resolve } = Promise.withResolvers<string>();
  Deno.serve(
    {
      port: 0,
      hostname: "127.0.0.1",
      signal: ac.signal,
      onListen: (addr) => resolve(`http://127.0.0.1:${(addr as Deno.NetAddr).port}`),
    },
    handler,
  );
  return { url: await promise, abort: () => ac.abort() };
}

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function signRs256(
  privateKey: CryptoKey,
  claims: Record<string, unknown>,
): Promise<string> {
  const enc = new TextEncoder();
  const header = b64url(enc.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const body = b64url(enc.encode(JSON.stringify(claims)));
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    enc.encode(`${header}.${body}`),
  );
  return `${header}.${body}.${b64url(new Uint8Array(sig))}`;
}

function rbacRecord(
  opts: { service: string; scope: string; roleName: string; sub: string; actx: string; iss?: string },
): Record<string, unknown> {
  return {
    $type: RBAC_NSID,
    protects: { [opts.roleName]: { service: opts.service, scope: opts.scope } },
    roles: {
      [opts.roleName]: {
        role_name: opts.roleName,
        definition: {
          ...(opts.iss ? { iss: opts.iss } : {}),
          aud: `api://DigitalOcean?actx=${opts.actx}`,
          sub: opts.sub,
          policies: [opts.roleName],
        },
      },
    },
    policies: {
      [opts.roleName]: {
        meta: { policy: opts.roleName },
        schemas: { "/v1/oidc/issue": { type: "object", properties: { capability: { enum: ["create"] } } } },
      },
    },
  };
}

Deno.test("[defect9] the gate pins its trusted issuers to configuration, never to the token's aud", async () => {
  const attackerKeys = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const attackerJwk = await crypto.subtle.exportKey("jwk", attackerKeys.publicKey);
  attackerJwk.alg = "RS256";
  attackerJwk.use = "sig";

  let attackerIssuerUrl = "";
  const attackerApp = new Hono();
  attackerApp.get("/.well-known/openid-configuration", (c) =>
    c.json({ issuer: attackerIssuerUrl, jwks_uri: `${attackerIssuerUrl}/.well-known/jwks` }));
  attackerApp.get("/.well-known/jwks", (c) => c.json({ keys: [attackerJwk] }));
  const attacker = await serve(attackerApp.fetch);
  attackerIssuerUrl = attacker.url;

  const attackUuid = crypto.randomUUID();
  const attackDid = `did:plc:${attackUuid}`;
  const attackSub = `actx:${attackUuid}:plc:${crypto.randomUUID().split("-")[0]}:role:worker`;

  const legitUuid = crypto.randomUUID();
  const legitDid = `did:plc:${legitUuid}`;
  const legitSub = `actx:${legitUuid}:plc:${crypto.randomUUID().split("-")[0]}:role:worker`;

  const rbacByRepo = new Map<string, Record<string, unknown>>();
  const pdsApp = new Hono();
  pdsApp.get("/xrpc/com.atproto.repo.listRecords", (c) => {
    const repo = c.req.query("repo") ?? "";
    const value = rbacByRepo.get(repo);
    return c.json({ records: value ? [{ uri: `at://${repo}/${RBAC_NSID}/test`, value }] : [] });
  });
  const pds = await serve(pdsApp.fetch);

  const { app: plcApp, registerDid } = createPlcDirectory();
  const plc = await serve(plcApp.fetch);
  registerDid(attackDid, pds.url);
  registerDid(legitDid, pds.url);

  let issuerUrl = "";
  const { app } = createOidcIssuer({
    getIssuerUrl: () => issuerUrl,
    getDroplet: () => undefined,
    serviceUrl: issuerUrl,
    plcDirectoryUrl: plc.url,
  });
  const provider = await serve(app.fetch);
  issuerUrl = provider.url;

  rbacByRepo.set(attackDid, rbacRecord({
    service: issuerUrl,
    scope: "droplets.wid",
    roleName: "attacker-role",
    sub: attackSub,
    actx: attackUuid,
    iss: attackerIssuerUrl,
  }));
  rbacByRepo.set(legitDid, rbacRecord({
    service: issuerUrl,
    scope: "droplets.wid",
    roleName: "legit-role",
    sub: legitSub,
    actx: legitUuid,
  }));

  const attackToken = await signRs256(attackerKeys.privateKey, {
    sub: attackSub,
    iss: attackerIssuerUrl,
    aud: `api://DigitalOcean?actx=${attackUuid}`,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  });

  const attackRes = await fetch(`${issuerUrl}/v1/oidc/issue`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${attackToken}` },
    body: JSON.stringify({ sub: attackSub, ttl: 3600 }),
  });
  console.log("ATTACK   (self-signed, caller-named PDS + iss):", attackRes.status, await attackRes.text());

  const crossTenantToken = await signRs256(attackerKeys.privateKey, {
    sub: legitSub,
    iss: attackerIssuerUrl,
    aud: `api://DigitalOcean?actx=${legitUuid}`,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  });
  const crossTenantRes = await fetch(`${issuerUrl}/v1/oidc/issue`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${crossTenantToken}` },
    body: JSON.stringify({ sub: legitSub, ttl: 3600 }),
  });
  console.log(
    "CROSS-TENANT (attacker signs for the other actx; that repo's record names no attacker issuer):",
    crossTenantRes.status,
    await crossTenantRes.text(),
  );
  let callbackResult = "admitted";
  try {
    await OIDCToken.validate(attackToken, () => [attackerIssuerUrl]);
  } catch (err) {
    callbackResult = `rejected: ${String(err)}`;
  }
  console.log("CALLBACK (issuer handed in by getIssuers, unconfigured):", callbackResult);

  const legitToken = await OIDCToken.create(legitUuid, { sub: legitSub });
  const legitRes = await fetch(`${issuerUrl}/v1/oidc/issue`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${legitToken.asString}` },
    body: JSON.stringify({ sub: legitSub, ttl: 3600 }),
  });
  const legitBody = await legitRes.text();
  console.log("CONTROL  (provider-minted, provider-written RBAC record):", legitRes.status, legitBody);

  assertEquals(
    attackRes.status,
    401,
    "a self-signed token whose aud names its own actx/PDS/issuer must be rejected",
  );
  assertEquals(
    crossTenantRes.status,
    401,
    "naming another actx must not admit the attacker: the record read from THAT repo names no attacker-controllable issuer",
  );
  await assertRejects(() => OIDCToken.validate(attackToken, () => [attackerIssuerUrl]));
  assertEquals(legitRes.status, 200, `provider-minted token must still be admitted: ${legitBody}`);
  assertExists(JSON.parse(legitBody).token);

  configureOidc({ trustedIssuerUrls: [attackerIssuerUrl] });
  const admitted = await OIDCToken.validate(attackToken, () => [attackerIssuerUrl]);
  console.log("ALLOWLIST(issuer named in configuration):", admitted.actx, admitted.sub);
  assertEquals(admitted.actx, attackUuid);
  assertEquals(admitted.sub, attackSub);


  attacker.abort();
  pds.abort();
  plc.abort();
  provider.abort();
});
