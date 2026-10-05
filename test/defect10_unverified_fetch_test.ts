import { assertEquals, assertExists } from "@std/assert";
import { Hono } from "hono";
import { createOidcIssuer, OIDCToken } from "@publicdomainrelay/oidc-issuer-hono";
import { createPlcDirectory } from "./plc_directory.ts";

const RBAC_NSID = "com.fedproxy.rbac";

// The caller's chosen host. In production this is any name the caller owns;
// here the harness bridges the name onto a local port so the connection is
// observable, the same bridge atproto-market's harness uses.
const ATTACKER_HOST = "attacker.localhost";

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

interface Hit {
  url: string;
  host: string;
}

const outbound: Hit[] = [];
const realFetch = globalThis.fetch;
let didDocPort = 0;

globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
  const url = typeof input === "string"
    ? input
    : input instanceof URL
    ? input.href
    : (input as Request).url;
  const u = new URL(url);
  outbound.push({ url, host: u.host });
  if (u.hostname === ATTACKER_HOST) {
    return realFetch(`http://127.0.0.1:${didDocPort}${u.pathname}${u.search}`, init);
  }
  return realFetch(input as string, init);
}) as typeof fetch;

Deno.test("[defect10] no server-side fetch derived from an unverified aud, per DID method", async () => {
  const attackerKeys = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );

  let issuerUrl = "";

  const rbacFor = (actx: string, sub: string): Record<string, unknown> => ({
    $type: RBAC_NSID,
    protects: { "attacker-role": { service: issuerUrl, scope: "droplets.wid" } },
    roles: {
      "attacker-role": {
        role_name: "attacker-role",
        definition: { aud: `api://DigitalOcean?actx=${actx}`, sub, policies: ["attacker-role"] },
      },
    },
    policies: {
      "attacker-role": {
        meta: { policy: "attacker-role" },
        schemas: { "/v1/oidc/issue": { type: "object", properties: { capability: { enum: ["create"] } } } },
      },
    },
  });

  // PDS named by the did:web DID document — the caller's own document names it.
  const pdsWebHits: string[] = [];
  const pdsWebApp = new Hono();
  pdsWebApp.get("/xrpc/com.atproto.repo.listRecords", (c) => {
    pdsWebHits.push(`${c.req.method} ${c.req.path}?repo=${c.req.query("repo") ?? ""}`);
    return c.json({
      records: [{
        uri: "at://x/1",
        value: rbacFor(ATTACKER_HOST, `actx:${ATTACKER_HOST}:plc:deadbeef:role:worker`),
      }],
    });
  });
  const pdsWeb = await serve(pdsWebApp.fetch);

  const didDocHits: string[] = [];
  const { promise: didDocReady, resolve: resolveDidDocPort } = Promise.withResolvers<number>();
  const didDocAc = new AbortController();
  Deno.serve(
    {
      port: 0,
      hostname: "127.0.0.1",
      signal: didDocAc.signal,
      onListen: (addr) => {
        didDocPort = (addr as Deno.NetAddr).port;
        resolveDidDocPort(didDocPort);
      },
    },
    (req) => {
      const u = new URL(req.url);
      didDocHits.push(`${req.method} ${u.pathname}`);
      return Response.json({
        "@context": ["https://www.w3.org/ns/did/v1"],
        id: `did:web:${ATTACKER_HOST}`,
        service: [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: pdsWeb.url }],
      });
    },
  );
  await didDocReady;

  // PDS named by the PLC directory's DID document.
  const pdsPlcHits: string[] = [];
  const plcRepo = new Map<string, { actx: string; sub: string }>();
  const pdsPlcApp = new Hono();
  pdsPlcApp.get("/xrpc/com.atproto.repo.listRecords", (c) => {
    const repo = c.req.query("repo") ?? "";
    pdsPlcHits.push(`${c.req.method} ${c.req.path}?repo=${repo}`);
    const entry = plcRepo.get(repo);
    return c.json({
      records: entry
        ? [{ uri: `at://${repo}/${RBAC_NSID}/1`, value: rbacFor(entry.actx, entry.sub) }]
        : [],
    });
  });
  const pdsPlc = await serve(pdsPlcApp.fetch);

  const { app: plcApp, registerDid } = createPlcDirectory();
  const plcHits: string[] = [];
  const { promise: plcReady, resolve: resolvePlcUrl } = Promise.withResolvers<string>();
  const plcAc = new AbortController();
  Deno.serve(
    {
      port: 0,
      hostname: "127.0.0.1",
      signal: plcAc.signal,
      onListen: (addr) => resolvePlcUrl(`http://127.0.0.1:${(addr as Deno.NetAddr).port}`),
    },
    (req) => {
      plcHits.push(`${req.method} ${new URL(req.url).pathname}`);
      return plcApp.fetch(req);
    },
  );
  const plcUrl = await plcReady;

  const plcUuid = crypto.randomUUID();
  const plcDid = `did:plc:${plcUuid}`;
  const plcSub = `actx:${plcUuid}:plc:deadbeef:role:worker`;
  const internalLookingActx = "metadata-google-internal";
  registerDid(plcDid, pdsPlc.url);

  const { app } = createOidcIssuer({
    getIssuerUrl: () => issuerUrl,
    getDroplet: () => undefined,
    serviceUrl: issuerUrl,
    plcDirectoryUrl: plcUrl,
  });
  const provider = await serve(app.fetch);
  issuerUrl = provider.url;
  const providerHost = new URL(issuerUrl).host;
  plcRepo.set(plcDid, { actx: plcUuid, sub: plcSub });

  const post = async (token: string, body: Record<string, unknown>) => {
    const res = await fetch(`${issuerUrl}/v1/oidc/issue`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.text() };
  };

  const mark = () => ({
    outbound: outbound.length,
    didDoc: didDocHits.length,
    pdsWeb: pdsWebHits.length,
    plc: plcHits.length,
    pdsPlc: pdsPlcHits.length,
  });
  const since = (b: ReturnType<typeof mark>) => ({
    outbound: outbound.slice(b.outbound).filter((h) => h.host !== providerHost),
    didDoc: didDocHits.slice(b.didDoc),
    pdsWeb: pdsWebHits.slice(b.pdsWeb),
    plc: plcHits.slice(b.plc),
    pdsPlc: pdsPlcHits.slice(b.pdsPlc),
  });

  const measurements: string[] = [];
  const runCase = async (label: string, contract: string, actx: string, sub: string) => {
    const before = mark();
    const token = await signRs256(attackerKeys.privateKey, {
      sub,
      iss: contract,
      aud: `api://DigitalOcean?actx=${actx}`,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const res = await post(token, { sub, ttl: 3600 });
    const mine = since(before);
    measurements.push(
      `${label}\n    actx=${actx}\n    status=${res.status} body=${res.body}\n    outbound=${JSON.stringify(mine.outbound)}` +
        `\n    servers reached: didDoc=${mine.didDoc.length} pdsWeb=${mine.pdsWeb.length} plc=${mine.plc.length} pdsPlc=${mine.pdsPlc.length}`,
    );
    return mine;
  };

  // --- M1: did:web. The caller writes the host into aud; actx has a dot.
  const web = await runCase(
    "M1 did:web",
    "https://attacker-issuer.invalid",
    ATTACKER_HOST,
    `actx:${ATTACKER_HOST}:plc:deadbeef:role:worker`,
  );

  // --- M2: did:plc. Resolution goes through the pinned directory.
  const plcCase = await runCase("M2 did:plc", "https://attacker-issuer.invalid", plcUuid, plcSub);

  // --- M3: an internal-looking name with no dot is classified did:plc, so it
  //         cannot move the host of the first hop.
  const internal = await runCase(
    "M3 did:plc (internal-looking name)",
    "https://attacker-issuer.invalid",
    internalLookingActx,
    `actx:${internalLookingActx}:plc:deadbeef:role:worker`,
  );

  // --- CONTROL: the legitimate flow. A provider-minted token for a did:plc actx
  //     registered under the pinned directory must still be admitted — and the
  //     RBAC fetch must still happen, so this is a reorder and not a removal.
  const beforeControl = mark();
  const controlToken = await OIDCToken.create(plcUuid, { sub: plcSub });
  const control = await post(controlToken.asString, { sub: plcSub, ttl: 3600 });
  const controlHits = since(beforeControl);
  measurements.push(
    `CONTROL (provider-minted, did:plc under the pinned directory)\n    actx=${plcUuid}\n    status=${control.status} body=${control.body}\n    outbound=${JSON.stringify(controlHits.outbound)}` +
      `\n    servers reached: didDoc=${controlHits.didDoc.length} pdsWeb=${controlHits.pdsWeb.length} plc=${controlHits.plc.length} pdsPlc=${controlHits.pdsPlc.length}`,
  );

  console.log("-- defect10 measurements ------------------------------------");
  for (const m of measurements) console.log(m);
  console.log(`  did:web DID-document server received: ${JSON.stringify(didDocHits)}`);
  console.log(`  did:web PDS server received:          ${JSON.stringify(pdsWebHits)}`);
  console.log(`  pinned PLC directory received:        ${JSON.stringify(plcHits)}`);
  console.log(`  did:plc PDS server received:          ${JSON.stringify(pdsPlcHits)}`);
  console.log("-------------------------------------------------------------");

  // NEGATIVE, and it holds in both directions: for did:plc the first hop is the
  // pinned directory, so no request goes to a host taken from the caller's aud.
  const allowedPlcHosts = [new URL(plcUrl).host, new URL(pdsPlc.url).host];
  for (const [i, c] of [plcCase, internal].entries()) {
    for (const h of c.outbound) {
      if (!allowedPlcHosts.includes(h.host)) {
        throw new Error(`did:plc case ${i}: request went to ${h.url}`);
      }
    }
  }

  // The defect: before any verification, the provider fetched a host the caller named.
  assertEquals(web.outbound.length, 0, "no outbound request for an unverified aud (did:web)");
  assertEquals(web.didDoc.length, 0, "the caller-named host must receive nothing");
  assertEquals(web.pdsWeb.length, 0, "the PDS named by the caller's DID document must receive nothing");

  // Same for the pinned-directory case: the fetch must not happen pre-verification either.
  assertEquals(plcCase.outbound.length, 0, "no outbound request for an unverified aud (did:plc)");
  assertEquals(plcCase.plc.length, 0, "no PLC lookup for an unverified aud");
  assertEquals(plcCase.pdsPlc.length, 0, "no PDS lookup for an unverified aud");
  assertEquals(internal.outbound.length, 0, "no outbound request for an unverified aud (did:plc, internal name)");

  // The positive control: not a lockout — admitted, and the RBAC fetch still runs.
  assertEquals(control.status, 200, `the legitimate did:plc flow must still work: ${control.body}`);
  assertExists(JSON.parse(control.body).token);
  assertEquals(controlHits.plc.length, 1, "the verified did:plc path must still resolve through the pinned directory");
  assertEquals(controlHits.pdsPlc.length, 1, "the verified did:plc path must still read its RBAC record");

  didDocAc.abort();
  pdsWeb.abort();
  pdsPlc.abort();
  plcAc.abort();
  provider.abort();
});
