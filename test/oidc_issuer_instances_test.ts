import { assert, assertEquals, assertNotEquals, assertRejects } from "@std/assert";
import { createMemoryJwkStore, createOidcIssuer, PROVISIONING_TOKEN_PATH } from "@publicdomainrelay/oidc-issuer-hono";
import { parse as parseYaml } from "@std/yaml";

function provisioningTokenOf(userData: string): string {
  const doc = parseYaml(userData.replace(/^#cloud-config\n/, "")) as { write_files: Array<{ path: string; content: string }> };
  return doc.write_files.find((f) => f.path === PROVISIONING_TOKEN_PATH)?.content.trim() ?? "";
}

const ISSUER_A = "https://issuer-a.instances.example";
const ISSUER_B = "https://issuer-b.instances.example";

async function discovery(app: { fetch: (req: Request) => Response | Promise<Response> }, base: string) {
  const res = await app.fetch(new Request(`${base}/.well-known/openid-configuration`));
  return await res.json() as { issuer: string; jwks_uri: string };
}

async function jwks(app: { fetch: (req: Request) => Response | Promise<Response> }, base: string) {
  const res = await app.fetch(new Request(`${base}/.well-known/jwks`));
  return await res.json() as { keys: Array<{ kid: string; n: string }> };
}

Deno.test("two issuers in one process keep their own issuer URL, key and JWKS", async () => {
  const a = createOidcIssuer({ getIssuerUrl: () => ISSUER_A });
  const b = createOidcIssuer({ getIssuerUrl: () => ISSUER_B });

  const [discA, discB] = [await discovery(a.app, ISSUER_A), await discovery(b.app, ISSUER_B)];
  assertEquals(discA.issuer, ISSUER_A);
  assertEquals(discB.issuer, ISSUER_B);
  assertEquals(discA.jwks_uri, `${ISSUER_A}/.well-known/jwks`);
  assertEquals(discB.jwks_uri, `${ISSUER_B}/.well-known/jwks`);
  assertEquals(a.getIssuerUrl(), ISSUER_A);
  assertEquals(b.getIssuerUrl(), ISSUER_B);

  const [jwksA, jwksB] = [await jwks(a.app, ISSUER_A), await jwks(b.app, ISSUER_B)];
  assertEquals(jwksA.keys.length, 1);
  assertEquals(jwksB.keys.length, 1);
  assertNotEquals(jwksA.keys[0].kid, jwksB.keys[0].kid);
  assertNotEquals(jwksA.keys[0].n, jwksB.keys[0].n);
});

Deno.test("a token from one issuer verifies only at that issuer", async () => {
  const a = createOidcIssuer({ getIssuerUrl: () => ISSUER_A });
  const b = createOidcIssuer({ getIssuerUrl: () => ISSUER_B });

  const tokenA = await a.createToken("teama", { sub: "actx:teama:role:worker" });
  const tokenB = await b.createToken("teamb", { sub: "actx:teamb:role:worker" });
  assertEquals(tokenA.claims["iss"], ISSUER_A);
  assertEquals(tokenB.claims["iss"], ISSUER_B);

  assertEquals((await a.validateToken(tokenA.asString)).actx, "teama");
  assertEquals((await b.validateToken(tokenB.asString)).actx, "teamb");
  await assertRejects(() => b.validateToken(tokenA.asString));
  await assertRejects(() => a.validateToken(tokenB.asString));
});

Deno.test("provisioning data is minted by its own issuer and its nonce lives in that issuer only", async () => {
  const a = createOidcIssuer({ getIssuerUrl: () => ISSUER_A });
  const b = createOidcIssuer({ getIssuerUrl: () => ISSUER_B });

  const enrichedA = await a.provisioningEnricher.enrich("#cloud-config\n", "teama");
  const enrichedB = await b.provisioningEnricher.enrich("#cloud-config\n", "teamb");
  assert(enrichedA.userData.includes(`THIS_ENDPOINT="${ISSUER_A}"`));
  assert(enrichedB.userData.includes(`THIS_ENDPOINT="${ISSUER_B}"`));

  const tokenA = provisioningTokenOf(enrichedA.userData);
  assertEquals((await a.validateToken(tokenA)).actx, "teama");
  await assertRejects(() => b.validateToken(tokenA));
});

Deno.test("issuers that share a JwkStore and an issuer URL share the key the store holds", async () => {
  const store = createMemoryJwkStore();
  const first = createOidcIssuer({ getIssuerUrl: () => ISSUER_A, store });
  const second = createOidcIssuer({ getIssuerUrl: () => ISSUER_A, store });
  const token = await first.createToken("shared", { sub: "actx:shared" });
  assertEquals((await second.validateToken(token.asString)).actx, "shared");
  assertEquals((await jwks(first.app, ISSUER_A)).keys[0].kid, (await jwks(second.app, ISSUER_A)).keys[0].kid);
});

Deno.test("a provisioning without an issuer base URL is refused at provision time", async () => {
  const empty = createOidcIssuer({ getIssuerUrl: () => "" });
  await assertRejects(() => empty.createProvisioningData("team", "#cloud-config\n"), Error, "issuer base URL");
  await assertRejects(() => empty.provisioningEnricher.enrich("#cloud-config\n", "team"), Error, "issuer base URL");

  const unset = createOidcIssuer({ getIssuerUrl: () => { throw new Error("relay not connected"); } });
  await assertRejects(() => unset.createProvisioningData("team", null), Error, "issuer base URL");

  const notHttp = createOidcIssuer({ getIssuerUrl: () => "did:web:issuer.example" });
  await assertRejects(() => notHttp.createProvisioningData("team", null), Error, "issuer base URL");
});

Deno.test("the on-network reporter has no hardcoded base URL and fails closed without one", async () => {
  const source = await Deno.readTextFile(new URL("../lib/oidc-issuer-hono/mod.ts", import.meta.url));
  assert(!source.includes("xrpc.fedproxy.com"), "no fedproxy literal in the issuer module");

  const issuer = createOidcIssuer({ getIssuerUrl: () => ISSUER_A });
  const { userData } = await issuer.createProvisioningData("team", "#cloud-config\n");
  assert(!userData.includes("fedproxy.com"), "no fedproxy fallback in the reporter");
  const start = userData.indexOf("#!/usr/bin/env bash", userData.indexOf("send-onnetwork.sh"));
  const script = userData.slice(start, userData.indexOf("onNetwork reported OK", start));
  const baseUrlGuard = script.split("\n").find((l) => l.includes('[ -z "${BASE_URL}" ]')) ?? "";
  assert(baseUrlGuard.includes("exit 1"), `an empty base_url stops the reporter: ${baseUrlGuard}`);
});
