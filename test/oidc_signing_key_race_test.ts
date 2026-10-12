import { assert, assertEquals } from "@std/assert";
import { createOidcIssuer, PROVISIONING_TOKEN_PATH } from "@publicdomainrelay/oidc-issuer-hono";
import { parse as parseYaml } from "@std/yaml";

function provisioningTokenOf(userData: string): string {
  const doc = parseYaml(userData.replace(/^#cloud-config\n/, "")) as { write_files: Array<{ path: string; content: string }> };
  return doc.write_files.find((f) => f.path === PROVISIONING_TOKEN_PATH)?.content.trim() ?? "";
}

function base64UrlDecode(part: string): Uint8Array<ArrayBuffer> {
  const b64 = part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "=");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

Deno.test("provisioning token minted while discovery is first served verifies against the published jwks", async () => {
  const issuer = "https://issuer.race.example";
  const oidcIssuer = createOidcIssuer({
    getIssuerUrl: () => issuer,
    getDroplet: () => Promise.resolve({ id: "d", tags: [], networks: { v4: [] } }),
  });
  const { app } = oidcIssuer;
  const enricher = oidcIssuer.provisioningEnricher;

  const [discovery, enriched] = await Promise.all([
    app.fetch(new Request(`${issuer}/.well-known/openid-configuration`)),
    enricher.enrich("#cloud-config\n", "team"),
  ]);
  await discovery.body?.cancel();

  const token = provisioningTokenOf(enriched.userData);
  const [headerPart, payloadPart, sigPart] = token.split(".");
  const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerPart))) as { kid: string };

  const jwksRes = await app.fetch(new Request(`${issuer}/.well-known/jwks`));
  const jwks = await jwksRes.json() as { keys: Array<JsonWebKey & { kid: string }> };
  assertEquals(jwks.keys.map((k) => k.kid), [header.kid]);

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwks.keys[0],
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const verified = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    base64UrlDecode(sigPart),
    new TextEncoder().encode(`${headerPart}.${payloadPart}`),
  );
  assert(verified, "provisioning token signature does not verify against the published jwks");

  await oidcIssuer.validateToken(token);
});
