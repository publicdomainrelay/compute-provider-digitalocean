import { assertEquals, assertStringIncludes } from "@std/assert";
import { SECRETS_PREFIX } from "@publicdomainrelay/compute-provider-firecracker";
import { createOidcIssuer } from "@publicdomainrelay/oidc-issuer-hono";

Deno.test("the firecracker bid config points the guest at the token the provisioning script writes", async () => {
  const issuer = createOidcIssuer({ getIssuerUrl: () => "https://issuer.example" });
  const data = await issuer.createProvisioningData("team", "#cloud-config\n");
  const script = JSON.stringify(data);
  for (const file of ["token", "base_url", "team_uuid"]) {
    assertStringIncludes(script, `${SECRETS_PREFIX}/${file}`);
  }
  assertEquals(SECRETS_PREFIX.startsWith("/root/secrets/"), true);
});
