import { assertEquals, assertStringIncludes } from "@std/assert";
import { SECRETS_PREFIX } from "@publicdomainrelay/compute-provider-firecracker";
import { configureOidc, ProvisioningData } from "@publicdomainrelay/oidc-issuer-hono";

Deno.test("the firecracker bid config points the guest at the token the provisioning script writes", async () => {
  configureOidc({ getIssuerUrl: () => "https://issuer.example" });
  const data = await ProvisioningData.create("team", "#cloud-config\n", "https://issuer.example");
  const script = JSON.stringify(data);
  for (const file of ["token", "base_url", "team_uuid"]) {
    assertStringIncludes(script, `${SECRETS_PREFIX}/${file}`);
  }
  assertEquals(SECRETS_PREFIX.startsWith("/root/secrets/"), true);
});
