import { assert, assertEquals } from "@std/assert";
import { createOidcIssuer } from "@publicdomainrelay/oidc-issuer-hono";

const ISSUER = "http://127.0.0.1:9978";
const issuer = createOidcIssuer({ getIssuerUrl: () => ISSUER });

function reporter(userData: string): { script: string; unit: string[] } {
  const scriptStart = userData.indexOf("#!/usr/bin/env bash", userData.indexOf("send-onnetwork.sh"));
  const script = userData.slice(scriptStart, userData.indexOf("onNetwork reported OK", scriptStart));
  const unitStart = userData.indexOf("Description=Report onNetwork to compute provider");
  const unit = userData.slice(unitStart, userData.indexOf("WantedBy=", unitStart)).split("\n").map((l) => l.trim());
  return { script, unit };
}

Deno.test("the oidc reporter never publishes the guest's hostname as its address", async () => {
  const { userData } = await issuer.createProvisioningData("reporterteam", "#cloud-config\n");
  const { script } = reporter(userData);
  assert(!script.includes("hostname"), "no hostname fallback: a bare name is not an address a requester can reach");
  assert(script.includes("/run/guest-fqdn"), "reads the rendezvous file the transport writes");
});

Deno.test("the oidc reporter waits for the transport long enough for a slow boot and says why when it gives up", async () => {
  const { userData } = await issuer.createProvisioningData("reporterteam", "#cloud-config\n");
  const { script, unit } = reporter(userData);
  const waits = [...script.matchAll(/seq 1 (\d+)\); do\s+FQDN=/g)].map((m) => Number(m[1]));
  assertEquals(waits.length, 1);
  assert(waits[0] * 2 >= 600, `waits ${waits[0] * 2}s for /run/guest-fqdn; a guest whose transport starts late needs 600s`);
  assert(script.includes("systemctl list-jobs"), "dumps the pending jobs when it gives up");
  assert(unit.some((l) => l.startsWith("After=") && l.includes("iroh.service")), "ordered after the iroh listener");
  assert(unit.includes("StandardOutput=journal+console"), "its account reaches the guest console the bidder keeps");
});
