import { assertEquals } from "@std/assert";
import { createOidcIssuer } from "@publicdomainrelay/oidc-issuer-hono";

async function signToken(hostKeyPath: string, token: string): Promise<string> {
  const child = new Deno.Command("ssh-keygen", {
    args: ["-Y", "sign", "-n", "prove-sshd", "-f", hostKeyPath],
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const writer = child.stdin.getWriter();
  await writer.write(new TextEncoder().encode(token));
  await writer.close();
  return new TextDecoder().decode((await child.output()).stdout).trim();
}

Deno.test("[integration] OIDC workload identity provisioning flow", async () => {
  const tmpDir = await Deno.makeTempDir();
  const hostKeyPath = `${tmpDir}/ssh_host_ed25519_key`;
  const secretsDir = `${tmpDir}/root/secrets/digitalocean.com/serviceaccount`;

  await new Deno.Command("ssh-keygen", {
    args: ["-t", "ed25519", "-f", hostKeyPath, "-N", "", "-C", "test"],
    stdout: "null",
    stderr: "null",
  }).output();
  const [keyType, publicKey] = (await Deno.readTextFile(`${hostKeyPath}.pub`)).trim().split(/\s+/);

  const ac = new AbortController();
  const listening = Promise.withResolvers<number>();
  let issuerUrl = "";
  const teamUuid = crypto.randomUUID();
  const dropletId = crypto.randomUUID().slice(0, 8);
  const oidcIssuer = createOidcIssuer({
    getIssuerUrl: () => issuerUrl,
    getDroplet: (id: string) => (id === dropletId ? { id: dropletId, tags: [] } : undefined),
  });
  const server = Deno.serve(
    { port: 0, hostname: "127.0.0.1", signal: ac.signal, onListen: (addr) => listening.resolve(addr.port) },
    oidcIssuer.app.fetch,
  );
  issuerUrl = `http://127.0.0.1:${await listening.promise}`;

  try {
    const provisioningData = await oidcIssuer.createProvisioningData(teamUuid, null);
    provisioningData.associateWithDroplet(dropletId);
    const tokenData = provisioningData.token.asString;
    const sshSig = await signToken(hostKeyPath, tokenData);

    const reportRes = await fetch(`${issuerUrl}/v1/host-keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ keys: [{ type: keyType, publicKey }], token: tokenData, signature: sshSig }),
    });
    assertEquals(reportRes.status, 200, `host-keys report failed: ${await reportRes.text()}`);

    const proveRes = await fetch(`${issuerUrl}/v1/oidc/prove`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${tokenData}` },
      body: JSON.stringify({ sig: sshSig }),
    });
    const proveBody = await proveRes.json();
    assertEquals(proveRes.status, 200, `Prove failed: ${JSON.stringify(proveBody)}`);

    const finalToken = proveBody.token as string;
    if (!finalToken || finalToken === "null") throw new Error("No token in prove response");

    const validated = await oidcIssuer.validateToken(finalToken);
    assertEquals(validated.actx, teamUuid);

    await Deno.mkdir(secretsDir, { recursive: true });
    await Deno.writeTextFile(`${secretsDir}/token`, finalToken);
    await Deno.writeTextFile(`${secretsDir}/team_uuid`, teamUuid);
    await Deno.writeTextFile(`${secretsDir}/base_url`, issuerUrl);
    const writtenToken = await Deno.readTextFile(`${secretsDir}/token`);
    assertEquals(writtenToken, finalToken);
    assertEquals((await oidcIssuer.validateToken(writtenToken)).actx, teamUuid);
  } finally {
    ac.abort();
    await server.finished;
    await Deno.remove(tmpDir, { recursive: true }).catch(() => {});
  }
});
