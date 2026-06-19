import { assertEquals } from "@std/assert";
import {
  createOidcIssuer,
  ProvisioningData,
  OIDCToken,
} from "@publicdomainrelay/oidc-issuer-hono";

const SSH_KEYGEN_RETRIES = 5;
const SSHD_START_MS = 2000;

Deno.test("[integration] OIDC workload identity provisioning flow", async () => {
  const tmpDir = await Deno.makeTempDir();
  const hostKeyPath = `${tmpDir}/ssh_host_ed25519_key`;
  const secretsDir = `${tmpDir}/root/secrets/digitalocean.com/serviceaccount`;

  // ── 1. Generate SSH host keypair ──────────────────────────────────
  const keygen = new Deno.Command("ssh-keygen", {
    args: ["-t", "ed25519", "-f", hostKeyPath, "-N", "", "-C", "test"],
    stdout: "null",
    stderr: "null",
  });
  await keygen.output();

  // ── 2. Allocate ports ─────────────────────────────────────────────
  const sshListener = Deno.listen({ port: 0, hostname: "127.0.0.1" });
  const sshPort = sshListener.addr.port;
  sshListener.close();

  const issuerListener = Deno.listen({ port: 0, hostname: "127.0.0.1" });
  const issuerPort = issuerListener.addr.port;
  issuerListener.close();

  // ── 3. Start sshd ─────────────────────────────────────────────────
  const sshd = new Deno.Command("/usr/sbin/sshd", {
    args: [
      "-D",
      "-p",
      String(sshPort),
      "-h",
      hostKeyPath,
      "-f",
      "/dev/null",
      "-o",
      "StrictModes no",
      "-o",
      "UsePAM no",
      "-o",
      "PidFile none",
      "-o",
      "MaxStartups 10",
    ],
    stdout: "null",
    stderr: "null",
  });
  const sshdProc = sshd.spawn();

  // Wait for sshd to be ready, retrying
  let sshdReady = false;
  for (let i = 0; i < SSH_KEYGEN_RETRIES; i++) {
    await new Promise((r) => setTimeout(r, SSHD_START_MS / SSH_KEYGEN_RETRIES));
    try {
      const testCmd = new Deno.Command("ssh-keyscan", {
        args: ["-t", "ed25519", "-p", String(sshPort), "127.0.0.1"],
        stdout: "null",
        stderr: "null",
      });
      const { code } = await testCmd.output();
      if (code === 0) {
        sshdReady = true;
        break;
      }
    } catch {
      /* retry */
    }
  }

  if (!sshdReady) {
    try { sshdProc.kill("SIGTERM"); } catch {/* ignore */}
    await Deno.remove(tmpDir, { recursive: true }).catch(() => {});
    throw new Error("sshd not reachable after retries");
  }

  try {
    // ── 4. Setup test data ──────────────────────────────────────────
    const teamUuid = crypto.randomUUID();
    const dropletId = crypto.randomUUID().slice(0, 8);
    const issuerUrl = `http://127.0.0.1:${issuerPort}`;

    const dropletRecord = {
      id: dropletId,
      networks: { v4: [{ ip_address: "127.0.0.1", type: "public" }] },
      tags: [],
    };

    const getDroplet = (id: string) => {
      if (id === dropletId) return dropletRecord;
      return undefined;
    };

    // ── 5. Create OIDC issuer + start server ────────────────────────
    const { app } = createOidcIssuer({
      getIssuerUrl: () => issuerUrl,
      getDroplet,
      serviceUrl: issuerUrl,
    });

    const ac = new AbortController();
    const server = Deno.serve(
      {
        port: issuerPort,
        hostname: "127.0.0.1",
        signal: ac.signal,
      },
      app.fetch,
    );

    try {
      // ── 6. Create provisioning data ───────────────────────────────
      const provisioningData = await ProvisioningData.create(
        teamUuid,
        null,
        issuerUrl,
      );
      provisioningData.associateWithDroplet(dropletId);

      // ── 7. SSH-sign the provisioning token ────────────────────────
      const tokenData = provisioningData.token.asString;

      const signProc = new Deno.Command("ssh-keygen", {
        args: ["-Y", "sign", "-n", "prove-sshd", "-f", hostKeyPath],
        stdin: "piped",
        stdout: "piped",
        stderr: "piped",
      });
      const signChild = signProc.spawn();
      const signWriter = signChild.stdin.getWriter();
      await signWriter.write(new TextEncoder().encode(tokenData));
      await signWriter.close();
      const signResult = await signChild.output();

      const sshSig = new TextDecoder().decode(signResult.stdout).trim();

      // ── 8. POST /v1/oidc/prove ────────────────────────────────────
      const proveRes = await fetch(
        `http://127.0.0.1:${issuerPort}/v1/oidc/prove`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${tokenData}`,
          },
          body: JSON.stringify({ sig: sshSig, port: sshPort }),
        },
      );

      const proveBody = await proveRes.json();

      assertEquals(
        proveRes.status,
        200,
        `Prove failed: ${JSON.stringify(proveBody)}`,
      );

      const finalToken = proveBody.token as string;
      if (!finalToken || finalToken === "null") {
        throw new Error("No token in prove response");
      }

      // ── 9. Validate the returned JWT ──────────────────────────────
      const validated = await OIDCToken.validate(finalToken);
      assertEquals(validated.actx, teamUuid);

      // ── 10. Write to secrets path ─────────────────────────────────
      await Deno.mkdir(secretsDir, { recursive: true });
      await Deno.writeTextFile(`${secretsDir}/token`, finalToken);
      await Deno.writeTextFile(`${secretsDir}/team_uuid`, teamUuid);
      await Deno.writeTextFile(`${secretsDir}/base_url`, issuerUrl);

      // ── 11. Verify written token ──────────────────────────────────
      const writtenToken = await Deno.readTextFile(`${secretsDir}/token`);
      assertEquals(writtenToken, finalToken);

      const reValidated = await OIDCToken.validate(writtenToken);
      assertEquals(reValidated.actx, teamUuid);
    } finally {
      ac.abort();
      await server.finished;
    }
  } finally {
    try {
      sshdProc.kill("SIGTERM");
    } catch {/* already dead */}
    await sshdProc.status;
    await Deno.remove(tmpDir, { recursive: true }).catch(() => {});
  }
});
