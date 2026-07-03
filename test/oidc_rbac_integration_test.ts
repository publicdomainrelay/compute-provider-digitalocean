import { assertEquals, assertExists } from "@std/assert";
import {
  createOidcIssuer,
  ProvisioningData,
  OIDCToken,
} from "@publicdomainrelay/oidc-issuer-hono";
import {
  resolvePDS,
  getRBACRecord,
} from "@publicdomainrelay/rbac-atproto";
import { createPlcDirectory } from "./plc_directory.ts";
import { Hono } from "hono";

const RBAC_NSID = "com.fedproxy.rbac";

Deno.test("[integration] RBAC-protected /v1/oidc/issue flow", async () => {
  const tmpDir = await Deno.makeTempDir();
  const hostKeyPath = `${tmpDir}/ssh_host_ed25519_key`;
  const secretsDir = `${tmpDir}/root/secrets/digitalocean.com/serviceaccount`;

  // ── 1. Generate SSH host keypair ──────────────────────────────────
  await new Deno.Command("ssh-keygen", {
    args: ["-t", "ed25519", "-f", hostKeyPath, "-N", "", "-C", "test"],
    stdout: "null", stderr: "null",
  }).output();

  // ── 2. Setup test data ────────────────────────────────────────────
  const actxUuid = crypto.randomUUID();
  const actxDid = `did:plc:${actxUuid}`;
  const requesterPlc = crypto.randomUUID().split("-")[0];
  const roleName = `ex-${actxUuid}-${requesterPlc}-worker`;
  const subject = `actx:${actxUuid}:plc:${requesterPlc}:role:worker`;

  let issuerUrl = "";

  // ── 3. Start PLC directory (port 0) ───────────────────────────────
  const { app: plcApp, registerDid } = createPlcDirectory();
  const plcAc = new AbortController();
  const { promise: plcPortReady, resolve: resolvePlcPort } = Promise.withResolvers<number>();
  Deno.serve(
    { port: 0, hostname: "127.0.0.1", signal: plcAc.signal, onListen: (addr) => resolvePlcPort((addr as Deno.NetAddr).port) },
    plcApp.fetch,
  );

  // ── 4. Start mock PDS (handler captures rbacRecord by reference) ──
  let rbacRecord: Record<string, unknown> = {};
  const pdsApp = new Hono();
  pdsApp.get("/xrpc/com.atproto.repo.listRecords", (c) => {
    const repo = c.req.query("repo");
    const collection = c.req.query("collection");
    if (repo === actxDid && collection === RBAC_NSID) {
      return c.json({
        records: [{ uri: `at://${actxDid}/${RBAC_NSID}/test`, value: rbacRecord }],
      });
    }
    return c.json({ records: [] });
  });
  const pdsAc = new AbortController();
  const { promise: pdsPortReady, resolve: resolvePdsPort } = Promise.withResolvers<number>();
  Deno.serve(
    { port: 0, hostname: "127.0.0.1", signal: pdsAc.signal, onListen: (addr) => resolvePdsPort((addr as Deno.NetAddr).port) },
    pdsApp.fetch,
  );

  // ── 5. Resolve ports + build non-issuer URLs ──────────────────────
  const plcPort = await plcPortReady;
  const pdsPort = await pdsPortReady;
  const pdsUrl = `http://127.0.0.1:${pdsPort}`;
  const plcDirectoryUrl = `http://127.0.0.1:${plcPort}`;
  registerDid(actxDid, pdsUrl);

  // ── 6. sshd — hold listener until sshd confirms ready ─────────────
  const sshLn = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const sshPort = (sshLn.addr as Deno.NetAddr).port;
  const sshd = new Deno.Command("/usr/sbin/sshd", {
    args: [
      "-D", "-p", String(sshPort), "-h", hostKeyPath,
      "-f", "/dev/null", "-o", "StrictModes no", "-o", "UsePAM no",
      "-o", "PidFile none", "-o", "MaxStartups 10",
    ],
    stdout: "null", stderr: "null",
  });
  try { sshLn.close(); } catch {/* ok */}
  const sshdProc = sshd.spawn();

  let sshdReady = false;
  for (let i = 0; i < 10; i++) {
    await new Promise((r) => setTimeout(r, 200));
    try {
      const { code } = await new Deno.Command("ssh-keyscan", {
        args: ["-t", "ed25519", "-p", String(sshPort), "127.0.0.1"],
        stdout: "null", stderr: "null",
      }).output();
      if (code === 0) { sshdReady = true; break; }
    } catch { /* retry */ }
  }
  if (!sshdReady) {
    plcAc.abort(); pdsAc.abort();
    try { sshdProc.kill("SIGTERM"); } catch {/* ignore */}
    await Deno.remove(tmpDir, { recursive: true }).catch(() => {});
    throw new Error("sshd not reachable");
  }

  // ── 7. Start compute provider (port 0, bind 127.0.0.1) ────────────
  const dropletById = new Map<string, Record<string, unknown>>();
  const dropletId = crypto.randomUUID().slice(0, 8);
  const dropletRecord = {
    id: dropletId,
    networks: { v4: [{ ip_address: "127.0.0.1", type: "public" }] },
    tags: [`oidc-sub:plc:${requesterPlc}`, "oidc-sub:role:worker"],
  };
  dropletById.set(dropletId, dropletRecord);

  const { app } = createOidcIssuer({
    getIssuerUrl: () => issuerUrl,
    getDroplet: (id) => dropletById.get(id),
    serviceUrl: issuerUrl,
    plcDirectoryUrl,
  });

  const issuerAc = new AbortController();
  const { promise: issuerPortReady, resolve: resolveIssuerPort } = Promise.withResolvers<number>();
  Deno.serve(
    { port: 0, hostname: "127.0.0.1", signal: issuerAc.signal, onListen: (addr) => resolveIssuerPort((addr as Deno.NetAddr).port) },
    app.fetch,
  );
  const issuerPort = await issuerPortReady;
  issuerUrl = `http://127.0.0.1:${issuerPort}`;

  // ── 8. Build rbacRecord (now that issuerUrl is known) ─────────────
  rbacRecord = {
    $type: RBAC_NSID,
    protects: {
      [roleName]: { service: issuerUrl, scope: "droplets.wid" },
    },
    roles: {
      [roleName]: {
        role_name: roleName,
        definition: {
          aud: `api://DigitalOcean?actx=${actxUuid}`,
          sub: subject,
          policies: [roleName],
        },
      },
    },
    policies: {
      [roleName]: {
        meta: { policy: roleName },
        schemas: {
          "/v1/oidc/issue": {
            type: "object",
            $schema: "http://json-schema.org/draft-07/schema#",
            required: ["capability", "allowed_parameters"],
            properties: {
              capability: { enum: ["create"] },
              allowed_parameters: {
                type: "object",
                properties: {
                  aud: { type: "string" },
                  sub: { type: "string", const: subject },
                  ttl: { type: "number", const: 3600 },
                },
              },
            },
          },
        },
      },
    },
    custom_claims_roles_index: { job_workflow_ref: {} },
    createdAt: new Date().toISOString(),
  };

  try {
    // ── 8. Verify PLC resolution works ──────────────────────────────
    const resolvedPdsUrl = await resolvePDS(actxDid, plcDirectoryUrl);
    assertEquals(resolvedPdsUrl, pdsUrl);

    // ── 9. Verify RBAC record is fetchable ──────────────────────────
    const fetchedRbac = await getRBACRecord(pdsUrl, actxDid, issuerUrl, "droplets.wid");
    assertEquals(Object.keys(fetchedRbac.roles).length, 1);
    assertEquals(fetchedRbac.roles[roleName].definition.sub, subject);

    // ── 10. Create provisioning data → prove → get workload token ───
    const provisioningData = await ProvisioningData.create(actxUuid, null, issuerUrl);
    provisioningData.associateWithDroplet(dropletId);

    const tokenData = provisioningData.token.asString;

    const signProc = new Deno.Command("ssh-keygen", {
      args: ["-Y", "sign", "-n", "prove-sshd", "-f", hostKeyPath],
      stdin: "piped", stdout: "piped", stderr: "piped",
    });
    const signChild = signProc.spawn();
    const signWriter = signChild.stdin.getWriter();
    await signWriter.write(new TextEncoder().encode(tokenData));
    await signWriter.close();
    const signResult = await signChild.output();
    const sshSig = new TextDecoder().decode(signResult.stdout).trim();

    const proveRes = await fetch(`${issuerUrl}/v1/oidc/prove`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${tokenData}`,
      },
      body: JSON.stringify({ sig: sshSig, port: sshPort }),
    });
    const proveBody = await proveRes.json();
    assertEquals(proveRes.status, 200, `Prove failed: ${JSON.stringify(proveBody)}`);
    const workloadToken = proveBody.token as string;
    assertExists(workloadToken);

    const validatedWl = await OIDCToken.validate(workloadToken);
    assertEquals(validatedWl.actx, actxUuid);

    // ── 11. Call /v1/oidc/issue with workload token (RBAC check) ────
    const issueRes = await fetch(`${issuerUrl}/v1/oidc/issue`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${workloadToken}`,
      },
      body: JSON.stringify({ sub: subject, ttl: 3600 }),
    });

    const issueBody = await issueRes.json();
    assertEquals(issueRes.status, 200, `Issue failed: ${JSON.stringify(issueBody)}`);
    const issuedToken = issueBody.token as string;
    assertExists(issuedToken);

    const validatedIssue = await OIDCToken.validate(issuedToken);
    assertEquals(validatedIssue.actx, actxUuid);

    // ── 12. Test: unauthorized caller (no token) → 401 ──────────────
    const noAuthRes = await fetch(`${issuerUrl}/v1/oidc/issue`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sub: subject }),
    });
    assertEquals(noAuthRes.status, 401);

    // ── 13. Test: actx with no RBAC record → 401 ────────────────────
    const noRbacUuid = crypto.randomUUID();
    const noRbacDid = `did:plc:${noRbacUuid}`;
    registerDid(noRbacDid, pdsUrl);

    const noRbacProvisioning = await ProvisioningData.create(noRbacUuid, null, issuerUrl);
    const noRbacDropletId = crypto.randomUUID().slice(0, 8);
    const noRbacDroplet = {
      id: noRbacDropletId,
      networks: { v4: [{ ip_address: "127.0.0.1", type: "public" }] },
      tags: [],
    };
    dropletById.set(noRbacDropletId, noRbacDroplet);
    noRbacProvisioning.associateWithDroplet(noRbacDropletId);

    const noRbacTokenData = noRbacProvisioning.token.asString;
    const noRbacSignProc = new Deno.Command("ssh-keygen", {
      args: ["-Y", "sign", "-n", "prove-sshd", "-f", hostKeyPath],
      stdin: "piped", stdout: "piped", stderr: "piped",
    });
    const noRbacSignChild = noRbacSignProc.spawn();
    const noRbacSignWriter = noRbacSignChild.stdin.getWriter();
    await noRbacSignWriter.write(new TextEncoder().encode(noRbacTokenData));
    await noRbacSignWriter.close();
    const noRbacSignResult = await noRbacSignChild.output();
    const noRbacSig = new TextDecoder().decode(noRbacSignResult.stdout).trim();

    const noRbacProveRes = await fetch(`${issuerUrl}/v1/oidc/prove`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${noRbacTokenData}`,
      },
      body: JSON.stringify({ sig: noRbacSig, port: sshPort }),
    });
    const noRbacProveBody = await noRbacProveRes.json();
    assertEquals(noRbacProveRes.status, 200, `No-RBAC prove failed: ${JSON.stringify(noRbacProveBody)}`);
    const noRbacWlToken = noRbacProveBody.token as string;

    const noRbacIssueRes = await fetch(`${issuerUrl}/v1/oidc/issue`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${noRbacWlToken}`,
      },
      body: JSON.stringify({ sub: `actx:${noRbacUuid}:plc:test:role:worker`, ttl: 3600 }),
    });
    assertEquals(
      noRbacIssueRes.status,
      401,
      "Should reject token whose actx has no RBAC record",
    );

    // ── 14. Write token to secrets dir ──────────────────────────────
    await Deno.mkdir(secretsDir, { recursive: true });
    await Deno.writeTextFile(`${secretsDir}/token`, issuedToken);
    await Deno.writeTextFile(`${secretsDir}/team_uuid`, actxUuid);
    await Deno.writeTextFile(`${secretsDir}/base_url`, issuerUrl);

    const writtenToken = await Deno.readTextFile(`${secretsDir}/token`);
    assertEquals(writtenToken, issuedToken);

    const reValidated = await OIDCToken.validate(writtenToken);
    assertEquals(reValidated.actx, actxUuid);
  } finally {
    issuerAc.abort();
    plcAc.abort();
    pdsAc.abort();
    try { sshdProc.kill("SIGTERM"); } catch {/* ignore */}
    await sshdProc.status;
    await Deno.remove(tmpDir, { recursive: true }).catch(() => {});
  }
});
