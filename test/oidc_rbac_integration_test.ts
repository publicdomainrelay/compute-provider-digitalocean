import { assertEquals, assertExists } from "@std/assert";
import {
  createOidcIssuer,
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

  const [hostKeyType, hostPublicKey] = (await Deno.readTextFile(`${hostKeyPath}.pub`)).trim().split(/\s+/);
  const reportHostKey = async (token: string, signature: string) => {
    const res = await fetch(`${issuerUrl}/v1/host-keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ keys: [{ type: hostKeyType, publicKey: hostPublicKey }], token, signature }),
    });
    assertEquals(res.status, 200, `host-keys report failed: ${await res.text()}`);
  };

  // ── 7. Start compute provider (port 0, bind 127.0.0.1) ────────────
  const dropletById = new Map<string, Record<string, unknown>>();
  const dropletId = crypto.randomUUID().slice(0, 8);
  const dropletRecord = {
    id: dropletId,
    tags: [`oidc-sub:plc:${requesterPlc}`, "oidc-sub:role:worker"],
  };
  dropletById.set(dropletId, dropletRecord);

  const oidcIssuer = createOidcIssuer({
    getIssuerUrl: () => issuerUrl,
    getDroplet: (id) => dropletById.get(id),
    plcDirectoryUrl,
  });
  const { app } = oidcIssuer;

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
    const provisioningData = await oidcIssuer.createProvisioningData(actxUuid, null);
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

    await reportHostKey(tokenData, sshSig);
    const proveRes = await fetch(`${issuerUrl}/v1/oidc/prove`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${tokenData}`,
      },
      body: JSON.stringify({ sig: sshSig }),
    });
    const proveBody = await proveRes.json();
    assertEquals(proveRes.status, 200, `Prove failed: ${JSON.stringify(proveBody)}`);
    const workloadToken = proveBody.token as string;
    assertExists(workloadToken);

    const validatedWl = await oidcIssuer.validateToken(workloadToken);
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

    const validatedIssue = await oidcIssuer.validateToken(issuedToken);
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

    const noRbacProvisioning = await oidcIssuer.createProvisioningData(noRbacUuid, null);
    const noRbacDropletId = crypto.randomUUID().slice(0, 8);
    const noRbacDroplet = {
      id: noRbacDropletId,
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

    await reportHostKey(noRbacTokenData, noRbacSig);
    const noRbacProveRes = await fetch(`${issuerUrl}/v1/oidc/prove`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${noRbacTokenData}`,
      },
      body: JSON.stringify({ sig: noRbacSig }),
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

    const reValidated = await oidcIssuer.validateToken(writtenToken);
    assertEquals(reValidated.actx, actxUuid);
  } finally {
    issuerAc.abort();
    plcAc.abort();
    pdsAc.abort();
    await Deno.remove(tmpDir, { recursive: true }).catch(() => {});
  }
});
