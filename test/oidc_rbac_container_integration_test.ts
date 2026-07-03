import { assertEquals, assertExists } from "@std/assert";
import {
  createOidcIssuer,
  ProvisioningData,
  OIDCToken,
} from "@publicdomainrelay/oidc-issuer-hono";
import { runContainer } from "@publicdomainrelay/compute-provider-local";
import type { ContainerBackend } from "@publicdomainrelay/container-backend-abc";
import { createContainerBackend } from "@publicdomainrelay/container-backend-container";
import { createDockerBackend } from "@publicdomainrelay/container-backend-docker";
import { getRBACRecord } from "@publicdomainrelay/rbac-atproto";
import { createPlcDirectory } from "./plc_directory.ts";
import { getHostLanIp } from "./host_lan_ip.ts";
import { Hono } from "hono";

const RBAC_NSID = "com.fedproxy.rbac";
const TOKEN_PATH = "/root/secrets/digitalocean.com/serviceaccount/token";
const POLL_TIMEOUT_MS = 180_000;
const POLL_INTERVAL_MS = 2_000;

async function execInContainer(
  backend: ContainerBackend,
  containerName: string,
  args: string[],
): Promise<string> {
  const { code, stdout } = await backend.exec(containerName, args);
  if (code !== 0) throw new Error(`container exec failed: ${args.join(" ")}`);
  return stdout;
}

async function pollForToken(
  backend: ContainerBackend,
  containerName: string,
): Promise<string> {
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    try {
      const token = await execInContainer(backend, containerName, ["cat", TOKEN_PATH]);
      if (token && token.length > 10) return token;
    } catch {/* not ready */}
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
  throw new Error(`Token not found at ${TOKEN_PATH} within ${POLL_TIMEOUT_MS}ms`);
}

async function cleanupContainer(backend: ContainerBackend, containerName: string): Promise<void> {
  await backend.rm(containerName).catch(() => {});
}

Deno.test("[integration] Container receives workload token + RBAC issue", async () => {
  const backend: ContainerBackend = Deno.build.os === "darwin"
    ? createContainerBackend()
    : createDockerBackend();
  const backendReady = await backend.ensureRunning();
  if (!backendReady) {
    console.log("[test] SKIP: container backend not available");
    return;
  }

  // Test data (doesn't depend on ports)
  const actxUuid = crypto.randomUUID();
  const actxDid = `did:plc:${actxUuid}`;
  const requesterPlc = crypto.randomUUID().split("-")[0];
  const roleName = `ex-${actxUuid}-${requesterPlc}-worker`;
  const subject = `actx:${actxUuid}:plc:${requesterPlc}:role:worker`;

  let issuerUrl = "";

  // ── PLC directory ────────────────────────────────────────────────────
  const { app: plcApp, registerDid } = createPlcDirectory();
  const plcAc = new AbortController();
  const { promise: plcPortReady, resolve: resolvePlcPort } = Promise.withResolvers<number>();
  Deno.serve({ port: 0, hostname: "127.0.0.1", signal: plcAc.signal, onListen: (addr) => resolvePlcPort((addr as Deno.NetAddr).port) }, plcApp.fetch);

  // ── mock PDS (handler captures rbacRecord by reference) ──────────────
  let rbacRecord: Record<string, unknown> = {};
  const pdsApp = new Hono();
  pdsApp.get("/xrpc/com.atproto.repo.listRecords", (c) => {
    if (c.req.query("repo") === actxDid && c.req.query("collection") === RBAC_NSID) {
      return c.json({ records: [{ uri: `at://${actxDid}/${RBAC_NSID}/test`, value: rbacRecord }] });
    }
    return c.json({ records: [] });
  });
  const pdsAc = new AbortController();
  const { promise: pdsPortReady, resolve: resolvePdsPort } = Promise.withResolvers<number>();
  Deno.serve({ port: 0, hostname: "127.0.0.1", signal: pdsAc.signal, onListen: (addr) => resolvePdsPort((addr as Deno.NetAddr).port) }, pdsApp.fetch);

  // ── resolve ports + build non-issuer URLs ────────────────────────────
  const plcPort = await plcPortReady;
  const pdsPort = await pdsPortReady;
  const pdsUrl = `http://127.0.0.1:${pdsPort}`;
  const plcDirectoryUrl = `http://127.0.0.1:${plcPort}`;
  const gatewayIp = await getHostLanIp();
  registerDid(actxDid, pdsUrl);

  // ── droplet ──────────────────────────────────────────────────────────
  const dropletId = crypto.randomUUID().slice(0, 8);
  const droplet: Record<string, unknown> = {
    id: dropletId,
    networks: { v4: [{ ip_address: "127.0.0.1", type: "public" }] },
    tags: [`oidc-sub:plc:${requesterPlc}`, "oidc-sub:role:worker"],
  };

  // ── OIDC issuer (issuerUrl uses let — resolved after server starts) ──
  const { app } = createOidcIssuer({
    getIssuerUrl: () => issuerUrl,
    getDroplet: (id) => id === dropletId ? droplet : undefined,
    serviceUrl: issuerUrl,
    plcDirectoryUrl,
  });
  const issuerAc = new AbortController();
  const { promise: issuerPortReady, resolve: resolveIssuerPort } = Promise.withResolvers<number>();
  Deno.serve({ port: 0, hostname: "0.0.0.0", signal: issuerAc.signal, onListen: (addr) => resolveIssuerPort((addr as Deno.NetAddr).port) }, app.fetch);
  const issuerPort = await issuerPortReady;
  issuerUrl = `http://${gatewayIp}:${issuerPort}`;

  // ── rbacRecord (now that issuerUrl is known) ─────────────────────────
  rbacRecord = {
    $type: RBAC_NSID,
    protects: { [roleName]: { service: issuerUrl, scope: "droplets.wid" } },
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

  let containerName = "";
  try {
    // Verify RBAC record reachable
    const fetched = await getRBACRecord(pdsUrl, actxDid, issuerUrl, "droplets.wid");
    assertEquals(Object.keys(fetched.roles).length, 1);

    // Create provisioning data
    const pd = await ProvisioningData.create(actxUuid, null, issuerUrl);
    pd.associateWithDroplet(dropletId);

    // Launch container — onIp updates droplet BEFORE cloud-init runs prove
    containerName = `test-rbac-${crypto.randomUUID().slice(0, 8)}`;
    const info = await runContainer(backend, pd.userData, {
      distro: "ubuntu",
      containerName,
      onIp(ip, _name) {
        droplet["networks"] = { v4: [{ ip_address: ip, type: "public" }] };
      },
    });

    // Poll for workload token
    const workloadToken = await pollForToken(backend, info.containerName);
    const validatedWl = await OIDCToken.validate(workloadToken);
    assertEquals(validatedWl.actx, actxUuid);

    // Use token to call /v1/oidc/issue (RBAC check)
    const issueRes = await fetch(`${issuerUrl}/v1/oidc/issue`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${workloadToken}` },
      body: JSON.stringify({ sub: subject, ttl: 3600 }),
    });
    const issueBody = await issueRes.json();
    assertEquals(issueRes.status, 200, `Issue failed: ${JSON.stringify(issueBody)}`);
    const issuedToken = issueBody.token as string;
    assertExists(issuedToken);
    const validatedIssue = await OIDCToken.validate(issuedToken);
    assertEquals(validatedIssue.actx, actxUuid);

    // Unauthorized → 401
    const noAuthRes = await fetch(`${issuerUrl}/v1/oidc/issue`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sub: subject }),
    });
    assertEquals(noAuthRes.status, 401);
  } finally {
    issuerAc.abort();
    plcAc.abort();
    pdsAc.abort();
    if (containerName) await cleanupContainer(backend, containerName);
  }
});
