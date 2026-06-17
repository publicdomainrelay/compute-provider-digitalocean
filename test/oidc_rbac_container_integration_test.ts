import { assertEquals, assertExists } from "@std/assert";
import {
  createOidcIssuer,
  ProvisioningData,
  OIDCToken,
} from "@publicdomainrelay/oidc-issuer";
import { runContainer } from "@publicdomainrelay/compute-provider-local";
import type { ContainerBackend } from "@publicdomainrelay/container-backend-abc";
import { createContainerBackend } from "@publicdomainrelay/container-backend-container";
import { createDockerBackend } from "@publicdomainrelay/container-backend-docker";
import { getRBACRecord } from "@publicdomainrelay/rbac-atproto";
import { createPlcDirectory } from "./plc_directory.ts";
import { Hono } from "hono";

const RBAC_NSID = "com.fedproxy.rbac";
const TOKEN_PATH = "/root/secrets/digitalocean.com/serviceaccount/token";
const POLL_TIMEOUT_MS = 180_000;
const POLL_INTERVAL_MS = 2_000;

function allocatePort(): number {
  const l = Deno.listen({ port: 0, hostname: "127.0.0.1" });
  const p = l.addr.port;
  try { l.close(); } catch {/* ok */}
  return p;
}

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

  // Infrastructure ports. Compute provider binds 0.0.0.0 so containers reach it
  // at 172.17.0.1 (Docker bridge). All other infra on 127.0.0.1.
  const plcPort = allocatePort();
  const pdsPort = allocatePort();
  const issuerPort = allocatePort();

  const pdsUrl = `http://127.0.0.1:${pdsPort}`;
  const plcDirectoryUrl = `http://127.0.0.1:${plcPort}`;
  const issuerUrl = `http://172.17.0.1:${issuerPort}`;

  // Test data
  const actxUuid = crypto.randomUUID();
  const actxDid = `did:plc:${actxUuid}`;
  const requesterPlc = crypto.randomUUID().split("-")[0];
  const roleName = `ex-${actxUuid}-${requesterPlc}-worker`;
  const subject = `actx:${actxUuid}:plc:${requesterPlc}:role:worker`;

  const rbacRecord = {
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

  // PLC directory
  const { app: plcApp, registerDid } = createPlcDirectory();
  const plcAc = new AbortController();
  Deno.serve({ port: plcPort, hostname: "127.0.0.1", signal: plcAc.signal }, plcApp.fetch);
  registerDid(actxDid, pdsUrl);

  // Mock PDS (listRecords only)
  const pdsApp = new Hono();
  pdsApp.get("/xrpc/com.atproto.repo.listRecords", (c) => {
    if (c.req.query("repo") === actxDid && c.req.query("collection") === RBAC_NSID) {
      return c.json({ records: [{ uri: `at://${actxDid}/${RBAC_NSID}/test`, value: rbacRecord }] });
    }
    return c.json({ records: [] });
  });
  const pdsAc = new AbortController();
  Deno.serve({ port: pdsPort, hostname: "127.0.0.1", signal: pdsAc.signal }, pdsApp.fetch);

  // Droplet record — mutable, updated via onIp when container gets its real IP.
  const dropletId = crypto.randomUUID().slice(0, 8);
  const droplet: Record<string, unknown> = {
    id: dropletId,
    networks: { v4: [{ ip_address: "127.0.0.1", type: "public" }] },
    tags: [`oidc-sub:plc:${requesterPlc}`, "oidc-sub:role:worker"],
  };

  // Compute provider (bind 0.0.0.0)
  const { app } = createOidcIssuer({
    getIssuerUrl: () => issuerUrl,
    getDroplet: (id) => id === dropletId ? droplet : undefined,
    serviceUrl: issuerUrl,
    plcDirectoryUrl,
  });
  const issuerAc = new AbortController();
  Deno.serve({ port: issuerPort, hostname: "0.0.0.0", signal: issuerAc.signal }, app.fetch);

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
      onIp(ip, name) {
        droplet["networks"] = { v4: [{ ip_address: ip, type: "public" }] };
        droplet["containerName"] = name;
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
