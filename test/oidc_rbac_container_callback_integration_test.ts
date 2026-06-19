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
const CALLBACK_TIMEOUT_MS = 300_000;

function allocatePort(): number {
  const l = Deno.listen({ port: 0, hostname: "127.0.0.1" });
  const p = l.addr.port;
  try { l.close(); } catch {/* ok */}
  return p;
}

async function cleanupContainer(backend: ContainerBackend, containerName: string): Promise<void> {
  await backend.rm(containerName).catch(() => {});
}

Deno.test("[integration] Container receives workload token via callback + RBAC issue", async () => {
  if (!Deno.env.get("TEST_CONTAINER")) {
    console.log("[test] TEST_CONTAINER not set — skipping container test");
    return;
  }
  const backend: ContainerBackend = Deno.build.os === "darwin"
    ? createContainerBackend()
    : createDockerBackend();
  const backendReady = await backend.ensureRunning();
  if (!backendReady) {
    console.log("[test] SKIP: container backend not available");
    return;
  }

  // Infrastructure ports
  const plcPort = allocatePort();
  const pdsPort = allocatePort();
  const issuerPort = allocatePort();
  const callbackPort = allocatePort();

  const pdsUrl = `http://127.0.0.1:${pdsPort}`;
  const plcDirectoryUrl = `http://127.0.0.1:${plcPort}`;
  const gatewayIp = await backend.defaultGateway();
  // Issuer bound to 0.0.0.0 so container can reach it at gateway IP
  const issuerUrl = `http://${gatewayIp}:${issuerPort}`;

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

  // Callback server — container POSTs token here after provisioning
  let resolveCallback: (v: { token: string }) => void;
  const callbackPromise = new Promise<{ token: string }>((resolve) => {
    resolveCallback = resolve;
  });

  const callbackAc = new AbortController();
  const callbackServer = Deno.serve(
    { port: callbackPort, hostname: "0.0.0.0", signal: callbackAc.signal },
    async (req) => {
      const url = new URL(req.url);
      if (req.method === "POST" && url.pathname === "/token") {
        const body = await req.json() as { token: string };
        resolveCallback(body);
        return new Response("ok");
      }
      return new Response("not found", { status: 404 });
    },
  );

  // PLC directory
  const { app: plcApp, registerDid } = createPlcDirectory();
  const plcAc = new AbortController();
  Deno.serve({ port: plcPort, hostname: "127.0.0.1", signal: plcAc.signal }, plcApp.fetch);
  registerDid(actxDid, pdsUrl);

  // Mock PDS
  const pdsApp = new Hono();
  pdsApp.get("/xrpc/com.atproto.repo.listRecords", (c) => {
    if (c.req.query("repo") === actxDid && c.req.query("collection") === RBAC_NSID) {
      return c.json({ records: [{ uri: `at://${actxDid}/${RBAC_NSID}/test`, value: rbacRecord }] });
    }
    return c.json({ records: [] });
  });
  const pdsAc = new AbortController();
  Deno.serve({ port: pdsPort, hostname: "127.0.0.1", signal: pdsAc.signal }, pdsApp.fetch);

  // Droplet — mutable, updated via onIp
  const dropletId = crypto.randomUUID().slice(0, 8);
  const droplet: Record<string, unknown> = {
    id: dropletId,
    networks: { v4: [{ ip_address: "127.0.0.1", type: "public" }] },
    tags: [`oidc-sub:plc:${requesterPlc}`, "oidc-sub:role:worker"],
  };

  // OIDC issuer (bind 0.0.0.0 so container can reach)
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
    assertEquals(Object.keys((await getRBACRecord(pdsUrl, actxDid, issuerUrl, "droplets.wid")).roles).length, 1);

    // Base userData: agent user + poll for token file + POST to callback
    const callbackUrl = `http://${gatewayIp}:${callbackPort}/token`;
    const tokenPath = "/root/secrets/digitalocean.com/serviceaccount/token";
    const baseUserData = `#cloud-config
users:
  - name: agent
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
ssh_pwauth: true
runcmd:
  - |
    while [ ! -f ${tokenPath} ]; do sleep 3; done
    curl -sf --json "{\\"token\\":\\"$(cat ${tokenPath})\\"}" ${callbackUrl}
`;

    const pd = await ProvisioningData.create(actxUuid, baseUserData, issuerUrl);
    pd.associateWithDroplet(dropletId);

    // Launch container — onIp updates droplet BEFORE cloud-init runs prove
    containerName = `test-rbac-cb-${crypto.randomUUID().slice(0, 8)}`;
    const info = await runContainer(backend, pd.userData, {
      distro: "ubuntu",
      containerName,
      onIp(ip, _name) {
        droplet["networks"] = { v4: [{ ip_address: ip, type: "public" }] };
      },
    });

    // Wait for callback with token
    const timeout = setTimeout(() => resolveCallback({ token: "" }), CALLBACK_TIMEOUT_MS);
    const { token: workloadToken } = await callbackPromise;
    clearTimeout(timeout);

    if (!workloadToken || workloadToken.length < 10) {
      throw new Error("No token received via callback");
    }
    console.log(`[test] Token received via callback (${workloadToken.length} chars)`);

    const validatedWl = await OIDCToken.validate(workloadToken);
    assertEquals(validatedWl.actx, actxUuid);

    // /v1/oidc/issue with RBAC
    const issueRes = await fetch(`${issuerUrl}/v1/oidc/issue`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${workloadToken}` },
      body: JSON.stringify({ sub: subject, ttl: 3600 }),
    });
    const issueBody = await issueRes.json();
    assertEquals(issueRes.status, 200, `Issue failed: ${JSON.stringify(issueBody)}`);
    const issuedToken = issueBody.token as string;
    assertExists(issuedToken);
    assertEquals((await OIDCToken.validate(issuedToken)).actx, actxUuid);
    console.log("[test] RBAC-protected token issuance succeeded");

    // Unauthorized → 401
    assertEquals(
      (await fetch(`${issuerUrl}/v1/oidc/issue`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sub: subject }),
      })).status,
      401,
    );
  } finally {
    issuerAc.abort();
    plcAc.abort();
    pdsAc.abort();
    callbackAc.abort();
    if (containerName) await cleanupContainer(backend, containerName);
  }
});
