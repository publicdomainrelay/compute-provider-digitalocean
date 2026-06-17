import { assertEquals, assertExists } from "@std/assert";
import {
  createOidcIssuer,
  ProvisioningData,
  OIDCToken,
} from "@publicdomainrelay/oidc-issuer";
import { containerInspectIp, pollSsh } from "@publicdomainrelay/compute-provider-local";
import { getRBACRecord } from "@publicdomainrelay/rbac-atproto";
import { createPlcDirectory } from "./plc_directory.ts";
import { Hono } from "hono";

const RBAC_NSID = "com.fedproxy.rbac";
const VM_IMAGE = "atcr.io/johnandersen777.bsky.social/ccripoc-qemu-runner:latest";
const DISTRO = "ubuntu";
const SSH_TIMEOUT_MS = 600_000;
const CALLBACK_TIMEOUT_MS = 600_000;

function allocatePort(): number {
  const l = Deno.listen({ port: 0, hostname: "127.0.0.1" });
  const p = l.addr.port;
  try { l.close(); } catch {/* ok */}
  return p;
}

async function dockerRm(containerName: string): Promise<void> {
  await new Deno.Command("docker", {
    args: ["rm", "-f", containerName],
    stdout: "null", stderr: "null",
  }).output().catch(() => {});
}

Deno.test("[integration] VM receives workload token + RBAC issue", async () => {
  if (!Deno.env.get("TEST_VM")) {
    console.log("[test] TEST_VM not set — skipping VM test");
    return;
  }
  try { Deno.statSync("/dev/kvm"); } catch {
    console.log("[test] /dev/kvm not available — skipping VM test");
    return;
  }

  const tmpDir = await Deno.makeTempDir();
  const sshKeyPath = `${tmpDir}/vm_ssh_key`;

  // Generate SSH keypair for accessing VM
  await new Deno.Command("ssh-keygen", {
    args: ["-t", "ed25519", "-f", sshKeyPath, "-N", "", "-C", "test-vm"],
    stdout: "null", stderr: "null",
  }).output();
  const sshPubKey = await Deno.readTextFile(`${sshKeyPath}.pub`);

  // Infrastructure
  const plcPort = allocatePort();
  const pdsPort = allocatePort();
  const issuerPort = allocatePort();
  const callbackPort = allocatePort();

  const pdsUrl = `http://127.0.0.1:${pdsPort}`;
  const plcDirectoryUrl = `http://127.0.0.1:${plcPort}`;
  const issuerUrl = `http://172.17.0.1:${issuerPort}`;

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

  // Callback server — VM POSTs token here after provisioning
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

  // Droplet — mutable
  const dropletId = crypto.randomUUID().slice(0, 8);
  const droplet: Record<string, unknown> = {
    id: dropletId,
    networks: { v4: [{ ip_address: "127.0.0.1", type: "public" }] },
    tags: [`oidc-sub:plc:${requesterPlc}`, "oidc-sub:role:worker"],
  };

  // Compute provider
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

    // User data: SSH key for access + callback after provisioning
    const callbackUrl = `http://172.17.0.1:${callbackPort}/token`;
    const tokenPath = "/root/secrets/digitalocean.com/serviceaccount/token";
    const baseUserData = `#cloud-config
users:
  - name: root
    ssh_authorized_keys:
      - ${sshPubKey.trim()}
    lock_passwd: false
ssh_pwauth: true
runcmd:
  - |
    while [ ! -f ${tokenPath} ]; do sleep 3; done
    curl -sf --json "{\\"token\\":\\"$(cat ${tokenPath})\\"}" ${callbackUrl}
`;

    const pd = await ProvisioningData.create(actxUuid, baseUserData, issuerUrl);
    pd.associateWithDroplet(dropletId);

    // Write user-data
    const cacheDir = "/root/.cache/simple-qemu";
    const udFile = await Deno.makeTempFile({ prefix: "ud-", suffix: ".yaml" });
    await Deno.writeTextFile(udFile, pd.userData);

    // Launch QEMU VM
    containerName = `test-vm-${crypto.randomUUID().slice(0, 8)}`;
    await dockerRm(containerName);

    console.log(`[test] Starting QEMU VM: ${containerName}`);
    const runResult = await new Deno.Command("docker", {
      args: [
        "run", "-d",
        "--name", containerName, "--privileged",
        "--memory", "6g", "--memory-swap", "6g",
        "--device", "/dev/kvm",
        "-v", `${cacheDir}:/root/.cache/simple-qemu`,
        "-v", `${udFile}:/tmp/user-data:ro`,
        "-e", "USER_DATA_FILE=/tmp/user-data",
        VM_IMAGE,
        `--distro=${DISTRO}`,
      ],
      stdout: "piped", stderr: "piped",
    }).output();
    if (runResult.code !== 0) throw new Error(`docker run failed: ${new TextDecoder().decode(runResult.stderr)}`);

    await new Promise((r) => setTimeout(r, 3_000));
    const ip = await containerInspectIp(containerName);
    console.log(`[test] VM IP: ${ip}`);

    const sshReady = await pollSsh(ip, 22, SSH_TIMEOUT_MS);
    if (!sshReady) throw new Error(`SSH not ready for ${containerName}`);

    // Update droplet with real IP + containerName
    droplet["networks"] = { v4: [{ ip_address: ip, type: "public" }] };
    droplet["containerName"] = containerName;
    console.log(`[test] SSH ready, waiting for token callback...`);

    // Wait for callback with token
    const timeout = setTimeout(() => resolveCallback({ token: "" }), CALLBACK_TIMEOUT_MS);
    const { token: workloadToken } = await callbackPromise;
    clearTimeout(timeout);

    if (!workloadToken || workloadToken.length < 10) {
      throw new Error("No token received via callback");
    }
    console.log(`[test] Token received (${workloadToken.length} chars)`);

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
    if (containerName) await dockerRm(containerName);
    await Deno.remove(tmpDir, { recursive: true }).catch(() => {});
  }
});
