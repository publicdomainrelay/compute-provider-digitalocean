import { assertEquals, assertExists } from "@std/assert";
import {
  createOidcIssuer,
  createOidcProvisioningEnricher,
  ProvisioningData,
  OIDCToken,
} from "@publicdomainrelay/oidc-issuer-hono";
import { pollSsh } from "@publicdomainrelay/compute-provider-local";
import { createDockerBackend } from "@publicdomainrelay/container-backend-docker";
import { getRBACRecord } from "@publicdomainrelay/rbac-atproto";
import { createFirecrackerComputeProvider } from "@publicdomainrelay/compute-provider-firecracker";
import { createFirecrackerMicrovm } from "@publicdomainrelay/microvm-firecracker";
import { createFirecrackerNodeImage } from "@publicdomainrelay/node-image-firecracker";
import { qemuCacheDir } from "@publicdomainrelay/qemu-standalone";
import { createPlcDirectory } from "./plc_directory.ts";
import { getHostLanIp } from "./host_lan_ip.ts";
import { Hono } from "hono";

const RBAC_NSID = "com.fedproxy.rbac";
const QEMU_IMAGE = "atcr.io/johnandersen777.bsky.social/ccripoc-qemu-runner:latest";
const DISTRO = "ubuntu";
const SSH_TIMEOUT_MS = 600_000;
const CALLBACK_TIMEOUT_MS = 600_000;

// The guest is a VM either way, and the thing under test -- that a guest comes
// up, proves its workload identity to the issuer, and is handed a token it can
// then spend on an RBAC-protected issue -- does not care which VMM booted it.
// So the arm is a parameter: "qemu" is the local provider's VM mode, booted by
// its runner image; "firecracker" is the firecracker compute provider, which
// gives each guest its own container. Everything else in this file is shared,
// and a difference between the two arms is a difference between two substrates
// rather than between two tests.
type Arm = "qemu" | "firecracker";

const FIRECRACKER_ENV = {
  nodeimage: "SOCIALWEB_FIRECRACKER_NODEIMAGE",
  config: "SOCIALWEB_FIRECRACKER_CONFIG",
  repoDir: "SOCIALWEB_FIRECRACKER_REPO_DIR",
  runnerImage: "SOCIALWEB_FIRECRACKER_RUNNER_IMAGE",
  preinstall: "SOCIALWEB_FIRECRACKER_PREINSTALL",
} as const;

async function dockerRm(containerName: string): Promise<void> {
  await new Deno.Command("docker", {
    args: ["rm", "-f", containerName],
    stdout: "null", stderr: "null",
  }).output().catch(() => {});
}

function firecrackerSkipReason(): string | null {
  const missing = Object.values(FIRECRACKER_ENV).filter((k) =>
    k !== FIRECRACKER_ENV.preinstall && !Deno.env.get(k)
  );
  if (missing.length > 0) return `${missing.join(", ")} unset`;
  const workRoot = Deno.env.get("SOCIALWEB_FIRECRACKER_WORK_ROOT");
  if (!workRoot) return "SOCIALWEB_FIRECRACKER_WORK_ROOT unset";
  const image = Deno.env.get(FIRECRACKER_ENV.runnerImage)!;
  const probe = new Deno.Command("docker", {
    args: ["image", "inspect", image],
    stdout: "null", stderr: "null",
  }).outputSync();
  if (probe.code !== 0) {
    return `the runner image ${image} is not present locally; build it with ` +
      `deno task build:firecracker-runner`;
  }
  return null;
}

async function runArm(arm: Arm): Promise<void> {
  const tmpDir = await Deno.makeTempDir();
  const sshKeyPath = `${tmpDir}/vm_ssh_key`;

  await new Deno.Command("ssh-keygen", {
    args: ["-t", "ed25519", "-f", sshKeyPath, "-N", "", "-C", "test-vm"],
    stdout: "null", stderr: "null",
  }).output();
  const sshPubKey = await Deno.readTextFile(`${sshKeyPath}.pub`);

  const actxUuid = crypto.randomUUID();
  const actxDid = `did:plc:${actxUuid}`;
  const requesterPlc = crypto.randomUUID().split("-")[0];
  const roleName = `ex-${actxUuid}-${requesterPlc}-worker`;
  const subject = `actx:${actxUuid}:plc:${requesterPlc}:role:worker`;

  let issuerUrl = "";

  let resolveCallback: (v: { token: string }) => void;
  const callbackPromise = new Promise<{ token: string }>((resolve) => {
    resolveCallback = resolve;
  });
  const callbackAc = new AbortController();
  const { promise: cbPortReady, resolve: resolveCbPort } = Promise.withResolvers<number>();
  Deno.serve(
    { port: 0, hostname: "0.0.0.0", signal: callbackAc.signal, onListen: (addr) => resolveCbPort((addr as Deno.NetAddr).port) },
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

  const { app: plcApp, registerDid } = createPlcDirectory();
  const plcAc = new AbortController();
  const { promise: plcPortReady, resolve: resolvePlcPort } = Promise.withResolvers<number>();
  Deno.serve({ port: 0, hostname: "127.0.0.1", signal: plcAc.signal, onListen: (addr) => resolvePlcPort((addr as Deno.NetAddr).port) }, plcApp.fetch);

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

  const callbackPort = await cbPortReady;
  const plcPort = await plcPortReady;
  const pdsPort = await pdsPortReady;
  const pdsUrl = `http://127.0.0.1:${pdsPort}`;
  const plcDirectoryUrl = `http://127.0.0.1:${plcPort}`;
  const docker = createDockerBackend();
  // The address the guest dials the host on. For the QEMU arm this is the
  // docker bridge gateway the guest is attached to. For firecracker the guest
  // is behind pasta inside its own container, and pasta forwards its traffic to
  // that container's network, so the same address is the one that reaches the
  // host from both.
  const gatewayIp = await getHostLanIp();
  registerDid(actxDid, pdsUrl);

  const dropletId = crypto.randomUUID().slice(0, 8);
  const droplet: Record<string, unknown> = {
    id: dropletId,
    networks: { v4: [{ ip_address: "127.0.0.1", type: "public" }] },
    tags: [`oidc-sub:plc:${requesterPlc}`, "oidc-sub:role:worker"],
  };

  const { app } = createOidcIssuer({
    getIssuerUrl: () => issuerUrl,
    // The firecracker arm's provider names its own guests, so the record is
    // returned for whichever id the issuer is asked about: what is under test
    // here is that the guest proves its identity and is handed a token, not
    // that a particular provider keys its lookup the same way.
    getDroplet: (id) => (arm === "qemu" && id !== dropletId ? undefined : droplet),
    serviceUrl: issuerUrl,
    plcDirectoryUrl,
    log: (level, message, meta) => {
      if (level === "warn" || level === "error") {
        console.log(`[${arm}][issuer][${level}] ${message} ${JSON.stringify(meta ?? {})}`);
      }
    },
  });
  const issuerAc = new AbortController();
  const { promise: issuerPortReady, resolve: resolveIssuerPort } = Promise.withResolvers<number>();
  Deno.serve({ port: 0, hostname: "0.0.0.0", signal: issuerAc.signal, onListen: (addr) => resolveIssuerPort((addr as Deno.NetAddr).port) }, app.fetch);
  const issuerPort = await issuerPortReady;
  issuerUrl = `http://${gatewayIp}:${issuerPort}`;

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
  let destroyGuest: (() => Promise<void>) | null = null;

  try {
    assertEquals(Object.keys((await getRBACRecord(pdsUrl, actxDid, issuerUrl, "droplets.wid")).roles).length, 1);

    const callbackUrl = `http://${gatewayIp}:${callbackPort}/token`;
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

    let ip = "";

    if (arm === "qemu") {
      const pd = await ProvisioningData.create(actxUuid, baseUserData, issuerUrl);
      pd.associateWithDroplet(dropletId);

      const cacheDir = qemuCacheDir();
      const udFile = await Deno.makeTempFile({ prefix: "ud-", suffix: ".yaml" });
      await Deno.writeTextFile(udFile, pd.userData);

      containerName = `test-vm-${crypto.randomUUID().slice(0, 8)}`;
      await dockerRm(containerName);

      console.log(`[${arm}] starting QEMU VM ${containerName}`);
      const runResult = await new Deno.Command("docker", {
        args: [
          "run", "-d",
          "--name", containerName, "--privileged",
          "--memory", "6g", "--memory-swap", "6g",
          "--device", "/dev/kvm",
          "-v", `${cacheDir}:/root/.cache/simple-qemu`,
          "-v", `${udFile}:/tmp/user-data:ro`,
          "-e", "USER_DATA_FILE=/tmp/user-data",
          QEMU_IMAGE,
          `--distro=${DISTRO}`,
        ],
        stdout: "piped", stderr: "piped",
      }).output();
      if (runResult.code !== 0) throw new Error(`docker run failed: ${new TextDecoder().decode(runResult.stderr)}`);

      await new Promise((r) => setTimeout(r, 3_000));
      ip = await docker.inspectIp(containerName);
      console.log(`[${arm}] VM IP ${ip}`);
      droplet.networks = { v4: [{ ip_address: ip, type: "public" }] };
      droplet.containerName = containerName;
      destroyGuest = () => dockerRm(containerName);

      const sshReady = await pollSsh(ip, 22, SSH_TIMEOUT_MS);
      if (!sshReady) throw new Error(`SSH not ready for ${containerName}`);
      console.log(`[${arm}] SSH ready; waiting for the token callback`);
    } else {
      // The provider is given the enriched user_data's job: it calls the OIDC
      // enricher itself, which is the half of the exchange that happens on this
      // side. There is no SSH poll here on purpose -- a firecracker guest behind
      // pasta dials out and is not reachable inbound, which is why the market
      // path reaches its guests through a tunnel rather than by connecting to
      // them. The callback below is an outbound connection and is the signal
      // that the guest came up and did the exchange.
      const workRoot = Deno.env.get("SOCIALWEB_FIRECRACKER_WORK_ROOT")!;
      const provider = createFirecrackerComputeProvider({
        logger: {
          info: () => {},
          warn: () => {},
          error: () => {},
          debug: () => {},
        } as never,
        atproto: {
          getAgentDid: () => `did:plc:${actxUuid}`,
          createRecord: () => Promise.reject(new Error("this test writes no records")),
          deleteRecord: () => Promise.resolve(),
        } as never,
        // The stub's app is never mounted on; this arm builds no routes. The
        // cast is for the two Hono instances in this workspace (npm here, JSR
        // in the provider) being structurally equal and nominally distinct.
        serve: { app: new Hono() as never, onConnected: () => {} },
        getIssuerUrl: () => issuerUrl,
        image: createFirecrackerNodeImage({
          binary: Deno.env.get(FIRECRACKER_ENV.nodeimage)!,
          configPath: Deno.env.get(FIRECRACKER_ENV.config)!,
          repoDir: Deno.env.get(FIRECRACKER_ENV.repoDir)!,
          preinstallPath: Deno.env.get(FIRECRACKER_ENV.preinstall),
        }),
        microvm: createFirecrackerMicrovm({
          backend: createDockerBackend(),
          runnerImage: Deno.env.get(FIRECRACKER_ENV.runnerImage)!,
        }),
        workRoot,
        oidcProvisioner: createOidcProvisioningEnricher(() => issuerUrl),
      });

      const result = await provider.provider.provision(
        {
          cpus: 2,
          mem: "2G",
          disk: "4G",
          network: "default",
          role: "worker",
          user_data: baseUserData,
        },
        actxDid,
      );
      ip = String((result.metadata as Record<string, unknown>).ip ?? "");
      const guestName = String((result.metadata as Record<string, unknown>).name ?? "");
      droplet.networks = { v4: [{ ip_address: ip, type: "public" }] };
      droplet.containerName = guestName;
      console.log(`[${arm}] guest placed at ${ip} (${result.providerId}); waiting for the token callback`);
      destroyGuest = () => provider.provider.destroy(result.providerId);
    }

    const timeout = setTimeout(() => resolveCallback({ token: "" }), CALLBACK_TIMEOUT_MS);
    const { token: workloadToken } = await callbackPromise;
    clearTimeout(timeout);

    if (!workloadToken || workloadToken.length < 10) {
      throw new Error(
        `the guest never reported a workload token to ${callbackUrl}. The guest was placed at ${ip}, ` +
          `so it booted; what did not happen is the exchange at ${issuerUrl}/v1/oidc/prove, which ` +
          `needs the guest to have read its provisioning token, signed it with its ssh host key, ` +
          `and reached the issuer`,
      );
    }
    console.log(`[${arm}] token received (${workloadToken.length} chars)`);

    const validatedWl = await OIDCToken.validate(workloadToken);
    assertEquals(validatedWl.actx, actxUuid);

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
    console.log(`[${arm}] RBAC-protected token issuance succeeded`);

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
    if (destroyGuest) await destroyGuest().catch(() => {});
    if (containerName) await dockerRm(containerName);
    await Deno.remove(tmpDir, { recursive: true }).catch(() => {});
  }
}

Deno.test("[integration] QEMU guest receives workload token + RBAC issue", async () => {
  if (!Deno.env.get("TEST_VM")) {
    console.log("[test] TEST_VM not set — skipping QEMU arm");
    return;
  }
  try { Deno.statSync("/dev/kvm"); } catch {
    console.log("[test] /dev/kvm not available — skipping QEMU arm");
    return;
  }
  await runArm("qemu");
});

Deno.test("[integration] firecracker guest receives workload token + RBAC issue", async () => {
  if (!Deno.env.get("TEST_VM")) {
    console.log("[test] TEST_VM not set — skipping firecracker arm");
    return;
  }
  const reason = firecrackerSkipReason();
  if (reason !== null) {
    console.log(`[test] skipping the firecracker arm: ${reason}`);
    return;
  }
  await runArm("firecracker");
});
