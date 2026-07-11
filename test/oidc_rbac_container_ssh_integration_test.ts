// End-to-end: get a real shell into a real container over the xrpc relay
// tunnel, with the guest provisioned ONLY from cloud-init user_data (no
// container exec / apt-get / hand-built sshd). This folds the intent of the old
// ssh e2e test into the cloud-init-driven compute-provider harness
// (see oidc_rbac_container_callback_integration_test.ts).
//
//   real ssh -> ProxyCommand (websocat) -> xrpc relay
//     <- (outbound) in-guest tunnel-subscriber -> 127.0.0.1:22 sshd
//
// The guest pulls the tunnel-subscriber at boot via `deno run jsr:...` from a
// local hono-jsr registry that serves the fresh xrpc relay workspace. This
// is the fedproxy-client replacement: ssh-over-websocket rides the xrpc relay.
//
//   deno test -A test/oidc_rbac_container_ssh_integration_test.ts

import { assert, assertStringIncludes } from "@std/assert";
import { Secp256k1Keypair } from "@atproto/crypto";
import { runContainer } from "@publicdomainrelay/compute-provider-local";
import type { ContainerBackend } from "@publicdomainrelay/container-backend-abc";
import { createContainerBackend } from "@publicdomainrelay/container-backend-container";
import { createDockerBackend } from "@publicdomainrelay/container-backend-docker";
import { createRelayFactory } from "@publicdomainrelay/hono-factory-did-key-ingress-proxy-xrpc";
import { createPackageRegistryFactory } from "@publicdomainrelay/hono-factory-package-registry";
import { createLocalFsStore } from "@publicdomainrelay/package-store-local-fs";
import { didToSubdomain, TUNNEL_NSID } from "@publicdomainrelay/did-key-ingress-proxy-common";
import { buildTunnelUserData } from "@publicdomainrelay/cloud-init-common";

const SSH_READY_TIMEOUT_MS = 300_000;

// Org root holds every @publicdomainrelay/* workspace package (did-key-ingress-proxy,
// typescript-helpers, ...). The registry serves the subscriber's full dep
// closure fresh from source.
const ORG_ROOT_DIR = new URL("../../", import.meta.url).pathname;

async function hasCommand(cmd: string): Promise<boolean> {
  try {
    const { code } = await new Deno.Command("which", { args: [cmd], stdout: "null", stderr: "null" }).output();
    return code === 0;
  } catch {
    return false;
  }
}

Deno.test("[integration] real shell into a cloud-init guest over the xrpc relay tunnel", async () => {
  if (!(await hasCommand("ssh")) || !(await hasCommand("websocat"))) {
    console.log("[test] SKIP: ssh and websocat are required on the host");
    return;
  }
  const backend: ContainerBackend = Deno.build.os === "darwin"
    ? createContainerBackend()
    : createDockerBackend();
  if (!(await backend.ensureRunning())) {
    console.log("[test] SKIP: container backend not available");
    return;
  }

  const gatewayIp = await backend.defaultGateway();

  const cleanups: Array<() => void | Promise<void>> = [];
  let containerName = "";
  try {
    // ── JSR registry (port 0) ─────────────────────────────────────────
    const registryApp = createPackageRegistryFactory({
      store: createLocalFsStore({ baseDir: ORG_ROOT_DIR }),
      label: "test-registry",
      passthrough: true,
    });
    const registryAc = new AbortController();
    const { promise: regPortReady, resolve: resolveRegPort } = Promise.withResolvers<number>();
    Deno.serve({ port: 0, hostname: "0.0.0.0", signal: registryAc.signal, onListen: (addr) => resolveRegPort((addr as Deno.NetAddr).port) }, registryApp.fetch);
    cleanups.push(() => registryAc.abort());
    const registryPort = await regPortReady;

    // ── relay dispatcher (port 0) ─────────────────────────────────────
    const relayApp = createRelayFactory({ hostname: "localhost", additionalHosts: [gatewayIp] }).createApp();
    const relayAc = new AbortController();
    const { promise: relPortReady, resolve: resolveRelPort } = Promise.withResolvers<number>();
    Deno.serve({ port: 0, hostname: "0.0.0.0", signal: relayAc.signal, onListen: (addr) => resolveRelPort((addr as Deno.NetAddr).port) }, relayApp.fetch);
    cleanups.push(() => relayAc.abort());
    const relayPort = await relPortReady;

    // ssh client keypair + relay subscriber keypair.
    const tmp = await Deno.makeTempDir({ prefix: "ssh-relay-" });
    cleanups.push(() => Deno.remove(tmp, { recursive: true }).catch(() => {}));
    const keyPath = `${tmp}/id_ed25519`;
    {
      const { code, stderr } = await new Deno.Command("ssh-keygen", {
        args: ["-t", "ed25519", "-N", "", "-C", "ssh-relay", "-f", keyPath],
        stdout: "null", stderr: "piped",
      }).output();
      assert(code === 0, `ssh-keygen failed: ${new TextDecoder().decode(stderr)}`);
    }
    const pubKey = (await Deno.readTextFile(`${keyPath}.pub`)).trim();

    // TODO: derive subdomain from guest's sshd host key instead of pre-generated keypair.
    // Guest now derives secp256k1 identity from /etc/ssh/ssh_host_ed25519_key at boot.
    // Test should pre-seed host key, derive secp256k1 via HKDF, and compute subdomain.
    // For now, generate a temp secp256k1 keypair for subdomain — reconnect after
    // onNetwork discovery endpoint is complete.
    const keypair = await Secp256k1Keypair.create({ exportable: true });
    const subdomain = didToSubdomain(keypair.did());

    // Guest cloud-init: sshd@127.0.0.1:22 + tunnel-subscriber dialing the relay.
    // Guest derives secp256k1 identity from sshd host key at boot — no privateKeyHex in cloud-init.
    const userData = buildTunnelUserData({
      ingressProxyHost: `${gatewayIp}:${relayPort}`,
      audHost: "localhost",
      jsrUrl: `${gatewayIp}:${registryPort}`,
      sshAuthorizedKey: pubKey,
    });

    containerName = `test-ssh-relay-${crypto.randomUUID().slice(0, 8)}`;
    await runContainer(backend, userData, { distro: "ubuntu", containerName });
    cleanups.push(() => backend.rm(containerName).catch(() => {}));

    // Host ProxyCommand stays websocat (as the reference cli.ts): it wraps ssh
    // stdio in a WebSocket to the relay tunnel endpoint for the guest subdomain;
    // the relay forwards raw bytes to the in-guest tunnel-subscriber -> sshd.
    // ws-c: overlay connects the TCP socket to the relay on 127.0.0.1 while
    // --ws-c-uri sets the WebSocket handshake request URI (path + Host header)
    // to the guest subdomain, so the relay routes by subdomain without needing
    // *.localhost DNS resolution. (A plain `ws://<sub>.localhost` URL would try
    // to resolve the name; `-H 'Host: ...'` is not honored as the authority.)
    const proxyCommand =
      `websocat --binary - ws-c:tcp:127.0.0.1:${relayPort} ` +
      `--ws-c-uri=ws://${subdomain}.localhost/xrpc/${TUNNEL_NSID}`;

    const sshArgs = (program: string) => [
      "-o", `ProxyCommand=${proxyCommand}`,
      "-o", "StrictHostKeyChecking=no",
      "-o", "UserKnownHostsFile=/dev/null",
      "-o", "IdentitiesOnly=yes",
      "-o", "BatchMode=yes",
      "-o", "ConnectTimeout=15",
      "-o", "LogLevel=ERROR",
      "-i", keyPath,
      "root@tunnel",
      program,
    ];

    const token = crypto.randomUUID();
    const deadline = Date.now() + SSH_READY_TIMEOUT_MS;
    let out = "";
    let code = 1;
    let stderr = "";
    while (Date.now() < deadline) {
      const r = await new Deno.Command("ssh", { args: sshArgs(`echo PASS:${token}; id -un`), stdout: "piped", stderr: "piped" }).output();
      code = r.code;
      out = new TextDecoder().decode(r.stdout);
      stderr = new TextDecoder().decode(r.stderr);
      if (code === 0 && out.includes(`PASS:${token}`)) break;
      await new Promise((res) => setTimeout(res, 5000));
    }

    assert(code === 0, `ssh over relay tunnel failed (code ${code}): ${stderr.slice(0, 400)}`);
    console.log(`[test] ssh stdout: ${out.replace(/\n/g, " | ")}`);
    assertStringIncludes(out, `PASS:${token}`, "shell command output round-tripped over the relay tunnel");
    assertStringIncludes(out, "root", "ran as root inside the cloud-init guest");
  } finally {
    for (const c of cleanups.reverse()) {
      try { await c(); } catch { /* best effort */ }
    }
    await new Promise((r) => setTimeout(r, 200));
  }
});
