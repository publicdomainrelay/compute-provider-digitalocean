import { assert, assertEquals, assertStringIncludes } from "@std/assert";
import { Hono } from "@hono/hono";
import { parse } from "@std/yaml";
import type { ComputeAtproto, GuestHostKeysReport } from "@publicdomainrelay/compute-provider-abc";
import { createFirecrackerComputeProvider } from "@publicdomainrelay/compute-provider-firecracker";
import type { Microvm, MicrovmSpec } from "@publicdomainrelay/microvm-firecracker";
import type { NodeImageStore } from "@publicdomainrelay/node-image-abc";
import { createOidcIssuer, PROVISIONING_TOKEN_PATH } from "@publicdomainrelay/oidc-issuer-hono";

const ISSUER = "https://issuer.hostkeys.example";

interface HostKey {
  dir: string;
  type: string;
  publicKey: string;
}

async function hostKey(): Promise<HostKey> {
  const dir = await Deno.makeTempDir({ prefix: "oidc-hostkeys-" });
  const gen = await new Deno.Command("ssh-keygen", {
    args: ["-q", "-t", "ed25519", "-N", "", "-f", `${dir}/ssh_host_ed25519_key`],
  }).output();
  assert(gen.success, "ssh-keygen");
  const [type, publicKey] = (await Deno.readTextFile(`${dir}/ssh_host_ed25519_key.pub`)).trim().split(/\s+/);
  return { dir, type, publicKey };
}

async function sign(key: HostKey, data: string): Promise<string> {
  const child = new Deno.Command("ssh-keygen", {
    args: ["-Y", "sign", "-n", "prove-sshd", "-f", `${key.dir}/ssh_host_ed25519_key`],
    stdin: "piped",
    stdout: "piped",
    stderr: "null",
  }).spawn();
  const w = child.stdin.getWriter();
  await w.write(new TextEncoder().encode(data));
  await w.close();
  const out = await child.output();
  assert(out.success, "ssh-keygen -Y sign");
  return new TextDecoder().decode(out.stdout);
}

function fileOf(userData: string, path: string): string {
  const doc = parse(userData.replace(/^#cloud-config\n/, "")) as { write_files: Array<{ path: string; content: string }> };
  return doc.write_files.find((f) => f.path === path)?.content ?? "";
}

function tokenOf(userData: string): string {
  return fileOf(userData, PROVISIONING_TOKEN_PATH).trim();
}

function post(app: { fetch: (req: Request) => Response | Promise<Response> }, path: string, body: unknown, bearer?: string) {
  return app.fetch(
    new Request(`${ISSUER}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) },
      body: JSON.stringify(body),
    }),
  );
}

Deno.test("provisioningValidate verifies against the reported key and nothing in lib execs ssh-keyscan", async () => {
  const reports: Array<{ nonce: string; keys: unknown[] }> = [];
  const issuer = createOidcIssuer({
    getIssuerUrl: () => ISSUER,
    getDroplet: (id) => ({ id, tags: ["oidc-sub:plc:requester", "oidc-sub:role:worker"] }),
    reportedHostKeyWaitMs: 300,
    onHostKeys: (report) => {
      reports.push(report);
      return Promise.resolve({ ok: true });
    },
  });
  const guest = await hostKey();
  const stranger = await hostKey();
  try {
    const pd = await issuer.createProvisioningData("team", "#cloud-config\n");
    pd.associateWithDroplet("guest-1");
    assertStringIncludes(pd.userData, "guest-hostkeys.service");
    assertStringIncludes(pd.userData, `${ISSUER}/v1/host-keys`);
    const token = tokenOf(pd.userData);
    assertEquals(token, pd.token.asString, "the provisioning token is written to its file, once");
    assert(!pd.userData.includes(`PROVISIONING_TOKEN="${token}"`), "the token is read from the file, not inlined");
    const unit = fileOf(pd.userData, "/etc/systemd/system/provisioning-token.service");
    assertStringIncludes(unit, "guest-hostkeys.service");

    const sig = await sign(guest, token);
    const early = await post(issuer.app, "/v1/oidc/prove", { sig }, token);
    assertEquals(early.status, 401, "no prove before the guest reported its key");

    const keys = [{ type: guest.type, publicKey: guest.publicKey }];
    const forged = await post(issuer.app, "/v1/host-keys", { keys, token, signature: await sign(stranger, token) });
    assertEquals(forged.status, 403, "a signature by another key over the token is refused");
    const noToken = await post(issuer.app, "/v1/host-keys", { keys, token: "x.y.z", signature: sig });
    assertEquals(noToken.status, 403, "a report without an issued token is refused");
    assertEquals(reports, []);

    const ok = await post(issuer.app, "/v1/host-keys", { keys, token, signature: sig });
    assertEquals(ok.status, 200, await ok.text());
    assertEquals(reports.length, 1);
    assertEquals(reports[0].nonce, pd.nonce);
    assertEquals(reports[0].keys, keys);

    const other = [{ type: stranger.type, publicKey: stranger.publicKey }];
    const second = await post(issuer.app, "/v1/host-keys", {
      keys: other,
      token,
      signature: await sign(stranger, token),
    });
    assertEquals(second.status, 409, "a second, different ed25519 key for the token is refused");

    const proveWrong = await post(issuer.app, "/v1/oidc/prove", { sig: await sign(stranger, token) }, token);
    assertEquals(proveWrong.status, 200);
    assertEquals((await proveWrong.json()).valid, false, "prove checks the reported key, not any key");

    const pd2 = await issuer.createProvisioningData("team", "#cloud-config\n");
    pd2.associateWithDroplet("guest-2");
    const token2 = tokenOf(pd2.userData);
    const g2 = await post(issuer.app, "/v1/host-keys", { keys, token: token2, signature: await sign(guest, token2) });
    assertEquals(g2.status, 200);
    const proved = await post(issuer.app, "/v1/oidc/prove", { sig: await sign(guest, token2) }, token2);
    const body = await proved.json();
    assert(typeof body.token === "string", JSON.stringify(body));
    const claims = JSON.parse(atob(body.token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    assertEquals(claims.sub, "actx:team:plc:requester:role:worker");
    assertEquals(claims.droplet_id, "guest-2");
  } finally {
    await Deno.remove(guest.dir, { recursive: true });
    await Deno.remove(stranger.dir, { recursive: true });
  }

  const offenders: string[] = [];
  const scan = async (dir: string): Promise<void> => {
    for await (const entry of Deno.readDir(dir)) {
      const path = `${dir}/${entry.name}`;
      if (entry.isDirectory) await scan(path);
      else if (entry.name.endsWith(".ts") && (await Deno.readTextFile(path)).includes("ssh-keyscan")) {
        offenders.push(path);
      }
    }
  };
  await scan(new URL("../lib", import.meta.url).pathname);
  assertEquals(offenders, [], "no library code scans a guest for its host key");
});

function fakeMicrovm() {
  const booted: MicrovmSpec[] = [];
  const microvm: Microvm = {
    name: "firecracker",
    boot: (spec: MicrovmSpec) => {
      booted.push(spec);
      return Promise.resolve({
        name: spec.name,
        guestIp: spec.network.guestIp,
        vmmPid: 4242,
        pastaPid: 4243,
        socket: "/the/socket",
        console: "/the/console",
        workDir: spec.workDir,
        container: spec.name,
        fingerprint: "sha256-test",
      });
    },
    stop: async (workDir: string) => {
      await Deno.remove(workDir, { recursive: true }).catch(() => {});
    },
    watch: () => () => {},
    inspect: () => Promise.resolve({ exists: true, running: true }),
    hostAddressForGuest: () => Promise.resolve("172.17.0.1"),
  };
  return { microvm, booted };
}

const STORE: NodeImageStore = {
  name: "firecracker",
  ensure: () =>
    Promise.resolve({
      state: "present",
      fingerprint: "sha256-test",
      dir: "/the/store/sha256-test",
      config: "/the/configuration.json",
      rootfsMiB: 2048,
    }),
};

Deno.test("a firecracker guest's proven host keys reach the bidder under its provider id; pasta forwards no inbound port", async () => {
  const root = await Deno.makeTempDir({ prefix: "fc-hostkeys-" });
  const guest = await hostKey();
  try {
    const app = new Hono();
    const fake = fakeMicrovm();
    const { provider } = createFirecrackerComputeProvider({
      logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} } as never,
      atproto: {
        getAgentDid: () => "did:plc:thebidder00000000000000",
        createRecord: () => Promise.reject(new Error("this test writes no records")),
        deleteRecord: () => Promise.resolve(),
      } as unknown as ComputeAtproto,
      serve: { app, onConnected: (fn: (ref: string) => void) => fn("did:web:issuer.hostkeys.example") } as never,
      getIssuerUrl: () => ISSUER,
      image: STORE,
      microvm: fake.microvm,
      workRoot: root,
      oidcProvisioning: true,
      hostBootId: () => Promise.resolve("boot-a"),
    });
    const reports: GuestHostKeysReport[] = [];
    assert(provider.onHostKeys, "the provider reports guest host keys");
    provider.onHostKeys((report) => {
      reports.push(report);
      return Promise.resolve({ ok: true });
    });
    const { providerId } = await provider.provision({
      cpus: 1,
      mem: "1G",
      disk: "4G",
      network: "default",
      role: "worker",
      user_data: "#cloud-config\nruncmd:\n  - [ sh, -c, \"true\" ]\n",
    }, "did:plc:requester");
    const spec = fake.booted[0];
    assert(!(spec.pastaArgs ?? []).includes("-t"), `pasta forwards an inbound port: ${spec.pastaArgs}`);
    assertEquals(provider.getDroplet?.(String(providerId))?.containerName, undefined);

    const userData = await Deno.readTextFile(spec.userDataFile);
    const token = tokenOf(userData);
    assert(token, "the guest's user_data carries its provisioning token file");
    const keys = [{ type: guest.type, publicKey: guest.publicKey }];
    const res = await post(app, "/v1/host-keys", { keys, token, signature: await sign(guest, token) });
    assertEquals(res.status, 200, await res.text());
    assertEquals(reports.map((r) => String(r.id)), [String(providerId)]);
    assertEquals(reports[0].keys, keys);

    const proved = await post(app, "/v1/oidc/prove", { sig: await sign(guest, token) }, token);
    assert(typeof (await proved.json()).token === "string", "the guest's token exchange still works");
  } finally {
    await Deno.remove(root, { recursive: true }).catch(() => {});
    await Deno.remove(guest.dir, { recursive: true });
  }
});
