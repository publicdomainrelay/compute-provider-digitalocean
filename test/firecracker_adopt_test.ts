import { assert, assertEquals } from "@std/assert";
import { Hono } from "@hono/hono";
import type { ComputeAtproto, GuestGone } from "@publicdomainrelay/compute-provider-abc";
import { createFirecrackerComputeProvider } from "@publicdomainrelay/compute-provider-firecracker";
import type { Microvm, MicrovmExit, MicrovmSpec } from "@publicdomainrelay/microvm-firecracker";
import type { NodeImageStore } from "@publicdomainrelay/node-image-abc";

interface ContainerState {
  exists: boolean;
  running: boolean;
  exitCode?: number;
}

function fakeMicrovm(states: Map<string, ContainerState>) {
  const booted: MicrovmSpec[] = [];
  const stopped: string[] = [];
  const watchers = new Map<string, (exit: MicrovmExit) => void>();
  const microvm: Microvm = {
    name: "firecracker",
    boot: (spec: MicrovmSpec) => {
      booted.push(spec);
      states.set(spec.name, { exists: true, running: true });
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
      stopped.push(workDir);
      await Deno.remove(workDir, { recursive: true }).catch(() => {});
    },
    watch: (container: string, onExit: (exit: MicrovmExit) => void) => {
      watchers.set(container, onExit);
      return () => watchers.delete(container);
    },
    inspect: (container: string) => Promise.resolve(states.get(container) ?? { exists: false, running: false }),
    hostAddressForGuest: () => Promise.resolve("172.17.0.1"),
  };
  return { microvm, booted, stopped, watchers };
}

function aStore(): NodeImageStore {
  return {
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
}

function aProvider(microvm: Microvm, workRoot: string, bootId: string) {
  return createFirecrackerComputeProvider({
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} } as never,
    atproto: {
      getAgentDid: () => "did:plc:thebidder00000000000000",
      createRecord: () => Promise.reject(new Error("this test writes no records")),
      deleteRecord: () => Promise.resolve(),
    } as unknown as ComputeAtproto,
    serve: { app: new Hono(), onConnected: () => {} },
    getIssuerUrl: () => "https://issuer.example",
    image: aStore(),
    microvm,
    workRoot,
    hostBootId: () => Promise.resolve(bootId),
  }).provider;
}

const VM = {
  cpus: 1,
  mem: "1G",
  disk: "4G",
  network: "default",
  role: "worker",
  user_data: "#cloud-config\nruncmd:\n  - [ sh, -c, \"true\" ]\n",
};

const BOOT_A = "0b6a7a3e-0000-4000-8000-00000000000a";
const BOOT_B = "0b6a7a3e-0000-4000-8000-00000000000b";

async function withRoot(fn: (root: string) => Promise<void>) {
  const root = await Deno.makeTempDir({ prefix: "fc-adopt-" });
  try {
    await fn(root);
  } finally {
    await Deno.remove(root, { recursive: true }).catch(() => {});
  }
}

Deno.test("a restarted provider adopts a still-running guest without booting it again", async () => {
  await withRoot(async (root) => {
    const states = new Map<string, ContainerState>();
    const before = fakeMicrovm(states);
    const { providerId } = await aProvider(before.microvm, root, BOOT_A).provision(VM, "did:plc:requester");
    const name = String(providerId);

    const after = fakeMicrovm(states);
    const restarted = aProvider(after.microvm, root, BOOT_A);
    assert(restarted.adopt, "the provider offers no way to adopt a guest after a restart");
    const gone: GuestGone[] = [];
    restarted.onGuestGone?.((g) => gone.push(g));

    const adopted = await restarted.adopt(name);
    assertEquals(adopted.state, "running");
    assertEquals(after.booted, [], "adopting a running guest booted it again");
    assert(after.watchers.has(name), "the adopted guest is not watched");
    const droplet = restarted.getDroplet?.(name);
    assert(droplet, "the adopted guest is not served to the issuer");
    assertEquals(droplet.tags, ["oidc-sub:plc:requester", "oidc-sub:role:worker"]);

    const second = await restarted.provision(VM, "did:plc:requester");
    const firstIp = before.booted[0].network.guestIp;
    assert(after.booted[0].network.guestIp !== firstIp, `a new guest reused the adopted guest's range ${firstIp}`);
    assert(String(second.providerId) !== name);

    after.watchers.get(name)!({ container: name, reason: "exited", exitCode: 0, logs: "" });
    for (let i = 0; i < 50 && gone.length === 0; i++) await new Promise((r) => setTimeout(r, 5));
    assertEquals(gone.map((g) => String(g.id)), [name], "an adopted guest that exits is not reported gone");
  });
});

Deno.test("a guest whose container is gone at adopt time is reported vmm_exited and cleaned up", async () => {
  await withRoot(async (root) => {
    const states = new Map<string, ContainerState>();
    const before = fakeMicrovm(states);
    const { providerId } = await aProvider(before.microvm, root, BOOT_A).provision(VM, "did:plc:requester");
    const name = String(providerId);
    states.set(name, { exists: true, running: false, exitCode: 137 });

    const after = fakeMicrovm(states);
    const restarted = aProvider(after.microvm, root, BOOT_A);
    const adopted = await restarted.adopt!(name);
    assertEquals(adopted.state, "gone");
    if (adopted.state !== "gone") return;
    assertEquals(adopted.gone.reason, "vmm_exited");
    assertEquals(adopted.gone.exitCode, 137);
    assertEquals(after.booted, []);
    assertEquals(after.stopped, [`${root}/${name}`], "the gone guest's work dir was left");
    assertEquals(restarted.getDroplet?.(name), undefined);
  });
});

Deno.test("a guest lost to a host reboot is reported host_reboot", async () => {
  await withRoot(async (root) => {
    const states = new Map<string, ContainerState>();
    const before = fakeMicrovm(states);
    const { providerId } = await aProvider(before.microvm, root, BOOT_A).provision(VM, "did:plc:requester");
    const name = String(providerId);
    states.set(name, { exists: true, running: false, exitCode: 0 });

    const after = fakeMicrovm(states);
    const adopted = await aProvider(after.microvm, root, BOOT_B).adopt!(name);
    assertEquals(adopted.state, "gone");
    if (adopted.state !== "gone") return;
    assertEquals(adopted.gone.reason, "host_reboot");
  });
});

Deno.test("a guest with no container and no work dir is reported vmm_exited", async () => {
  await withRoot(async (root) => {
    const after = fakeMicrovm(new Map());
    const adopted = await aProvider(after.microvm, root, BOOT_A).adopt!("fc-1379be663dd9-0319b646");
    assertEquals(adopted.state, "gone");
    if (adopted.state !== "gone") return;
    assertEquals(adopted.gone.reason, "vmm_exited");
    assertEquals(after.booted, []);
  });
});
