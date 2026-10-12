import { assert, assertEquals } from "@std/assert";
import { Hono } from "@hono/hono";
import type { ContainerBackend } from "@publicdomainrelay/container-backend-abc";
import type { ComputeAtproto, GuestGone } from "@publicdomainrelay/compute-provider-abc";
import { createFirecrackerComputeProvider } from "@publicdomainrelay/compute-provider-firecracker";
import { createFirecrackerMicrovm } from "@publicdomainrelay/microvm-firecracker";
import type { Microvm, MicrovmExit, MicrovmSpec } from "@publicdomainrelay/microvm-firecracker";
import type { NodeImageStore } from "@publicdomainrelay/node-image-abc";

const RUNNER_IMAGE = "localhost/socialweb-firecracker-runner:local";

interface FakeContainer {
  running: boolean;
  exitCode: number;
  exists: boolean;
}

function fakeBackend(containers: Map<string, FakeContainer>, calls: string[]): ContainerBackend {
  const result = { code: 0, stdout: "", stderr: "" };
  return {
    type: "docker",
    bin: "docker",
    command: (args: string[]) => {
      calls.push(args.join(" "));
      if (args[0] === "inspect") {
        const name = args[args.length - 1];
        const c = containers.get(name);
        if (!c || !c.exists) {
          return Promise.resolve({ code: 1, stdout: "", stderr: `Error: No such object: ${name}` });
        }
        return Promise.resolve({ code: 0, stdout: `${c.running} ${c.exitCode}\n`, stderr: "" });
      }
      return Promise.resolve(result);
    },
    inspectIp: () => Promise.resolve("172.30.0.2"),
    inspectGateway: () => Promise.resolve("172.30.0.1"),
    defaultGateway: () => Promise.resolve("172.17.0.1"),
    imageExists: () => Promise.resolve(true),
    pullImage: () => Promise.resolve(),
    rm: (name: string) => {
      calls.push(`rm ${name}`);
      const c = containers.get(name);
      if (c) c.exists = false;
      return Promise.resolve();
    },
    kill: (name: string) => {
      calls.push(`kill ${name}`);
      const c = containers.get(name);
      if (c) c.running = false;
      return Promise.resolve();
    },
    exec: () => Promise.resolve(result),
    isRunning: () => Promise.resolve(true),
    ensureRunning: () => Promise.resolve(true),
    logStream: () => new ReadableStream<string>(),
  };
}

Deno.test("a guest whose runner container exits on its own is reported as exited", async () => {
  const containers = new Map([["fc-a", { running: true, exitCode: 0, exists: true }]]);
  const microvm = createFirecrackerMicrovm({
    backend: fakeBackend(containers, []),
    runnerImage: RUNNER_IMAGE,
    watchIntervalMs: 10,
  });
  const exited = Promise.withResolvers<MicrovmExit>();
  const cancel = microvm.watch("fc-a", exited.resolve);
  try {
    await new Promise((r) => setTimeout(r, 40));
    containers.get("fc-a")!.running = false;
    const exit = await exited.promise;
    assertEquals(exit.container, "fc-a");
    assertEquals(exit.reason, "exited");
    assertEquals(exit.exitCode, 0);
  } finally {
    cancel();
  }
});

Deno.test("a guest whose runner container was removed is reported as removed", async () => {
  const containers = new Map([["fc-b", { running: true, exitCode: 0, exists: true }]]);
  const microvm = createFirecrackerMicrovm({
    backend: fakeBackend(containers, []),
    runnerImage: RUNNER_IMAGE,
    watchIntervalMs: 10,
  });
  const exited = Promise.withResolvers<MicrovmExit>();
  const cancel = microvm.watch("fc-b", exited.resolve);
  try {
    containers.get("fc-b")!.exists = false;
    const exit = await exited.promise;
    assertEquals(exit.reason, "removed");
  } finally {
    cancel();
  }
});

Deno.test("a cancelled watch never reports", async () => {
  const containers = new Map([["fc-c", { running: false, exitCode: 0, exists: true }]]);
  const microvm = createFirecrackerMicrovm({
    backend: fakeBackend(containers, []),
    runnerImage: RUNNER_IMAGE,
    watchIntervalMs: 10,
  });
  let reported = false;
  const cancel = microvm.watch("fc-c", () => {
    reported = true;
  });
  cancel();
  await new Promise((r) => setTimeout(r, 40));
  assert(!reported, "a watch cancelled by destroy reported the guest it was cancelled for");
});

Deno.test("stopping a guest removes its work directory once its container is gone", async () => {
  const root = Deno.makeTempDirSync({ prefix: "microvm-stop-" });
  try {
    const workDir = `${root}/guests/fc-d`;
    await Deno.mkdir(workDir, { recursive: true });
    await Deno.writeTextFile(`${workDir}/result.json`, JSON.stringify({ name: "fc-d" }));
    await Deno.writeTextFile(`${workDir}/rootfs.ext4`, "a rootfs");
    const containers = new Map([["fc-d", { running: true, exitCode: 0, exists: true }]]);
    const calls: string[] = [];
    const microvm = createFirecrackerMicrovm({ backend: fakeBackend(containers, calls), runnerImage: RUNNER_IMAGE });

    await microvm.stop(workDir);

    assert(calls.includes("rm fc-d"), `the guest's container was not removed: ${calls.join("; ")}`);
    const left = await Deno.stat(workDir).then(() => true, () => false);
    assert(!left, `the work directory ${workDir} outlived its guest, holding a rootfs copy`);
  } finally {
    await Deno.remove(root, { recursive: true }).catch(() => {});
  }
});

Deno.test("a work directory is kept while its container still exists", async () => {
  const root = Deno.makeTempDirSync({ prefix: "microvm-stop-kept-" });
  try {
    const workDir = `${root}/guests/fc-e`;
    await Deno.mkdir(workDir, { recursive: true });
    const containers = new Map([["fc-e", { running: true, exitCode: 0, exists: true }]]);
    const backend = fakeBackend(containers, []);
    const stubborn: ContainerBackend = { ...backend, rm: () => Promise.resolve() };
    const microvm = createFirecrackerMicrovm({ backend: stubborn, runnerImage: RUNNER_IMAGE });

    const err = await microvm.stop(workDir).then(() => undefined, (e: unknown) => e);

    assert(err instanceof Error, "stop reported success while the guest's container still exists");
    assert((await Deno.stat(workDir)).isDirectory, "the work directory was removed under a live container");
  } finally {
    await Deno.remove(root, { recursive: true }).catch(() => {});
  }
});

interface WatchedMicrovm {
  microvm: Microvm;
  booted: MicrovmSpec[];
  stopped: string[];
  watchers: Map<string, (exit: MicrovmExit) => void>;
  cancelled: string[];
}

function watchedMicrovm(): WatchedMicrovm {
  const booted: MicrovmSpec[] = [];
  const stopped: string[] = [];
  const watchers = new Map<string, (exit: MicrovmExit) => void>();
  const cancelled: string[] = [];
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
    stop: (workDir: string) => {
      stopped.push(workDir);
      return Promise.resolve();
    },
    watch: (container: string, onExit: (exit: MicrovmExit) => void) => {
      watchers.set(container, onExit);
      return () => {
        cancelled.push(container);
      };
    },
    hostAddressForGuest: () => Promise.resolve("172.17.0.1"),
  };
  return { microvm, booted, stopped, watchers, cancelled };
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

function aProvider(microvm: Microvm, workRoot: string, warnings: string[]) {
  return createFirecrackerComputeProvider({
    logger: {
      info: () => {},
      warn: (event: string) => {
        warnings.push(event);
      },
      error: () => {},
      debug: () => {},
    } as never,
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

Deno.test("a guest that dies on its own is reported gone, released and cleaned up", async () => {
  const workRoot = Deno.makeTempDirSync({ prefix: "fc-gone-" });
  try {
    const fake = watchedMicrovm();
    const warnings: string[] = [];
    const provider = aProvider(fake.microvm, workRoot, warnings);
    const gone = Promise.withResolvers<GuestGone>();
    assert(provider.onGuestGone, "the provider offers no way to learn a guest died on its own");
    provider.onGuestGone(gone.resolve);

    const { providerId } = await provider.provision(VM, "did:plc:requester");
    const name = String(providerId);
    const watcher = fake.watchers.get(name);
    assert(watcher, `the provider never watched the container of guest ${name}`);

    watcher({ container: name, reason: "exited", exitCode: 0, logs: "firecracker exiting successfully" });
    const reported = await gone.promise;

    assertEquals(String(reported.id), name);
    assertEquals(provider.getDroplet?.(name), undefined, "a dead guest is still served to the issuer");
    assertEquals(fake.stopped, [`${workRoot}/${name}`], "the dead guest's container and work dir were left");
    assert(warnings.includes("microvm_exited"), `no microvm_exited warning was logged: ${warnings}`);

    await provider.destroy(providerId);
    assertEquals(fake.stopped.length, 2, "a later vm.delete for the dead guest must still be safe to run");
  } finally {
    await Deno.remove(workRoot, { recursive: true }).catch(() => {});
  }
});

Deno.test("destroy cancels the watch and does not report the guest as dead", async () => {
  const workRoot = Deno.makeTempDirSync({ prefix: "fc-destroy-" });
  try {
    const fake = watchedMicrovm();
    const provider = aProvider(fake.microvm, workRoot, []);
    const reported: GuestGone[] = [];
    provider.onGuestGone?.((g) => reported.push(g));

    const { providerId } = await provider.provision(VM, "did:plc:requester");
    const name = String(providerId);
    await provider.destroy(providerId);

    assertEquals(fake.cancelled, [name]);
    assertEquals(fake.stopped, [`${workRoot}/${name}`]);
    assertEquals(reported, []);
  } finally {
    await Deno.remove(workRoot, { recursive: true }).catch(() => {});
  }
});

Deno.test("destroy of a guest this process never booted still stops it and removes its work dir", async () => {
  const workRoot = Deno.makeTempDirSync({ prefix: "fc-orphan-" });
  try {
    const fake = watchedMicrovm();
    const provider = aProvider(fake.microvm, workRoot, []);

    await provider.destroy("fc-1379be663dd9-0319b646");
    await provider.destroy("../../etc");

    assertEquals(fake.stopped, [`${workRoot}/fc-1379be663dd9-0319b646`]);
  } finally {
    await Deno.remove(workRoot, { recursive: true }).catch(() => {});
  }
});
