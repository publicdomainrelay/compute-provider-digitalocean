import { assert, assertEquals } from "@std/assert";
import type { ContainerBackend } from "@publicdomainrelay/container-backend-abc";
import { createFirecrackerMicrovm } from "@publicdomainrelay/microvm-firecracker";
import type { MicrovmSpec } from "@publicdomainrelay/microvm-firecracker";

const RUNNER_IMAGE = "localhost/socialweb-firecracker-runner:local";

// Deliberately not the spec's gateway: pasta's gateway and the host as the
// guest's container reaches it are two different machines, and a test that
// cannot tell them apart cannot catch the provider naming the wrong one.
const CONTAINER_HOST = "172.17.0.1";

function backendThatBoots(spec: MicrovmSpec, written: string[]): ContainerBackend {
  const result = {
    name: spec.name,
    fingerprint: "sha256-test",
    vmm_pid: 4321,
    pasta_pid: 4322,
    guest_ip: spec.network.guestIp,
    socket: `${spec.workDir}/firecracker.socket`,
    console: `${spec.workDir}/console.log`,
    work_dir: spec.workDir,
  };
  return {
    type: "docker",
    bin: "docker",
    command: (args: string[]) => {
      written.push(args.join(" "));
      if (args[0] === "run") Deno.writeTextFileSync(`${spec.workDir}/result.json`, JSON.stringify(result));
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    },
    inspectIp: () => Promise.resolve(spec.network.guestIp),
    inspectGateway: () => Promise.resolve(spec.network.gateway),
    defaultGateway: () => Promise.resolve(CONTAINER_HOST),
    imageExists: () => Promise.resolve(true),
    pullImage: () => Promise.resolve(),
    rm: () => Promise.resolve(),
    kill: () => Promise.resolve(),
    exec: () => Promise.resolve({ code: 0, stdout: "", stderr: "" }),
    isRunning: () => Promise.resolve(true),
    ensureRunning: () => Promise.resolve(true),
    logStream: () => new ReadableStream<string>(),
  };
}

function aSpec(workDir: string): MicrovmSpec {
  return {
    name: "fc-test-0001",
    imageDir: workDir,
    workDir,
    userDataFile: `${workDir}/user-data.yaml`,
    network: { guestIp: "172.30.0.2", prefix: 30, gateway: "172.30.0.1", pastaIp: "172.30.0.1" },
  };
}

Deno.test("the work directory a guest is booted in is writable from inside its container", async () => {
  const root = Deno.makeTempDirSync({ prefix: "microvm-workdir-" });
  try {
    const workDir = `${root}/guests/fc-test-0001`;
    // The bidder creates this directory and the guest's launcher writes into it,
    // as two different uids: whoever creates it decides the mode unless the boot
    // step opens it, and a launcher that cannot write the copy of the rootfs
    // boots no guest at all.
    await Deno.mkdir(workDir, { recursive: true, mode: 0o755 });

    const written: string[] = [];
    const microvm = createFirecrackerMicrovm({
      backend: backendThatBoots(aSpec(workDir), written),
      runnerImage: RUNNER_IMAGE,
    });
    const result = await microvm.boot(aSpec(workDir));

    assertEquals(result.guestIp, "172.30.0.2");
    assert(written.some((line) => line.startsWith("run ")), "the guest boots in a container");
    const mode = (await Deno.stat(workDir)).mode! & 0o777;
    assertEquals(mode, 0o777, `the work directory is ${mode.toString(8)}, not 777`);
  } finally {
    await Deno.remove(root, { recursive: true }).catch(() => {});
  }
});

Deno.test("the container a guest boots in is privileged and holds the kvm and tap devices", async () => {
  const root = Deno.makeTempDirSync({ prefix: "microvm-flags-" });
  try {
    const workDir = `${root}/guests/fc-test-0002`;
    await Deno.mkdir(workDir, { recursive: true });

    const written: string[] = [];
    const microvm = createFirecrackerMicrovm({
      backend: backendThatBoots(aSpec(workDir), written),
      runnerImage: RUNNER_IMAGE,
    });
    await microvm.boot(aSpec(workDir));

    const run = written.find((line) => line.startsWith("run ")) ?? "";
    // pasta sandboxes itself in namespaces of its own and mounts a fresh /proc
    // inside them. Measured on the host that boots these guests: no capability
    // subset gets past "Failed to remount /", only --privileged does, and the
    // launcher is an unprivileged user that still needs both devices.
    assert(run.includes("--privileged"), `the guest's container is not privileged: ${run}`);
    assert(run.includes("/dev/kvm"), `the guest's container has no /dev/kvm: ${run}`);
    assert(run.includes("/dev/net/tun"), `the guest's container has no /dev/net/tun: ${run}`);
  } finally {
    await Deno.remove(root, { recursive: true }).catch(() => {});
  }
});

Deno.test("a guest is told to reach the host at the container's gateway, not pasta's", async () => {
  const root = Deno.makeTempDirSync({ prefix: "microvm-hostaddr-" });
  try {
    const workDir = `${root}/guests/fc-test-0003`;
    await Deno.mkdir(workDir, { recursive: true });
    const spec = aSpec(workDir);
    const microvm = createFirecrackerMicrovm({
      backend: backendThatBoots(spec, []),
      runnerImage: RUNNER_IMAGE,
    });

    // A guest's loopback is its own, so this address is where its registry fetch
    // and its token exchange have to land to arrive at the host at all. Naming
    // pasta's gateway instead points them at the container, whose loopback has
    // neither, and the guest comes up with a tunnel subscriber that can never
    // fetch itself and so never registers a tunnel.
    assertEquals(await microvm.hostAddressForGuest(), CONTAINER_HOST);
    assert(
      (await microvm.hostAddressForGuest()) !== spec.network.gateway,
      "the guest would be sent to pasta's gateway, which is the container's loopback and not the host",
    );
  } finally {
    await Deno.remove(root, { recursive: true }).catch(() => {});
  }
});
