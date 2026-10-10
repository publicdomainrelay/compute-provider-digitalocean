import { assertEquals } from "@std/assert";
import { createFirecrackerComputeProvider } from "@publicdomainrelay/compute-provider-firecracker";
import type { ComputeAtproto } from "@publicdomainrelay/compute-provider-abc";
import type { Microvm, MicrovmSpec } from "@publicdomainrelay/microvm-firecracker";
import type { NodeImageStatus, NodeImageStore } from "@publicdomainrelay/node-image-abc";
import { Hono } from "@hono/hono";

const ROOTFS_MIB = 2048;

function aStore(state: NodeImageStatus["state"]): NodeImageStore {
  return {
    name: "firecracker",
    ensure: () =>
      Promise.resolve({
        state,
        fingerprint: "sha256-1111111111111111111111111111111111111111111111111111111111111111",
        dir: "/the/store/sha256-1111111111111111111111111111111111111111111111111111111111111111",
        config: "/the/configuration.json",
        rootfsMiB: ROOTFS_MIB,
      }),
  };
}

function aMicrovm(booted: MicrovmSpec[]): Microvm {
  return {
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
        fingerprint: "sha256-1111111111111111111111111111111111111111111111111111111111111111",
      });
    },
    stop: () => Promise.resolve(),
  } as Microvm;
}

function aProvider(state: NodeImageStatus["state"], booted: MicrovmSpec[]) {
  return createFirecrackerComputeProvider({
    logger: {
      info: () => {},
      warn: () => {},
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
    image: aStore(state),
    microvm: aMicrovm(booted),
    workRoot: Deno.makeTempDirSync({ prefix: "disk-check-" }),
  }).provider;
}

const VM = {
  cpus: 2,
  mem: "2G",
  disk: "4G",
  network: "default",
  role: "worker",
  user_data: "#cloud-config\nruncmd:\n  - [ sh, -c, \"true\" ]\n",
};

Deno.test("a contract that asks for a bigger disk boots a guest grown to it", async () => {
  const booted: MicrovmSpec[] = [];
  const provider = aProvider("present", booted);
  await provider.provision({ ...VM, disk: "4G" }, "did:plc:requester");
  assertEquals(
    booted[0].diskMib,
    4096,
    `the contract asks for 4G and the guest was booted from the image's own 2048 MiB filesystem, ` +
      `which is the size it would keep: nothing downstream of this asks for the disk again`,
  );
});

Deno.test("a reused image is asked for the contract's disk as well as a present one", async () => {
  const booted: MicrovmSpec[] = [];
  const provider = aProvider("reused", booted);
  await provider.provision({ ...VM, disk: "8G" }, "did:plc:requester");
  assertEquals(booted[0].diskMib, 8192);
});

Deno.test("a disk named in a spelling nothing parses is left to the guest's own", async () => {
  const booted: MicrovmSpec[] = [];
  const provider = aProvider("present", booted);
  await provider.provision({ ...VM, disk: "as much as fits" }, "did:plc:requester");
  assertEquals(
    booted[0].diskMib,
    undefined,
    "a disk the provider cannot read is not a size to grow a filesystem to, and growing to a " +
      "guess is growing to a number nobody asked for",
  );
});

Deno.test("the contract's number is what is passed on, whatever it is", async () => {
  const booted: MicrovmSpec[] = [];
  const provider = aProvider("present", booted);
  await provider.provision({ ...VM, disk: "1G" }, "did:plc:requester");
  assertEquals(
    booted[0].diskMib,
    1024,
    "the provider passes the contract's number on and the guest's own tool grows only what has to " +
      "grow: shrinking is not something this does, and the runner is what decides that",
  );
});
