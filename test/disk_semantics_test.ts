import { assert, assertEquals, assertRejects } from "@std/assert";
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

Deno.test("a disk bigger than the image is refused rather than silently undersized", async () => {
  const booted: MicrovmSpec[] = [];
  const provider = aProvider("present", booted);
  const err = await assertRejects(() => provider.provision({ ...VM, disk: "4G" }, "did:plc:requester")) as Error;
  assertEquals(booted.length, 0, "a guest was booted, so the refusal happened after the VM was placed");
  assert(
    err.message.includes("4G") && err.message.includes(`${ROOTFS_MIB} MiB`),
    `the refusal does not say what was asked for and what the image holds: ${err.message}`,
  );
});

Deno.test("a disk the image can hold is provisioned", async () => {
  const booted: MicrovmSpec[] = [];
  const provider = aProvider("present", booted);
  const result = await provider.provision({ ...VM, disk: "2G" }, "did:plc:requester");
  assertEquals(booted.length, 1);
  assertEquals((result.metadata as Record<string, unknown>).mode, "firecracker");
});

Deno.test("a reused image is measured as well as a present one", async () => {
  const booted: MicrovmSpec[] = [];
  const provider = aProvider("reused", booted);
  await assertRejects(() => provider.provision({ ...VM, disk: "8G" }, "did:plc:requester"));
  assertEquals(booted.length, 0);
});

Deno.test("a disk named in a spelling nothing parses is left to the guest's own", async () => {
  const booted: MicrovmSpec[] = [];
  const provider = aProvider("present", booted);
  await provider.provision({ ...VM, disk: "as much as fits" }, "did:plc:requester");
  assertEquals(
    booted.length,
    1,
    "a disk the provider cannot read is not a disk this can hold a contract to, and refusing over " +
      "one would be refusing over a spelling rather than over a size",
  );
});
