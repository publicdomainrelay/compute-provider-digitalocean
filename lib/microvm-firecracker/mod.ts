import type { ContainerBackend } from "@publicdomainrelay/container-backend-abc";

export interface MicrovmNetwork {
  guestIp: string;
  prefix: number;
  gateway: string;
  pastaIp: string;
  interface?: string;
  tap?: string;
  bridge?: string;
  guestMac?: string;
}

export interface MicrovmSpec {
  name: string;
  imageDir: string;
  workDir: string;
  userDataFile: string;
  vcpu?: number;
  memMib?: number;

  diskMib?: number;
  instanceTimeoutSec?: number;
  pastaArgs?: string[];
  network: MicrovmNetwork;
}

export interface MicrovmResult {
  name: string;
  fingerprint: string;
  vmmPid: number;
  pastaPid: number;
  guestIp: string;
  socket: string;
  console: string;
  workDir: string;
  container: string;
}

export interface Microvm {
  readonly name: string;
  boot(spec: MicrovmSpec): Promise<MicrovmResult>;
  stop(workDir: string): Promise<void>;
}

export interface FirecrackerMicrovmOptions {
  backend: ContainerBackend;
  runnerImage: string;
  firecrackerPath?: string;
  bootTimeoutMs?: number;
  logger?: { info(event: string, extra?: Record<string, unknown>): void };
}

const DEFAULT_BOOT_TIMEOUT_MS = 180_000;
const DEFAULT_FIRECRACKER = "/usr/local/bin/firecracker";

interface WireSpec {
  name: string;
  image_dir: string;
  work_dir: string;
  firecracker: string;
  user_data_file: string;
  vcpu?: number;
  mem_mib?: number;

  disk_mib?: number;
  instance_timeout_sec?: number;
  pasta_args?: string[];
  network: {
    guest_ip: string;
    prefix: number;
    gateway: string;
    pasta_ip: string;
    interface?: string;
    tap?: string;
    bridge?: string;
    guest_mac?: string;
  };
}

function toWire(spec: MicrovmSpec, firecracker: string): WireSpec {
  return {
    name: spec.name,
    image_dir: spec.imageDir,
    work_dir: spec.workDir,
    firecracker,
    user_data_file: spec.userDataFile,
    vcpu: spec.vcpu,
    mem_mib: spec.memMib,

    disk_mib: spec.diskMib,
    instance_timeout_sec: spec.instanceTimeoutSec,
    pasta_args: spec.pastaArgs,
    network: {
      guest_ip: spec.network.guestIp,
      prefix: spec.network.prefix,
      gateway: spec.network.gateway,
      pasta_ip: spec.network.pastaIp,
      interface: spec.network.interface,
      tap: spec.network.tap,
      bridge: spec.network.bridge,
      guest_mac: spec.network.guestMac,
    },
  };
}

function parseResult(raw: string, container: string, source: string): MicrovmResult {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw) as Record<string, unknown>;
  } catch (cause) {
    throw new Error(`${source} is not the JSON a guest's result is: ${raw.slice(0, 400)}`, { cause });
  }
  for (const field of ["name", "guest_ip", "socket", "console", "work_dir"]) {
    if (typeof parsed[field] !== "string" || parsed[field] === "") {
      throw new Error(`${source} carries no ${field}: ${raw.slice(0, 400)}`);
    }
  }
  for (const field of ["vmm_pid", "pasta_pid"]) {
    if (typeof parsed[field] !== "number" || parsed[field] <= 0) {
      throw new Error(
        `${source} gives ${field} as ${String(parsed[field])}, and a pid that is not a positive ` +
          `number names no process, so the guest behind it could never be stopped or inspected`,
      );
    }
  }
  return {
    name: parsed.name as string,
    fingerprint: typeof parsed.fingerprint === "string" ? parsed.fingerprint : "",
    vmmPid: parsed.vmm_pid as number,
    pastaPid: parsed.pasta_pid as number,
    guestIp: parsed.guest_ip as string,
    socket: parsed.socket as string,
    console: parsed.console as string,
    workDir: parsed.work_dir as string,
    container,
  };
}

export function createFirecrackerMicrovm(opts: FirecrackerMicrovmOptions): Microvm {
  if (!opts.runnerImage) {
    throw new Error(
      "createFirecrackerMicrovm needs the image the guest is booted in. The guest is a firecracker " +
        "microVM, and booting one needs /dev/kvm, /dev/net/tun and the network capabilities that " +
        "pasta's tap setup uses. This process does not run with those, and must not: it runs where " +
        "the bidder runs. The container is given them instead, one per guest, exactly as the QEMU " +
        "provider and the local provider already do.",
    );
  }
  const backend = opts.backend;
  const runnerImage = opts.runnerImage;
  const bootTimeoutMs = opts.bootTimeoutMs ?? DEFAULT_BOOT_TIMEOUT_MS;
  const firecracker = opts.firecrackerPath ?? DEFAULT_FIRECRACKER;

  async function containerLogs(name: string, tail = 60): Promise<string> {
    const out = await backend.command(["logs", "--tail", String(tail), name]).catch(() => null);
    if (out === null) return "(logs unavailable)";
    return `${out.stdout}\n${out.stderr}`.trim().slice(-4000);
  }

  return {
    name: "firecracker",
    async boot(spec: MicrovmSpec): Promise<MicrovmResult> {
      if (spec.network.guestIp === spec.network.gateway) {
        throw new Error(
          `guest ${spec.name} would be addressed as its own gateway (${spec.network.guestIp}). The ` +
            `gateway is the address the guest dials this host on, so a guest holding it ARPs for ` +
            `itself and the frames it sends are answered by the interface it sent them from.`,
        );
      }
      const container = spec.name;
      const specPath = `${spec.workDir}/boot-spec.json`;
      const resultPath = `${spec.workDir}/result.json`;
      await Deno.mkdir(spec.workDir, { recursive: true });
      // The work directory is written from both sides: the bidder writes the spec
      // and reads the result, and the guest's launcher writes the copy of the
      // rootfs, the seed and the result — as an unprivileged user of its own, since
      // pasta started as root drops whoever starts the VMM to nobody. The two are
      // different uids, and the directory is created by whichever runs first, so it
      // is opened to both here rather than left at what one side's umask happened
      // to make it.
      await Deno.chmod(spec.workDir, 0o777);
      await Deno.writeTextFile(specPath, JSON.stringify(toWire(spec, firecracker), null, 2));
      await Deno.remove(resultPath).catch(() => {});

      // The image directory and the work directory are mounted at the paths they
      // already have, so the spec means the same thing inside the container as
      // out of it: a guest's socket and console are named in the result, and the
      // caller reads them from this side.
      const runArgs = [
        "run", "-d",
        "--name", container,
        "--device", "/dev/kvm",
        "--device", "/dev/net/tun",
        "--cap-add", "NET_ADMIN",
        "--security-opt", "seccomp=unconfined",
        "-v", `${spec.imageDir}:${spec.imageDir}:ro`,
        "-v", `${spec.workDir}:${spec.workDir}`,
        runnerImage,
        // The runner image's entrypoint is what execs the launcher, as the
        // unprivileged user it has to run as; naming it again here would arrive
        // as a positional argument and stop the launcher's own flag parsing.
        "-spec", specPath, "-result", resultPath, "-foreground",
      ];
      const started = await backend.command(runArgs);
      if (started.code !== 0) {
        throw new Error(
          `starting the container that boots guest ${spec.name} failed: ${started.stderr.trim()} ` +
            `-- the guest is only ever a process inside a container, because booting one needs ` +
            `/dev/kvm, /dev/net/tun and the capabilities pasta's tap setup uses, and the bidder ` +
            `does not run with those`,
        );
      }

      const deadline = Date.now() + bootTimeoutMs;
      while (Date.now() < deadline) {
        try {
          const raw = await Deno.readTextFile(resultPath);
          const result = parseResult(raw, container, resultPath);
          opts.logger?.info("microvm_booted", {
            name: result.name,
            container,
            guestIp: result.guestIp,
            fingerprint: result.fingerprint,
          });
          return result;
        } catch (err) {
          if (!(err instanceof Deno.errors.NotFound)) throw err;
        }
        const running = await backend.command(["inspect", "-f", "{{.State.Running}}", container]);
        if (running.code === 0 && running.stdout.trim() === "false") {
          throw new Error(
            `the container that boots guest ${spec.name} exited before it reported a guest, so no ` +
              `guest exists. Its output:\n${await containerLogs(container)}`,
          );
        }
        if (running.code !== 0) {
          throw new Error(
            `guest ${spec.name} has no container named ${container} and no result at ${resultPath}, ` +
              `so it neither booted nor reported why: ${running.stderr.trim()}`,
          );
        }
        await new Promise((r) => setTimeout(r, 300));
      }
      throw new Error(
        `guest ${spec.name} had not reported a result ${bootTimeoutMs}ms after its container ` +
          `started. Its output:\n${await containerLogs(container)}`,
      );
    },
    async stop(workDir: string): Promise<void> {
      let container = "";
      try {
        const raw = await Deno.readTextFile(`${workDir}/result.json`);
        container = (JSON.parse(raw) as { name?: string }).name ?? "";
      } catch {
        container = "";
      }
      if (!container) {
        container = workDir.split("/").filter((p) => p !== "").pop() ?? "";
      }
      if (!container) {
        throw new Error(`cannot tell which container holds the guest whose work directory is ${workDir}`);
      }
      await backend.kill(container).catch(() => {});
      await backend.rm(container).catch(() => {});
    },
  };
}
