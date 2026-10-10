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
  instanceTimeoutSec?: number;
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
}

export interface Microvm {
  readonly name: string;
  boot(spec: MicrovmSpec): Promise<MicrovmResult>;
  stop(workDir: string): Promise<void>;
}

export interface FirecrackerMicrovmOptions {
  binary: string;
  firecracker: string;
  pasta?: string;
  logger?: { info(event: string, extra?: Record<string, unknown>): void };
}

interface WireSpec {
  name: string;
  image_dir: string;
  work_dir: string;
  firecracker: string;
  pasta?: string;
  user_data_file: string;
  vcpu?: number;
  mem_mib?: number;
  instance_timeout_sec?: number;
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

function toWire(spec: MicrovmSpec, firecracker: string, pasta?: string): WireSpec {
  return {
    name: spec.name,
    image_dir: spec.imageDir,
    work_dir: spec.workDir,
    firecracker,
    pasta,
    user_data_file: spec.userDataFile,
    vcpu: spec.vcpu,
    mem_mib: spec.memMib,
    instance_timeout_sec: spec.instanceTimeoutSec,
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

function parseResult(lines: string[], binary: string, code: number, stderr: string): MicrovmResult {
  const json = [...lines].reverse().find((line) => line.trimStart().startsWith("{"));
  if (json === undefined) {
    throw new Error(
      `${binary} -spec exited ${code} without a JSON result on any line of its output. The guest's ` +
        `own console goes to a file next to it rather than here, so this is the launcher refusing ` +
        `or dying before a guest existed: ${stderr.trim()}`,
    );
  }
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(json) as Record<string, unknown>;
  } catch (cause) {
    throw new Error(`${binary} -spec printed a line that is not JSON: ${json}`, { cause });
  }
  for (const field of ["name", "guest_ip", "socket", "console", "work_dir"]) {
    if (typeof parsed[field] !== "string" || parsed[field] === "") {
      throw new Error(`${binary} -spec printed a result with no ${field}: ${json}`);
    }
  }
  for (const field of ["vmm_pid", "pasta_pid"]) {
    if (typeof parsed[field] !== "number" || parsed[field] <= 0) {
      throw new Error(
        `${binary} -spec printed ${field} as ${String(parsed[field])}, and a pid that is not a ` +
          `positive number names no process: the guest behind it could never be stopped or ` +
          `inspected. Result: ${json}`,
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
  };
}

export function createFirecrackerMicrovm(opts: FirecrackerMicrovmOptions): Microvm {
  if (!opts.binary) {
    throw new Error(
      "createFirecrackerMicrovm needs the path of the socialweb-nodeboot binary. There is no " +
        "default: the guest is booted from an image on this host by a VMM on this host, and a " +
        "guessed path is a boot that does nothing.",
    );
  }
  if (!opts.firecracker) {
    throw new Error(
      "createFirecrackerMicrovm needs the path of the firecracker binary. It is not on PATH on " +
        "every host that builds the image -- on the reference host it lives under the image " +
        "directory's artifacts -- so it is configuration rather than a lookup.",
    );
  }
  const binary = opts.binary;

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
      const specPath = `${spec.workDir}/boot-spec.json`;
      await Deno.mkdir(spec.workDir, { recursive: true });
      await Deno.writeTextFile(specPath, JSON.stringify(toWire(spec, opts.firecracker, opts.pasta), null, 2));
      const command = new Deno.Command(binary, {
        args: ["-spec", specPath],
        stdout: "piped",
        stderr: "piped",
      });
      const { code, stdout, stderr } = await command.output();
      const lines = new TextDecoder().decode(stdout).split("\n").filter((l) => l.trim() !== "");
      const parsed = parseResult(lines, binary, code, new TextDecoder().decode(stderr));
      opts.logger?.info("microvm_booted", {
        name: parsed.name,
        vmmPid: parsed.vmmPid,
        pastaPid: parsed.pastaPid,
        guestIp: parsed.guestIp,
        fingerprint: parsed.fingerprint,
      });
      return parsed;
    },
    async stop(workDir: string): Promise<void> {
      const command = new Deno.Command(binary, {
        args: ["-stop", "-work-dir", workDir],
        stdout: "piped",
        stderr: "piped",
      });
      const { code, stderr } = await command.output();
      if (code !== 0) {
        throw new Error(
          `${binary} -stop -work-dir ${workDir} exited ${code}: ${new TextDecoder().decode(stderr).trim()}`,
        );
      }
    },
  };
}
