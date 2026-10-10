import type {
  EnsureOptions,
  NodeImageState,
  NodeImageStatus,
  NodeImageStore,
} from "@publicdomainrelay/node-image-abc";

export interface FirecrackerNodeImageOptions {
  binary: string;
  configPath: string;
  preinstallPath?: string;
  repoDir?: string;
  logger?: { info(event: string, extra?: Record<string, unknown>): void };
  onBuildLine?: (line: string) => void;
}

const STATES: NodeImageState[] = ["present", "built", "reused"];

function parseStatus(lines: string[], binary: string, code: number, stderr: string): NodeImageStatus {
  const reversed = [...lines].reverse();
  const json = reversed.find((line) => line.trimStart().startsWith("{"));
  if (json === undefined) {
    throw new Error(
      `${binary} -ensure -json exited ${code} without a JSON object on any line of its output. ` +
        `The builder reports each artifact as it is written and prints the object last, so a run ` +
        `whose last object is absent ended before it could say what it did: ${stderr.trim()}`,
    );
  }
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(json) as Record<string, unknown>;
  } catch (cause) {
    throw new Error(`${binary} -ensure -json printed a line that is not JSON: ${json}`, { cause });
  }
  for (const field of ["state", "fingerprint", "dir", "config"]) {
    if (typeof parsed[field] !== "string" || parsed[field] === "") {
      throw new Error(`${binary} -ensure -json printed an object with no ${field}: ${json}`);
    }
  }
  const state = parsed.state as NodeImageState;
  if (!STATES.includes(state)) {
    throw new Error(
      `${binary} -ensure -json printed the state ${String(parsed.state)}, which names nothing this ` +
        `knows how to read an image from. The states that exist are ${STATES.join(", ")}.`,
    );
  }
  if (state !== "present" && state !== "reused" && code !== 0) {
    throw new Error(`${binary} -ensure reported ${state} and exited ${code}: ${stderr.trim()}`);
  }
  return {
    state,
    fingerprint: parsed.fingerprint as string,
    dir: parsed.dir as string,
    config: parsed.config as string,
    reusedFrom: typeof parsed.reusedFrom === "string" ? parsed.reusedFrom : undefined,
    kernel: typeof parsed.kernel === "string" ? parsed.kernel : undefined,
    initramfs: typeof parsed.initramfs === "string" ? parsed.initramfs : undefined,
    rootfs: typeof parsed.rootfs === "string" ? parsed.rootfs : undefined,
  };
}

export function createFirecrackerNodeImage(opts: FirecrackerNodeImageOptions): NodeImageStore {
  if (!opts.binary) {
    throw new Error(
      "createFirecrackerNodeImage needs the path of the socialweb-nodeimage binary. There is no " +
        "default that would be right on another host: the image is built from that host's own " +
        "kernel and module tree, so a guessed path is a build that reads the wrong inputs.",
    );
  }
  if (!opts.configPath) {
    throw new Error(
      "createFirecrackerNodeImage needs the path of the image builder's configuration. The image " +
        "is named by the inputs that configuration reads, and the name is never taken from a setting.",
    );
  }

  const binary = opts.binary;
  const configPath = opts.configPath;

  async function run(reuseStale: boolean): Promise<NodeImageStatus> {
    const args = ["-ensure", "-json"];
    if (reuseStale) args.push("-reuse-stale");
    if (opts.preinstallPath) args.push("-preinstall", opts.preinstallPath);
    args.push("-config", configPath);
    const command = new Deno.Command(binary, {
      args,
      cwd: opts.repoDir,
      stdout: "piped",
      stderr: "piped",
    });
    const { code, stdout, stderr } = await command.output();
    const text = new TextDecoder().decode(stdout);
    const lines = text.split("\n").filter((line) => line.trim() !== "");
    for (const line of lines) {
      if (!line.trimStart().startsWith("{")) opts.onBuildLine?.(line);
    }
    return parseStatus(lines, binary, code, new TextDecoder().decode(stderr));
  }

  return {
    name: "firecracker",
    async ensure(o?: EnsureOptions): Promise<NodeImageStatus> {
      const reuseStale = o?.reuseStale ?? false;
      const status = await run(reuseStale);
      opts.logger?.info("node_image_status", {
        state: status.state,
        fingerprint: status.fingerprint,
        dir: status.dir,
        reuseStale,
        reusedFrom: status.reusedFrom,
      });
      return status;
    },
  };
}
