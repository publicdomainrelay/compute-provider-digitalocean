import type { Distro, DistroConfig } from "@publicdomainrelay/qemu-standalone";
import { buildImage, runVM } from "@publicdomainrelay/qemu-standalone";
import { Command } from "@publicdomainrelay/cli-args-env";
import cliArgsEnv from "./cli-args-env.json" with { type: "json" };

const subcommand = Deno.args.find((a) => a === "build" || a === "run");
if (!subcommand) {
  console.error("Usage: qemu-standalone build|run [--distro=fedora|ubuntu]");
  console.error("  build  Create SquashFS LiveOS disk image");
  console.error("  run    Start QEMU VM (reads cloud-init user-data from stdin or USER_DATA_FILE)");
  Deno.exit(1);
}

const rest = Deno.args.filter((a) => a !== subcommand);
const { options } = await new Command(
  "CONFIG_PATH_HONO_QEMU_STANDALONE",
  cliArgsEnv,
  null,
  rest,
).resolve();

const distro = options.distro as Distro;
if (distro !== "fedora" && distro !== "ubuntu") {
  console.error(`Unknown distro: ${distro}. Use fedora or ubuntu.`);
  Deno.exit(1);
}

if (subcommand === "build") {
  await buildImage(distro);
} else {
  let userData = "";
  const filePath = Deno.env.get("USER_DATA_FILE");
  if (filePath) {
    try {
      userData = await Deno.readTextFile(filePath);
    } catch {
      console.error(`Error reading user-data from ${filePath}`);
    }
  }
  if (!userData) {
    userData = await readStdin();
  }
  await runVM(distro, userData);
}

async function readStdin(): Promise<string> {
  let result = "";
  if (!Deno.stdin.isTerminal()) {
    const decoder = new TextDecoder();
    for await (const chunk of Deno.stdin.readable) {
      result += decoder.decode(chunk);
    }
  }
  return result;
}
