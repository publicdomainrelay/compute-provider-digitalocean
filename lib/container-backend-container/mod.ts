import type { CliResult } from "@publicdomainrelay/container-backend-common";
import type { ContainerBackend } from "@publicdomainrelay/container-backend-abc";

function cli(
  args: string[],
  opts?: { inherit?: boolean },
): Promise<CliResult> {
  const cmd = new Deno.Command("container", {
    args,
    stdout: opts?.inherit ? "inherit" : "piped",
    stderr: opts?.inherit ? "inherit" : "piped",
  });
  return cmd.output().then((out) => ({
    code: out.code,
    stdout: opts?.inherit ? "" : new TextDecoder().decode(out.stdout).trim(),
    stderr: opts?.inherit ? "" : new TextDecoder().decode(out.stderr).trim(),
  }));
}

export function createContainerBackend(): ContainerBackend {
  return {
    type: "container",
    bin: "container",

    command: cli,

    async inspectIp(containerName: string): Promise<string> {
      const { code, stdout } = await cli(["inspect", containerName]);
      if (code !== 0) throw new Error(`container inspect failed for ${containerName}`);
      const info = JSON.parse(stdout);
      const addr = info?.[0]?.status?.networks?.[0]?.ipv4Address;
      if (!addr) throw new Error(`no IP found in container inspect for ${containerName}`);
      return addr.split("/")[0];
    },

    async inspectGateway(containerName: string): Promise<string> {
      const { code, stdout } = await cli(["inspect", containerName]);
      if (code !== 0) throw new Error(`container inspect failed for ${containerName}`);
      const info = JSON.parse(stdout);
      const gw = info?.[0]?.status?.networks?.[0]?.ipv4Gateway;
      if (!gw) throw new Error(`no gateway found in container inspect for ${containerName}`);
      return gw;
    },

    async defaultGateway(): Promise<string> {
      const { code, stdout } = await cli(["network", "inspect", "default"]);
      if (code !== 0) throw new Error("container network inspect failed");
      const info = JSON.parse(stdout);
      const gw = info?.[0]?.status?.ipv4Gateway;
      if (!gw) throw new Error("no gateway found in container network inspect");
      return gw;
    },

    async imageExists(tag: string): Promise<boolean> {
      const { code } = await cli(["image", "inspect", tag]);
      return code === 0;
    },

    async pullImage(image: string): Promise<void> {
      const { code, stderr } = await cli(["image", "pull", image], { inherit: true });
      if (code !== 0) throw new Error(`container image pull failed for ${image}: ${stderr}`);
    },

    async rm(name: string): Promise<void> {
      await cli(["delete", "--force", name]);
    },

    async kill(name: string): Promise<void> {
      await cli(["kill", name]);
    },

    async exec(containerName: string, args: string[]): Promise<CliResult> {
      return cli(["exec", containerName, ...args]);
    },

    async isRunning(): Promise<boolean> {
      const { code, stdout } = await cli(["system", "status"]);
      if (code !== 0) return false;
      return stdout.includes("running") || stdout.includes("apiserver");
    },

    async ensureRunning(): Promise<boolean> {
      if (await this.isRunning()) return true;
      console.log("==> container system not running — starting...");
      const { code, stderr } = await new Deno.Command("container", {
        args: ["system", "start", "--enable-kernel-install", "--timeout", "60"],
        stdout: "inherit",
        stderr: "inherit",
      }).output();
      if (code !== 0) {
        console.error(`container system start failed (exit ${code}): ${new TextDecoder().decode(stderr)}`);
        return false;
      }
      for (let i = 0; i < 20; i++) {
        if (await this.isRunning()) {
          console.log("==> container system ready");
          return true;
        }
        await new Promise((r) => setTimeout(r, 500));
      }
      console.error("container system start timed out waiting for apiserver");
      return false;
    },

    logStream(containerName: string): ReadableStream<string> {
      return new ReadableStream({
        start: async (controller) => {
          const child = new Deno.Command("container", {
            args: ["logs", "-f", containerName],
            stdout: "piped",
          }).spawn();
          const reader = child.stdout.getReader();
          const decoder = new TextDecoder();
          let leftover = "";
          try {
            while (true) {
              const { value, done } = await reader.read();
              if (done) break;
              leftover += decoder.decode(value, { stream: true });
              const lines = leftover.split("\n");
              leftover = lines.pop() ?? "";
              for (const line of lines) {
                if (line.trim()) controller.enqueue(line);
              }
            }
          } finally {
            controller.close();
            try { child.kill("SIGTERM"); } catch { /* already exited */ }
          }
        },
      });
    },
  };
}
