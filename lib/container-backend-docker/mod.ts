import type { CliResult } from "@publicdomainrelay/container-backend-common";
import type { ContainerBackend } from "@publicdomainrelay/container-backend-abc";

function cli(
  args: string[],
  opts?: { inherit?: boolean },
): Promise<CliResult> {
  // On Windows, docker lives inside WSL2. Prepend "wsl docker" automatically.
  const isWindows = Deno.build.os === "windows";
  const binArgs = isWindows ? ["docker", ...args] : args;
  const bin = isWindows ? "wsl" : "docker";

  const cmd = new Deno.Command(bin, {
    args: binArgs,
    stdout: opts?.inherit ? "inherit" : "piped",
    stderr: opts?.inherit ? "inherit" : "piped",
  });
  return cmd.output().then((out) => ({
    code: out.code,
    stdout: opts?.inherit ? "" : new TextDecoder().decode(out.stdout).trim(),
    stderr: opts?.inherit ? "" : new TextDecoder().decode(out.stderr).trim(),
  }));
}

export function createDockerBackend(): ContainerBackend {
  return {
    type: "docker",
    bin: "docker",

    command: cli,

    async inspectIp(containerName: string): Promise<string> {
      const { code, stdout } = await cli([
        "inspect", "--format",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        containerName,
      ]);
      if (code !== 0) throw new Error(`docker inspect failed for ${containerName}`);
      return stdout;
    },

    async inspectGateway(containerName: string): Promise<string> {
      const { code, stdout } = await cli([
        "inspect", "--format",
        "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}",
        containerName,
      ]);
      if (code !== 0) throw new Error(`docker inspect failed for ${containerName}`);
      if (!stdout) throw new Error(`no gateway found in docker inspect for ${containerName}`);
      return stdout;
    },

    async defaultGateway(): Promise<string> {
      const { code, stdout } = await cli([
        "network", "inspect", "bridge", "--format",
        "{{(index .IPAM.Config 0).Gateway}}",
      ]);
      if (code !== 0) throw new Error("docker network inspect failed");
      if (!stdout) throw new Error("no gateway found in docker network inspect");
      return stdout;
    },

    async imageExists(tag: string): Promise<boolean> {
      const { code, stdout } = await cli(["images", "-q", tag]);
      return code === 0 && stdout.length > 0;
    },

    async pullImage(image: string): Promise<void> {
      const { code, stderr } = await cli(["pull", image], { inherit: true });
      if (code !== 0) throw new Error(`docker pull failed for ${image}: ${stderr}`);
    },

    async rm(name: string): Promise<void> {
      await cli(["rm", "-f", name]);
    },

    async kill(name: string): Promise<void> {
      await cli(["kill", name]);
    },

    async exec(containerName: string, args: string[]): Promise<CliResult> {
      return cli(["exec", containerName, ...args]);
    },

    async isRunning(): Promise<boolean> {
      const { code } = await cli(["info"]);
      return code === 0;
    },

    async ensureRunning(): Promise<boolean> {
      if (await this.isRunning()) return true;

      // Try to start the docker daemon
      for (const startCmd of [
        ["sudo", "service", "docker", "start"],
        ["sudo", "systemctl", "start", "docker"],
      ]) {
        const c = new Deno.Command(startCmd[0], {
          args: startCmd.slice(1),
          stdout: "null",
          stderr: "null",
        });
        const { code } = await c.output();
        if (code === 0) {
          // Wait a moment for the daemon to be ready
          for (let i = 0; i < 10; i++) {
            if (await this.isRunning()) return true;
            await new Promise((r) => setTimeout(r, 500));
          }
        }
      }

      console.error("docker not running — could not start daemon");
      return false;
    },
  };
}
