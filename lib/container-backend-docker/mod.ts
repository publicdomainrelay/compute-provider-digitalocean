import type { CliResult } from "@publicdomainrelay/container-backend-common";
import type { ContainerBackend } from "@publicdomainrelay/container-backend-abc";

function cli(
  args: string[],
  opts?: { inherit?: boolean },
): Promise<CliResult> {
  const cmd = new Deno.Command("docker", {
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
      console.error("docker not running — start docker daemon first");
      return false;
    },
  };
}
