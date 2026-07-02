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

// ── *.localhost DNS resolution for Windows ───────────────────────────────
// macOS/Linux system resolvers treat *.localhost as loopback. Windows does
// not. Deno's fetch() ignores manual Host headers, so we use Deno.connect
// + raw HTTP/1.1 to reach 127.0.0.1 while preserving the Host header for
// dispatcher subdomain routing.

let installedLocalhostDNS = false;

async function rawHttpFetch(
  port: number, host: string, path: string,
  input: string | URL | Request, init?: RequestInit,
): Promise<Response> {
  const u = typeof input === "string" ? new URL(input)
    : input instanceof URL ? input : new URL(input.url);
  const method = init?.method ?? (input instanceof Request ? input.method : "GET");
  const reqHeaders = new Headers(input instanceof Request ? input.headers : init?.headers);
  reqHeaders.set("Host", host);
  const bodyStr = init?.body as string | undefined
    ?? (input instanceof Request ? await input.text().catch(() => "") : "");
  if (bodyStr && !reqHeaders.has("content-type")) reqHeaders.set("content-type", "application/json");
  if (bodyStr && !reqHeaders.has("content-length")) {
    reqHeaders.set("content-length", String(new TextEncoder().encode(bodyStr).length));
  }

  const headerLines = [`${method} ${u.pathname}${u.search} HTTP/1.1`];
  for (const [k, v] of reqHeaders) headerLines.push(`${k}: ${v}`);
  headerLines.push("connection: close");
  const reqStr = headerLines.join("\r\n") + "\r\n\r\n";

  const conn = await Deno.connect({ hostname: "127.0.0.1", port });
  try {
    await conn.write(new TextEncoder().encode(reqStr));
    if (bodyStr) await conn.write(new TextEncoder().encode(bodyStr));
    const chunks: Uint8Array[] = [];
    const readBuf = new Uint8Array(8192);
    while (true) {
      let n: number | null = null;
      try { n = await conn.read(readBuf); } catch { break; }
      if (n === null || n === 0) break;
      chunks.push(readBuf.slice(0, n));
    }
    const rawBytes = chunks.reduce((acc, c) => {
      const t = new Uint8Array(acc.length + c.length);
      t.set(acc); t.set(c, acc.length); return t;
    }, new Uint8Array(0));
    const raw = new TextDecoder().decode(rawBytes);
    const headerEnd = raw.indexOf("\r\n\r\n");
    if (headerEnd < 0) return new Response(raw, { status: 502 });
    const headerSection = raw.slice(0, headerEnd);
    let bodySection = raw.slice(headerEnd + 4);
    const lines = headerSection.split("\r\n");
    const status = parseInt(lines[0].split(" ")[1] || "500");
    const respHeaders = new Headers();
    let isChunked = false;
    for (let i = 1; i < lines.length; i++) {
      const ci = lines[i].indexOf(": ");
      if (ci >= 0) {
        const k = lines[i].slice(0, ci).toLowerCase();
        const v = lines[i].slice(ci + 2);
        respHeaders.set(k, v);
        if (k === "transfer-encoding" && v === "chunked") isChunked = true;
      }
    }
    if (isChunked) {
      let out = "";
      while (bodySection.length > 0) {
        const crlf = bodySection.indexOf("\r\n");
        if (crlf < 0) break;
        const size = parseInt(bodySection.slice(0, crlf), 16);
        if (size === 0) break;
        out += bodySection.slice(crlf + 2, crlf + 2 + size);
        bodySection = bodySection.slice(crlf + 2 + size + 2);
      }
      bodySection = out;
    }
    return new Response(bodySection, { status, headers: respHeaders });
  } finally {
    try { conn.close(); } catch { /* ok */ }
  }
}

function installLocalhostDNS(): void {
  if (installedLocalhostDNS || Deno.build.os !== "windows") return;
  const realFetch = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    let url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    // Match both https:// and http:// — the test interceptor may have already
    // downgraded the scheme before we see it.
    const m = url.match(/^https?:\/\/([^/]+)(\/.*)?$/);
    if (m && (m[1].endsWith(".localhost") || m[1] === "localhost" || m[1].includes(".localhost:"))) {
      const host = m[1];
      const port = host.includes(":") ? parseInt(host.split(":").pop()!) : 443;
      return rawHttpFetch(port, host, m[2] ?? "/", input, init);
    }
    return realFetch(input as string | URL | Request, init);
  }) as typeof fetch;
  installedLocalhostDNS = true;
}

// ── Backend factory ──────────────────────────────────────────────────────

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
      // Windows: *.localhost DNS doesn't resolve. Install fetch interceptor
      // so services discoverable via subdomain.localhost are reachable.
      installLocalhostDNS();

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
