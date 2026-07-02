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

    // Header section is ASCII; find the \r\n\r\n separator on raw bytes so a
    // multi-byte UTF-8 body never gets sliced mid-codepoint below.
    const CRLFCRLF = new Uint8Array([13, 10, 13, 10]);
    let headerEnd = -1;
    for (let i = 0; i + 4 <= rawBytes.length; i++) {
      if (
        rawBytes[i] === CRLFCRLF[0] && rawBytes[i + 1] === CRLFCRLF[1] &&
        rawBytes[i + 2] === CRLFCRLF[2] && rawBytes[i + 3] === CRLFCRLF[3]
      ) { headerEnd = i; break; }
    }
    if (headerEnd < 0) return new Response(new TextDecoder().decode(rawBytes), { status: 502 });

    const headerSection = new TextDecoder("ascii").decode(rawBytes.slice(0, headerEnd));
    let bodyBytes = rawBytes.slice(headerEnd + 4);
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
      const out: number[] = [];
      let offset = 0;
      while (offset < bodyBytes.length) {
        let crlf = -1;
        for (let i = offset; i + 2 <= bodyBytes.length; i++) {
          if (bodyBytes[i] === 13 && bodyBytes[i + 1] === 10) { crlf = i; break; }
        }
        if (crlf < 0) break;
        const sizeLine = new TextDecoder("ascii").decode(bodyBytes.slice(offset, crlf));
        const size = parseInt(sizeLine, 16);
        if (!size) break;
        const chunkStart = crlf + 2;
        for (let i = chunkStart; i < chunkStart + size; i++) out.push(bodyBytes[i]);
        offset = chunkStart + size + 2;
      }
      bodyBytes = new Uint8Array(out);
    }
    return new Response(bodyBytes, { status, headers: respHeaders });
  } finally {
    try { conn.close(); } catch { /* ok */ }
  }
}

function isLocalhostSubdomainWithPort(host: string): boolean {
  if (!host.includes(":")) return false;
  const hostname = host.slice(0, host.lastIndexOf(":"));
  return hostname === "localhost" || hostname.endsWith(".localhost");
}

function installLocalhostDNS(): void {
  if (installedLocalhostDNS || Deno.build.os !== "windows") return;
  const realFetch = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    let url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    // Match both https:// and http:// — the test interceptor may have already
    // downgraded the scheme before we see it.
    const m = url.match(/^https?:\/\/([^/]+)(\/.*)?$/);
    if (m && isLocalhostSubdomainWithPort(m[1])) {
      const host = m[1];
      const port = parseInt(host.split(":").pop()!);
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

      // Try to start the docker daemon. On Windows this must run inside
      // WSL2 (same as cli()) — a bare "sudo" binary does not exist on the
      // host and Deno.Command would reject with NotFound.
      const isWindows = Deno.build.os === "windows";
      for (const startCmd of [
        ["sudo", "service", "docker", "start"],
        ["sudo", "systemctl", "start", "docker"],
      ]) {
        const bin = isWindows ? "wsl" : startCmd[0];
        const binArgs = isWindows ? startCmd : startCmd.slice(1);
        try {
          const c = new Deno.Command(bin, {
            args: binArgs,
            stdout: "null",
            stderr: "null",
          });
          const { code } = await c.output();
          if (code === 0) {
            for (let i = 0; i < 10; i++) {
              if (await this.isRunning()) return true;
              await new Promise((r) => setTimeout(r, 500));
            }
          }
        } catch (err) {
          console.error(`docker start command failed: ${bin} ${binArgs.join(" ")}: ${err}`);
        }
      }

      console.error("docker not running — could not start daemon");
      return false;
    },
  };
}
