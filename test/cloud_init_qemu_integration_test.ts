import { assertEquals } from "@std/assert";
import { dockerInspectIp, pollSsh } from "@publicdomainrelay/compute-provider-local";

const USER_DATA_PATH = new URL("./cloud-init.yaml", import.meta.url).pathname;
const VM_IMAGE = "atcr.io/johnandersen777.bsky.social/ccripoc-qemu-runner:latest";
const QEMU_SCRIPT = new URL(
  "../../.reference/compute-contract-reference-implementation-poc/src/typescript/qemu/qemu-standalone.ts",
  import.meta.url,
).pathname;
const SSH_TIMEOUT_MS = 600_000;
const CALLBACK_TIMEOUT_MS = 600_000;
const DISTRO = "ubuntu";
const DENO_BIN = "/home/johnandersen777/.deno/bin/deno";

function hostCacheDir(): string {
  const home = Deno.env.get("HOME");
  if (!home) throw new Error("HOME not set");
  return `${home}/.cache/simple-qemu`;
}

function diskImagePath(distro: string): string {
  return `${hostCacheDir()}/liveos-${distro}.img`;
}

async function dockerRun(
  args: string[],
  opts?: { inherit?: boolean },
): Promise<{ code: number; stdout: string; stderr: string }> {
  const cmd = new Deno.Command("docker", {
    args,
    stdout: opts?.inherit ? "inherit" : "piped",
    stderr: opts?.inherit ? "inherit" : "piped",
  });
  const out = await cmd.output();
  return {
    code: out.code,
    stdout: opts?.inherit ? "" : new TextDecoder().decode(out.stdout).trim(),
    stderr: opts?.inherit ? "" : new TextDecoder().decode(out.stderr).trim(),
  };
}

async function imageExists(tag: string): Promise<boolean> {
  const { code, stdout } = await dockerRun(["images", "-q", tag]);
  return code === 0 && stdout.length > 0;
}

async function pullImage(image: string): Promise<void> {
  const { code, stderr } = await dockerRun(["pull", image], { inherit: true });
  if (code !== 0) throw new Error(`docker pull failed for ${image}: ${stderr}`);
}

async function buildDiskImageIfNeeded(distro: string): Promise<void> {
  const imgPath = diskImagePath(distro);
  try {
    await Deno.stat(imgPath);
    console.log(`[test] disk image already cached: ${imgPath}`);
    return;
  } catch { /* not found, build it */ }

  const dir = hostCacheDir();
  await Deno.mkdir(dir, { recursive: true });

  const home = Deno.env.get("HOME")!;
  console.log(`[test] building QEMU disk image for ${distro} on host (sudo, HOME=${home})...`);
  const cmd = new Deno.Command("sudo", {
    args: ["env", `HOME=${home}`, DENO_BIN, "run", "-A", QEMU_SCRIPT, "build", `--distro=${distro}`],
    stdout: "inherit",
    stderr: "inherit",
  });
  const { code } = await cmd.output();
  if (code !== 0) throw new Error(`disk image build failed (exit ${code})`);

  try {
    await Deno.stat(imgPath);
    console.log(`[test] disk image built: ${imgPath}`);
  } catch {
    throw new Error(`disk image not found after build: ${imgPath}`);
  }
}

async function dockerRm(containerName: string): Promise<void> {
  await new Deno.Command("docker", {
    args: ["rm", "-f", containerName],
    stdout: "null",
    stderr: "null",
  }).output().catch(() => {});
}

Deno.test("[integration] QEMU VM boots cloud-init and posts hostname to callback", async () => {
  try {
    Deno.statSync("/dev/kvm");
  } catch {
    console.log("[test] /dev/kvm not available — skipping QEMU test");
    return;
  }

  let resolveCallback: (v: { hostname: string }) => void;
  const received = new Promise<{ hostname: string }>((resolve) => {
    resolveCallback = resolve;
  });

  const ac = new AbortController();

  const server = Deno.serve(
    { port: 0, hostname: "0.0.0.0", signal: ac.signal },
    async (req) => {
      const url = new URL(req.url);
      if (req.method === "POST" && url.pathname === "/cloud-init-done") {
        const body = await req.text();
        const data = JSON.parse(body);
        const hostname: string = data.hostname ?? "";
        console.log(`[test-server] QEMU callback from hostname=${hostname}`);
        resolveCallback({ hostname });
        return new Response("ok");
      }
      return new Response("not found", { status: 404 });
    },
  );

  try {
    const port = server.addr.port;
    console.log(`[test] callback server on port ${port}`);

    let template = await Deno.readTextFile(USER_DATA_PATH);
    template = template.replaceAll("<REPLACE_WITH_TEST_PORT>", String(port));
    const userData = template;

    if (!(await imageExists(VM_IMAGE))) {
      console.log(`[test] pulling VM image: ${VM_IMAGE}`);
      await pullImage(VM_IMAGE);
    } else {
      console.log(`[test] VM image already cached: ${VM_IMAGE}`);
    }

    await buildDiskImageIfNeeded(DISTRO);

    // User-data temp file in user-writable dir
    const udFile = await Deno.makeTempFile({
      prefix: "userdata-",
      suffix: ".yaml",
    });
    await Deno.writeTextFile(udFile, userData);

    // QEMU cache lives in /root (sudo build writes there). Docker daemon
    // runs as root so it can read it directly — no copy needed.
    const qemuCacheDir = "/root/.cache/simple-qemu";

    const containerName = `test-qemu-${crypto.randomUUID().slice(0, 8)}`;

    await dockerRm(containerName);

    console.log(`[test] starting QEMU container: ${containerName}`);
    const { code, stderr } = await dockerRun([
      "run", "-d",
      "--name", containerName,
      "--privileged",
      "--memory", "6g",
      "--memory-swap", "6g",
      "--device", "/dev/kvm",
      "-v", `${qemuCacheDir}:/root/.cache/simple-qemu`,
      "-v", `${udFile}:/tmp/user-data:ro`,
      "-e", "USER_DATA_FILE=/tmp/user-data",
      VM_IMAGE,
      `--distro=${DISTRO}`,
    ]);

    if (code !== 0) {
      await Deno.remove(udFile).catch(() => {});
      throw new Error(`docker run failed (exit ${code}): ${stderr}`);
    }

    try {
      await new Promise((r) => setTimeout(r, 2_000));

      const ip = await dockerInspectIp(containerName);
      console.log(`[test] QEMU container IP: ${ip}`);

      console.log(`[test] waiting for SSH on ${ip}:22 (timeout ${SSH_TIMEOUT_MS}ms)...`);
      const sshReady = await pollSsh(ip, 22, SSH_TIMEOUT_MS);
      if (!sshReady) {
        throw new Error(`SSH not ready within ${SSH_TIMEOUT_MS}ms for ${containerName}`);
      }
      console.log(`[test] SSH ready on ${ip}:22`);

      const timeout = setTimeout(() => {
        resolveCallback({ hostname: "" });
      }, CALLBACK_TIMEOUT_MS);

      const result = await received;
      clearTimeout(timeout);

      assertEquals(
        typeof result.hostname,
        "string",
        "hostname should be a string",
      );
      console.log(`[test] QEMU callback received: hostname=${result.hostname}`);
    } finally {
      await Deno.remove(udFile).catch(() => {});
      await dockerRm(containerName);
    }
  } finally {
    ac.abort();
    await server.finished;
  }
});
