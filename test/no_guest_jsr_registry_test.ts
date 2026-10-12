import { assert, assertEquals, assertStringIncludes } from "@std/assert";
import { withOnNetworkReporter } from "@publicdomainrelay/compute-provider-common";

const ROOT = new URL("../", import.meta.url).pathname;
const SCANNED = ["lib", "hono-compute-provider", "hono-firecracker-standalone", "deno.json"];
const SCANNED_EXTENSIONS = [".ts", ".json", ".sh", ".yaml", ".yml", "Dockerfile"];
const FORBIDDEN: RegExp[] = [
  /JSR_URL/,
  /injectJsrUrl/,
  /jsrBaseDir|jsrPort|jsrRegistry/,
  /createPackageRegistryFactory/,
  /hono-factory-package-registry/,
  /package-store-local-fs/,
  /tunnel-subscriber/,
  /websocat/i,
  /wootty/i,
  /fedproxy-client/,
];

async function scannedFiles(): Promise<string[]> {
  const files: string[] = [];
  const stack = SCANNED.map((top) => `${ROOT}${top}`);
  while (stack.length) {
    const path = stack.pop()!;
    const stat = await Deno.stat(path);
    if (stat.isFile) {
      files.push(path);
      continue;
    }
    for await (const entry of Deno.readDir(path)) {
      const child = `${path}/${entry.name}`;
      if (entry.isDirectory) stack.push(child);
      else if (SCANNED_EXTENSIONS.some((ext) => entry.name.endsWith(ext))) files.push(child);
    }
  }
  return files;
}

function guestUserData(): string {
  const bundle = JSON.stringify({
    accept: { uri: "at://did:plc:x/com.publicdomainrelay.temp.market.accept/1", cid: "bafya" },
    guest_onnetwork_url: "http://did-key-abc.relay.localhost:42855/v1/on-network",
  });
  return [
    "#cloud-config",
    "write_files:",
    "  - path: /root/secrets/publicdomainrelay.com/market/accept.json",
    `    content: '${bundle}'`,
    "",
  ].join("\n");
}

Deno.test("no guest JSR registry is served and no user_data names JSR_URL", async () => {
  const offenders: string[] = [];
  for (const path of await scannedFiles()) {
    const text = await Deno.readTextFile(path);
    for (const re of FORBIDDEN) if (re.test(text)) offenders.push(`${path.slice(ROOT.length)} ${re}`);
  }
  assertEquals(offenders, []);
});

Deno.test("the guest's on-network reporter waits on the iroh listener, never a tunnel subscriber", () => {
  const out = withOnNetworkReporter(guestUserData(), "https://x");
  assertStringIncludes(out, "After=network-online.target iroh.service");
  assertStringIncludes(out, "Wants=network-online.target iroh.service");
  assert(!out.includes("tunnel"), "the reporter names no tunnel unit");
  assert(!out.includes("JSR_URL"), "user_data names no guest package registry");
});
