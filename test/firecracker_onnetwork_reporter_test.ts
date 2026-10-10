import { assert, assertEquals, assertStringIncludes } from "@std/assert";
import {
  onNetworkTargets,
  onNetworkUrlFromBundle,
  withOnNetworkBaseUrl,
  withOnNetworkReporter,
} from "@publicdomainrelay/compute-provider-firecracker";

const ACCEPT_PATH = "/root/secrets/publicdomainrelay.com/market/accept.json";

function guestUserData(onNetworkUrl?: string): string {
  const bundle = JSON.stringify(
    {
      accept: { uri: "at://did:plc:x/com.publicdomainrelay.temp.market.accept/1", cid: "bafya" },
      ...(onNetworkUrl ? { guest_onnetwork_url: onNetworkUrl } : {}),
    },
    null,
    2,
  );
  return [
    "#cloud-config",
    "write_files:",
    `  - path: ${ACCEPT_PATH}`,
    "    content: |-",
    ...bundle.split("\n").map((line) => `      ${line}`),
    "bootcmd:",
    "  - - sh",
    "    - -c",
    "    - grep -qxF '192.168.0.20 relay.localhost' /etc/hosts || echo '192.168.0.20 relay.localhost' >> /etc/hosts",
    "runcmd:",
    "  - - sh",
    "    - -c",
    "    - echo base",
    "",
  ].join("\n");
}

Deno.test("the bundle's guest_onnetwork_url is what the guest reports to", () => {
  const userData = guestUserData("http://did-key-abc.relay.localhost:42855/v1/on-network");
  assertEquals(
    onNetworkUrlFromBundle(userData, "https://did-key-prov.relay.localhost"),
    "http://did-key-abc.relay.localhost:42855/v1/on-network",
  );
});

Deno.test("a bundle without the URL falls back to this provider's own endpoint", () => {
  assertEquals(
    onNetworkUrlFromBundle(guestUserData(), "https://did-key-prov.relay.localhost/"),
    "https://did-key-prov.relay.localhost/v1/on-network",
  );
});

Deno.test("a relay name behind a dispatcher is also tried at the address the guest reaches it on", () => {
  const userData = guestUserData("http://did-key-abc.relay.localhost:42855/v1/on-network");
  assertEquals(onNetworkTargets(userData, "https://did-key-prov.relay.localhost"), [
    { url: "http://did-key-abc.relay.localhost:42855/v1/on-network" },
    {
      url: "http://did-key-abc.relay.localhost:42855/v1/on-network",
      resolve: "did-key-abc.relay.localhost:42855:192.168.0.20",
    },
  ]);
});

Deno.test("a public relay URL needs no second target", () => {
  const userData = guestUserData("https://did-key-abc.xrpc.fedproxy.com/v1/on-network");
  assertEquals(onNetworkTargets(userData, "https://did-key-prov.xrpc.fedproxy.com"), [
    { url: "https://did-key-abc.xrpc.fedproxy.com/v1/on-network" },
  ]);
});

Deno.test("the reporter is composed into user_data as a unit and script, not into the image", () => {
  const out = withOnNetworkReporter(guestUserData("http://did-key-abc.relay.localhost:42855/v1/on-network"), "https://x");
  assertStringIncludes(out, "/usr/local/bin/send-onnetwork.sh");
  assertStringIncludes(out, "/etc/systemd/system/guest-onnetwork.service");
  assertStringIncludes(out, "/run/guest-fqdn");
  assertStringIncludes(out, `jq -r '.accept.uri // empty'`);
  assertStringIncludes(out, "systemctl start --no-block guest-onnetwork.service");
  assert(!out.includes("packages:\n  - curl"), "the node image already carries curl and jq");
});

Deno.test("user_data that already reports the FQDN is left alone", () => {
  const withReporter = withOnNetworkReporter(guestUserData("http://did-key-abc.relay.localhost:42855/v1/on-network"), "https://x");
  assertEquals(withOnNetworkReporter(withReporter, "https://x"), withReporter);
});

Deno.test("the composed report script is a script bash accepts", async () => {
  const out = withOnNetworkReporter(
    guestUserData("http://did-key-abc.relay.localhost:42855/v1/on-network"),
    "https://did-key-prov.relay.localhost",
  );
  const lines = out.split("\n");
  const start = lines.findIndex((l) => l.includes("path: /usr/local/bin/send-onnetwork.sh"));
  assert(start > 0, "the report script is not in the user_data");
  const script: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (line.startsWith("  - path: ")) break;
    script.push(line.startsWith("      ") ? line.slice(6) : line);
  }
  const dir = await Deno.makeTempDir();
  const path = `${dir}/send-onnetwork.sh`;
  try {
    await Deno.writeTextFile(path, script.join("\n"));
    const { code, stderr } = await new Deno.Command("bash", {
      args: ["-n", path],
      stderr: "piped",
    }).output();
    assertEquals(code, 0, `bash rejected the report script: ${new TextDecoder().decode(stderr)}`);
  } finally {
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
});

Deno.test("the guest is told where to report, without an OIDC exchange having to succeed", () => {
  // The reporter the enricher composes reads its URL out of base_url, and the
  // only writer of that file is the provisioning-token script, which writes it
  // only when its token exchange succeeds. A provider with no issuer therefore
  // leaves the guest falling back to the public dispatcher, whose /v1/on-network
  // is a 404 - the service fails and the requester waits out its timeout.
  const url = "https://did-key-abc.xrpc.fedproxy.com/v1/on-network";
  const composed = withOnNetworkBaseUrl(guestUserData(url), "https://issuer.example");
  assertStringIncludes(composed, "/root/secrets/digitalocean.com/serviceaccount/base_url");
  // The script appends /v1/on-network, so the file holds the origin and no path.
  assertStringIncludes(composed, "https://did-key-abc.xrpc.fedproxy.com");
  assertEquals(composed.includes("https://did-key-abc.xrpc.fedproxy.com/v1/on-network\n"), false);
});

Deno.test("a guest that already names base_url is left alone", () => {
  const already = `${guestUserData()}\n  - path: /root/secrets/digitalocean.com/serviceaccount/base_url\n    content: "https://mine.example\n"\n`;
  assertEquals(withOnNetworkBaseUrl(already, "https://issuer.example"), already);
});
