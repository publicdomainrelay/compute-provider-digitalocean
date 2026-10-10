import { assert, assertEquals, assertThrows } from "@std/assert";
import {
  addressTheRequesterNamed,
  guestMacFor,
  networkFor,
  parseMemMiB,
} from "@publicdomainrelay/compute-provider-firecracker";

// The guest's address is not configured by cloud-init. The firecracker base
// image ships fcnet-setup.sh, taken from firecracker's own integration tests,
// which reads each NIC's MAC, takes the last four hex groups and turns them
// into a dotted quad. That makes the MAC the only thing that decides the
// guest's address, so these tests reimplement that script and hold the
// provider to agreeing with it. A disagreement is a guest that comes up at an
// address the host did not route to it, which reads as a tunnel that never
// appears rather than as an addressing bug.

function fcnetAddressFromMac(mac: string): string {
  const m = /(?<=06:00:)([0-9a-f]{2}:?){4}/.exec(mac);
  if (m === null) throw new Error(`fcnet-setup.sh would not match ${mac}`);
  const octets = m[0].replace(/:$/, "").split(":").map((hex) => parseInt(hex, 16));
  return octets.join(".");
}

Deno.test("the MAC a guest is given makes fcnet-setup.sh configure the address the host routed to it", () => {
  for (let index = 0; index < 400; index++) {
    const network = networkFor("172.30.0.0", index);
    assertEquals(
      fcnetAddressFromMac(network.guestMac),
      network.guestIp,
      `block ${index}: the guest would configure ${fcnetAddressFromMac(network.guestMac)} from its ` +
        `MAC ${network.guestMac}, and the host placed it at ${network.guestIp}`,
    );
  }
});

Deno.test("every guest gets a distinct /30 with the gateway and pasta's address outside the guest's own", () => {
  const seen = new Set<string>();
  for (let index = 0; index < 200; index++) {
    const n = networkFor("172.30.0.0", index);
    assertEquals(n.prefix, 30);
    assert(!seen.has(n.guestIp), `block ${index} reuses ${n.guestIp}`);
    seen.add(n.guestIp);
    const base = n.guestIp.split(".").map(Number);
    assertEquals(n.gateway, `${base[0]}.${base[1]}.${base[2]}.${base[3] - 1}`);
    assertEquals(n.pastaIp, `${base[0]}.${base[1]}.${base[2]}.${base[3] - 2}`);
    assert(n.guestIp !== n.gateway, "a guest addressed as its own gateway ARPs for itself");
    assert(n.pastaIp !== n.gateway, "pasta discards an ARP for the address it holds itself");
  }
});

Deno.test("the 16384 blocks a range based at 172.30.0.0 holds are the whole pool, and the pool is exhausted rather than wrapped", () => {
  const last = networkFor("172.30.0.0", 16383);
  assertEquals(last.guestIp.split(".")[2], "255");
  assertThrows(
    () => networkFor("172.30.0.0", 16384),
    Error,
    "outside the 16384 /30 blocks",
  );
});

Deno.test("a MAC is derived only from an IPv4 address", () => {
  assertThrows(() => guestMacFor("172.30.0"), Error, "is not an IPv4 address");
  assertThrows(() => guestMacFor("2001:db8::1"), Error, "is not an IPv4 address");
  assertThrows(() => guestMacFor("172.30.0.256"), Error, "is not an IPv4 address");
});

Deno.test("a host address the requester already named is the one the guest is given", () => {
  const named = [
    "#cloud-config",
    "bootcmd:",
    "  - - sh",
    "    - -c",
    "    - grep -qxF '192.168.0.20 relay.localhost' /etc/hosts || echo '192.168.0.20 relay.localhost' >> /etc/hosts",
  ].join("\n");
  // The requester's line is in the document the guest boots with, and cloud-init
  // resolves a name before the provider's own runcmd can append a line for it, so
  // the provider has to agree with it rather than write a second, later, losing one.
  assertEquals(addressTheRequesterNamed(named), "192.168.0.20");
});

Deno.test("a requester that named no host address leaves the provider to choose one", () => {
  const unnamed = ["#cloud-config", "write_files:", "  - path: /etc/motd", "    content: hello"].join("\n");
  assertEquals(addressTheRequesterNamed(unnamed), undefined);
});

Deno.test("the memory an RFP asks for is read in the units the lexicon writes it in", () => {
  assertEquals(parseMemMiB("4G"), 4096);
  assertEquals(parseMemMiB("512M"), 512);
  assertEquals(parseMemMiB("512MiB"), 512);
  assertEquals(parseMemMiB("2GiB"), 2048);
  assertEquals(parseMemMiB("1T"), 1024 * 1024);
  assertEquals(parseMemMiB("1024"), 1024);
  assertEquals(parseMemMiB(2048), undefined);
  assertEquals(parseMemMiB("lots"), undefined);
});
