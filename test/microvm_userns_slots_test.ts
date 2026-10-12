import { assertEquals, assertThrows } from "@std/assert";
import { parseSubid, slotFor } from "@publicdomainrelay/microvm-firecracker-userns";

const SUBID = "alice:589824:65536\nswc-bidder:1048576:16777216\n";

Deno.test("parseSubid reads the account's range and refuses an account without one", () => {
  assertEquals(parseSubid(SUBID, "swc-bidder"), { base: 1048576, count: 16777216 });
  assertThrows(() => parseSubid(SUBID, "nobody-here"), Error, "/etc/subuid");
});

Deno.test("two slots map disjoint ranges and the VMM uid sits inside its own slot", () => {
  const r = parseSubid(SUBID, "swc-bidder");
  const a = slotFor(r, r, 65536, 1000, 0);
  const b = slotFor(r, r, 65536, 1000, 1);
  assertEquals(a.vmmUid, 1048576 + 1000);
  assertEquals(b.uid, a.uid + 65536);
  assertEquals(b.uid >= a.uid + 65536, true);
  assertThrows(() => slotFor(r, r, 65536, 1000, 256), Error, "outside");
  assertThrows(() => slotFor(r, r, 65536, 70000, 0), Error, "inner id");
});
