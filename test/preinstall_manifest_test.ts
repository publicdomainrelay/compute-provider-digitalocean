import { assert, assertEquals, assertThrows } from "@std/assert";
import { preinstallManifest, shellCommandLine } from "@publicdomainrelay/compute-provider-firecracker";
import {
  acceptBundleModule,
  getUserDataModules,
  registerUserDataModule,
} from "@publicdomainrelay/cloud-init-common";

const CTX = {
  vmName: "test-vm",
  ingressProxyHost: "relay.example:8443",
  audHost: "relay.example",
  sshAuthorizedKey: "ssh-ed25519 AAAA the requester",
};

registerUserDataModule("test-static", () => ({
  packages: ["a-static-package"],
  write_files: [
    { path: "/etc/the-file", owner: "root:root", permissions: "0600", content: "first\n" },
  ],
  runcmdPrepend: [["sh", "-c", "install -d -m 0700 /etc/the-dir"]],
}));

registerUserDataModule("test-also-writes-the-file", () => ({
  write_files: [
    { path: "/etc/the-file", owner: "root:root", permissions: "0644", content: "second\n" },
  ],
}));

registerUserDataModule("test-per-guest-package", (ctx) => ({
  packages: ctx.vmName === undefined ? [] : ["only-when-named"],
}));

registerUserDataModule("test-owned-elsewhere", () => ({
  write_files: [{ path: "/home/ubuntu/x", owner: "ubuntu", content: "x\n" }],
}));

registerUserDataModule("test-apt-sources", () => ({
  apt: { sources: { extra: { source: "deb http://example/x ./" } } },
  packages: ["x"],
}));

registerUserDataModule("test-odd-prepend", () => ({
  runcmdPrepend: [{ not: "a command" }],
}));

Deno.test("a file is baked when the guest cannot tell which guest it is", () => {
  const modules = ["tunnel", "secrets"];
  const manifest = preinstallManifest({ modules, ctx: CTX });

  assert(
    manifest.packages.includes("jq") && manifest.packages.includes("curl"),
    `the secrets module installs jq and curl at boot, and the manifest that is meant to make that ` +
      `step unnecessary does not carry them: ${JSON.stringify(manifest.packages)}`,
  );
  assert(
    manifest.packages.includes("openssh-server"),
    `the tunnel module installs openssh-server at boot: ${JSON.stringify(manifest.packages)}`,
  );

  const under = (ctx: Partial<typeof CTX>) =>
    getUserDataModules(modules).flatMap((m) => m(ctx).write_files ?? []);
  const asOneGuestSeesIt = new Map(
    under({}).map((f) => [f.path, `${f.permissions ?? ""}\n${f.content}`]),
  );
  const written = under(CTX);
  assert(written.length > 0, "these modules write nothing, so this test asserts nothing");

  for (const source of written) {
    const identical = asOneGuestSeesIt.get(source.path) ===
      `${source.permissions ?? ""}\n${source.content}`;
    const baked = manifest.files.find((f) => f.path === source.path);
    const left = manifest.leftToBoot.files.includes(source.path);
    assert(
      !(baked !== undefined && left),
      `${source.path} is carried as baked and as left to boot at once, so which of the two the ` +
        `image gets is decided by something other than the derivation`,
    );
    if (identical) {
      assertEquals(
        baked?.content,
        source.content,
        `${source.path} is written the same way whatever the guest is, and the manifest does not ` +
          `carry it, so the guest installs at boot what the image was supposed to have baked`,
      );
    } else {
      assert(
        baked === undefined,
        `${source.path} is written differently for one guest than for another -- a guest's own ` +
          `identity is inside it -- and it was baked into an image every guest boots`,
      );
    }
  }
});

Deno.test("the requester's key is left to boot rather than baked into every guest's image", () => {
  const manifest = preinstallManifest({ modules: ["tunnel"], ctx: CTX });
  assert(
    manifest.leftToBoot.files.includes("/root/.ssh/authorized_keys"),
    `the tunnel module writes the requesting party's public key into /root/.ssh/authorized_keys, ` +
      `and the derivation baked it: the image is built once and booted by every guest, so that key ` +
      `would be one contract's key inside every later guest. Left to boot were: ` +
      `${JSON.stringify(manifest.leftToBoot.files)}`,
  );
  assert(
    !manifest.files.some((f) => f.path === "/root/.ssh/authorized_keys"),
    "the requesting party's key is in the preinstall manifest",
  );
});

Deno.test("a per-guest package is left to boot too", () => {
  const manifest = preinstallManifest({ modules: ["test-per-guest-package"], ctx: CTX });
  assertEquals(manifest.leftToBoot.packages, ["only-when-named"]);
  assertEquals(manifest.packages, []);
});

Deno.test("an argv command keeps its arguments apart", () => {
  assertEquals(
    shellCommandLine(["sh", "-c", "echo a b > /root/c"], "the module"),
    String.raw`'sh' '-c' 'echo a b > /root/c'`,
  );
  assertEquals(
    shellCommandLine(["sh", "-c", "echo it's here"], "the module"),
    String.raw`'sh' '-c' 'echo it'\''s here'`,
  );
  assertEquals(shellCommandLine("apt-get update", "the module"), "apt-get update");
});

Deno.test("the last module to write a path is the one that is baked", () => {
  const manifest = preinstallManifest({
    modules: ["test-static", "test-also-writes-the-file"],
  });
  assertEquals(
    manifest.files.filter((f) => f.path === "/etc/the-file").length,
    1,
    `two modules write /etc/the-file and the manifest carries it twice: cloud-init applies the ` +
      `later one, so the baked file has to be the later one and only one of it`,
  );
  assertEquals(manifest.files.find((f) => f.path === "/etc/the-file")?.content, "second\n");
  assertEquals(manifest.files.find((f) => f.path === "/etc/the-file")?.mode, "0644");
});

Deno.test("a module function is refused rather than derived from", () => {
  const err = assertThrows(
    () =>
      preinstallManifest({
        modules: [acceptBundleModule("/root/accept.json", { $type: "the-one-contract" }) as never],
      }),
    Error,
  );
  assert(
    err.message.includes("acceptBundleModule"),
    `the refusal does not say what kind of thing it was given: ${err.message}`,
  );
});

Deno.test("a file owned by anyone but root is refused rather than baked as root's", () => {
  const err = assertThrows(() => preinstallManifest({ modules: ["test-owned-elsewhere"] }), Error);
  assert(
    err.message.includes("/home/ubuntu/x") && err.message.includes("ubuntu"),
    `the refusal does not name the file and the owner it cannot bake: ${err.message}`,
  );
});

Deno.test("apt sources are refused rather than silently not baked", () => {
  const err = assertThrows(() => preinstallManifest({ modules: ["test-apt-sources"] }), Error);
  assert(
    err.message.includes("apt sources"),
    `the refusal does not say what cannot be baked: ${err.message}`,
  );
});

Deno.test("a prepended step that is not a command is refused", () => {
  const err = assertThrows(() => preinstallManifest({ modules: ["test-odd-prepend"] }), Error);
  assert(
    err.message.includes("runcmd entry"),
    `the refusal does not say which entry it could not render: ${err.message}`,
  );
});
