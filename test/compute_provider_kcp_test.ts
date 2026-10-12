import { assert, assertEquals, assertRejects, assertStringIncludes } from "@std/assert";
import { Hono } from "@hono/hono";
import {
  type ComputeVM,
  type ComputeVMLostReason,
  type ComputeVMStatus,
  FIELD_MANAGER_COMPUTE_VM_PROVIDER,
  FINALIZER_COMPUTE_VM,
  USER_DATA_SECRET_KEY,
} from "@publicdomainrelay/compute-provider-kcp-common";
import type { ComputeAtproto, ComputeProvider, GuestGone, VM } from "@publicdomainrelay/compute-provider-abc";
import { goneReasonOf } from "@publicdomainrelay/compute-provider-kcp-abc";
import { createComputeProviderKcp, createKcpComputeVMClient } from "@publicdomainrelay/compute-provider-kcp";
import { createComputeProviderKcpFactory } from "@publicdomainrelay/hono-factory-compute-provider-kcp";
import { createComputeProviderFirecracker } from "@publicdomainrelay/compute-provider-firecracker";

const KCP = "https://kcp.test";
const WS = "root:bidders:bob";
const VM_PATH = `/clusters/${WS}/apis/socialweb.computer/v1alpha1/computevms`;
const SECRET_PATH = `/clusters/${WS}/api/v1/namespaces/default/secrets`;
const HANDLE = "bobvmbuilder.bsky.social";
const ISSUER = "https://kcpprov.relay.localhost";
const GUEST_HOST = "10.0.2.2";
const REQUESTER = "did:plc:requesterrequester";
const NOW = "2026-10-11T00:00:00.000Z";

const quiet = { info() {}, warn() {}, error() {}, debug() {} };

const VM_INPUT: VM = {
  cpus: 2,
  mem: "4G",
  disk: "20G",
  network: "",
  role: "builder",
  user_data: "#cloud-config\nruncmd:\n  - echo hello\n",
};

interface Seen {
  method: string;
  path: string;
  query: URLSearchParams;
  type: string | null;
  auth: string | null;
  body: Record<string, unknown> | null;
}

const encoder = new TextEncoder();

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

function notFound(): Response {
  return json({ kind: "Status", code: 404, reason: "NotFound" }, 404);
}

class FakeKcp {
  readonly vms = new Map<string, ComputeVM>();
  readonly secrets = new Map<string, Record<string, unknown>>();
  readonly seen: Seen[] = [];
  watchRefused = false;
  #rv = 100;
  #uid = 0;
  readonly #watchers = new Set<ReadableStreamDefaultController<Uint8Array>>();

  seed(name: string, handle: string, status: ComputeVMStatus): void {
    this.vms.set(name, this.#stamp({
      apiVersion: "socialweb.computer/v1alpha1",
      kind: "ComputeVM",
      metadata: { name, uid: `uid-seed-${name}`, finalizers: [FINALIZER_COMPUTE_VM] },
      spec: {
        vm: { cpus: 1, mem: "1G", disk: "10G", role: "worker" },
        owner: { handle },
        userDataSecret: `${name}-user-data`,
        requester: { did: "did:plc:seededrequester" },
      },
      status,
    }));
  }

  setStatus(name: string, status: ComputeVMStatus): void {
    const vm = this.vms.get(name);
    if (!vm) throw new Error(`fake kcp holds no ${name}`);
    const next = this.#stamp({ ...structuredClone(vm), status: { ...(vm.status ?? {}), ...status } });
    this.vms.set(name, next);
    this.#emit("MODIFIED", next);
  }

  finalize(name: string): void {
    const vm = this.vms.get(name);
    if (!vm) throw new Error(`fake kcp holds no ${name}`);
    this.vms.delete(name);
    this.#emit("DELETED", this.#stamp(structuredClone(vm)));
  }

  writes(kind: "computevms" | "secrets", method: string): Seen[] {
    const base = kind === "computevms" ? VM_PATH : SECRET_PATH;
    return this.seen.filter((s) => s.method === method && s.path.startsWith(`${base}/`));
  }

  #stamp(vm: ComputeVM): ComputeVM {
    vm.metadata = { ...(vm.metadata ?? {}), resourceVersion: String(++this.#rv) };
    return vm;
  }

  #emit(type: string, object: ComputeVM): void {
    const line = encoder.encode(JSON.stringify({ type, object }) + "\n");
    for (const controller of this.#watchers) controller.enqueue(line);
  }

  fetch = (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    this.seen.push({
      method,
      path: url.pathname,
      query: url.searchParams,
      type: headers.get("content-type"),
      auth: headers.get("authorization"),
      body,
    });
    return Promise.resolve(this.#route(url, method, body, init?.signal ?? undefined));
  };

  #route(url: URL, method: string, body: Record<string, unknown> | null, signal?: AbortSignal): Response {
    const path = url.pathname;
    if (path === VM_PATH && method === "GET") {
      if (url.searchParams.get("watch")) return this.#watch(signal);
      return json({
        apiVersion: "socialweb.computer/v1alpha1",
        kind: "ComputeVMList",
        metadata: { resourceVersion: String(this.#rv) },
        items: [...this.vms.values()],
      });
    }
    if (path.startsWith(`${VM_PATH}/`)) {
      const name = decodeURIComponent(path.slice(VM_PATH.length + 1));
      const vm = this.vms.get(name);
      if (method === "GET") return vm ? json(vm) : notFound();
      if (method === "PATCH" && body) {
        const metadata = body.metadata as Record<string, unknown>;
        const applied = this.#stamp({
          ...(body as ComputeVM),
          metadata: {
            ...metadata,
            uid: vm?.metadata?.uid ?? `uid-${++this.#uid}`,
            finalizers: [FINALIZER_COMPUTE_VM],
            creationTimestamp: NOW,
          },
          ...(vm?.status ? { status: vm.status } : {}),
        });
        this.vms.set(name, applied);
        this.#emit(vm ? "MODIFIED" : "ADDED", applied);
        return json(applied);
      }
      if (method === "DELETE") {
        if (!vm) return notFound();
        const next = this.#stamp({
          ...structuredClone(vm),
          metadata: { ...vm.metadata, deletionTimestamp: NOW },
        });
        this.vms.set(name, next);
        this.#emit("MODIFIED", next);
        return json(next);
      }
    }
    if (path.startsWith(`${SECRET_PATH}/`)) {
      const name = decodeURIComponent(path.slice(SECRET_PATH.length + 1));
      if (method === "PATCH" && body) {
        this.secrets.set(name, body);
        return json(body);
      }
      if (method === "DELETE") return this.secrets.delete(name) ? json({ kind: "Status", code: 200 }) : notFound();
      if (method === "GET") return this.secrets.has(name) ? json(this.secrets.get(name)) : notFound();
    }
    return json({ kind: "Status", code: 404, message: `no route ${method} ${path}` }, 404);
  }

  #watch(signal?: AbortSignal): Response {
    if (this.watchRefused) return json({ kind: "Status", code: 405, message: "watch is not served here" }, 405);
    let controller!: ReadableStreamDefaultController<Uint8Array>;
    const stream = new ReadableStream<Uint8Array>({
      start: (c) => {
        controller = c;
        this.#watchers.add(c);
      },
      cancel: () => {
        this.#watchers.delete(controller);
      },
    });
    signal?.addEventListener("abort", () => {
      this.#watchers.delete(controller);
      try {
        controller.error(new DOMException("aborted", "AbortError"));
      } catch {
        return;
      }
    });
    return new Response(stream, { status: 200 });
  }
}

interface RecordedAtproto extends ComputeAtproto {
  created: { collection: string; record: Record<string, unknown> }[];
  deleted: { collection: string; rkey: string }[];
}

function fakeAtproto(): RecordedAtproto {
  const created: { collection: string; record: Record<string, unknown> }[] = [];
  const deleted: { collection: string; rkey: string }[] = [];
  return {
    created,
    deleted,
    getAgentDid: () => "did:plc:bidderbidder",
    createRecord(collection, record) {
      created.push({ collection, record });
      return Promise.resolve({
        $type: "com.atproto.repo.strongRef",
        uri: `at://did:plc:bidderbidder/${collection}/${created.length}`,
        cid: `bafy${created.length}`,
      });
    },
    deleteRecord(collection, rkey) {
      deleted.push({ collection, rkey });
      return Promise.resolve();
    },
  };
}

function providerFor(kcp: FakeKcp, atproto: ComputeAtproto = fakeAtproto()): ComputeProvider {
  return createComputeProviderKcp({
    logger: quiet,
    atproto,
    client: createKcpComputeVMClient({ credentials: { server: KCP, workspace: WS, token: "t" }, fetch: kcp.fetch }),
    handle: HANDLE,
    guestHostAddress: GUEST_HOST,
    getIssuerUrl: () => ISSUER,
    bootTimeoutMs: 3_000,
    releaseTimeoutMs: 3_000,
    pollIntervalMs: 20,
    resyncBackoffMs: 20,
  });
}

async function until(cond: () => boolean, what: string, ms = 3_000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

function tracked<T>(promise: Promise<T>): { promise: Promise<T>; done: () => boolean } {
  let settled = false;
  promise.then(() => (settled = true), () => (settled = true));
  return { promise, done: () => settled };
}

function decodeUserData(secret: Record<string, unknown>): string {
  const data = secret.data as Record<string, string>;
  const bytes = Uint8Array.from(atob(data[USER_DATA_SECRET_KEY]), (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

async function provisioned(kcp: FakeKcp, provider: ComputeProvider): Promise<string> {
  const pending = provider.provision(VM_INPUT, REQUESTER);
  await until(() => kcp.vms.size > 0 && kcp.secrets.size > 0, "the ComputeVM and its Secret");
  const name = [...kcp.vms.keys()].at(-1)!;
  kcp.setStatus(name, { phase: "Running", network: { guestIP: "10.0.2.15", hostAddress: GUEST_HOST, prefix: 24 } });
  const result = await pending;
  assertEquals(result.providerId, name);
  return name;
}

Deno.test("provision applies the ComputeVM and resolves only once the controller reports Running", async () => {
  const kcp = new FakeKcp();
  const provider = providerFor(kcp);
  await provider.setup!();
  try {
    const pending = tracked(provider.provision(VM_INPUT, REQUESTER));
    await until(() => kcp.vms.size === 1 && kcp.secrets.size === 1, "the ComputeVM and its Secret");
    const [name] = [...kcp.vms.keys()];
    assert(/^fc-[0-9a-f]+-[0-9a-f]{8}$/.test(name), name);

    const apply = kcp.writes("computevms", "PATCH")[0];
    assertEquals(apply.type, "application/apply-patch+yaml");
    assertEquals(apply.query.get("fieldManager"), FIELD_MANAGER_COMPUTE_VM_PROVIDER);
    assertEquals(apply.query.get("force"), "true");
    assertEquals(apply.auth, "Bearer t");
    const spec = (apply.body as ComputeVM).spec!;
    assertEquals(spec.owner, { handle: HANDLE });
    assertEquals(spec.vm, { cpus: 2, mem: "4G", disk: "20G", role: "builder" });
    assertEquals(spec.requester.did, REQUESTER);
    assertEquals(spec.userDataSecret, `${name}-user-data`);

    const secret = kcp.secrets.get(`${name}-user-data`)!;
    const owners = (secret.metadata as { ownerReferences: { kind: string; name: string; uid: string }[] }).ownerReferences;
    assertEquals(owners.map((o) => [o.kind, o.name, o.uid]), [["ComputeVM", name, kcp.vms.get(name)!.metadata!.uid]]);
    const userData = decodeUserData(secret);
    assertStringIncludes(userData, "guest-onnetwork.service");
    assertStringIncludes(userData, `echo ${GUEST_HOST} kcpprov.relay.localhost >> /etc/hosts`);
    assertStringIncludes(userData, "echo hello");

    kcp.setStatus(name, { phase: "Preparing" });
    kcp.setStatus(name, { phase: "Booting" });
    await new Promise((r) => setTimeout(r, 50));
    assertEquals(pending.done(), false, "provision resolved before the ComputeVM was Running");

    kcp.setStatus(name, { phase: "Running", network: { guestIP: "10.0.2.15", hostAddress: GUEST_HOST, prefix: 24 } });
    const result = await pending.promise;
    assertEquals(result.providerId, name);
    assertEquals(result.metadata.ip, "10.0.2.15");
    assertEquals(result.metadata.mode, "kcp");
  } finally {
    await provider.teardown!();
  }
});

Deno.test("the user_data Secret is written once, however often the ComputeVM's status moves", async () => {
  const kcp = new FakeKcp();
  const provider = providerFor(kcp);
  await provider.setup!();
  try {
    const name = await provisioned(kcp, provider);
    kcp.setStatus(name, { message: "observed", conditions: [{ type: "RuntimeObserved", status: "True" }] });
    kcp.setStatus(name, { market: { address: "guest.example" } });
    await new Promise((r) => setTimeout(r, 50));
    assertEquals(kcp.writes("secrets", "PATCH").length, 1);
    assertEquals(kcp.writes("computevms", "PATCH").length, 1);
  } finally {
    await provider.teardown!();
  }
});

Deno.test("provision fails with the controller's reason when the ComputeVM ends before Running, and releases it", async () => {
  const kcp = new FakeKcp();
  const provider = providerFor(kcp);
  await provider.setup!();
  try {
    const gone: GuestGone[] = [];
    provider.onGuestGone!((g) => gone.push(g));
    const pending = provider.provision(VM_INPUT, REQUESTER);
    await until(() => kcp.secrets.size === 1, "the Secret");
    const [name] = [...kcp.vms.keys()];
    kcp.setStatus(name, { phase: "Failed", message: "the guest image sha256 did not match" });
    await assertRejects(() => pending, Error, "the guest image sha256 did not match");
    await until(() => kcp.writes("computevms", "DELETE").length === 1, "the failed ComputeVM's delete");
    assertEquals(gone, []);
  } finally {
    await provider.teardown!();
  }
});

Deno.test("destroy resolves only after kcp answers 404 for the ComputeVM, then drops its Secret", async () => {
  const kcp = new FakeKcp();
  const provider = providerFor(kcp);
  await provider.setup!();
  try {
    const gone: GuestGone[] = [];
    provider.onGuestGone!((g) => gone.push(g));
    const name = await provisioned(kcp, provider);
    const destroying = tracked(provider.destroy(name));
    await until(() => kcp.writes("computevms", "DELETE").length === 1, "the DELETE");
    kcp.setStatus(name, { phase: "Releasing" });
    await new Promise((r) => setTimeout(r, 80));
    assertEquals(destroying.done(), false, "destroy resolved while the finalizer still held the ComputeVM");
    assertEquals(kcp.secrets.has(`${name}-user-data`), true);
    kcp.finalize(name);
    await destroying.promise;
    assertEquals(kcp.secrets.has(`${name}-user-data`), false);
    assertEquals(gone, [], "a requested destroy is not a guest gone");
  } finally {
    await provider.teardown!();
  }
});

Deno.test("createBidConfig writes exactly the record the firecracker provider writes", async () => {
  const kcpAtproto = fakeAtproto();
  const fcAtproto = fakeAtproto();
  const provider = providerFor(new FakeKcp(), kcpAtproto);
  const firecracker = createComputeProviderFirecracker({
    logger: quiet,
    atproto: fcAtproto,
    image: {} as never,
    microvm: {} as never,
    workRoot: "/nonexistent",
    getIssuerUrl: () => ISSUER,
    serve: {} as never,
  });
  const ours = await provider.createBidConfig(NOW);
  const theirs = await firecracker.createBidConfig(NOW);
  assertEquals(kcpAtproto.created, fcAtproto.created);
  assertEquals(ours, theirs);
});

Deno.test("setup() rebuilds getDroplet from the ComputeVMs this handle owns in kcp", async () => {
  const kcp = new FakeKcp();
  kcp.seed("fc-aaaa-00000001", HANDLE, { phase: "Running" });
  kcp.seed("fc-aaaa-00000002", HANDLE, { phase: "Booting" });
  kcp.seed("fc-bbbb-00000003", "someone-else.example", { phase: "Running" });
  const provider = providerFor(kcp);
  assertEquals(provider.getDroplet!("fc-aaaa-00000001"), undefined);
  await provider.setup!();
  try {
    assertEquals(provider.getDroplet!("fc-aaaa-00000001"), {
      id: "fc-aaaa-00000001",
      tags: ["oidc-sub:plc:seededrequester", "oidc-sub:role:worker"],
    });
    assertEquals(provider.getDroplet!("fc-aaaa-00000002")?.id, "fc-aaaa-00000002");
    assertEquals(provider.getDroplet!("fc-bbbb-00000003"), undefined);
  } finally {
    await provider.teardown!();
  }
});

Deno.test("the Lost reasons map onto the vm.terminated reasons", () => {
  const table: [ComputeVMLostReason | undefined, string][] = [
    ["HostRebooted", "host_reboot"],
    ["UnitGone", "vmm_exited"],
    ["UnitFailed", "vmm_exited"],
    ["VMMExited", "vmm_exited"],
    ["OOMKilled", "oom"],
    ["IdentityMismatch", "identity_mismatch"],
    [undefined, "vmm_exited"],
  ];
  for (const [lost, terminated] of table) assertEquals(goneReasonOf(lost), terminated, String(lost));
});

Deno.test("a ComputeVM going Lost fires onGuestGone with its reason", async () => {
  const kcp = new FakeKcp();
  const reasons: [string, ComputeVMLostReason][] = [
    ["fc-aaaa-00000001", "HostRebooted"],
    ["fc-aaaa-00000002", "UnitGone"],
    ["fc-aaaa-00000003", "OOMKilled"],
    ["fc-aaaa-00000004", "IdentityMismatch"],
  ];
  for (const [name] of reasons) kcp.seed(name, HANDLE, { phase: "Running" });
  const provider = providerFor(kcp);
  await provider.setup!();
  try {
    const name = await provisioned(kcp, provider);
    const gone: GuestGone[] = [];
    provider.onGuestGone!((g) => gone.push(g));
    kcp.setStatus(name, { phase: "Lost", lostReason: "VMMExited" });
    for (const [seeded, lostReason] of reasons) kcp.setStatus(seeded, { phase: "Lost", lostReason });
    await until(() => gone.length === 5, "five guests gone");
    assertEquals(
      gone.map((g) => [g.id, g.reason]).sort(),
      [
        [name, "vmm_exited"],
        ["fc-aaaa-00000001", "host_reboot"],
        ["fc-aaaa-00000002", "vmm_exited"],
        ["fc-aaaa-00000003", "oom"],
        ["fc-aaaa-00000004", "identity_mismatch"],
      ].sort(),
    );
    await until(() => kcp.writes("computevms", "DELETE").length === 5, "every Lost ComputeVM released");
    kcp.setStatus(name, { phase: "Lost", lostReason: "VMMExited", message: "again" });
    await new Promise((r) => setTimeout(r, 50));
    assertEquals(gone.length, 5, "a Lost guest is reported once");
    assertEquals(provider.getDroplet!(name), undefined);
  } finally {
    await provider.teardown!();
  }
});

Deno.test("adopt answers running for a live ComputeVM and gone with its reason for a Lost or missing one", async () => {
  const kcp = new FakeKcp();
  kcp.seed("fc-aaaa-00000001", HANDLE, { phase: "Running" });
  kcp.seed("fc-aaaa-00000002", HANDLE, { phase: "Lost", lostReason: "HostRebooted" });
  const provider = providerFor(kcp);
  await provider.setup!();
  try {
    assertEquals(await provider.adopt!("fc-aaaa-00000001"), { state: "running" });
    assertEquals(await provider.adopt!("fc-aaaa-00000002"), {
      state: "gone",
      gone: { id: "fc-aaaa-00000002", reason: "host_reboot" },
    });
    assertEquals(await provider.adopt!("fc-aaaa-00000009"), {
      state: "gone",
      gone: { id: "fc-aaaa-00000009", reason: "vmm_exited" },
    });
    await until(() => kcp.writes("computevms", "DELETE").length === 1, "the Lost ComputeVM released");
  } finally {
    await provider.teardown!();
  }
});

Deno.test("a watch kcp refuses degrades to bounded re-listing and provision still sees Running", async () => {
  const kcp = new FakeKcp();
  kcp.watchRefused = true;
  const provider = providerFor(kcp);
  await provider.setup!();
  try {
    await provisioned(kcp, provider);
    assert(kcp.seen.filter((s) => s.path === VM_PATH && !s.query.get("watch")).length >= 2, "kcp was re-listed");
  } finally {
    await provider.teardown!();
  }
});

Deno.test("the kcp token file is read again for every request, so the Go side can rotate it", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const tokenFile = `${dir}/token`;
    const kcp = new FakeKcp();
    const client = createKcpComputeVMClient({ credentials: { server: KCP, workspace: WS, tokenFile }, fetch: kcp.fetch });
    await Deno.writeTextFile(tokenFile, "first\n");
    await client.list();
    await Deno.writeTextFile(tokenFile, "second\n");
    await client.list();
    assertEquals(kcp.seen.map((s) => s.auth), ["Bearer first", "Bearer second"]);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("the factory mounts the OIDC issuer and POST /v1/on-network on the provider's serve once it connects", async () => {
  const connected: ((ingressRef: string) => void | Promise<void>)[] = [];
  const serve = { app: new Hono(), onConnected: (cb: (ingressRef: string) => void | Promise<void>) => void connected.push(cb) };
  const kcp = new FakeKcp();
  const built = createComputeProviderKcpFactory({
    logger: quiet,
    atproto: fakeAtproto(),
    serve,
    credentials: { server: KCP, workspace: WS, token: "t" },
    fetch: kcp.fetch,
    handle: HANDLE,
    guestHostAddress: GUEST_HOST,
    getIssuerUrl: () => ISSUER,
  });
  assertEquals(built.provider.name, "kcp");
  assertEquals((await serve.app.request("/.well-known/openid-configuration")).status, 404);
  for (const cb of connected) await cb("did:web:kcpprov.relay.localhost");
  assertEquals((await serve.app.request("/.well-known/openid-configuration")).status, 200);
  assertEquals((await serve.app.request("/v1/on-network", { method: "POST", body: "{}" })).status, 401);
  assertEquals((await built.createApp().request("/.well-known/openid-configuration")).status, 200);
});
