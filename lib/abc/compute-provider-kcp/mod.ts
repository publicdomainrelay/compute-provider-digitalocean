import type { GuestGone, VM } from "@publicdomainrelay/compute-provider-abc";
import {
  COMPUTE_VM_RESOURCE,
  type ComputeVM,
  type ComputeVMLostReason,
  type ComputeVMPhase,
  USER_DATA_SECRET_KEY,
  USER_DATA_SECRET_NAMESPACE,
} from "@publicdomainrelay/compute-provider-kcp-common";

export type GuestGoneReason = "host_reboot" | "vmm_exited" | "oom" | "identity_mismatch";

const GONE_REASON_BY_LOST: Readonly<Record<ComputeVMLostReason, GuestGoneReason>> = {
  HostRebooted: "host_reboot",
  UnitGone: "vmm_exited",
  UnitFailed: "vmm_exited",
  VMMExited: "vmm_exited",
  OOMKilled: "oom",
  IdentityMismatch: "identity_mismatch",
};

export const COMPUTE_VM_API_VERSION = `${COMPUTE_VM_RESOURCE.group}/${COMPUTE_VM_RESOURCE.version}`;

export function goneReasonOf(lost: ComputeVMLostReason | undefined): GuestGoneReason {
  return (lost && GONE_REASON_BY_LOST[lost]) ?? "vmm_exited";
}

export function phaseOf(vm: ComputeVM | undefined): ComputeVMPhase | undefined {
  return vm?.status?.phase;
}

export function hasEnded(vm: ComputeVM | undefined): boolean {
  const phase = phaseOf(vm);
  return phase === "Lost" || phase === "Failed";
}

export function isReleasing(vm: ComputeVM | undefined): boolean {
  return vm?.metadata?.deletionTimestamp !== undefined || phaseOf(vm) === "Releasing";
}

export function goneOf(name: string, vm: ComputeVM | undefined): GuestGone {
  return { id: name, reason: goneReasonOf(vm?.status?.lostReason) };
}

export function endedMessage(name: string, vm: ComputeVM): string {
  const status = vm.status ?? {};
  const why = [status.lostReason, status.message].filter((part) => part).join(": ");
  return `ComputeVM ${name} ended ${status.phase ?? "without a phase"}${why ? ` (${why})` : ""}`;
}

export function userDataSecretName(name: string): string {
  return `${name}-user-data`;
}

export interface ComputeVMInput {
  name: string;
  handle: string;
  vm: Pick<VM, "cpus" | "mem" | "disk" | "role">;
  requesterDid: string;
  reuseStale?: boolean;
  stopGraceSeconds?: number;
}

export function computeVMFor(input: ComputeVMInput): ComputeVM {
  return {
    apiVersion: COMPUTE_VM_API_VERSION,
    kind: COMPUTE_VM_RESOURCE.kind,
    metadata: { name: input.name },
    spec: {
      vm: { cpus: input.vm.cpus, mem: input.vm.mem, disk: input.vm.disk, role: input.vm.role },
      owner: { handle: input.handle },
      userDataSecret: userDataSecretName(input.name),
      requester: { did: input.requesterDid },
      ...(input.reuseStale === undefined ? {} : { image: { reuseStale: input.reuseStale } }),
      ...(input.stopGraceSeconds === undefined ? {} : { stopGraceSeconds: input.stopGraceSeconds }),
    },
  };
}

export interface OwnerReference {
  apiVersion: string;
  kind: string;
  name: string;
  uid: string;
  blockOwnerDeletion?: boolean;
}

export interface UserDataSecret {
  apiVersion: "v1";
  kind: "Secret";
  metadata: { name: string; namespace: string; ownerReferences: OwnerReference[] };
  type: "Opaque";
  data: Record<string, string>;
}

const BASE64_CHUNK = 0x8000;

export function base64Of(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (let i = 0; i < bytes.length; i += BASE64_CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + BASE64_CHUNK));
  }
  return btoa(binary);
}

export function userDataSecretFor(owner: ComputeVM, userData: string): UserDataSecret {
  const name = owner.metadata?.name;
  const uid = owner.metadata?.uid;
  if (!name || !uid) {
    throw new Error(
      `the user_data Secret is owned by its ComputeVM, and the ComputeVM kcp answered with carries ` +
        `${name ? "no uid" : "no name"}, so the Secret would outlive it`,
    );
  }
  return {
    apiVersion: "v1",
    kind: "Secret",
    metadata: {
      name: owner.spec?.userDataSecret ?? userDataSecretName(name),
      namespace: USER_DATA_SECRET_NAMESPACE,
      ownerReferences: [{ apiVersion: COMPUTE_VM_API_VERSION, kind: COMPUTE_VM_RESOURCE.kind, name, uid }],
    },
    type: "Opaque",
    data: { [USER_DATA_SECRET_KEY]: base64Of(userData) },
  };
}

export function dropletOf(vm: ComputeVM): Record<string, unknown> | undefined {
  const name = vm.metadata?.name;
  if (!name || !vm.spec) return undefined;
  return {
    id: name,
    tags: [
      `oidc-sub:plc:${vm.spec.requester.did.split(":").pop() ?? ""}`,
      `oidc-sub:role:${vm.spec.vm.role}`,
    ],
  };
}

export interface ComputeVMChange {
  name: string;
  before?: ComputeVM;
  after?: ComputeVM;
}

export class ComputeVMCache {
  readonly #items = new Map<string, ComputeVM>();
  readonly #waiters = new Map<string, Set<(change: ComputeVMChange) => void>>();

  constructor(readonly handle: string) {}

  owns(vm: ComputeVM | undefined): boolean {
    return !!vm?.metadata?.name && vm.spec?.owner?.handle === this.handle;
  }

  get(name: string): ComputeVM | undefined {
    return this.#items.get(name);
  }

  names(): string[] {
    return [...this.#items.keys()];
  }

  replace(items: readonly ComputeVM[]): ComputeVMChange[] {
    const owned = new Map<string, ComputeVM>();
    for (const vm of items) if (this.owns(vm)) owned.set(vm.metadata!.name!, vm);
    const changes: ComputeVMChange[] = [];
    for (const name of [...this.#items.keys()]) {
      if (!owned.has(name)) changes.push(this.#set(name, undefined));
    }
    for (const [name, vm] of owned) {
      const before = this.#items.get(name);
      if (before && before.metadata?.resourceVersion === vm.metadata?.resourceVersion) continue;
      changes.push(this.#set(name, vm));
    }
    return changes;
  }

  upsert(vm: ComputeVM): ComputeVMChange | undefined {
    if (!this.owns(vm)) return undefined;
    return this.#set(vm.metadata!.name!, vm);
  }

  remove(name: string): ComputeVMChange | undefined {
    if (!this.#items.has(name)) return undefined;
    return this.#set(name, undefined);
  }

  nextChange(name: string, signal?: AbortSignal): Promise<ComputeVMChange | undefined> {
    return new Promise((resolve) => {
      const waiters = this.#waiters.get(name) ?? new Set();
      this.#waiters.set(name, waiters);
      const drop = () => {
        waiters.delete(settle);
        if (waiters.size === 0 && this.#waiters.get(name) === waiters) this.#waiters.delete(name);
      };
      const abandon = () => {
        drop();
        resolve(undefined);
      };
      const settle = (change: ComputeVMChange) => {
        signal?.removeEventListener("abort", abandon);
        drop();
        resolve(change);
      };
      if (signal?.aborted) return resolve(undefined);
      waiters.add(settle);
      signal?.addEventListener("abort", abandon, { once: true });
    });
  }

  #set(name: string, after: ComputeVM | undefined): ComputeVMChange {
    const before = this.#items.get(name);
    if (after) this.#items.set(name, after);
    else this.#items.delete(name);
    const change: ComputeVMChange = { name, before, after };
    for (const waiter of [...(this.#waiters.get(name) ?? [])]) waiter(change);
    return change;
  }
}
