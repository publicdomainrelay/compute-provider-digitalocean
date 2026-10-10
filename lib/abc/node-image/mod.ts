export type NodeImageState = "present" | "built" | "reused";

export interface NodeImageStatus {
  readonly state: NodeImageState;
  readonly fingerprint: string;
  readonly dir: string;
  readonly config: string;
  readonly reusedFrom?: string;
  readonly kernel?: string;
  readonly initramfs?: string;
  readonly rootfs?: string;
  readonly rootfsMiB?: number;
}

export interface EnsureOptions {
  readonly reuseStale?: boolean;
}

export interface NodeImageStore {
  readonly name: string;
  ensure(opts?: EnsureOptions): Promise<NodeImageStatus>;
}
