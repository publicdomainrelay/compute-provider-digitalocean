import type { StructuredLoggerInterface } from "@publicdomainrelay/logger";

export type StrongRef = { $type: "com.atproto.repo.strongRef"; uri: string; cid: string };

export type VM = {
  cpus: number;
  mem: string;
  disk: string;
  network: string;
  role: string;
  user_data: string;
  location?: { country?: string; region?: string };
  _uri?: string;
  _cid?: string;
};

export interface DropletSpec {
  region?: string;
  size?: string;
  image?: string;
}

export interface ProvisionResult {
  providerId: string | number;
  metadata: Record<string, unknown>;
}

export interface ComputeAtproto {
  getAgentDid(): string;
  createRecord(collection: string, record: Record<string, unknown>): Promise<StrongRef>;
  deleteRecord(collection: string, rkey: string): Promise<void>;
}

export interface ComputeProviderCtx {
  logger: StructuredLoggerInterface;
  atproto: ComputeAtproto;
}

export interface ComputeProvider {
  readonly name: string;
  provision(
    vm: VM,
    requesterDid: string,
    spec?: DropletSpec,
  ): Promise<ProvisionResult>;
  destroy(id: string | number): Promise<void>;
  createBidConfig(nowIso: string): Promise<StrongRef>;
  injectAcceptBundle(
    userData: string,
    bundle: Record<string, unknown>,
  ): string;
  getDroplet?(id: string): Record<string, unknown> | undefined;
  /** Read iroh node ID from a provisioned guest. Provider-specific mechanism
   * (container exec, SSH, etc.). Returns undefined if not an iroh transport. */
  getNodeId?(providerId: string): Promise<string | undefined>;
  setup?(): Promise<void>;
  teardown?(): Promise<void>;
}

export type ComputeProviderMode = "local" | "digitalocean";

export interface RbacProvisioner {
  provision(vm: { role: string }, requesterDid: string, ctx: {
    getAgentDid: () => string;
    getIssuerUrl: () => string;
    createRecord: (collection: string, record: Record<string, unknown>) => Promise<{ uri: string }>;
    parseAtUri: (uri: string) => { repo: string; collection: string; rkey: string };
  }): Promise<{ uri: string } | undefined>;
}
