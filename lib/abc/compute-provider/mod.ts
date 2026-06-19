import type { Logger } from "@publicdomainrelay/logger";

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

export interface ComputeProviderCtx {
  log: Logger;
  parseAtUri: (uri: string) => { repo: string; collection: string; rkey: string };
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
  setup?(): Promise<void>;
  teardown?(): Promise<void>;
}

export type ComputeProviderMode = "local" | "digitalocean";

export function parseAtUri(uri: string): { repo: string; collection: string; rkey: string } {
  const u = new URL(uri);
  const parts = u.pathname.split("/").filter(Boolean);
  return {
    repo: `${u.protocol}//${u.host}`,
    collection: parts[0] ?? "",
    rkey: parts[1] ?? "",
  };
}

export interface RbacProvisioner {
  provision(vm: { role: string }, requesterDid: string, ctx: {
    getAgentDid: () => string;
    getIssuerUrl: () => string;
    createRecord: (collection: string, record: Record<string, unknown>) => Promise<{ uri: string }>;
    parseAtUri: (uri: string) => { repo: string; collection: string; rkey: string };
  }): Promise<{ uri: string } | undefined>;
}
