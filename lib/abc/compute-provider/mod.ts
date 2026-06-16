import type { Logger } from "@publicdomainrelay/common";

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
  setup?(): Promise<void>;
  teardown?(): Promise<void>;
}

export type ComputeProviderMode = "local" | "digitalocean";

export function computeProviderModeFromEnv(): ComputeProviderMode {
  const env = Deno.env.get("COMPUTE_PROVIDER")?.toLowerCase();
  if (env === "local" || env === "digitalocean") return env;
  const cli = Deno.env.get("COMPUTE_PROVIDER_CLI")?.toLowerCase();
  if (cli === "local" || cli === "digitalocean") return cli;
  return "local";
}

export function reqEnv(name: string): string {
  const v = Deno.env.get(name);
  if (!v) {
    console.error(`env var ${name} is required`);
    Deno.exit(1);
  }
  return v;
}

export function optUrl(name: string, fallback: string): string {
  const v = Deno.env.get(name);
  return (v ?? fallback).replace(/\/+$/, "");
}

export function dropletSpecFromEnv(): DropletSpec {
  return {
    region: Deno.env.get("COMPUTE_PROVIDER_REGION") ?? "sfo3",
    size: Deno.env.get("COMPUTE_PROVIDER_SIZE") ?? "s-1vcpu-512mb-10gb",
    image: Deno.env.get("COMPUTE_PROVIDER_IMAGE") ?? "ubuntu",
  };
}

export function parseAtUri(uri: string): { repo: string; collection: string; rkey: string } {
  const u = new URL(uri);
  const parts = u.pathname.split("/").filter(Boolean);
  return {
    repo: `${u.protocol}//${u.host}`,
    collection: parts[0] ?? "",
    rkey: parts[1] ?? "",
  };
}
