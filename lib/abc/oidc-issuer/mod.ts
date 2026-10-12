import type { Logger } from "@publicdomainrelay/logger";

export class UnauthorizedException extends Error {
  constructor(msg: string) { super(msg); this.name = "UnauthorizedException"; }
}

export function parseAudience(aud: string): { actx: string; api: string } {
  const rest = aud.startsWith("api://") ? aud.slice(6) : null;
  if (!rest) throw new UnauthorizedException(`aud does not start with api://: ${aud}`);
  const qIdx = rest.indexOf("?");
  if (qIdx < 0) throw new UnauthorizedException(`aud missing ?actx=: ${aud}`);
  const api = rest.slice(0, qIdx);
  const params = new URLSearchParams(rest.slice(qIdx + 1));
  const actx = params.get("actx");
  if (!actx) throw new UnauthorizedException(`aud missing actx param: ${aud}`);
  return { actx, api };
}

export interface JwkStore {
  getJwkPem(issuer: string): string | null | Promise<string | null>;
  saveJwkPem(issuer: string, pem: string): void | Promise<void>;
}

export interface OIDCTokenData {
  actx: string;
  api: string;
  aud: string;
  sub: string;
  claims: Record<string, unknown>;
  asString: string;
}

export interface NonceStore {
  createProvisioningNonce(nonce: string, dropletId: string): void;
  getProvisioningNonceDropletId(nonce: string): string;
}

export interface ProvisioningDataInit {
  nonce: string;
  token: OIDCTokenData;
  userData: string;
}

export interface ProvisioningData extends ProvisioningDataInit {
  associateWithDroplet(dropletId: string): void;
}

export type DropletGetter = (
  id: string,
) => Record<string, unknown> | undefined | Promise<Record<string, unknown> | undefined>;

export type IssuersForAudience = (api: string, actx: string) => Promise<string[]> | string[];

export interface ReportedHostKey {
  type: string;
  publicKey: string;
  fingerprint?: string;
}

export interface HostKeysReported {
  nonce: string;
  keys: ReportedHostKey[];
}

export interface HostKeysReportAck {
  ok: boolean;
  status?: number;
  reason?: string;
}

export class HostKeyConflictException extends Error {
  constructor(msg: string) { super(msg); this.name = "HostKeyConflictException"; }
}

export interface OidcIssuerOptions {
  getIssuerUrl: () => string;
  getDroplet?: DropletGetter;
  plcDirectoryUrl?: string;
  log?: Logger;
  store?: JwkStore;
  nonceStore?: NonceStore;
  trustedIssuerUrls?: string[];
  defaultTtlSeconds?: number;
  reportedHostKeyWaitMs?: number;
  onHostKeys?: (report: HostKeysReported) => Promise<HostKeysReportAck>;
}

export interface AuthToken {
  sub: string;
  actx: string;
  asString: string;
  claims: Record<string, unknown>;
}

export interface OidcProvisioningEnricher {
  enrich(userData: string | null, teamUuid: string): Promise<{
    userData: string;
    nonce: string;
    associateWithDroplet(dropletId: string): void;
  }>;
}

export interface OidcIssuer {
  app: { fetch: (req: Request) => Response | Promise<Response> };
  getIssuerUrl(): string;
  getSigningKey(): Promise<CryptoKeyPair>;
  getPublicJwk(): Promise<JsonWebKey & { kid?: string }>;
  createToken(actx: string, claims: Record<string, unknown>, api?: string): Promise<OIDCTokenData>;
  validateToken(token: string, getIssuers?: IssuersForAudience): Promise<OIDCTokenData>;
  raiseIfUnauthorized(service: string, scope: string, token: string, path: string, method: string): Promise<AuthToken>;
  createProvisioningData(
    teamUuid: string,
    userData: string | null,
    opts?: { ttl?: number; nonceLen?: number },
  ): Promise<ProvisioningData>;
  provisioningEnricher: OidcProvisioningEnricher;
  bindReportedHostKey(token: string, signature: string, ed25519PublicKey: string): Promise<string>;
}
