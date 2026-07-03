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
  getJwkPem(issuer: string): string | null;
  saveJwkPem(issuer: string, pem: string): void;
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

export interface OidcIssuerOptions {
  getIssuerUrl: () => string;
  getDroplet: (id: string) => Record<string, unknown> | undefined;
  /** @deprecated No longer used — getIssuerUrl() provides the live URL. */
  serviceUrl?: string;
  plcDirectoryUrl?: string;
  log?: Logger;
  onIssuerUrl?: (baseUrl: string) => void | Promise<void>;
}

export interface OidcIssuer {
  app: { fetch: (req: Request) => Response | Promise<Response> };
}

export interface AuthToken {
  sub: string;
  actx: string;
  asString: string;
  claims: Record<string, unknown>;
}

export interface OidcProvisioningEnricher {
  enrich(userData: string, teamUuid: string, issuerUrl: string): Promise<{
    userData: string;
    nonce: string;
    associateWithDroplet(dropletId: string): void;
  }>;
}
