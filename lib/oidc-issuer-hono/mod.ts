import { Hono } from "hono";
import { cors } from "hono/cors";
import { parse as yamlParse, stringify as yamlStringify } from "npm:yaml@^2.7.0";
import * as jose from "jose";
import type { Logger } from "@publicdomainrelay/logger";
import { noopLogger } from "@publicdomainrelay/logger";
import {
  JwkStore,
  NonceStore,
  type OIDCTokenData,
  type OidcIssuerOptions,
  type OidcIssuer,
  type OidcProvisioningEnricher,
  type ProvisioningDataInit,
  type AuthToken,
  UnauthorizedException,
  parseAudience,
} from "@publicdomainrelay/oidc-issuer-abc";
import {
  resolvePDS,
  getRBACRecord,
  collectIssuers,
  checkRBACPolicy,
} from "@publicdomainrelay/rbac-atproto";

export type { Logger, JwkStore, NonceStore, OIDCTokenData, OidcIssuerOptions, OidcIssuer };
export { UnauthorizedException };

export function extractBearer(authHeader: string | undefined): string {
  if (!authHeader) throw new UnauthorizedException("Missing Authorization header");
  const parts = authHeader.split(" ");
  const token = parts[parts.length - 1];
  if (!token || token === "0") throw new UnauthorizedException("Missing bearer token");
  return token;
}

function subMatchesActx(sub: string | undefined, actx: string): boolean {
  if (!sub) return false;
  return sub === `actx:${actx}` || sub.startsWith(`actx:${actx}:`);
}

function createMemoryJwkStore(): JwkStore {
  const m = new Map<string, string>();
  return {
    getJwkPem: (issuer) => m.get(issuer) ?? null,
    saveJwkPem: (issuer, pem) => { m.set(issuer, pem); },
  };
}

let _getIssuerUrl: () => string = () => {
  throw new Error("oidc-issuer not configured: call configureOidc({ getIssuerUrl }) first");
};
let _jwkStore: JwkStore = createMemoryJwkStore();
let _defaultTtlSeconds = 60 * 60 * 24;
let _signingKey: CryptoKeyPair | null = null;
let _publicJwk: jose.JWK | null = null;

export function configureOidc(cfg: {
  getIssuerUrl?: () => string;
  store?: JwkStore;
  defaultTtlSeconds?: number;
}): void {
  if (cfg.getIssuerUrl) _getIssuerUrl = cfg.getIssuerUrl;
  if (cfg.store) _jwkStore = cfg.store;
  if (typeof cfg.defaultTtlSeconds === "number") _defaultTtlSeconds = cfg.defaultTtlSeconds;
}

export async function getSigningKey(): Promise<CryptoKeyPair> {
  if (_signingKey) return _signingKey;

  const issuer = _getIssuerUrl();
  const storedPem = _jwkStore.getJwkPem(issuer);
  if (storedPem) {
    const pemBody = storedPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const der = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));
    const priv = await crypto.subtle.importKey(
      "pkcs8", der,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      true, ["sign"],
    );
    const jwk = await jose.exportJWK(priv);
    const pubJwk = { ...jwk, d: undefined, dp: undefined, dq: undefined, p: undefined, q: undefined, qi: undefined };
    const pub = await crypto.subtle.importKey(
      "jwk", pubJwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      true, ["verify"],
    );
    _signingKey = { privateKey: priv, publicKey: pub };
  } else {
    _signingKey = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    );
    const pem = await jose.exportPKCS8(_signingKey.privateKey);
    _jwkStore.saveJwkPem(issuer, pem);
  }
  return _signingKey;
}

export async function getPublicJwk(): Promise<jose.JWK> {
  if (_publicJwk) return _publicJwk;
  const keys = await getSigningKey();
  const jwk = await jose.exportJWK(keys.publicKey);
  jwk.use = "sig";
  jwk.alg = "RS256";
  jwk.kid = await jose.calculateJwkThumbprint(jwk);
  _publicJwk = jwk;
  return _publicJwk;
}

const jwksCache = new Map<string, ReturnType<typeof jose.createRemoteJWKSet>>();

function getRemoteJwks(jwksUri: string) {
  if (!jwksCache.has(jwksUri)) {
    jwksCache.set(jwksUri, jose.createRemoteJWKSet(new URL(jwksUri)));
  }
  return jwksCache.get(jwksUri)!;
}

export class OIDCToken implements OIDCTokenData {
  actx!: string;
  api!: string;
  aud!: string;
  sub!: string;
  claims!: Record<string, unknown>;
  asString!: string;

  private constructor(data: OIDCTokenData) {
    Object.assign(this, data);
  }

  static async create(
    actx: string,
    claims: Record<string, unknown>,
    api = "DigitalOcean",
  ): Promise<OIDCToken> {
    const keys = await getSigningKey();
    const jwk = await getPublicJwk();
    const issuerUrl = _getIssuerUrl();
    let audience = `api://${api}?actx=${actx}`;

    const sub = claims["sub"] as string | undefined;
    if (!subMatchesActx(sub, actx)) {
      throw new Error(`'actx:${actx}' not found in sub '${sub}'`);
    }

    const payload = { ...claims };
    delete payload["ttl"];

    let expTime: number;
    if (typeof claims["ttl"] === "number") {
      expTime = Math.floor(Date.now() / 1000) + (claims["ttl"] as number);
    } else {
      expTime = Math.floor(Date.now() / 1000) + _defaultTtlSeconds;
    }

    if (typeof claims["aud"] === "string") {
      audience = claims["aud"];
    }

    const token = await new jose.SignJWT(payload as jose.JWTPayload)
      .setProtectedHeader({ alg: "RS256", kid: jwk.kid })
      .setIssuer(issuerUrl)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime(expTime)
      .sign(keys.privateKey);

    return new OIDCToken({
      actx,
      api,
      aud: audience,
      sub: sub!,
      claims: { ...payload, iss: issuerUrl, aud: audience },
      asString: token,
    });
  }

  static async validate(
    token: string,
    getIssuers?: (api: string, actx: string) => Promise<string[]> | string[],
  ): Promise<OIDCToken> {
    if (!token || token === "0") throw new UnauthorizedException("Unable to authenticate you, no token");
    if (token.split(".").length !== 3) throw new UnauthorizedException("Invalid token");

    const issuerUrl = _getIssuerUrl();

    const unverified = jose.decodeJwt(token);
    const rawAud = Array.isArray(unverified.aud) ? unverified.aud[0] : unverified.aud as string;
    const { actx, api } = parseAudience(rawAud ?? "");
    const expectedAud = `api://${api}?actx=${actx}`;

    const ownIssuers = [issuerUrl];
    const extraIssuers = getIssuers ? await getIssuers(api, actx) : [];
    const issuers = [...new Set([...ownIssuers, ...extraIssuers])];

    let lastErr: Error = new Error("no issuers");
    for (const issuer of issuers) {
      try {
        let jwks: jose.JWTVerifyGetKey;
        if (issuer === issuerUrl) {
          const keys = await getSigningKey();
          jwks = keys.publicKey as unknown as jose.JWTVerifyGetKey;
        } else {
          const openidConfig = await fetch(`${issuer}/.well-known/openid-configuration`).then((r) => r.json()) as { jwks_uri: string };
          jwks = getRemoteJwks(openidConfig.jwks_uri);
        }

        const { payload } = await jose.jwtVerify(token, jwks, {
          issuer,
          audience: expectedAud,
        });

        return new OIDCToken({
          actx,
          api,
          aud: expectedAud,
          sub: payload.sub!,
          claims: payload as Record<string, unknown>,
          asString: token,
        });
      } catch (e) {
        lastErr = e as Error;
      }
    }
    throw new UnauthorizedException(`OIDC token failed validation: ${lastErr.message}`);
  }
}

function createMemoryNonceStore(): NonceStore {
  const m = new Map<string, string>();
  return {
    createProvisioningNonce: (nonce, dropletId) => { m.set(nonce, dropletId); },
    getProvisioningNonceDropletId: (nonce) => {
      const id = m.get(nonce);
      if (id === undefined) throw new Error(`Nonce ${nonce} not found`);
      m.delete(nonce);
      return id;
    },
  };
}

let _nonceStore: NonceStore = createMemoryNonceStore();

export function configureProvisioning(cfg: { nonceStore?: NonceStore }): void {
  if (cfg.nonceStore) _nonceStore = cfg.nonceStore;
}

const DEFAULT_NONCE_LEN = 64;
const DEFAULT_TTL_SECONDS = 60 * 15;

export class ProvisioningData {
  nonce: string;
  token: OIDCToken;
  userData: string;

  private constructor(init: { nonce: string; token: OIDCToken; userData: string }) {
    this.nonce = init.nonce;
    this.token = init.token;
    this.userData = init.userData;
  }

  static async create(
    teamUuid: string,
    userData: string | null,
    issuerUrl: string,
    opts: { ttl?: number; nonceLen?: number } = {},
  ): Promise<ProvisioningData> {
    if (userData === null) userData = "";
    const nonceLen = opts.nonceLen ?? DEFAULT_NONCE_LEN;
    const ttl = opts.ttl ?? DEFAULT_TTL_SECONDS;

    const nonceBytes = crypto.getRandomValues(new Uint8Array(nonceLen / 2));
    const nonce = Array.from(nonceBytes).map((b) => b.toString(16).padStart(2, "0")).join("");

    const token = await OIDCToken.create(teamUuid, {
      nonce,
      sub: `actx:${teamUuid}:role:provisioning:nonce:${nonce}`,
      ttl,
    });

    let userDataObj: Record<string, unknown> = {};
    try {
      const parsed = yamlParse(userData);
      if (parsed && typeof parsed === "object") userDataObj = parsed as Record<string, unknown>;
    } catch {
      /* not valid YAML, start fresh */
    }

    // Key-only root login; password auth disabled to prevent DO's
    // expired-root-password PAM prompt ("Password change required but
    // no TTY available") from blocking non-interactive SSH.
    userDataObj["ssh_pwauth"] = false;
    userDataObj["disable_root"] = false;

    const runcmd = (userDataObj["runcmd"] as unknown[]) ?? [];
    const writeFiles = (userDataObj["write_files"] as unknown[]) ?? [];

    const provisionScriptContent = `#!/usr/bin/env bash
set -euo pipefail
set -x
TEAM_UUID="${teamUuid}"
THIS_ENDPOINT="${issuerUrl}"
PROVISIONING_TOKEN="${token.asString}"
PORT=22
SIG_JSON="$(echo -n "\${PROVISIONING_TOKEN}" \\
    | ssh-keygen -Y sign -n prove-sshd -f /etc/ssh/ssh_host_ed25519_key \\
    | jq -c --arg port "\${PORT}" --raw-input --slurp '{port: (\$port | fromjson), sig: .}')"
TOKEN="$(curl -sfL \\
    -H "Authorization: Bearer \${PROVISIONING_TOKEN}" \\
    -d "\${SIG_JSON}" \\
    "\${THIS_ENDPOINT}/v1/oidc/prove" \\
    | jq -r .token)"
if [ -n "\${TOKEN}" ] && [ "\${TOKEN}" != "null" ]; then
    mkdir -p /root/secrets/digitalocean.com/serviceaccount/
    echo "\${TOKEN}" > /root/secrets/digitalocean.com/serviceaccount/token
    echo "\${TEAM_UUID}" > /root/secrets/digitalocean.com/serviceaccount/team_uuid
    echo "\${THIS_ENDPOINT}" > /root/secrets/digitalocean.com/serviceaccount/base_url
    systemctl start --no-block setup-websocat.service 2>/dev/null || true
fi
`;

    const provisionUnitContent = `[Unit]
Description=Provisioning Token Exchange
After=ssh.service network-online.target
Wants=network-online.target
ConditionPathExists=!/root/secrets/digitalocean.com/serviceaccount/base_url

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/provisioning-token.sh

[Install]
WantedBy=multi-user.target
`;

    const onNetworkScriptContent = `#!/usr/bin/env bash
set -euo pipefail
# Wait for accept.json (injected by bidder) and OIDC token (from provisioning-token.service)
ACCEPT_JSON=/root/secrets/publicdomainrelay.com/market/accept.json
for i in \$(seq 1 30); do
  [ -f "\${ACCEPT_JSON}" ] && [ -f /root/secrets/digitalocean.com/serviceaccount/token ] && break
  sleep 2
done
[ ! -f "\${ACCEPT_JSON}" ] && { echo "accept.json not found, skipping onNetwork"; exit 0; }
TOKEN=\$(cat /root/secrets/digitalocean.com/serviceaccount/token 2>/dev/null)
BASE_URL=\$(cat /root/secrets/digitalocean.com/serviceaccount/base_url 2>/dev/null)
[ -z "\${TOKEN}" ] && { echo "no OIDC token, skipping onNetwork"; exit 0; }
[ -z "\${BASE_URL}" ] && BASE_URL="https://xrpc.fedproxy.com"

ACCEPT_URI=\$(jq -r '.accept.uri // empty' "\${ACCEPT_JSON}" 2>/dev/null)
ACCEPT_CID=\$(jq -r '.accept.cid // empty' "\${ACCEPT_JSON}" 2>/dev/null)
[ -z "\${ACCEPT_URI}" ] && { echo "no accept URI in accept.json"; exit 1; }

# Wait for tunnel-subscriber to write its dispatcher FQDN
FQDN=""
for i in \$(seq 1 30); do
  FQDN=\$(cat /run/guest-fqdn 2>/dev/null) && [ -n "\${FQDN}" ] && break
  sleep 2
done
[ -z "\${FQDN}" ] && FQDN=\$(hostname 2>/dev/null || echo "guest")
curl -sf --retry 10 --retry-delay 5 --retry-max-time 120 \\
  -X POST "\${BASE_URL}/v1/on-network" \\
  -H "Authorization: Bearer \${TOKEN}" \\
  -H "Content-Type: application/json" \\
  -d "\$(jq -n --arg au "\${ACCEPT_URI}" --arg ac "\${ACCEPT_CID}" --arg addr "\${FQDN}" \\
    '{acceptUri: \$au, acceptCid: \$ac, address: \$addr, createdAt: (now | todate)}')"
echo "onNetwork reported OK"
`;

    const onNetworkUnitContent = `[Unit]
Description=Report onNetwork to compute provider
After=provisioning-token.service tunnel-subscriber.service
Wants=provisioning-token.service tunnel-subscriber.service
ConditionPathExists=/root/secrets/publicdomainrelay.com/market/accept.json

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/send-onnetwork.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`;

    writeFiles.push({
      path: "/usr/local/bin/send-onnetwork.sh",
      permissions: "0700",
      content: onNetworkScriptContent,
    });
    writeFiles.push({
      path: "/etc/systemd/system/guest-onnetwork.service",
      permissions: "0644",
      content: onNetworkUnitContent,
    });

    writeFiles.push({
      path: "/usr/local/bin/provisioning-token.sh",
      permissions: "0700",
      content: provisionScriptContent,
    });
    writeFiles.push({
      path: "/etc/systemd/system/provisioning-token.service",
      permissions: "0644",
      content: provisionUnitContent,
    });

    runcmd.unshift("systemctl start --no-block guest-onnetwork.service");
    runcmd.unshift("systemctl enable guest-onnetwork.service");
    runcmd.unshift("systemctl start --no-block provisioning-token.service");
    runcmd.unshift("systemctl enable provisioning-token.service");
    runcmd.unshift("systemctl daemon-reload");

    userDataObj["write_files"] = writeFiles;
    userDataObj["runcmd"] = runcmd;

    const finalUserData = "#cloud-config\n" + yamlStringify(userDataObj, { lineWidth: 0 });

    return new ProvisioningData({ nonce, token, userData: finalUserData });
  }

  associateWithDroplet(dropletId: string): void {
    if (!dropletId) return;
    _nonceStore.createProvisioningNonce(this.nonce, dropletId);
  }
}

async function getPublicKeyFromSshd(
  publicIpv4: string,
  port: number,
  containerName?: string,
): Promise<string> {
  const containerCli = (() => { try { Deno.statSync("/usr/local/bin/container"); return "/usr/local/bin/container"; } catch { return "docker"; } })();
  const deadline = Date.now() + 300_000;
  while (Date.now() < deadline) {
    try {
      let cmd: Deno.Command;
      if (containerName) {
        cmd = new Deno.Command(containerCli, {
          args: ["exec", containerName, "ssh-keyscan", "-t", "ed25519", "-p", String(port), "127.0.0.1"],
          stdout: "piped", stderr: "piped",
        });
      } else {
        cmd = new Deno.Command("ssh-keyscan", {
          args: ["-t", "ed25519", "-p", String(port), publicIpv4],
          stdout: "piped", stderr: "piped",
        });
      }
      const { code, stdout } = await cmd.output();
      const out = new TextDecoder().decode(stdout).trim();

      if (code === 0) {
        const line = out.split("\n").find((l) => l.includes("ed25519"));
        if (line) {
          const parts = line.split(" ");
          return parts.slice(1).join(" ");
        }
      }
    } catch {
      /* retry */
    }
    await new Promise((r) => setTimeout(r, 2_000));
  }
  throw new Error(`ssh-keyscan timed out for ${publicIpv4}:${port}`);
}

async function validateSshSignature(
  publicKeyOpensshString: string,
  sshSignatureBlob: string,
  dataThatWasSigned: string,
): Promise<boolean> {
  const tmpDir = await Deno.makeTempDir();
  try {
    await Deno.writeTextFile(`${tmpDir}/allowed_signing_key.pub`, `* ${publicKeyOpensshString}`);
    await Deno.writeTextFile(`${tmpDir}/signature`, sshSignatureBlob);
    const dataPath = `${tmpDir}/data`;
    await Deno.writeTextFile(dataPath, dataThatWasSigned);

    const dataBytes = await Deno.readFile(dataPath);
    const child = new Deno.Command("ssh-keygen", {
      args: [
        "-Y", "check-novalidate",
        "-n", "prove-sshd",
        "-f", "allowed_signing_key.pub",
        "-s", "signature",
      ],
      cwd: tmpDir,
      stdin: "piped",
      stdout: "piped",
      stderr: "piped",
    }).spawn();
    const writer = child.stdin.getWriter();
    await writer.write(dataBytes);
    await writer.close();
    const { code } = await child.output();
    return code === 0;
  } finally {
    await Deno.remove(tmpDir, { recursive: true }).catch(() => {});
  }
}

async function provisioningValidate(
  token: string,
  signature: string,
  port: number,
  dropletGetter: (id: string) => Record<string, unknown> | Promise<Record<string, unknown> | undefined> | undefined,
): Promise<{ oidcToken: OIDCToken; droplet: Record<string, unknown> } | null> {
  const oidcToken = await OIDCToken.validate(token);
  const nonce = oidcToken.claims["nonce"] as string | undefined;
  if (!nonce) throw new Error("provisioning token missing nonce claim");

  const dropletId = _nonceStore.getProvisioningNonceDropletId(nonce);
  const droplet = await dropletGetter(dropletId);
  if (!droplet) throw new Error(`droplet ${dropletId} not found`);

  const networks = droplet["networks"] as { v4: { ip_address: string; type: string }[] } | undefined;
  const publicIpv4 = networks?.v4.find((n) => n.type === "public")?.ip_address;
  if (!publicIpv4) throw new Error(`no public IPv4 for droplet ${dropletId}`);

  const containerName = droplet["containerName"] as string | undefined;
  const publicKey = await getPublicKeyFromSshd(publicIpv4, port, containerName);

  const valid = await validateSshSignature(publicKey, signature, token);
  if (!valid) return null;
  return { oidcToken, droplet };
}

export async function raiseIfUnauthorized(
  service: string,
  scope: string,
  token: string,
  path: string,
  method: string,
  plcDirectoryUrl = "https://plc.directory",
  log: (level: string, msg: string, meta?: Record<string, unknown>) => void = () => {},
): Promise<AuthToken> {
  const unverifiedPayload = (() => {
    try {
      const [, payloadB64] = token.split(".");
      return JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")));
    } catch {
      return {};
    }
  })();

  const rawAud = Array.isArray(unverifiedPayload.aud)
    ? unverifiedPayload.aud[0]
    : unverifiedPayload.aud as string ?? "";

  let rbac = null;
  let getIssuers: ((api: string, actx: string) => Promise<string[]>) | undefined;

  let { actx, api } = parseAudience(rawAud);
  if (actx.includes(".")) {
    actx = "did:web:" + actx;
  } else {
    actx = "did:plc:" + actx;
  }

  log("info", "rbac gate", { actx, api, service, scope, path, method, rawAud });

  let pdsURL = "";
  try {
    pdsURL = await resolvePDS(actx, plcDirectoryUrl);
    log("info", "rbac gate resolved pds", { actx, pdsURL });
    rbac = await getRBACRecord(pdsURL, actx, service, scope, log);
    const issuers = collectIssuers(rbac);
    log("info", "rbac gate issuers", { actx, issuers });
    getIssuers = async (_api: string, _actx: string) => issuers;
    void api;
  } catch (err) {
    log("warn", "rbac gate resolve failed", { actx, service, scope, pdsURL, error: String(err) });
    throw new UnauthorizedException(
      `failed to resolve RBAC for actx=${actx}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const oidcToken = await OIDCToken.validate(token, getIssuers);
  log("info", "rbac gate token validated", { actx, sub: oidcToken.sub });

  if (rbac) {
    checkRBACPolicy(rbac, oidcToken.sub, path, method);
    log("info", "rbac gate authorized", { actx, sub: oidcToken.sub, path, method });
  }

  return oidcToken as AuthToken;
}

export function createOidcIssuer(opts: OidcIssuerOptions): OidcIssuer {
  const { getIssuerUrl, getDroplet } = opts;
  const plcDirectoryUrl = opts.plcDirectoryUrl ?? "https://plc.directory";
  const log = opts.log ?? noopLogger;

  configureOidc({ getIssuerUrl });

  const app = new Hono<{ Variables: { authToken: AuthToken; actx: string } }>();

  app.use("*", cors());

  app.use("*", async (c, next) => {
    log("info", "oidc request", { method: c.req.method, path: c.req.path });
    await next();
  });

  app.get("/.well-known/openid-configuration", async (c) => {
    await getPublicJwk();
    const issuerUrl = getIssuerUrl();
    return c.json({
      issuer: issuerUrl,
      jwks_uri: `${issuerUrl}/.well-known/jwks`,
      response_types_supported: ["id_token"],
      claims_supported: ["sub", "aud", "exp", "iat", "iss", "actx"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid"],
    });
  });

  app.get("/.well-known/jwks", async (c) => {
    const jwk = await getPublicJwk();
    return c.json({ keys: [jwk] });
  });

  app.use("/v1/oidc/issue", async (c, next) => {
    try {
      const token = extractBearer(c.req.header("Authorization"));
      const authToken = await raiseIfUnauthorized(
        getIssuerUrl(),
        "droplets.wid",
        token,
        "/v1/oidc/issue",
        c.req.method,
        plcDirectoryUrl,
        log,
      );
      c.set("authToken", authToken);
      c.set("actx", authToken.actx);
      await next();
    } catch (err) {
      log("warn", "rbac denied /v1/oidc/issue", { error: String(err) });
      return c.json({ id: "unauthorized", message: String(err) }, 401);
    }
  });

  app.post("/v1/oidc/issue", async (c) => {
    try {
      const body = await c.req.json<Record<string, unknown>>();
      const authToken = c.get("authToken") as AuthToken;
      const actx = authToken.actx;

      const sub = (body["sub"] as string | undefined) ?? actx;
      if (!subMatchesActx(sub, actx)) {
        log("warn", "issue sub mismatch", { actx, sub });
        return c.json({ id: "unauthorized", message: `sub must be scoped to actx:${actx}` }, 401);
      }

      const token = await OIDCToken.create(actx, { ...body, sub });
      log("info", "issue token", { actx, sub });
      return c.json({ token: token.asString });
    } catch (err) {
      log("error", "oidc issue failed", { error: String(err) });
      return c.json({ id: "server_error", message: String(err) }, 500);
    }
  });

  app.post("/v1/oidc/prove", async (c) => {
    try {
      const body = await c.req.json<{ sig: string; port: number }>();
      const token = extractBearer(c.req.header("Authorization"));

      const provToken = await OIDCToken.validate(token);
      const actx = provToken.actx;
      log("info", "prove start", { actx, sub: provToken.sub, port: body.port });

      const result = await provisioningValidate(token, body.sig, body.port, async (id) => {
        return await getDroplet(id);
      });
      if (!result) {
        log("warn", "prove rejected", { actx, reason: "provisioningValidate returned null" });
        return c.json({ valid: false });
      }

      const { oidcToken, droplet } = result;
      const dropletTags = ((droplet["tags"] as string[]) ?? []);
      const subject = [
        `actx:${oidcToken.actx}`,
        ...dropletTags
          .filter((t) => t.startsWith("oidc-sub:") && t.split(":").length === 3 && t.split(":")[1] !== "actx")
          .map((t) => t.split(":")[1] + ":" + t.split(":")[2]),
      ].join(":");

      const issued = await OIDCToken.create(oidcToken.actx, {
        sub: subject,
        droplet_id: droplet["id"],
      });
      log("info", "prove issued", { actx: oidcToken.actx, sub: subject, dropletId: droplet["id"] });
      return c.json({ token: issued.asString });
    } catch (err) {
      log("error", "oidc prove failed", { error: String(err), stack: err instanceof Error ? err.stack : undefined });
      return c.json({ id: "unauthorized", message: String(err) }, 401);
    }
  });

  return { app };
}

export function createOidcProvisioningEnricher(
  getIssuerUrl: () => string,
): OidcProvisioningEnricher {
  return {
    async enrich(userData: string, teamUuid: string, issuerUrl: string) {
      configureOidc({ getIssuerUrl });
      const pd = await ProvisioningData.create(teamUuid, userData, issuerUrl);
      return {
        userData: pd.userData,
        nonce: pd.nonce,
        associateWithDroplet(dropletId: string): void {
          pd.associateWithDroplet(dropletId);
        },
      };
    },
  };
}
