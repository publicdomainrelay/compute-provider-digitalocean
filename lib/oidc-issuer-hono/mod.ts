import { Hono } from "hono";
import { cors } from "hono/cors";
import { buildUserData } from "@publicdomainrelay/cloud-init-common";
import * as jose from "jose";
import type { Logger } from "@publicdomainrelay/logger";
import { noopLogger } from "@publicdomainrelay/logger";
import {
  type AuthToken,
  type DropletGetter,
  type IssuersForAudience,
  type JwkStore,
  type NonceStore,
  type OIDCTokenData,
  type OidcIssuer,
  type OidcIssuerOptions,
  type OidcProvisioningEnricher,
  type ProvisioningData,
  parseAudience,
  UnauthorizedException,
} from "@publicdomainrelay/oidc-issuer-abc";
import {
  checkRBACPolicy,
  collectIssuers,
  getRBACRecord,
  resolvePDS,
} from "@publicdomainrelay/rbac-atproto";

export type {
  AuthToken,
  DropletGetter,
  JwkStore,
  Logger,
  NonceStore,
  OIDCTokenData,
  OidcIssuer,
  OidcIssuerOptions,
  OidcProvisioningEnricher,
  ProvisioningData,
};
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

export function createMemoryJwkStore(): JwkStore {
  const m = new Map<string, string>();
  return {
    getJwkPem: (issuer) => m.get(issuer) ?? null,
    saveJwkPem: (issuer, pem) => {
      m.set(issuer, pem);
    },
  };
}

export function createMemoryNonceStore(): NonceStore {
  const m = new Map<string, string>();
  return {
    createProvisioningNonce: (nonce, dropletId) => {
      m.set(nonce, dropletId);
    },
    getProvisioningNonceDropletId: (nonce) => {
      const id = m.get(nonce);
      if (id === undefined) throw new Error(`Nonce ${nonce} not found`);
      m.delete(nonce);
      return id;
    },
  };
}

const DEFAULT_TOKEN_TTL_SECONDS = 60 * 60 * 24;
const DEFAULT_NONCE_LEN = 64;
const DEFAULT_PROVISIONING_TTL_SECONDS = 60 * 15;

async function signingKeyFromPem(storedPem: string): Promise<CryptoKeyPair> {
  const pemBody = storedPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));
  const priv = await crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true,
    ["sign"],
  );
  const jwk = await jose.exportJWK(priv);
  const pubJwk = { ...jwk, d: undefined, dp: undefined, dq: undefined, p: undefined, q: undefined, qi: undefined };
  const pub = await crypto.subtle.importKey(
    "jwk",
    pubJwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true,
    ["verify"],
  );
  return { privateKey: priv, publicKey: pub };
}

async function getPublicKeyFromSshd(
  publicIpv4: string,
  port: number,
  containerName?: string,
): Promise<string> {
  const containerCli = (() => {
    try {
      Deno.statSync("/usr/local/bin/container");
      return "/usr/local/bin/container";
    } catch {
      return "docker";
    }
  })();
  const deadline = Date.now() + 300_000;
  while (Date.now() < deadline) {
    try {
      let cmd: Deno.Command;
      if (containerName) {
        cmd = new Deno.Command(containerCli, {
          args: ["exec", containerName, "ssh-keyscan", "-t", "ed25519", "-p", String(port), "127.0.0.1"],
          stdout: "piped",
          stderr: "piped",
        });
      } else {
        cmd = new Deno.Command("ssh-keyscan", {
          args: ["-t", "ed25519", "-p", String(port), publicIpv4],
          stdout: "piped",
          stderr: "piped",
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
        "-Y",
        "check-novalidate",
        "-n",
        "prove-sshd",
        "-f",
        "allowed_signing_key.pub",
        "-s",
        "signature",
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

export function createOidcIssuer(opts: OidcIssuerOptions): OidcIssuer {
  const getIssuerUrl = opts.getIssuerUrl;
  const getDroplet: DropletGetter = opts.getDroplet ?? (() => undefined);
  const plcDirectoryUrl = opts.plcDirectoryUrl ?? "https://plc.directory";
  const log = opts.log ?? noopLogger;
  const jwkStore = opts.store ?? createMemoryJwkStore();
  const nonceStore = opts.nonceStore ?? createMemoryNonceStore();
  const trustedIssuerUrls = [...(opts.trustedIssuerUrls ?? [])];
  const defaultTtlSeconds = opts.defaultTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
  const remoteJwks = new Map<string, ReturnType<typeof jose.createRemoteJWKSet>>();

  let signingKey: Promise<CryptoKeyPair> | null = null;
  let publicJwk: Promise<jose.JWK> | null = null;

  async function loadOrGenerateSigningKey(): Promise<CryptoKeyPair> {
    const issuer = getIssuerUrl();
    const storedPem = await jwkStore.getJwkPem(issuer);
    if (storedPem) return await signingKeyFromPem(storedPem);
    const generated = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    );
    const pem = await jose.exportPKCS8(generated.privateKey);
    await jwkStore.saveJwkPem(issuer, pem);
    return generated;
  }

  function getSigningKey(): Promise<CryptoKeyPair> {
    signingKey ??= loadOrGenerateSigningKey().catch((err) => {
      signingKey = null;
      throw err;
    });
    return signingKey;
  }

  async function derivePublicJwk(): Promise<jose.JWK> {
    const keys = await getSigningKey();
    const jwk = await jose.exportJWK(keys.publicKey);
    jwk.use = "sig";
    jwk.alg = "RS256";
    jwk.kid = await jose.calculateJwkThumbprint(jwk);
    return jwk;
  }

  function getPublicJwk(): Promise<jose.JWK> {
    publicJwk ??= derivePublicJwk().catch((err) => {
      publicJwk = null;
      throw err;
    });
    return publicJwk;
  }

  function getRemoteJwks(jwksUri: string) {
    let jwks = remoteJwks.get(jwksUri);
    if (!jwks) {
      jwks = jose.createRemoteJWKSet(new URL(jwksUri));
      remoteJwks.set(jwksUri, jwks);
    }
    return jwks;
  }

  function requireIssuerBaseUrl(): string {
    let issuerUrl: string;
    try {
      issuerUrl = getIssuerUrl();
    } catch (err) {
      throw new Error(`refusing provisioning: no issuer base URL (${err instanceof Error ? err.message : String(err)})`);
    }
    let protocol = "";
    try {
      protocol = new URL(issuerUrl).protocol;
    } catch {
      protocol = "";
    }
    if (protocol !== "https:" && protocol !== "http:") {
      throw new Error(`refusing provisioning: issuer base URL is not an http(s) URL: '${issuerUrl}'`);
    }
    return issuerUrl;
  }

  async function createToken(
    actx: string,
    claims: Record<string, unknown>,
    api = "DigitalOcean",
  ): Promise<OIDCTokenData> {
    const keys = await getSigningKey();
    const jwk = await getPublicJwk();
    const issuerUrl = getIssuerUrl();
    let audience = `api://${api}?actx=${actx}`;

    const sub = claims["sub"] as string | undefined;
    if (!subMatchesActx(sub, actx)) {
      throw new Error(`'actx:${actx}' not found in sub '${sub}'`);
    }

    const payload = { ...claims };
    delete payload["ttl"];

    const ttl = typeof claims["ttl"] === "number" ? claims["ttl"] as number : defaultTtlSeconds;
    const expTime = Math.floor(Date.now() / 1000) + ttl;

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

    return {
      actx,
      api,
      aud: audience,
      sub: sub!,
      claims: { ...payload, iss: issuerUrl, aud: audience },
      asString: token,
    };
  }

  async function validateToken(token: string, getIssuers?: IssuersForAudience): Promise<OIDCTokenData> {
    if (!token || token === "0") throw new UnauthorizedException("Unable to authenticate you, no token");
    if (token.split(".").length !== 3) throw new UnauthorizedException("Invalid token");

    const issuerUrl = getIssuerUrl();

    const unverified = jose.decodeJwt(token);
    const rawAud = Array.isArray(unverified.aud) ? unverified.aud[0] : unverified.aud as string;
    const { actx, api } = parseAudience(rawAud ?? "");
    const expectedAud = `api://${api}?actx=${actx}`;

    const extraIssuers = (getIssuers ? await getIssuers(api, actx) : []).filter((issuer) =>
      trustedIssuerUrls.includes(issuer)
    );
    const issuers = [...new Set([issuerUrl, ...extraIssuers])];

    let lastErr: Error = new Error("no issuers");
    for (const issuer of issuers) {
      try {
        let jwks: jose.JWTVerifyGetKey;
        if (issuer === issuerUrl) {
          const keys = await getSigningKey();
          jwks = keys.publicKey as unknown as jose.JWTVerifyGetKey;
        } else {
          const openidConfig = await fetch(`${issuer}/.well-known/openid-configuration`).then((r) => r.json()) as {
            jwks_uri: string;
          };
          jwks = getRemoteJwks(openidConfig.jwks_uri);
        }

        const { payload } = await jose.jwtVerify(token, jwks, {
          issuer,
          audience: expectedAud,
        });

        return {
          actx,
          api,
          aud: expectedAud,
          sub: payload.sub!,
          claims: payload as Record<string, unknown>,
          asString: token,
        };
      } catch (e) {
        lastErr = e as Error;
      }
    }
    throw new UnauthorizedException(`OIDC token failed validation: ${lastErr.message}`);
  }

  async function raiseIfUnauthorized(
    service: string,
    scope: string,
    token: string,
    path: string,
    method: string,
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

    const caller = parseAudience(rawAud);
    log("info", "rbac gate", { actx: caller.actx, api: caller.api, service, scope, path, method, rawAud });

    const signatureVerifiedToken = await validateToken(token, () => trustedIssuerUrls);

    const actx = signatureVerifiedToken.actx.includes(".")
      ? "did:web:" + signatureVerifiedToken.actx
      : "did:plc:" + signatureVerifiedToken.actx;

    let rbac = null;
    let issuers: string[] = [];
    let pdsURL = "";
    try {
      pdsURL = await resolvePDS(actx, plcDirectoryUrl);
      log("info", "rbac gate resolved pds", { actx, pdsURL });
      rbac = await getRBACRecord(pdsURL, actx, service, scope, log);
      issuers = collectIssuers(rbac);
      log("info", "rbac gate issuers", { actx, issuers });
    } catch (err) {
      log("warn", "rbac gate resolve failed", { actx, service, scope, pdsURL, error: String(err) });
      throw new UnauthorizedException(
        `failed to resolve RBAC for actx=${actx}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    if (issuers.length > 0) {
      await validateToken(token, () => issuers.filter((issuer) => trustedIssuerUrls.includes(issuer)));
    }

    log("info", "rbac gate token validated", { actx, sub: signatureVerifiedToken.sub });

    if (rbac) {
      checkRBACPolicy(rbac, signatureVerifiedToken.sub, path, method);
      log("info", "rbac gate authorized", { actx, sub: signatureVerifiedToken.sub, path, method });
    }

    return signatureVerifiedToken as AuthToken;
  }

  async function createProvisioningData(
    teamUuid: string,
    baseUserData: string | null,
    provisioningOpts: { ttl?: number; nonceLen?: number } = {},
  ): Promise<ProvisioningData> {
    const issuerUrl = requireIssuerBaseUrl();
    const userData = baseUserData ?? "";
    const nonceLen = provisioningOpts.nonceLen ?? DEFAULT_NONCE_LEN;
    const ttl = provisioningOpts.ttl ?? DEFAULT_PROVISIONING_TTL_SECONDS;

    const nonceBytes = crypto.getRandomValues(new Uint8Array(nonceLen / 2));
    const nonce = Array.from(nonceBytes).map((b) => b.toString(16).padStart(2, "0")).join("");

    const token = await createToken(teamUuid, {
      nonce,
      sub: `actx:${teamUuid}:role:provisioning:nonce:${nonce}`,
      ttl,
    });

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
[ -z "\${BASE_URL}" ] && { echo "guest-onnetwork: no issuer base_url, not reporting"; exit 1; }

ACCEPT_URI=\$(jq -r '.accept.uri // empty' "\${ACCEPT_JSON}" 2>/dev/null)
ACCEPT_CID=\$(jq -r '.accept.cid // empty' "\${ACCEPT_JSON}" 2>/dev/null)
[ -z "\${ACCEPT_URI}" ] && { echo "no accept URI in accept.json"; exit 1; }

# Wait for the transport (iroh listener or tunnel-subscriber) to write the address
# a requester dials. Without it there is nothing reachable to report.
FQDN=""
for i in \$(seq 1 300); do
  FQDN=\$(cat /run/guest-fqdn 2>/dev/null) && [ -n "\${FQDN}" ] && break
  sleep 2
done
if [ -z "\${FQDN}" ]; then
  echo "guest-onnetwork: no /run/guest-fqdn after 600s, not reporting"
  systemctl list-jobs --no-pager 2>&1 | tail -20
  systemctl status iroh.service tunnel-subscriber.service ssh.service --no-pager 2>&1 | tail -40
  exit 1
fi
echo "guest-onnetwork: reporting \${FQDN}"
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
After=provisioning-token.service tunnel-subscriber.service iroh.service
Wants=provisioning-token.service tunnel-subscriber.service
ConditionPathExists=/root/secrets/publicdomainrelay.com/market/accept.json

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=900
ExecStart=/usr/local/bin/send-onnetwork.sh
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
`;

    const finalUserData = buildUserData({
      base: userData,
      modules: [() => ({
        disable_root: false,
        ssh_pwauth: false,
        write_files: [
          { path: "/usr/local/bin/send-onnetwork.sh", permissions: "0700", content: onNetworkScriptContent },
          { path: "/etc/systemd/system/guest-onnetwork.service", permissions: "0644", content: onNetworkUnitContent },
          { path: "/usr/local/bin/provisioning-token.sh", permissions: "0700", content: provisionScriptContent },
          { path: "/etc/systemd/system/provisioning-token.service", permissions: "0644", content: provisionUnitContent },
        ],
        runcmdPrepend: [
          "[ -d /root/.ssh ] && chmod 700 /root/.ssh || true",
          "sed -i 's/^root:[^:]*:[^:]*:[^:]*:[^:]*:/root::19000:0:99999:/' /etc/shadow || true",
          "systemctl daemon-reload",
          "systemctl enable provisioning-token.service",
          "systemctl start --no-block provisioning-token.service",
          "systemctl enable guest-onnetwork.service",
          "systemctl start --no-block guest-onnetwork.service",
        ],
      })],
    });

    return {
      nonce,
      token,
      userData: finalUserData,
      associateWithDroplet(dropletId: string): void {
        if (!dropletId) return;
        nonceStore.createProvisioningNonce(nonce, dropletId);
      },
    };
  }

  async function provisioningValidate(
    token: string,
    signature: string,
    port: number,
  ): Promise<{ oidcToken: OIDCTokenData; droplet: Record<string, unknown> } | null> {
    const oidcToken = await validateToken(token);
    const nonce = oidcToken.claims["nonce"] as string | undefined;
    if (!nonce) throw new Error("provisioning token missing nonce claim");

    const dropletId = await nonceStore.getProvisioningNonceDropletId(nonce);
    const droplet = await getDroplet(dropletId);
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

  const provisioningEnricher: OidcProvisioningEnricher = {
    async enrich(userData: string | null, teamUuid: string) {
      const pd = await createProvisioningData(teamUuid, userData);
      return {
        userData: pd.userData,
        nonce: pd.nonce,
        associateWithDroplet: (dropletId: string) => pd.associateWithDroplet(dropletId),
      };
    },
  };

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

      const token = await createToken(actx, { ...body, sub });
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

      const provToken = await validateToken(token);
      const actx = provToken.actx;
      log("info", "prove start", { actx, sub: provToken.sub, port: body.port });

      const result = await provisioningValidate(token, body.sig, body.port);
      if (!result) {
        log("warn", "prove rejected", { actx, reason: "provisioningValidate returned null" });
        return c.json({ valid: false });
      }

      const { oidcToken, droplet } = result;
      const dropletTags = (droplet["tags"] as string[]) ?? [];
      const subject = [
        `actx:${oidcToken.actx}`,
        ...dropletTags
          .filter((t) => t.startsWith("oidc-sub:") && t.split(":").length === 3 && t.split(":")[1] !== "actx")
          .map((t) => t.split(":")[1] + ":" + t.split(":")[2]),
      ].join(":");

      const issued = await createToken(oidcToken.actx, {
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

  return {
    app,
    getIssuerUrl,
    getSigningKey,
    getPublicJwk,
    createToken,
    validateToken,
    raiseIfUnauthorized,
    createProvisioningData,
    provisioningEnricher,
  };
}
