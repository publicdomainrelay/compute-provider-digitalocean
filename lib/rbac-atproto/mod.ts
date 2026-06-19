import type { RbacProvisioner, StrongRef } from "@publicdomainrelay/compute-provider-abc";
import { UnauthorizedException, type AuthToken } from "@publicdomainrelay/oidc-issuer-abc";

const RBAC_NSID = "com.fedproxy.rbac";

export interface RbacRecordOpts {
  roleName?: string;
  serviceBaseUrl: string;
  scope?: string;
  createdAt?: string;
}

export function buildRbacRecord(
  agentDidPlc: string,
  requesterPlc: string,
  role: string,
  opts: RbacRecordOpts,
): Record<string, unknown> {
  const serviceBaseUrl = opts.serviceBaseUrl;
  const scope = opts.scope ?? "droplets.wid";
  const slug = `${agentDidPlc}-${requesterPlc}-${role}`;
  const roleName = opts.roleName ?? `ex-${slug}`;
  const subject = `actx:${agentDidPlc}:plc:${requesterPlc}:role:${role}`;

  return {
    $type: RBAC_NSID,
    protects: {
      [roleName]: { service: serviceBaseUrl, scope },
    },
    roles: {
      [roleName]: {
        role_name: roleName,
        definition: {
          aud: `api://DigitalOcean?actx=${agentDidPlc}`,
          sub: subject,
          policies: [roleName],
        },
      },
    },
    policies: {
      [roleName]: {
        meta: { policy: roleName },
        schemas: {
          "/v1/oidc/issue": {
            type: "object",
            $schema: "http://json-schema.org/draft-07/schema#",
            required: ["capability", "allowed_parameters"],
            properties: {
              capability: { enum: ["create"] },
              allowed_parameters: {
                type: "object",
                properties: {
                  aud: { type: "string" },
                  sub: { type: "string", const: subject },
                  ttl: { type: "number", const: 3600 },
                },
              },
            },
          },
        },
      },
    },
    custom_claims_roles_index: { job_workflow_ref: {} },
    createdAt: opts.createdAt ?? new Date().toISOString(),
  };
}

export interface RbacContext {
  getAgentDid: () => string;
  getIssuerUrl: () => string;
  createRecord: (collection: string, record: Record<string, unknown>) => Promise<StrongRef>;
  deleteRecord?: (collection: string, rkey: string) => Promise<void>;
  parseAtUri: (uri: string) => { repo: string; collection: string; rkey: string };
  log?: (level: string, msg: string, meta?: Record<string, unknown>) => void;
}

const noopLog = (_l: string, _m: string, _e?: Record<string, unknown>) => {};

export async function configureRbac(
  vm: { role: string },
  requesterDid: string,
  ctx: RbacContext,
): Promise<StrongRef> {
  const log = ctx.log ?? noopLog;
  const agentDidPlc = ctx.getAgentDid().split(":").slice(-1)[0];
  const requesterPlc = requesterDid.split(":").slice(-1)[0];

  const record = buildRbacRecord(agentDidPlc, requesterPlc, vm.role, {
    serviceBaseUrl: ctx.getIssuerUrl(),
  });

  log("info", "creating rbac record", { nsid: RBAC_NSID, roleName: `ex-${agentDidPlc}-${requesterPlc}-${vm.role}` });
  const rbacRef = await ctx.createRecord(RBAC_NSID, record);
  log("info", "rbac record created", { nsid: RBAC_NSID, uri: rbacRef.uri });
  return rbacRef;
}

export async function deleteRbac(
  rbacRef: StrongRef,
  reason: string,
  ctx: RbacContext,
): Promise<void> {
  const log = ctx.log ?? noopLog;
  if (!ctx.deleteRecord) {
    log("warn", "no deleteRecord configured, skipping rbac delete", { uri: rbacRef.uri, reason });
    return;
  }
  const { collection, rkey } = ctx.parseAtUri(rbacRef.uri);
  log("info", "deleting rbac record", { uri: rbacRef.uri, collection, rkey, reason });
  try {
    await ctx.deleteRecord(collection, rkey);
    log("info", "rbac record deleted", { uri: rbacRef.uri, reason });
  } catch (err) {
    log("error", "failed to delete rbac record", { uri: rbacRef.uri, reason, err: String(err) });
  }
}

export interface RBACPolicy {
  meta: Record<string, string>;
  schemas: Record<string, RBACSchema>;
}

export interface RBACSchema {
  properties: {
    capability: { enum: string[] };
    body?: unknown;
  };
}

export interface RBACRoleDefinition {
  iss?: string;
  aud?: string;
  sub: string;
  policies: string[];
}

export interface RBACRole {
  role_name: string;
  definition: RBACRoleDefinition;
}

export interface RBACProtects {
  service: string;
  scope?: string;
}

export interface RBACRecord {
  protects?: Record<string, RBACProtects>;
  policies: Record<string, RBACPolicy>;
  roles: Record<string, RBACRole>;
}

export type { AuthToken };

export async function resolvePDS(
  did: string,
  plcDirectoryUrl = "https://plc.directory",
): Promise<string> {
  let didDoc: { service?: { id: string; type: string; serviceEndpoint: string }[] };

  if (did.startsWith("did:plc:")) {
    const res = await fetch(`${plcDirectoryUrl}/${encodeURIComponent(did)}`);
    if (!res.ok) throw new Error(`PLC lookup failed for ${did}: ${res.status}`);
    didDoc = await res.json();
  } else if (did.startsWith("did:web:")) {
    const host = did.slice("did:web:".length).replace(/:/g, "/");
    const res = await fetch(`https://${host}/.well-known/did.json`);
    if (!res.ok) throw new Error(`did:web lookup failed for ${did}: ${res.status}`);
    didDoc = await res.json();
  } else {
    throw new Error(`unsupported DID method: ${did}`);
  }

  const pds = didDoc.service?.find(
    (s) => s.type === "AtprotoPersonalDataServer" || s.id === "#atproto_pds",
  )?.serviceEndpoint;
  if (!pds) throw new Error(`no PDS in DID document for ${did}`);
  return pds;
}

export async function getRBACRecord(
  pdsURL: string,
  did: string,
  service: string,
  scope: string,
  log?: (level: string, msg: string, meta?: Record<string, unknown>) => void,
): Promise<RBACRecord> {
  const joined: RBACRecord = { policies: {}, roles: {} };
  let cursor = "";
  let total = 0;
  let anyProtects = false;
  let scanned = 0;
  const seenServices: string[] = [];

  log?.("info", "rbac lookup start", { pdsURL, did, wantService: service, wantScope: scope });

  for (;;) {
    const url = new URL(`${pdsURL}/xrpc/com.atproto.repo.listRecords`);
    url.searchParams.set("repo", did);
    url.searchParams.set("collection", "com.fedproxy.rbac");
    url.searchParams.set("limit", "100");
    if (cursor) url.searchParams.set("cursor", cursor);

    const res = await fetch(url.toString());
    if (!res.ok) throw new Error(`listRecords failed pds=${pdsURL} did=${did}: ${res.status}`);

    const out = await res.json() as { records: { uri: string; value: RBACRecord }[]; cursor?: string };

    for (const rec of out.records ?? []) {
      const rbac = rec.value;
      scanned++;
      let protectsThis = false;
      for (const [_name, protects] of Object.entries(rbac.protects ?? {})) {
        seenServices.push(`${protects.service}|${protects.scope ?? ""}`);
        if (protects.service === service || protects.service === "*") {
          if (protects.scope === scope || protects.scope === "*" || !protects.scope) {
            protectsThis = true;
          }
          break;
        }
      }
      log?.("info", "rbac record scanned", {
        uri: rec.uri,
        matched: protectsThis,
        protects: Object.values(rbac.protects ?? {}).map((p) => `${p.service}|${p.scope ?? ""}`),
      });
      if (!protectsThis) continue;
      anyProtects = true;
      for (const [name, policy] of Object.entries(rbac.policies ?? {})) {
        joined.policies[name] = policy;
      }
      for (const [name, role] of Object.entries(rbac.roles ?? {})) {
        joined.roles[name] = role;
      }
      total++;
    }

    if (!out.cursor) break;
    cursor = out.cursor;
  }

  if (!anyProtects) {
    log?.("warn", "rbac no match", { did, wantService: service, wantScope: scope, scanned, seenServices });
    throw new Error(
      `no com.fedproxy.rbac records protect did=${did} service=${service} scope=${scope} (scanned=${scanned} seen=[${seenServices.join(", ")}])`,
    );
  }
  if (total === 0) throw new Error(`no com.fedproxy.rbac record found for did=${did}`);
  log?.("info", "rbac matched", { did, total, roles: Object.keys(joined.roles) });
  return joined;
}

export function collectIssuers(rbac: RBACRecord): string[] {
  const seen = new Set<string>();
  for (const role of Object.values(rbac.roles)) {
    const iss = role.definition.iss;
    if (iss) seen.add(iss);
  }
  return [...seen];
}

function globMatch(pattern: string, s: string): boolean {
  if (pattern === "*") return true;
  const parts = pattern.split("*");
  let rest = s;
  for (let i = 0; i < parts.length; i++) {
    const prefix = parts[i];
    if (i === parts.length - 1) return rest === prefix;
    if (prefix.length > 0) {
      const idx = rest.indexOf(prefix);
      if (idx < 0) return false;
      rest = rest.slice(idx + prefix.length);
    }
  }
  return true;
}

function findMatchingSchema(
  schemas: Record<string, RBACSchema>,
  path: string,
): RBACSchema | null {
  if (schemas[path]) return schemas[path];
  let best = "";
  let bestSchema: RBACSchema | null = null;
  for (const [pattern, schema] of Object.entries(schemas)) {
    if (globMatch(pattern, path) && pattern.length > best.length) {
      best = pattern;
      bestSchema = schema;
    }
  }
  return bestSchema;
}

const HTTP_METHOD_CAPABILITY: Record<string, string> = {
  GET: "read",
  HEAD: "read",
  OPTIONS: "read",
  POST: "create",
  PUT: "update",
  PATCH: "update",
  DELETE: "delete",
};

export function checkRBACPolicy(
  rbac: RBACRecord,
  sub: string,
  path: string,
  method: string,
): void {
  const capability = HTTP_METHOD_CAPABILITY[method.toUpperCase()];
  if (!capability) throw new UnauthorizedException(`unsupported HTTP method ${method}`);

  const matchingPolicies: string[] = [];
  for (const role of Object.values(rbac.roles)) {
    if (role.definition.sub === sub) {
      matchingPolicies.push(...role.definition.policies);
    }
  }

  if (matchingPolicies.length === 0) {
    throw new UnauthorizedException(`no matching role found for sub: ${sub}`);
  }

  const denials: string[] = [];
  for (const policyName of matchingPolicies) {
    const policy = rbac.policies[policyName];
    if (!policy) continue;

    const schema = findMatchingSchema(policy.schemas, path);
    if (!schema) continue;

    const allowed = schema.properties.capability.enum;
    if (allowed.includes(capability)) return;

    denials.push(
      `policy '${policyName}': capability '${capability}' not in [${allowed.join(", ")}] for path '${path}'`,
    );
  }

  if (denials.length > 0) throw new UnauthorizedException(denials.join("; "));
  throw new UnauthorizedException(
    `no policy covers path='${path}' for sub='${sub}'`,
  );
}

export function createRbacProvisioner(): RbacProvisioner {
  return {
    async provision(vm, requesterDid, ctx) {
      const rbacCtx: RbacContext = {
        getAgentDid: ctx.getAgentDid,
        getIssuerUrl: ctx.getIssuerUrl,
        createRecord: ctx.createRecord as (
          collection: string,
          record: Record<string, unknown>,
        ) => Promise<StrongRef>,
        parseAtUri: ctx.parseAtUri,
      };
      return configureRbac(vm, requesterDid, rbacCtx);
    },
  };
}
