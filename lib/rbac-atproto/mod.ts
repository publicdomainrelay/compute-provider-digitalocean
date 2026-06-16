import type { StrongRef } from "@publicdomainrelay/compute-provider";

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
