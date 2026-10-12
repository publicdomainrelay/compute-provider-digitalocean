export const GROUP_NAME = "socialweb.computer";
export const VERSION = "v1alpha1";
export const CONDITION_PREPARED = "Prepared";
export const CONDITION_STARTED = "Started";
export const CONDITION_RUNTIME_OBSERVED = "RuntimeObserved";
export const CONDITION_GUEST_REPORTED = "GuestReported";
export const FINALIZER_COMPUTE_VM = "computevm.socialweb.computer/release";
export const FIELD_MANAGER_COMPUTE_VM_CONTROLLER = "computevm-controller";
export const FIELD_MANAGER_COMPUTE_VM_PROVIDER = "compute-provider-kcp";

export const COMPUTE_VM_PHASES = ["Pending", "Preparing", "Booting", "Running", "Releasing", "Lost", "Failed"] as const;
export type ComputeVMPhase = typeof COMPUTE_VM_PHASES[number];

export const COMPUTE_VM_LOST_REASONS = ["HostRebooted", "UnitGone", "UnitFailed", "OOMKilled", "VMMExited", "IdentityMismatch"] as const;
export type ComputeVMLostReason = typeof COMPUTE_VM_LOST_REASONS[number];

export interface ObjectMeta {
  name?: string;
  generateName?: string;
  namespace?: string;
  uid?: string;
  resourceVersion?: string;
  generation?: number;
  creationTimestamp?: string;
  deletionTimestamp?: string;
  deletionGracePeriodSeconds?: number;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
  finalizers?: string[];
  [key: string]: unknown;
}

export type Condition = Record<string, unknown>;

export interface ComputeVM {
  apiVersion?: string;
  kind?: string;
  metadata?: ObjectMeta;
  spec?: ComputeVMSpec;
  status?: ComputeVMStatus;
}

export interface ComputeVMSpec {
  vm: ComputeVMShape;
  owner: ComputeVMOwner;
  userDataSecret: string;
  requester: ComputeVMRequester;
  contract?: ComputeVMContract;
  image?: ComputeVMImageRequest;
  stopGraceSeconds?: number;
}

export interface ComputeVMShape {
  cpus: number;
  mem: string;
  disk: string;
  role: string;
}

export interface ComputeVMOwner {
  handle: string;
}

export interface ComputeVMRequester {
  did: string;
  plc?: string;
}

export interface ComputeVMContract {
  receiptUri?: string;
  receiptCid?: string;
  acceptUri?: string;
  acceptCid?: string;
  submitEventUrl?: string;
  acceptedAt?: string;
}

export interface ComputeVMImageRequest {
  reuseStale?: boolean;
}

export interface ComputeVMStatus {
  phase?: ComputeVMPhase;
  lostReason?: ComputeVMLostReason;
  observedGeneration?: number;
  network?: ComputeVMNetwork;
  image?: ComputeVMImage;
  runtime?: ComputeVMRuntime;
  workDir?: string;
  bootedAt?: string;
  message?: string;
  conditions?: Condition[];
  market?: ComputeVMMarket;
}

export interface ComputeVMNetwork {
  guestIP?: string;
  hostAddress?: string;
  prefix?: number;
  mac?: string;
}

export interface ComputeVMImage {
  ref?: string;
  sha256?: string;
  hypervisor?: string;
}

export interface ComputeVMRuntime {
  backend?: string;
  ref?: string;
  instance?: string;
  pid?: number;
  startTime?: string;
  hostBootID?: string;
  vmmID?: string;
}

export interface ComputeVMMarket {
  onNetworkUri?: string;
  address?: string;
  hostKeys?: ComputeVMHostKey[];
  hostKeysUri?: string;
  reportedAt?: string;
}

export interface ComputeVMHostKey {
  type: string;
  publicKey: string;
  fingerprint?: string;
}

export interface ApiResource {
  group: string;
  version: string;
  kind: string;
  listKind: string;
  plural: string;
  singular: string;
  schema: string;
  export: string;
}

export const COMPUTE_VM_RESOURCE: ApiResource = {
  group: "socialweb.computer",
  version: "v1alpha1",
  kind: "ComputeVM",
  listKind: "ComputeVMList",
  plural: "computevms",
  singular: "computevm",
  schema: "v1alpha1-1.computevms.socialweb.computer",
  export: "computevms",
};

export const API_RESOURCES: readonly ApiResource[] = [COMPUTE_VM_RESOURCE];

export type ApiTypeName =
  | "ComputeVM"
  | "ComputeVMContract"
  | "ComputeVMHostKey"
  | "ComputeVMImage"
  | "ComputeVMImageRequest"
  | "ComputeVMLostReason"
  | "ComputeVMMarket"
  | "ComputeVMNetwork"
  | "ComputeVMOwner"
  | "ComputeVMPhase"
  | "ComputeVMRequester"
  | "ComputeVMRuntime"
  | "ComputeVMShape"
  | "ComputeVMSpec"
  | "ComputeVMStatus"
  | "Condition"
  | "ObjectMeta";

type Shape =
  | { type: "string"; enum?: readonly string[] }
  | { type: "integer" }
  | { type: "boolean" }
  | { type: "array"; items: Shape }
  | { type: "object"; open: true }
  | { type: "object"; properties: Readonly<Record<string, Shape>>; required: readonly string[] }
  | { ref: ApiTypeName };

export interface ApiIssue {
  path: string;
  message: string;
}

export class ApiValidationError extends Error {
  constructor(readonly typeName: ApiTypeName, readonly issues: readonly ApiIssue[]) {
    super(`invalid ${typeName}: ${issues.map((i) => `${i.path || "(root)"}: ${i.message}`).join("; ")}`);
    this.name = "ApiValidationError";
  }
}

function joinPath(path: string, key: string): string {
  return path === "" ? key : `${path}.${key}`;
}

function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  switch (typeof value) {
    case "object":
      return "an object";
    case "string":
      return "a string";
    case "boolean":
      return "a boolean";
    case "number":
      return "a number";
    default:
      return typeof value;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function check(shape: Shape, value: unknown, path: string, out: ApiIssue[]): void {
  if ("ref" in shape) {
    check(SHAPES[shape.ref], value, path, out);
    return;
  }
  switch (shape.type) {
    case "object": {
      if (!isPlainObject(value)) {
        out.push({ path, message: `expected an object, got ${describe(value)}` });
        return;
      }
      if ("open" in shape) return;
      for (const [name, prop] of Object.entries(shape.properties)) {
        const v = value[name];
        if (v === undefined) {
          if (shape.required.includes(name)) out.push({ path: joinPath(path, name), message: "missing required field" });
          continue;
        }
        check(prop, v, joinPath(path, name), out);
      }
      for (const key of Object.keys(value).sort()) {
        if (!(key in shape.properties) && value[key] !== undefined) {
          out.push({ path: joinPath(path, key), message: "unknown field" });
        }
      }
      return;
    }
    case "array": {
      if (!Array.isArray(value)) {
        out.push({ path, message: `expected an array, got ${describe(value)}` });
        return;
      }
      value.forEach((item, i) => check(shape.items, item, `${path}[${i}]`, out));
      return;
    }
    case "string": {
      if (typeof value !== "string") {
        out.push({ path, message: `expected a string, got ${describe(value)}` });
        return;
      }
      if (shape.enum && !shape.enum.includes(value)) {
        out.push({ path, message: `${JSON.stringify(value)} is not one of ${shape.enum.join(", ")}` });
      }
      return;
    }
    case "integer": {
      if (typeof value !== "number" || !Number.isInteger(value)) {
        out.push({ path, message: `expected an integer, got ${describe(value)}` });
      }
      return;
    }
    case "boolean": {
      if (typeof value !== "boolean") {
        out.push({ path, message: `expected a boolean, got ${describe(value)}` });
      }
      return;
    }
  }
}

export function validate(typeName: ApiTypeName, value: unknown): ApiIssue[] {
  const out: ApiIssue[] = [];
  check(SHAPES[typeName], value, "", out);
  return out;
}

const SHAPES: Readonly<Record<ApiTypeName, Shape>> = {
  "ComputeVM": {
    "properties": {
      "apiVersion": {
        "type": "string"
      },
      "kind": {
        "type": "string"
      },
      "metadata": {
        "ref": "ObjectMeta"
      },
      "spec": {
        "ref": "ComputeVMSpec"
      },
      "status": {
        "ref": "ComputeVMStatus"
      }
    },
    "required": [],
    "type": "object"
  },
  "ComputeVMContract": {
    "properties": {
      "acceptCid": {
        "type": "string"
      },
      "acceptUri": {
        "type": "string"
      },
      "acceptedAt": {
        "type": "string"
      },
      "receiptCid": {
        "type": "string"
      },
      "receiptUri": {
        "type": "string"
      },
      "submitEventUrl": {
        "type": "string"
      }
    },
    "required": [],
    "type": "object"
  },
  "ComputeVMHostKey": {
    "properties": {
      "fingerprint": {
        "type": "string"
      },
      "publicKey": {
        "type": "string"
      },
      "type": {
        "type": "string"
      }
    },
    "required": [
      "type",
      "publicKey"
    ],
    "type": "object"
  },
  "ComputeVMImage": {
    "properties": {
      "hypervisor": {
        "type": "string"
      },
      "ref": {
        "type": "string"
      },
      "sha256": {
        "type": "string"
      }
    },
    "required": [],
    "type": "object"
  },
  "ComputeVMImageRequest": {
    "properties": {
      "reuseStale": {
        "type": "boolean"
      }
    },
    "required": [],
    "type": "object"
  },
  "ComputeVMLostReason": {
    "enum": [
      "HostRebooted",
      "UnitGone",
      "UnitFailed",
      "OOMKilled",
      "VMMExited",
      "IdentityMismatch"
    ],
    "type": "string"
  },
  "ComputeVMMarket": {
    "properties": {
      "address": {
        "type": "string"
      },
      "hostKeys": {
        "items": {
          "ref": "ComputeVMHostKey"
        },
        "type": "array"
      },
      "hostKeysUri": {
        "type": "string"
      },
      "onNetworkUri": {
        "type": "string"
      },
      "reportedAt": {
        "type": "string"
      }
    },
    "required": [],
    "type": "object"
  },
  "ComputeVMNetwork": {
    "properties": {
      "guestIP": {
        "type": "string"
      },
      "hostAddress": {
        "type": "string"
      },
      "mac": {
        "type": "string"
      },
      "prefix": {
        "type": "integer"
      }
    },
    "required": [],
    "type": "object"
  },
  "ComputeVMOwner": {
    "properties": {
      "handle": {
        "type": "string"
      }
    },
    "required": [
      "handle"
    ],
    "type": "object"
  },
  "ComputeVMPhase": {
    "enum": [
      "Pending",
      "Preparing",
      "Booting",
      "Running",
      "Releasing",
      "Lost",
      "Failed"
    ],
    "type": "string"
  },
  "ComputeVMRequester": {
    "properties": {
      "did": {
        "type": "string"
      },
      "plc": {
        "type": "string"
      }
    },
    "required": [
      "did"
    ],
    "type": "object"
  },
  "ComputeVMRuntime": {
    "properties": {
      "backend": {
        "type": "string"
      },
      "hostBootID": {
        "type": "string"
      },
      "instance": {
        "type": "string"
      },
      "pid": {
        "type": "integer"
      },
      "ref": {
        "type": "string"
      },
      "startTime": {
        "type": "string"
      },
      "vmmID": {
        "type": "string"
      }
    },
    "required": [],
    "type": "object"
  },
  "ComputeVMShape": {
    "properties": {
      "cpus": {
        "type": "integer"
      },
      "disk": {
        "type": "string"
      },
      "mem": {
        "type": "string"
      },
      "role": {
        "type": "string"
      }
    },
    "required": [
      "cpus",
      "mem",
      "disk",
      "role"
    ],
    "type": "object"
  },
  "ComputeVMSpec": {
    "properties": {
      "contract": {
        "ref": "ComputeVMContract"
      },
      "image": {
        "ref": "ComputeVMImageRequest"
      },
      "owner": {
        "ref": "ComputeVMOwner"
      },
      "requester": {
        "ref": "ComputeVMRequester"
      },
      "stopGraceSeconds": {
        "type": "integer"
      },
      "userDataSecret": {
        "type": "string"
      },
      "vm": {
        "ref": "ComputeVMShape"
      }
    },
    "required": [
      "vm",
      "owner",
      "userDataSecret",
      "requester"
    ],
    "type": "object"
  },
  "ComputeVMStatus": {
    "properties": {
      "bootedAt": {
        "type": "string"
      },
      "conditions": {
        "items": {
          "ref": "Condition"
        },
        "type": "array"
      },
      "image": {
        "ref": "ComputeVMImage"
      },
      "lostReason": {
        "ref": "ComputeVMLostReason"
      },
      "market": {
        "ref": "ComputeVMMarket"
      },
      "message": {
        "type": "string"
      },
      "network": {
        "ref": "ComputeVMNetwork"
      },
      "observedGeneration": {
        "type": "integer"
      },
      "phase": {
        "ref": "ComputeVMPhase"
      },
      "runtime": {
        "ref": "ComputeVMRuntime"
      },
      "workDir": {
        "type": "string"
      }
    },
    "required": [],
    "type": "object"
  },
  "Condition": {
    "open": true,
    "type": "object"
  },
  "ObjectMeta": {
    "open": true,
    "type": "object"
  }
};

export function validateComputeVM(value: unknown): ApiIssue[] {
  return validate("ComputeVM", value);
}

export function isComputeVM(value: unknown): value is ComputeVM {
  return validate("ComputeVM", value).length === 0;
}

export function assertComputeVM(value: unknown): asserts value is ComputeVM {
  const issues = validate("ComputeVM", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVM", issues);
}

export function parseComputeVM(value: unknown): ComputeVM {
  assertComputeVM(value);
  return value;
}

export function validateComputeVMSpec(value: unknown): ApiIssue[] {
  return validate("ComputeVMSpec", value);
}

export function isComputeVMSpec(value: unknown): value is ComputeVMSpec {
  return validate("ComputeVMSpec", value).length === 0;
}

export function assertComputeVMSpec(value: unknown): asserts value is ComputeVMSpec {
  const issues = validate("ComputeVMSpec", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVMSpec", issues);
}

export function parseComputeVMSpec(value: unknown): ComputeVMSpec {
  assertComputeVMSpec(value);
  return value;
}

export function validateComputeVMShape(value: unknown): ApiIssue[] {
  return validate("ComputeVMShape", value);
}

export function isComputeVMShape(value: unknown): value is ComputeVMShape {
  return validate("ComputeVMShape", value).length === 0;
}

export function assertComputeVMShape(value: unknown): asserts value is ComputeVMShape {
  const issues = validate("ComputeVMShape", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVMShape", issues);
}

export function parseComputeVMShape(value: unknown): ComputeVMShape {
  assertComputeVMShape(value);
  return value;
}

export function validateComputeVMOwner(value: unknown): ApiIssue[] {
  return validate("ComputeVMOwner", value);
}

export function isComputeVMOwner(value: unknown): value is ComputeVMOwner {
  return validate("ComputeVMOwner", value).length === 0;
}

export function assertComputeVMOwner(value: unknown): asserts value is ComputeVMOwner {
  const issues = validate("ComputeVMOwner", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVMOwner", issues);
}

export function parseComputeVMOwner(value: unknown): ComputeVMOwner {
  assertComputeVMOwner(value);
  return value;
}

export function validateComputeVMRequester(value: unknown): ApiIssue[] {
  return validate("ComputeVMRequester", value);
}

export function isComputeVMRequester(value: unknown): value is ComputeVMRequester {
  return validate("ComputeVMRequester", value).length === 0;
}

export function assertComputeVMRequester(value: unknown): asserts value is ComputeVMRequester {
  const issues = validate("ComputeVMRequester", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVMRequester", issues);
}

export function parseComputeVMRequester(value: unknown): ComputeVMRequester {
  assertComputeVMRequester(value);
  return value;
}

export function validateComputeVMContract(value: unknown): ApiIssue[] {
  return validate("ComputeVMContract", value);
}

export function isComputeVMContract(value: unknown): value is ComputeVMContract {
  return validate("ComputeVMContract", value).length === 0;
}

export function assertComputeVMContract(value: unknown): asserts value is ComputeVMContract {
  const issues = validate("ComputeVMContract", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVMContract", issues);
}

export function parseComputeVMContract(value: unknown): ComputeVMContract {
  assertComputeVMContract(value);
  return value;
}

export function validateComputeVMImageRequest(value: unknown): ApiIssue[] {
  return validate("ComputeVMImageRequest", value);
}

export function isComputeVMImageRequest(value: unknown): value is ComputeVMImageRequest {
  return validate("ComputeVMImageRequest", value).length === 0;
}

export function assertComputeVMImageRequest(value: unknown): asserts value is ComputeVMImageRequest {
  const issues = validate("ComputeVMImageRequest", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVMImageRequest", issues);
}

export function parseComputeVMImageRequest(value: unknown): ComputeVMImageRequest {
  assertComputeVMImageRequest(value);
  return value;
}

export function validateComputeVMStatus(value: unknown): ApiIssue[] {
  return validate("ComputeVMStatus", value);
}

export function isComputeVMStatus(value: unknown): value is ComputeVMStatus {
  return validate("ComputeVMStatus", value).length === 0;
}

export function assertComputeVMStatus(value: unknown): asserts value is ComputeVMStatus {
  const issues = validate("ComputeVMStatus", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVMStatus", issues);
}

export function parseComputeVMStatus(value: unknown): ComputeVMStatus {
  assertComputeVMStatus(value);
  return value;
}

export function validateComputeVMPhase(value: unknown): ApiIssue[] {
  return validate("ComputeVMPhase", value);
}

export function isComputeVMPhase(value: unknown): value is ComputeVMPhase {
  return validate("ComputeVMPhase", value).length === 0;
}

export function assertComputeVMPhase(value: unknown): asserts value is ComputeVMPhase {
  const issues = validate("ComputeVMPhase", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVMPhase", issues);
}

export function parseComputeVMPhase(value: unknown): ComputeVMPhase {
  assertComputeVMPhase(value);
  return value;
}

export function validateComputeVMLostReason(value: unknown): ApiIssue[] {
  return validate("ComputeVMLostReason", value);
}

export function isComputeVMLostReason(value: unknown): value is ComputeVMLostReason {
  return validate("ComputeVMLostReason", value).length === 0;
}

export function assertComputeVMLostReason(value: unknown): asserts value is ComputeVMLostReason {
  const issues = validate("ComputeVMLostReason", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVMLostReason", issues);
}

export function parseComputeVMLostReason(value: unknown): ComputeVMLostReason {
  assertComputeVMLostReason(value);
  return value;
}

export function validateComputeVMNetwork(value: unknown): ApiIssue[] {
  return validate("ComputeVMNetwork", value);
}

export function isComputeVMNetwork(value: unknown): value is ComputeVMNetwork {
  return validate("ComputeVMNetwork", value).length === 0;
}

export function assertComputeVMNetwork(value: unknown): asserts value is ComputeVMNetwork {
  const issues = validate("ComputeVMNetwork", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVMNetwork", issues);
}

export function parseComputeVMNetwork(value: unknown): ComputeVMNetwork {
  assertComputeVMNetwork(value);
  return value;
}

export function validateComputeVMImage(value: unknown): ApiIssue[] {
  return validate("ComputeVMImage", value);
}

export function isComputeVMImage(value: unknown): value is ComputeVMImage {
  return validate("ComputeVMImage", value).length === 0;
}

export function assertComputeVMImage(value: unknown): asserts value is ComputeVMImage {
  const issues = validate("ComputeVMImage", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVMImage", issues);
}

export function parseComputeVMImage(value: unknown): ComputeVMImage {
  assertComputeVMImage(value);
  return value;
}

export function validateComputeVMRuntime(value: unknown): ApiIssue[] {
  return validate("ComputeVMRuntime", value);
}

export function isComputeVMRuntime(value: unknown): value is ComputeVMRuntime {
  return validate("ComputeVMRuntime", value).length === 0;
}

export function assertComputeVMRuntime(value: unknown): asserts value is ComputeVMRuntime {
  const issues = validate("ComputeVMRuntime", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVMRuntime", issues);
}

export function parseComputeVMRuntime(value: unknown): ComputeVMRuntime {
  assertComputeVMRuntime(value);
  return value;
}

export function validateComputeVMMarket(value: unknown): ApiIssue[] {
  return validate("ComputeVMMarket", value);
}

export function isComputeVMMarket(value: unknown): value is ComputeVMMarket {
  return validate("ComputeVMMarket", value).length === 0;
}

export function assertComputeVMMarket(value: unknown): asserts value is ComputeVMMarket {
  const issues = validate("ComputeVMMarket", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVMMarket", issues);
}

export function parseComputeVMMarket(value: unknown): ComputeVMMarket {
  assertComputeVMMarket(value);
  return value;
}

export function validateComputeVMHostKey(value: unknown): ApiIssue[] {
  return validate("ComputeVMHostKey", value);
}

export function isComputeVMHostKey(value: unknown): value is ComputeVMHostKey {
  return validate("ComputeVMHostKey", value).length === 0;
}

export function assertComputeVMHostKey(value: unknown): asserts value is ComputeVMHostKey {
  const issues = validate("ComputeVMHostKey", value);
  if (issues.length > 0) throw new ApiValidationError("ComputeVMHostKey", issues);
}

export function parseComputeVMHostKey(value: unknown): ComputeVMHostKey {
  assertComputeVMHostKey(value);
  return value;
}
