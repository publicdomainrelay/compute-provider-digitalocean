export interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

export const BACKEND_TYPE_DOCKER = "docker" as const;
export const BACKEND_TYPE_CONTAINER = "container" as const;
export type BackendType = typeof BACKEND_TYPE_DOCKER | typeof BACKEND_TYPE_CONTAINER;

/** Auto-detect the right backend for this platform. */
export function detectBackend(): BackendType {
  return Deno.build.os === "darwin" ? BACKEND_TYPE_CONTAINER : BACKEND_TYPE_DOCKER;
}
