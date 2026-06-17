export interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

export const BACKEND_TYPE_DOCKER = "docker" as const;
export const BACKEND_TYPE_CONTAINER = "container" as const;
export type BackendType = typeof BACKEND_TYPE_DOCKER | typeof BACKEND_TYPE_CONTAINER;
