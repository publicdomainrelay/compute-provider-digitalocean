import type { CliResult } from "@publicdomainrelay/container-backend-common";

export interface ContainerBackend {
  readonly type: "docker" | "container";
  readonly bin: string;

  /** Raw command via backend binary. */
  command(args: string[], opts?: { inherit?: boolean }): Promise<CliResult>;

  /** Get container IP address (no CIDR suffix). */
  inspectIp(containerName: string): Promise<string>;

  /** Get host gateway IP reachable from inside the container. */
  inspectGateway(containerName: string): Promise<string>;

  /** Get default bridge gateway IP (no container required). */
  defaultGateway(): Promise<string>;

  /** Check if image exists locally. */
  imageExists(tag: string): Promise<boolean>;

  /** Pull image from registry. */
  pullImage(image: string): Promise<void>;

  /** Force-remove a container. */
  rm(name: string): Promise<void>;

  /** Kill a container. */
  kill(name: string): Promise<void>;

  /** Execute command inside a running container. */
  exec(containerName: string, args: string[]): Promise<CliResult>;

  /** Check if backend daemon is running. */
  isRunning(): Promise<boolean>;

  /** Start backend daemon if not running. Returns true if now running. */
  ensureRunning(): Promise<boolean>;
}
