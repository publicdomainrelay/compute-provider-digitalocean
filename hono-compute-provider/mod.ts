import { Command } from "@publicdomainrelay/cli-args-env";
import { createStructuredLogger, type LogLevel } from "@publicdomainrelay/logger";
import { createComputeProviderLocalFactory } from "@publicdomainrelay/hono-factory-compute-provider-local";
import { createComputeProviderDigitalOceanFactory } from "@publicdomainrelay/hono-factory-compute-provider-digitalocean";
import cliArgsEnv from "./cli-args-env.json" with { type: "json" };

let runtimeConfig = null;
try {
  const mod = await import("./config.json", { with: { type: "json" } });
  runtimeConfig = mod.default;
} catch { /* optional */ }

const { options } = await new Command(
  "CONFIG_PATH_HONO_COMPUTE_PROVIDER",
  cliArgsEnv,
  runtimeConfig,
).resolve();

const log = createStructuredLogger("hono-compute-provider", options.logLevel as LogLevel);

const port = options.port as number;
const providerMode = (options.provider as string) === "digitalocean"
  ? "digitalocean" as const
  : "local" as const;

const issuerUrl = (options.issuerUrl as string) || `http://localhost:${port}`;
const operatorHandle = options.operatorHandle as string;
const selfDid = options.selfDid as string;
const cacheDir = options.cacheDir as string | undefined;
const vmImage = options.vmImage as string;
const containerImage = options.containerImage as string;
const containerMode = options.containerMode as boolean;

log.info("starting compute provider", {
  port,
  provider: providerMode,
  issuerUrl,
  containerMode,
});

let app: ReturnType<ReturnType<typeof createComputeProviderLocalFactory>["createApp"]>;
let killAll: (() => Promise<void>) | undefined;

if (providerMode === "local") {
  const factory = createComputeProviderLocalFactory({
    operatorHandle,
    selfDid,
    issuerUrl,
    vmImage,
    containerMode,
    containerImage,
    cacheDir,
    log,
  });
  app = factory.createApp();
  killAll = () => factory.killAllDroplets();
} else {
  const digitaloceanBaseUrl = options.digitaloceanBaseUrl as string;
  const doToken = options.doToken as string;
  if (!doToken) {
    log.error("DO_TOKEN is required for digitalocean provider");
    Deno.exit(1);
  }
  const factory = createComputeProviderDigitalOceanFactory({
    operatorHandle,
    selfDid,
    issuerUrl,
    digitaloceanBaseUrl,
    doToken,
    log,
  });
  app = factory.createApp();
}

const signalHandler = () => {
  log.info("shutting down");
  killAll?.().then(() => Deno.exit(0));
};

Deno.addSignalListener("SIGINT", signalHandler);
Deno.addSignalListener("SIGTERM", signalHandler);

Deno.serve(
  { port, hostname: "0.0.0.0", onListen: () => log.info("listening", { port }) },
  app.fetch,
);
