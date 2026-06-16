import { Command } from "@cliffy/command";
import { createLogger } from "@publicdomainrelay/common";
import { createComputeProviderLocalFactory } from "@publicdomainrelay/hono-factory-compute-provider-local";
import { createComputeProviderDigitalOceanFactory } from "@publicdomainrelay/hono-factory-compute-provider-digitalocean";

const log = createLogger("hono-compute-provider");

function homeDir(): string {
  const h = Deno.env.get("HOME");
  if (!h) {
    console.error("HOME environment variable is not set.");
    Deno.exit(1);
  }
  return h;
}

async function main() {
  const { options } = await new Command()
    .name("hono-compute-provider")
    .version("0.0.0")
    .description("Compute provider server — provisions droplets via local Docker or DigitalOcean API")
    .option("-p, --port <port:number>", "HTTP port", { default: 8080 })
    .option("--provider <mode:string>", "Compute provider: local or digitalocean", { default: "local" })
    .option("--container-mode [mode:boolean]", "Use container mode instead of QEMU (local only)", { default: true })
    .option("--vm-image <image:string>", "Docker image for QEMU VMs", { default: "atcr.io/johnandersen777.bsky.social/ccripoc-qemu-runner" })
    .option("--container-image <image:string>", "Docker image for container runner", { default: "container-runner-ubuntu:latest" })
    .option("--cache-dir <dir:string>", "Cache directory for temp files")
    .option("--issuer-url <url:string>", "OIDC issuer URL")
    .option("--operator-handle <did:string>", "Operator handle DID", { default: "did:plc:localhost" })
    .option("--self-did <did:string>", "This host DID", { default: "did:plc:localhost" })
    .option("--digitalocean-base-url <url:string>", "DO API base URL", { default: "https://droplet-oidc.its1337.com" })
    .option("--do-token <token:string>", "DO API token")
    .env("PORT=<port:number>", "HTTP port")
    .env("COMPUTE_PROVIDER=<mode:string>", "Provider mode")
    .env("CONTAINER_MODE=<mode:boolean>", "Container mode")
    .env("VM_IMAGE=<image:string>", "VM image")
    .env("CONTAINER_IMAGE=<image:string>", "Container image")
    .env("CACHE_DIR=<dir:string>", "Cache dir")
    .env("ISSUER_URL=<url:string>", "Issuer URL")
    .env("OPERATOR_HANDLE=<did:string>", "Operator handle")
    .env("SELF_DID=<did:string>", "Self DID")
    .env("DIGITALOCEAN_BASE_URL=<url:string>", "DO base URL")
    .env("DO_TOKEN=<token:string>", "DO token")
    .parse(Deno.args);

  const port = options.port as number;
  const providerMode = (options.provider as string) === "digitalocean"
    ? "digitalocean" as const
    : "local" as const;

  const issuerUrl = (options.issuerUrl as string) || `http://localhost:${port}`;
  const operatorHandle = options.operatorHandle as string;
  const selfDid = options.selfDid as string;
  const cacheDir = (options.cacheDir as string) || `${homeDir()}/.cache/pdr-local`;
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

  log.info("listening", { port });
  Deno.serve({ port, hostname: "0.0.0.0" }, app.fetch);
}

if (import.meta.main) {
  main();
}
