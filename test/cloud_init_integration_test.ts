import { assertEquals } from "@std/assert";
import { runContainer } from "@publicdomainrelay/compute-provider-local";
import { createContainerBackend } from "@publicdomainrelay/container-backend-container";
import { createDockerBackend } from "@publicdomainrelay/container-backend-docker";

const USER_DATA_PATH = new URL("./cloud-init-test.yaml", import.meta.url).pathname;
const CALLBACK_TIMEOUT_MS = 120_000;

Deno.test("[integration] cloud-init posts hostname to test callback server", async () => {
  const backend = Deno.build.os === "darwin" ? createContainerBackend() : createDockerBackend();
  const backendReady = await backend.ensureRunning();
  if (!backendReady) {
    console.log("[test] SKIP: container backend not available");
    return;
  }

  let resolveCallback: (v: { hostname: string }) => void;
  const received = new Promise<{ hostname: string }>((resolve) => {
    resolveCallback = resolve;
  });

  const ac = new AbortController();

  const server = Deno.serve(
    {
      port: 0,
      hostname: "0.0.0.0",
      signal: ac.signal,
      onListen({ hostname, port }) {
        console.log(`[test-server] listening on ${hostname}:${port}`);
      },
    },
    async (req) => {
      const url = new URL(req.url);
      if (req.method === "POST" && url.pathname === "/cloud-init-done") {
        const body = await req.text();
        const data = JSON.parse(body);
        const hostname: string = data.hostname ?? "";
        console.log(`[test-server] cloud-init callback from hostname=${hostname}`);
        resolveCallback({ hostname });
        return new Response("ok");
      }
      return new Response("not found", { status: 404 });
    },
  );

  try {
    const port = server.addr.port;
    console.log(`[test] server bound to port ${port}`);

    let template = await Deno.readTextFile(USER_DATA_PATH);
    const gatewayIp = await backend.defaultGateway();
    template = template.replaceAll("<REPLACE_WITH_GATEWAY_IP>", gatewayIp);
    template = template.replaceAll("<REPLACE_WITH_TEST_PORT>", String(port));
    const userData = template;

    const containerName = `test-ci-${crypto.randomUUID().slice(0, 8)}`;

    const info = await runContainer(backend, userData, {
      distro: "ubuntu",
      containerName,
    });

    try {
      const timeout = setTimeout(() => {
        resolveCallback({ hostname: "" });
      }, CALLBACK_TIMEOUT_MS);

      const result = await received;
      clearTimeout(timeout);

      assertEquals(
        typeof result.hostname,
        "string",
        "hostname should be a string",
      );
      console.log(
        `[test] cloud-init callback received: hostname=${result.hostname}`,
      );
    } finally {
      await backend.rm(info.containerName).catch(() => {});
    }
  } finally {
    ac.abort();
    await server.finished;
  }
});
