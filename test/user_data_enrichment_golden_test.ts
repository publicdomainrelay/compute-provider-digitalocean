import { assertEquals } from "@std/assert";
import {
  addressTheRequesterNamed,
  EVENT_NSID,
  guestMacFor,
  injectAcceptBundle,
  networkFor,
  ON_NETWORK_NSID,
  onNetworkReporterModule,
  onNetworkTargets,
  onNetworkUrlFromBundle,
  parseMemMiB,
  pointGuestAtHost,
  preinstallManifest,
  SECRETS_PREFIX,
  shellCommandLine,
  shortId,
  SUBMIT_EVENT_NSID,
  WIF_SIMPLE_NSID,
  withOnNetworkBaseUrl,
  withOnNetworkReporter,
} from "@publicdomainrelay/compute-provider-common";
import golden from "./fixtures/user_data_enrichment_golden.json" with { type: "json" };

type GoldenCase = { fn: string; args: unknown[]; out?: unknown; sha256?: string };

const functions: Record<string, (...args: never[]) => unknown> = {
  injectAcceptBundle,
  onNetworkUrlFromBundle,
  onNetworkTargets,
  onNetworkReporterModule: (...args: Parameters<typeof onNetworkReporterModule>) =>
    onNetworkReporterModule(...args)({}),
  withOnNetworkReporter,
  withOnNetworkBaseUrl,
  addressTheRequesterNamed,
  pointGuestAtHost,
  networkFor,
  guestMacFor,
  shortId,
  parseMemMiB,
  preinstallManifest,
  shellCommandLine,
};

async function sha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.test("the NSID and path constants are the ones firecracker published", () => {
  assertEquals(
    { WIF_SIMPLE_NSID, ON_NETWORK_NSID, EVENT_NSID, SUBMIT_EVENT_NSID, SECRETS_PREFIX },
    golden.constants,
  );
});

Deno.test("user_data enrichment reproduces firecracker's output case for case", async (t) => {
  const inputs = golden.inputs as Record<string, string>;
  const outputs: unknown[] = [];
  const resolve = (arg: unknown): unknown => {
    if (arg && typeof arg === "object" && !Array.isArray(arg)) {
      const ref = arg as { $ref?: number; $input?: string };
      if (typeof ref.$ref === "number") return outputs[ref.$ref];
      if (typeof ref.$input === "string") return inputs[ref.$input];
    }
    return arg === null ? undefined : arg;
  };
  for (const [index, entry] of (golden.cases as GoldenCase[]).entries()) {
    const fn = functions[entry.fn];
    const out = fn(...(entry.args.map(resolve) as never[]));
    outputs.push(out);
    await t.step(`${index} ${entry.fn}`, async () => {
      if (entry.sha256 !== undefined) assertEquals(await sha256(out as string), entry.sha256);
      else assertEquals(out ?? null, entry.out);
    });
  }
});
