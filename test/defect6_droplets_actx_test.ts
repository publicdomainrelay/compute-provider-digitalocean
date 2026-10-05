import { assert, assertEquals } from "@std/assert";
import { Secp256k1Keypair } from "@atproto/crypto";
import { signerFromKeypair, signServiceAuth } from "@publicdomainrelay/atproto-repo-deno";
import { createComputeProviderLocalFactory } from "@publicdomainrelay/hono-factory-compute-provider-local";
import { createComputeProviderDigitalOceanFactory } from "@publicdomainrelay/hono-factory-compute-provider-digitalocean";
import {
  COMPUTE_VM_NSID,
  ON_BEHALF_OF_HEADER,
  serviceDidFromUrl,
} from "@publicdomainrelay/compute-provider-common";

const ISSUER = "http://127.0.0.1:9977";

const noopLog = {
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {},
} as never;

// A value that is NOT a JWT in any sense: no dots, no signature, nothing to
// decode. Nothing in the /v2 path is allowed to treat it as an identity.
const CLAIMED_ACTX = "did:plc:victimchosenbythecaller";

async function signedToken(lxm: string): Promise<{ token: string; actx: string }> {
  const keypair = await Secp256k1Keypair.create({ exportable: true });
  const did = keypair.did();
  const token = await signServiceAuth(signerFromKeypair(keypair), {
    aud: serviceDidFromUrl(ISSUER),
    lxm,
  });
  return { token, actx: did.split(":").pop() ?? did };
}

function localApp() {
  return createComputeProviderLocalFactory({
    operatorHandle: "did:plc:operator",
    selfDid: "did:plc:operator",
    issuerUrl: ISSUER,
    vmImage: "unused-in-this-test",
    containerMode: true,
    containerImage: "unused-in-this-test",
    log: noopLog,
  }).createApp();
}

Deno.test("defect6: /v2/* must not take the tenant identity from an unverified bearer token", async () => {
  const app = localApp();

  const res = await app.request("/v2/account", {
    headers: { authorization: `Bearer ${CLAIMED_ACTX}` },
  });
  const body = await res.json() as { account?: { team?: { uuid?: string } } };
  const seenActx = body?.account?.team?.uuid ?? null;
  console.log("[defect6] /v2/account with a bare, unverifiable bearer ->", res.status, JSON.stringify(body));

  assertEquals(
    seenActx,
    null,
    "GET /v2/account returned the raw Authorization header as the caller's " +
      "actx. extractBearer only checks the header is non-empty, so the caller " +
      "chooses both the identity and the tenant its droplets are filed under",
  );
  assertEquals(res.status, 401);
  assert(true);
});

Deno.test("defect6 control: a signed token for this method is still admitted, as the signer's identity", async () => {
  const app = localApp();
  const { token, actx } = await signedToken(COMPUTE_VM_NSID);

  const res = await app.request("/v2/account", {
    headers: { authorization: `Bearer ${token}` },
  });
  const body = await res.json() as { account?: { team?: { uuid?: string } } };
  console.log("[defect6] control: /v2/account with a signed service-auth token ->", res.status, JSON.stringify(body));

  // One token per request: the verifier's jti store refuses a replay, so a
  // second use of the same token is 401 by design.
  const list = await app.request("/v2/droplets", {
    headers: { authorization: `Bearer ${(await signedToken(COMPUTE_VM_NSID)).token}` },
  });
  const listBody = await list.json() as { droplets?: unknown[] };
  console.log("[defect6] control: /v2/droplets with the same token ->", list.status, JSON.stringify(listBody));

  assertEquals(res.status, 200);
  assertEquals(list.status, 200);
  assertEquals(body?.account?.team?.uuid, actx);
  assertEquals(listBody?.droplets, []);
});

Deno.test("defect6 control: a signed token minted for another method is refused", async () => {
  const app = localApp();
  const { token } = await signedToken("com.publicdomainrelay.temp.market.rfp");

  const res = await app.request("/v2/account", {
    headers: { authorization: `Bearer ${token}` },
  });
  console.log("[defect6] control: /v2/account with a token for another lxm ->", res.status, JSON.stringify(await res.json()));

  assertEquals(res.status, 401);
});

Deno.test("defect6: the DO proxy must not forward a caller-chosen actx upstream", async () => {
  const forwarded: string[] = [];
  let bound: (port: number) => void = () => {};
  const ready = new Promise<number>((resolve) => {
    bound = resolve;
  });
  const upstream = Deno.serve(
    { port: 0, onListen: (addr) => bound((addr as Deno.NetAddr).port) },
    (req) => {
      forwarded.push(req.headers.get(ON_BEHALF_OF_HEADER) ?? "");
      return Response.json({ droplets: [] });
    },
  );

  try {
    const app = createComputeProviderDigitalOceanFactory({
      operatorHandle: "did:plc:operator",
      selfDid: "did:plc:operator",
      issuerUrl: ISSUER,
      digitaloceanBaseUrl: `http://127.0.0.1:${await ready}`,
      doToken: "operator-do-token",
      log: noopLog,
    }).createApp();

    const res = await app.request("/v2/droplets", {
      headers: { authorization: `Bearer ${CLAIMED_ACTX}` },
    });
    console.log(
      `[defect6] GET /v2/droplets -> ${res.status}; ${ON_BEHALF_OF_HEADER} sent upstream =`,
      JSON.stringify(forwarded),
    );

    assertEquals(
      forwarded,
      [],
      `the provider forwarded ${ON_BEHALF_OF_HEADER}: ${CLAIMED_ACTX} to the ` +
        "upstream DO API under its own operator token. The value is the raw " +
        "Authorization header, unverified, so the caller picks the tenant the " +
        "operator's droplet list and droplet creations are attributed to",
    );
    assertEquals(res.status, 401);

    const { token, actx } = await signedToken(COMPUTE_VM_NSID);
    const okRes = await app.request("/v2/droplets", {
      headers: { authorization: `Bearer ${token}` },
    });
    console.log(
      `[defect6] control: GET /v2/droplets (signed) -> ${okRes.status}; ${ON_BEHALF_OF_HEADER} sent upstream =`,
      JSON.stringify(forwarded),
    );

    assertEquals(okRes.status, 200);
    assertEquals(forwarded, [actx]);
  } finally {
    await upstream.shutdown();
  }
});
