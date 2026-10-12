import { assert, assertEquals } from "@std/assert";
import { parse } from "@std/yaml";

const ORG_ROOT = new URL("../../", import.meta.url);
const INVENTORY = new URL("socialweb-computer-kcp/docs/compute-provider-requirements.yaml", ORG_ROOT);
const PLANS = new URL("socialweb-computer-kcp/docs/plans/", ORG_ROOT);
const INVENTORIED_SOURCES = [
  "hono-compute-provider/lib/compute-provider-firecracker/mod.ts",
  "hono-compute-provider/lib/microvm-firecracker/mod.ts",
];
const STATUS = /^(port|removed-legacy|superseded-by-(?:[0-9]{4}:)?[A-Z0-9]+(?:-[A-Z0-9]+)*)$/;
const SOURCE = /^([A-Za-z0-9._/-]+):(\d+)(?:-(\d+))?$/;
const GO_SIDE_MEETS = ["yes", "partial", "no", "not-applicable"];

interface Requirement {
  id: string;
  source: string[];
  behaviour: string;
  go_side: { meets: string; detail: string };
  parity_test: string[];
  status: string;
  covers?: string[];
}

async function inventory(): Promise<Requirement[]> {
  const doc = parse(await Deno.readTextFile(INVENTORY)) as { requirements?: Requirement[] };
  assert(Array.isArray(doc?.requirements), `${INVENTORY.pathname} has no requirements list`);
  return doc.requirements;
}

function exportedNames(source: string): string[] {
  const names = new Set<string>();
  for (const m of source.matchAll(/^export (?:async )?function (\w+)/gm)) names.add(m[1]);
  for (const m of source.matchAll(/^export const (\w+)/gm)) names.add(m[1]);
  return [...names];
}

function loggerEvents(source: string): string[] {
  const events = new Set<string>();
  for (const m of source.matchAll(/logger\??\.(?:info|warn|error|debug)\(\s*"([^"]+)"/g)) events.add(m[1]);
  return [...events];
}

async function planItemIds(): Promise<Set<string>> {
  const ids = new Set<string>();
  for await (const entry of Deno.readDir(PLANS)) {
    if (!entry.name.endsWith(".yaml")) continue;
    const plan = entry.name.slice(0, 4);
    const text = await Deno.readTextFile(new URL(entry.name, PLANS));
    for (const m of text.matchAll(/^\s+- id: ([A-Z0-9-]+)\s*$/gm)) {
      ids.add(m[1]);
      ids.add(`${plan}:${m[1]}`);
    }
  }
  return ids;
}

async function uncovered(kind: (source: string) => string[]): Promise<string[]> {
  const covered = new Set((await inventory()).flatMap((r) => r.covers ?? []));
  const missing: string[] = [];
  for (const path of INVENTORIED_SOURCES) {
    const source = await Deno.readTextFile(new URL(path, ORG_ROOT));
    for (const name of kind(source)) if (!covered.has(name)) missing.push(`${path}: ${name}`);
  }
  return missing;
}

Deno.test("every requirement names its id, source, behaviour, Go side, parity test and status", async () => {
  const requirements = await inventory();
  assert(requirements.length > 0, "the inventory lists no requirement");
  const ids = new Set<string>();
  const plans = await planItemIds();
  for (const r of requirements) {
    assert(typeof r.id === "string" && /^FC-[A-Z0-9-]+$/.test(r.id), `bad id ${JSON.stringify(r.id)}`);
    assert(!ids.has(r.id), `${r.id} is listed twice`);
    ids.add(r.id);
    assert(Array.isArray(r.source) && r.source.length > 0, `${r.id} names no TypeScript source`);
    assert(typeof r.behaviour === "string" && r.behaviour.trim().length > 0, `${r.id} has no behaviour`);
    assert(GO_SIDE_MEETS.includes(r.go_side?.meets), `${r.id} go_side.meets is ${r.go_side?.meets}`);
    assert(typeof r.go_side?.detail === "string" && r.go_side.detail.trim().length > 0, `${r.id} go_side has no detail`);
    assert(Array.isArray(r.parity_test) && r.parity_test.length > 0, `${r.id} names no parity test`);
    assert(STATUS.test(r.status), `${r.id} status ${JSON.stringify(r.status)}`);
    const superseding = /^superseded-by-(.+)$/.exec(r.status)?.[1];
    if (superseding) assert(plans.has(superseding), `${r.id} is superseded by ${superseding}, which no plan defines`);
  }
});

Deno.test("every source a requirement cites is a file and line that exist", async () => {
  const problems: string[] = [];
  for (const r of await inventory()) {
    for (const cited of r.source) {
      const m = SOURCE.exec(cited);
      if (!m) {
        problems.push(`${r.id}: ${cited} is not path:line or path:start-end`);
        continue;
      }
      const last = Number(m[3] ?? m[2]);
      let lines: number;
      try {
        lines = (await Deno.readTextFile(new URL(m[1], ORG_ROOT))).split("\n").length;
      } catch (err) {
        problems.push(`${r.id}: ${m[1]} cannot be read: ${String(err)}`);
        continue;
      }
      if (Number(m[2]) < 1 || last < Number(m[2]) || last > lines) {
        problems.push(`${r.id}: ${cited} is outside the ${lines} lines of ${m[1]}`);
      }
    }
  }
  assertEquals(problems, []);
});

Deno.test("every exported function and constant of the firecracker provider and its microvm is in a requirement", async () => {
  assertEquals(await uncovered(exportedNames), []);
});

Deno.test("every logger event of the firecracker provider and its microvm is in a requirement", async () => {
  assertEquals(await uncovered(loggerEvents), []);
});
