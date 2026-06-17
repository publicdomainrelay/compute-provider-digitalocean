#!/usr/bin/env -S deno run -A

// State paths

const STATEDIR = Deno.env.get("STATEDIR") ?? "/run/systemctl";
const WANTED = `${STATEDIR}/wanted`;
const ENABLED = `${STATEDIR}/enabled`;
const PIDS = `${STATEDIR}/pids`;
const EXITED = `${STATEDIR}/exited`;

const UNIT_SEARCH_PATHS = [
  "/etc/systemd/system",
  "/run/systemd/system",
  "/usr/lib/systemd/system",
];

const RECONCILE_INTERVAL_MS = 2000;

function log(msg: string) {
  console.error(`[systemctl-shim] ${msg}`);
}

async function ensureStateDirs() {
  for (const d of [WANTED, ENABLED, PIDS, EXITED]) {
    await Deno.mkdir(d, { recursive: true }).catch(() => {});
  }
}

// Unit-name helpers

function resolveUnitName(name: string): string {
  return name.includes(".") ? name : `${name}.service`;
}

function canonical(name: string): string {
  const n = resolveUnitName(name);
  return n === "sshd.service" ? "ssh.service" : n;
}

function isSupervisableService(unitName: string): boolean {

  return /\.service$/.test(unitName);
}

function isPathUnit(unitName: string): boolean {
  return /\.path$/.test(unitName);
}

// INI parser (dependency-free; accumulates duplicate keys with "\n")

type IniFile = Record<string, Record<string, string>>;

function parseIni(text: string): IniFile {
  const out: IniFile = {};
  let section = "";
  for (let line of text.split("\n")) {
    const hash = line.indexOf("#");
    const semi = line.indexOf(";");
    const cut = Math.min(hash === -1 ? Infinity : hash, semi === -1 ? Infinity : semi);
    if (cut !== Infinity) line = line.slice(0, cut);
    line = line.trim();
    if (!line) continue;

    const sec = line.match(/^\[(.+)\]$/);
    if (sec) {
      section = sec[1];
      out[section] ??= {};
      continue;
    }
    if (!section) continue;

    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    const val = line.slice(eq + 1).trim();
    out[section][key] = out[section][key] !== undefined
      ? out[section][key] + "\n" + val
      : val;
  }
  return out;
}

// Unit model

interface Unit {
  name: string;
  type: "simple" | "forking" | "oneshot" | "notify";
  execStart: string;
  execStartPre: string[];
  workingDirectory: string;
  environment: string[];
  restart: "no" | "always" | "on-failure";
  restartSec: number;
  remainAfterExit: boolean;
  timeoutStopSec: number;
  conditionPathExists: string[];
  // path unit fields (from [Path] section)
  pathExists?: string[];
  pathChanged?: string[];
  pathUnit?: string; // associated unit to activate when path conditions met
}

function unitDefaults(name: string): Unit {
  return {
    name,
    type: "simple",
    execStart: "",
    execStartPre: [],
    workingDirectory: "",
    environment: [],
    restart: "no",
    restartSec: 5,
    remainAfterExit: false,
    timeoutStopSec: 10,
    conditionPathExists: [],
  };
}

function sshdUnit(): Unit {
  return {
    ...unitDefaults("ssh.service"),
    type: "simple",
    execStart: "pkill -x sshd 2>/dev/null; sleep 0.3; exec /usr/sbin/sshd -D -e -p 22",
    execStartPre: ["/usr/sbin/sshd -t"],
    restart: "always",
    restartSec: 2,
  };
}

async function findUnitFile(name: string): Promise<string | null> {
  const file = resolveUnitName(name);
  for (const dir of UNIT_SEARCH_PATHS) {
    try {
      await Deno.stat(`${dir}/${file}`);
      return `${dir}/${file}`;
    } catch { /* keep looking */ }
  }
  return null;
}

async function parseUnitFile(path: string, name: string): Promise<Unit> {
  const ini = parseIni(await Deno.readTextFile(path));
  const svc = ini["Service"] ?? {};
  const unt = ini["Unit"] ?? {};
  const u = unitDefaults(name);

  if (svc["Type"]) u.type = svc["Type"] as Unit["type"];
  if (svc["ExecStart"]) u.execStart = svc["ExecStart"];
  if (svc["ExecStartPre"]) u.execStartPre = svc["ExecStartPre"].split("\n");
  if (svc["WorkingDirectory"]) u.workingDirectory = svc["WorkingDirectory"];
  if (svc["Environment"]) u.environment = svc["Environment"].split("\n");
  if (svc["Restart"]) u.restart = svc["Restart"] as Unit["restart"];
  if (svc["RestartSec"]) u.restartSec = parseInt(svc["RestartSec"], 10) || 5;
  if (svc["RemainAfterExit"]) {
    u.remainAfterExit = svc["RemainAfterExit"] === "yes" || svc["RemainAfterExit"] === "true";
  }
  if (svc["TimeoutStopSec"]) u.timeoutStopSec = parseInt(svc["TimeoutStopSec"], 10) || 10;
  if (unt["ConditionPathExists"]) u.conditionPathExists = unt["ConditionPathExists"].split("\n");

  const pth = ini["Path"] ?? {};
  if (pth["PathExists"]) u.pathExists = pth["PathExists"].split("\n");
  if (pth["PathChanged"]) u.pathChanged = pth["PathChanged"].split("\n");
  if (pth["Unit"]) u.pathUnit = pth["Unit"];

  return u;
}

async function resolveUnit(name: string): Promise<Unit | null> {
  const n = canonical(name);
  if (n === "ssh.service") return sshdUnit();
  const path = await findUnitFile(n);
  if (!path) return null;
  return await parseUnitFile(path, n);
}

// Condition / process helpers

function checkConditions(unit: Unit): boolean {
  for (const cond of unit.conditionPathExists) {
    const negate = cond.startsWith("!");
    const path = negate ? cond.slice(1) : cond;
    let exists = false;
    try { Deno.statSync(path); exists = true; } catch { /* missing */ }
    if (negate && exists) {
      log(`${unit.name}: ConditionPathExists=!${path} (exists) -> skip`);
      return false;
    }
    if (!negate && !exists) {
      log(`${unit.name}: ConditionPathExists=${path} (missing) -> skip`);
      return false;
    }
  }
  return true;
}

function pidAlive(pid: number): boolean {
  try { Deno.statSync(`/proc/${pid}/comm`); return true; } catch { return false; }
}

function readPid(unitName: string): number | null {
  try {
    return parseInt(Deno.readTextFileSync(`${PIDS}/${canonical(unitName)}`).trim(), 10);
  } catch { return null; }
}

function serviceRunning(unitName: string): boolean {
  const pid = readPid(unitName);
  return pid !== null && pidAlive(pid);
}

function serviceExited(unitName: string): boolean {
  try { Deno.statSync(`${EXITED}/${canonical(unitName)}`); return true; } catch { return false; }
}

function parseEnvLine(line: string): Array<[string, string]> {
  const tokens: string[] = [];
  let cur = "";
  let inQuote = false;
  for (const ch of line) {
    if (ch === '"') { inQuote = !inQuote; continue; }
    if (ch === " " && !inQuote) { if (cur) { tokens.push(cur); cur = ""; } continue; }
    cur += ch;
  }
  if (cur) tokens.push(cur);

  const pairs: Array<[string, string]> = [];
  for (const t of tokens) {
    const eq = t.indexOf("=");
    if (eq > 0) pairs.push([t.slice(0, eq), t.slice(eq + 1)]);
  }
  return pairs;
}

function envObject(unit: Unit): Record<string, string> {
  const env: Record<string, string> = { ...Deno.env.toObject() };
  for (const line of unit.environment) {
    for (const [k, v] of parseEnvLine(line)) env[k] = v;
  }
  return env;
}

function commandOpts(unit: Unit, script: string): Deno.CommandOptions {
  const opts: Deno.CommandOptions = {
    args: ["-c", script],
    stdout: "inherit",
    stderr: "inherit",
    env: envObject(unit),
  };
  if (unit.workingDirectory) opts.cwd = unit.workingDirectory;
  return opts;
}

// Desired-state mutators (used by both command mode and the supervisor)

async function want(name: string) {
  await ensureStateDirs();
  await Deno.writeTextFile(`${WANTED}/${canonical(name)}`, "");
}

async function unwant(name: string) {
  await Deno.remove(`${WANTED}/${canonical(name)}`).catch(() => {});
}

function isWanted(unitName: string): boolean {
  try { Deno.statSync(`${WANTED}/${canonical(unitName)}`); return true; } catch { return false; }
}

async function markEnabled(name: string) {
  await ensureStateDirs();
  await Deno.writeTextFile(`${ENABLED}/${canonical(name)}`, "");
}

async function markDisabled(name: string) {
  await Deno.remove(`${ENABLED}/${canonical(name)}`).catch(() => {});
}

function isEnabled(unitName: string): boolean {
  try { Deno.statSync(`${ENABLED}/${canonical(unitName)}`); return true; } catch { return false; }
}

async function writePid(unitName: string, pid: number) {
  await Deno.writeTextFile(`${PIDS}/${canonical(unitName)}`, String(pid));
}

async function clearPid(unitName: string) {
  await Deno.remove(`${PIDS}/${canonical(unitName)}`).catch(() => {});
}

// Supervisor (PID 1)

const supervised = new Set<string>();

async function runExecStartPre(unit: Unit): Promise<boolean> {
  for (const pre of unit.execStartPre) {
    log(`${unit.name}: ExecStartPre ${pre}`);
    const { code } = await new Deno.Command("bash", commandOpts(unit, pre)).output();
    if (code !== 0) {
      log(`${unit.name}: ExecStartPre failed (rc=${code})`);
      return false;
    }
  }
  return true;
}

async function supervisePathUnit(key: string): Promise<void> {
  while (isWanted(key)) {
    const unit = await resolveUnit(key);
    if (!unit) {
      log(`${key}: unit file not found, dropping`);
      await unwant(key);
      return;
    }

    // default: trigger <name>.service (e.g. setup-wootty.path → setup-wootty.service)
    const triggerUnit = unit.pathUnit ?? key.replace(/\.path$/, ".service");

    let conditionsMet = true;
    const paths = unit.pathExists ?? [];
    for (const p of paths) {
      const negate = p.startsWith("!");
      const resolved = negate ? p.slice(1) : p;
      let exists = false;
      try { Deno.statSync(resolved); exists = true; } catch { /* missing */ }
      if (negate && exists) { conditionsMet = false; break; }
      if (!negate && !exists) { conditionsMet = false; break; }
    }

    if (conditionsMet) {
      log(`${key}: path conditions met, triggering ${triggerUnit}`);
      await want(triggerUnit);
      await unwant(key); // one-shot trigger
      return;
    }

    await new Promise((r) => setTimeout(r, RECONCILE_INTERVAL_MS));
  }
}

async function superviseUnit(name: string): Promise<void> {
  const key = canonical(name);
  try {
    if (isPathUnit(key)) {
      return await supervisePathUnit(key);
    }

    if (!isSupervisableService(key)) {

      return;
    }

    const unit = await resolveUnit(key);
    if (!unit || !unit.execStart) {
      log(`${key}: no runnable unit, dropping`);
      await unwant(key);
      return;
    }

    if (!checkConditions(unit)) {
      await unwant(key); 
      return;
    }

    if (!(await runExecStartPre(unit))) {
      await unwant(key);
      return;
    }

    if (unit.type === "oneshot") {
      log(`Starting ${key} (oneshot)`);
      const { code } = await new Deno.Command("bash", commandOpts(unit, unit.execStart)).output();
      log(`${key}: oneshot finished (rc=${code})`);
      if (unit.remainAfterExit) {
        await Deno.writeTextFile(`${EXITED}/${key}`, String(code));
      }
      await unwant(key); 
      return;
    }

    // simple / forking / notify -- supervise with restart policy.
    log(`Starting ${key} (${unit.type})`);
    while (isWanted(key)) {
      const child = new Deno.Command("bash", commandOpts(unit, unit.execStart)).spawn();
      await writePid(key, child.pid);
      const { code } = await child.status; 

      if (!isWanted(key)) {
        log(`${key}: stopped (rc=${code})`);
        break;
      }
      const shouldRestart = unit.restart === "always" ||
        (unit.restart === "on-failure" && code !== 0);
      if (!shouldRestart) {
        log(`${key}: exited rc=${code}, restart=${unit.restart} -> done`);
        break;
      }
      log(`${key}: exited rc=${code}, restarting in ${unit.restartSec}s`);
      await new Promise((r) => setTimeout(r, unit.restartSec * 1000));
    }
    await clearPid(key);
  } finally {
    
    supervised.delete(key);
  }
}

async function reconcile() {
  let names: string[] = [];
  try {
    for await (const e of Deno.readDir(WANTED)) {
      if (e.isFile) names.push(e.name);
    }
  } catch { /* dir not ready yet */ }

  for (const name of names) {
    const key = canonical(name);
    if (supervised.has(key)) continue;
    supervised.add(key);
    superviseUnit(key); 
  }
}

// cloud-init bootstrap (run once, inside --init)

const DEFAULT_USER_DATA = `#cloud-config
users:
  - name: agent
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
chpasswd:
  expire: False
  users:
  - name: agent
    password: agent
    type: text
ssh_pwauth: true
`;

async function seedCloudInit() {
  const seedDir = "/var/lib/cloud/seed/nocloud";
  await Deno.mkdir(seedDir, { recursive: true }).catch(() => {});

  const udFile = Deno.env.get("USER_DATA_FILE") ?? "/tmp/user-data";
  try {
    await Deno.stat(udFile);
    await Deno.copyFile(udFile, `${seedDir}/user-data`);
    log(`cloud-init: using user-data from ${udFile}`);
  } catch {
    await Deno.writeTextFile(`${seedDir}/user-data`, DEFAULT_USER_DATA);
    log("cloud-init: no user-data provided, using default");
  }

  const iid = `container-${Math.random().toString(36).slice(2, 10)}`;
  await Deno.writeTextFile(`${seedDir}/meta-data`, `instance-id: ${iid}\nlocal-hostname: container\n`);
}

async function runCloudInit() {
  for (const stage of [["init", "--local"], ["init"], ["modules", "--mode=config"], ["modules", "--mode=final"]]) {
    log(`cloud-init ${stage.join(" ")}`);
    await new Deno.Command("cloud-init", { args: stage, stdout: "inherit", stderr: "inherit" })
      .output().catch(() => {});
  }
  log("cloud-init complete");
}

async function generateHostKeys() {
  try {
    await Deno.stat("/etc/ssh/ssh_host_ed25519_key");
  } catch {
    log("Generating SSH host keys");
    await new Deno.Command("ssh-keygen", { args: ["-A"], stdout: "inherit", stderr: "inherit" }).output();
  }
}

// --init entrypoint (PID 1)

async function initMode() {
  await ensureStateDirs();
  log("PID 1 supervisor starting");

  await generateHostKeys();

  // sshd must be up before cloud-init runcmd (provisioning prove ssh-keyscans us).
  await want("ssh.service");
  await reconcile();

  // Reconcile loop runs concurrently with cloud-init: runcmd writes wanted/
  
  const timer = setInterval(() => { reconcile(); }, RECONCILE_INTERVAL_MS);

  await seedCloudInit();
  await runCloudInit();

  log("PID 1: reconcile loop active; supervising services");
  
  void timer;
}

// systemctl command mode

async function passthroughToRealSystemctl(): Promise<boolean> {
  
  let isSystemd = false;
  try { isSystemd = (await Deno.readTextFile("/proc/1/comm")).trim() === "systemd"; } catch { /* */ }
  if (!isSystemd) {
    try { isSystemd = (await Deno.realPath("/proc/1/exe")).includes("systemd"); } catch { /* */ }
  }
  if (!isSystemd) return false;
  const { code } = await new Deno.Command("/usr/bin/systemctl", {
    args: Deno.args, stdout: "inherit", stderr: "inherit",
  }).output();
  Deno.exit(code);
}

async function stopUnit(name: string) {
  const key = canonical(name);
  await unwant(key); 

  const pid = readPid(key);
  if (pid && pidAlive(pid)) {
    const unit = (await resolveUnit(key)) ?? unitDefaults(key);
    log(`Stopping ${key} (PID ${pid})`);
    try { Deno.kill(pid, "SIGTERM"); } catch { /* gone */ }
    const deadline = Date.now() + unit.timeoutStopSec * 1000;
    while (Date.now() < deadline && pidAlive(pid)) {
      await new Promise((r) => setTimeout(r, 200));
    }
    if (pidAlive(pid)) { try { Deno.kill(pid, "SIGKILL"); } catch { /* */ } }
  }
  await clearPid(key);
  await Deno.remove(`${EXITED}/${key}`).catch(() => {});
}

async function commandMode() {
  if (await passthroughToRealSystemctl()) return;

  await ensureStateDirs();
  const [cmd, ...rest] = Deno.args;

  // List units when invoked with no arguments.
  if (!cmd) {
    console.log("UNIT LOAD ACTIVE SUB");
    try {
      for await (const e of Deno.readDir(WANTED)) {
        if (e.isFile) {
          console.log(`${e.name} loaded ${serviceRunning(e.name) ? "active" : "inactive"} systemctl-shim`);
        }
      }
    } catch { /* */ }
    return;
  }

  // Split flags from unit names.
  let now = false;
  const units: string[] = [];
  for (const a of rest) {
    if (a === "--no-block") continue; 
    else if (a === "--now") now = true;
    else units.push(a);
  }

  switch (cmd) {
    case "daemon-reload":
    case "daemon-reexec":
      log(`${cmd}: no-op`);
      break;

    case "enable":
      for (const u of units) {
        await markEnabled(u);
        if (now) await want(u);
        console.log(`Enabled ${canonical(u)}${now ? " (now)" : ""}`);
      }
      break;

    case "disable":
      for (const u of units) { await markDisabled(u); await unwant(u); }
      break;

    case "start":
      
      for (const u of units) await want(u);
      break;

    case "stop":
      for (const u of units) await stopUnit(u);
      break;

    case "restart":
    case "try-restart":
      for (const u of units) { await stopUnit(u); await want(u); }
      break;

    case "is-active": {
      const u = units[0];
      if (u && (serviceRunning(u) || serviceExited(u))) { console.log("active"); Deno.exit(0); }
      console.log("inactive"); Deno.exit(3);
      break;
    }

    case "is-enabled": {
      const u = units[0];
      if (u && isEnabled(u)) { console.log("enabled"); Deno.exit(0); }
      console.log("disabled"); Deno.exit(1);
      break;
    }

    case "status": {
      const u = canonical(units[0] ?? "");
      console.log(`* ${u} - systemctl-shim`);
      if (serviceRunning(u)) console.log(`   Active: active (running) -- PID ${readPid(u)}`);
      else if (serviceExited(u)) console.log("   Active: active (exited)");
      else console.log("   Active: inactive (dead)");
      break;
    }

    case "--version":
    case "version":
      console.log("systemctl-shim 4.0 (deno PID1 reconcile, container mode)");
      break;

    default:
      console.error(`systemctl-shim: unsupported command: ${cmd}`);
      Deno.exit(1);
  }
}

// Entry

if (Deno.args[0] === "--init") {
  initMode();
} else {
  commandMode();
}
