import type {
  Microvm,
  MicrovmContainerState,
  MicrovmExit,
  MicrovmResult,
  MicrovmSpec,
} from "@publicdomainrelay/microvm-firecracker";

export interface SubidRange {
  base: number;
  count: number;
}

export interface UsernsSlot {
  index: number;
  uid: number;
  gid: number;
  vmmUid: number;
  vmmGid: number;
}

export interface UsernsMicrovmOptions {
  nodeboot: string;
  firecracker: string;
  stage: string;
  runtimeDir: string;
  account?: string;
  pasta?: string;
  slotSize?: number;
  innerId?: number;
  hostAddress?: string;
  bootTimeoutMs?: number;
  watchIntervalMs?: number;
  logger?: { info(event: string, extra?: Record<string, unknown>): void };
}

const DEFAULT_SLOT_SIZE = 65536;
const DEFAULT_INNER_ID = 1000;
const DEFAULT_HOST_ADDRESS = "192.0.2.1";
const DEFAULT_PASTA = "/usr/bin/pasta";
const DEFAULT_BOOT_TIMEOUT_MS = 180_000;
const DEFAULT_WATCH_INTERVAL_MS = 5_000;
const UNIT_PREFIX = "socialweb-vm-";
const DEFAULT_TAP = "fctap0";
const GUEST_ROUTE_SCRIPT = [
  'tap=$1 guest=$2 own=$3; shift 3',
  'br=$(basename "$(readlink /sys/class/net/$tap/master)")',
  'mac=$(bridge fdb show brport "$tap" | awk \'!/permanent/ {print $1; exit}\')',
  '[ -n "$mac" ] || { echo "no guest MAC learned on $tap yet" >&2; exit 1; }',
  'ip route replace "$guest/32" dev "$br" src "$own"',
  'ip neigh replace "$guest" lladdr "$mac" dev "$br" nud permanent',
  'exec "$@"',
].join("\n");

export function parseSubid(text: string, account: string): SubidRange {
  for (const line of text.split("\n")) {
    const [name, base, count] = line.trim().split(":");
    if (name === account && base && count) return { base: Number(base), count: Number(count) };
  }
  throw new Error(
    `${account} has no subordinate id range. Each guest's VMM runs in a user namespace mapped to a ` +
      `slice of the range of the account that starts it, through the setuid newuidmap/newgidmap; ` +
      `install adds "${account}:<base>:<count>" to /etc/subuid and /etc/subgid.`,
  );
}

export function slotFor(uids: SubidRange, gids: SubidRange, slotSize: number, innerId: number, index: number): UsernsSlot {
  const slots = Math.floor(Math.min(uids.count, gids.count) / slotSize);
  if (index < 0 || index >= slots) {
    throw new Error(`slot ${index} is outside the ${slots} slots of ${slotSize} ids the subordinate range holds`);
  }
  if (innerId < 0 || innerId >= slotSize) throw new Error(`inner id ${innerId} is outside a slot of ${slotSize}`);
  const uid = uids.base + index * slotSize;
  const gid = gids.base + index * slotSize;
  return { index, uid, gid, vmmUid: uid + innerId, vmmGid: gid + innerId };
}

async function run(argv: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  const out = await new Deno.Command(argv[0], { args: argv.slice(1), stdout: "piped", stderr: "piped" }).output();
  const dec = new TextDecoder();
  return { code: out.code, stdout: dec.decode(out.stdout), stderr: dec.decode(out.stderr) };
}

async function mustRun(argv: string[]): Promise<string> {
  const r = await run(argv);
  if (r.code !== 0) throw new Error(`${argv.join(" ")} exited ${r.code}: ${r.stderr.trim()}`);
  return r.stdout;
}

export function createUsernsFirecrackerMicrovm(opts: UsernsMicrovmOptions): Microvm {
  const slotSize = opts.slotSize ?? DEFAULT_SLOT_SIZE;
  const innerId = opts.innerId ?? DEFAULT_INNER_ID;
  const hostAddress = opts.hostAddress ?? DEFAULT_HOST_ADDRESS;
  const pasta = opts.pasta ?? DEFAULT_PASTA;
  const bootTimeoutMs = opts.bootTimeoutMs ?? DEFAULT_BOOT_TIMEOUT_MS;
  const watchIntervalMs = opts.watchIntervalMs ?? DEFAULT_WATCH_INTERVAL_MS;
  const usedSlots = new Map<string, number>();
  const staged = new Map<string, Promise<string>>();
  const netExec = new Map<string, string[]>();

  const identity = (async () => {
    const self = (await mustRun(["id", "-un"])).trim();
    const account = opts.account || self;
    const uid = (await mustRun(["id", "-u", account])).trim();
    const uids = parseSubid(await Deno.readTextFile("/etc/subuid"), account);
    const gids = parseSubid(await Deno.readTextFile("/etc/subgid"), account);
    const runtime = `/run/user/${uid}`;
    const asAccount = account === self ? [] : [
      "sudo", "-n", "-u", account, "env", `XDG_RUNTIME_DIR=${runtime}`, `DBUS_SESSION_BUS_ADDRESS=unix:path=${runtime}/bus`,
    ];
    return { account, uids, gids, asAccount };
  })();

  async function systemctl(args: string[]) {
    const { asAccount } = await identity;
    return await run([...asAccount, "systemctl", "--user", ...args]);
  }

  function stageFile(src: string): Promise<string> {
    const hit = staged.get(src);
    if (hit) return hit;
    const p = (async () => {
      const dir = `${opts.runtimeDir}/bin`;
      await Deno.mkdir(dir, { recursive: true, mode: 0o755 });
      await Deno.chmod(opts.runtimeDir, 0o755);
      await Deno.chmod(dir, 0o755);
      const dst = `${dir}/${src.split("/").pop()}`;
      await mustRun(["cp", "--reflink=auto", "-f", src, dst]);
      await Deno.chmod(dst, 0o755);
      return dst;
    })();
    staged.set(src, p);
    return p;
  }

  function stageImage(imageDir: string): Promise<string> {
    const hit = staged.get(imageDir);
    if (hit) return hit;
    const p = (async () => {
      const dir = `${opts.runtimeDir}/images`;
      await Deno.mkdir(dir, { recursive: true, mode: 0o755 });
      await Deno.chmod(dir, 0o755);
      const dst = `${dir}/${imageDir.replace(/\/+$/, "").split("/").pop()}`;
      const exists = await Deno.stat(dst).then(() => true, () => false);
      if (!exists) {
        await mustRun(["cp", "-a", "--reflink=auto", imageDir, `${dst}.tmp`]);
        await mustRun(["chmod", "-R", "a+rX", `${dst}.tmp`]);
        await Deno.rename(`${dst}.tmp`, dst);
      }
      return dst;
    })();
    staged.set(imageDir, p);
    return p;
  }

  function takeSlot(workDir: string, slots: number): number {
    const taken = new Set(usedSlots.values());
    for (let i = 0; i < slots; i++) {
      if (!taken.has(i)) {
        usedSlots.set(workDir, i);
        return i;
      }
    }
    throw new Error(`every one of the ${slots} user namespace slots is held by a running guest`);
  }

  async function unitState(unit: string): Promise<MicrovmContainerState> {
    const r = await systemctl(["show", "-p", "LoadState,ActiveState,ExecMainStatus", unit]);
    const props = Object.fromEntries(
      r.stdout.trim().split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]),
    );
    if (props.LoadState !== "loaded") return { exists: false, running: false };
    const code = Number(props.ExecMainStatus);
    return {
      exists: true,
      running: ["active", "activating", "deactivating", "reloading"].includes(props.ActiveState),
      exitCode: Number.isFinite(code) ? code : undefined,
    };
  }

  async function childrenOf(pid: number): Promise<number[]> {
    const out: number[] = [];
    const tasks = await Array.fromAsync(Deno.readDir(`/proc/${pid}/task`)).catch(() => []);
    for (const t of tasks) {
      const raw = await Deno.readTextFile(`/proc/${pid}/task/${t.name}/children`).catch(() => "");
      out.push(...raw.trim().split(/\s+/).filter((p) => p !== "").map(Number));
    }
    return out;
  }

  async function descendantNamed(pid: number, comm: string): Promise<number | undefined> {
    for (const child of await childrenOf(pid)) {
      const name = (await Deno.readTextFile(`/proc/${child}/comm`).catch(() => "")).trim();
      if (name === comm) return child;
      const deeper = await descendantNamed(child, comm);
      if (deeper !== undefined) return deeper;
    }
    return undefined;
  }

  async function logTail(workDir: string): Promise<string> {
    return (await Deno.readTextFile(`${workDir}/nodeboot.log`).catch(() => "(no nodeboot.log)")).slice(-4000);
  }

  function unitOf(name: string): string {
    return `${UNIT_PREFIX}${name}.service`;
  }

  return {
    name: "firecracker-userns",
    async boot(spec: MicrovmSpec): Promise<MicrovmResult> {
      const { account, uids, gids } = await identity;
      const slots = Math.floor(Math.min(uids.count, gids.count) / slotSize);
      const slot = slotFor(uids, gids, slotSize, innerId, takeSlot(spec.workDir, slots));
      const [nodeboot, firecracker, stage, imageDir] = await Promise.all([
        stageFile(opts.nodeboot),
        stageFile(opts.firecracker),
        stageFile(opts.stage),
        stageImage(spec.imageDir),
      ]);
      await Deno.mkdir(spec.workDir, { recursive: true });
      await Deno.chmod(spec.workDir, 0o700);
      await mustRun(["setfacl", "-m", `u:${account}:rwx,u:${slot.vmmUid}:rwx`, spec.workDir]);
      const specPath = `${spec.workDir}/boot-spec.json`;
      const resultPath = `${spec.workDir}/result.json`;
      await Deno.remove(resultPath).catch(() => {});
      await Deno.writeTextFile(specPath, JSON.stringify({
        name: spec.name,
        image_dir: imageDir,
        work_dir: spec.workDir,
        firecracker,
        pasta: stage,
        pasta_args: [
          String(slot.uid), String(slot.gid), String(slotSize), String(innerId),
          pasta, "--map-host-loopback", hostAddress,
        ],
        user_data_file: spec.userDataFile,
        vcpu: spec.vcpu,
        mem_mib: spec.memMib,
        disk_mib: spec.diskMib,
        instance_timeout_sec: spec.instanceTimeoutSec,
        vmm_uid: slot.vmmUid,
        network: {
          guest_ip: spec.network.guestIp,
          prefix: spec.network.prefix,
          gateway: spec.network.gateway,
          pasta_ip: spec.network.pastaIp,
          interface: spec.network.interface,
          tap: spec.network.tap,
          bridge: spec.network.bridge,
          guest_mac: spec.network.guestMac,
        },
      }, null, 2));
      await Deno.chmod(specPath, 0o644);
      const unit = unitOf(spec.name);
      const { asAccount } = await identity;
      const log = `${spec.workDir}/nodeboot.log`;
      await mustRun([
        ...asAccount, "systemd-run", "--user", "--quiet", "--collect", "--unit", unit,
        "-p", "Type=exec", "-p", "KillMode=control-group", "-p", "KillSignal=SIGKILL", "-p", "TimeoutStopSec=10",
        "-p", `StandardOutput=append:${log}`, "-p", `StandardError=append:${log}`,
        nodeboot, "-spec", specPath, "-result", resultPath, "-foreground",
      ]);
      opts.logger?.info("microvm_userns_unit_started", {
        name: spec.name, unit, account, slot: slot.index, uidBase: slot.uid, vmmUid: slot.vmmUid, slotSize,
      });
      const deadline = Date.now() + bootTimeoutMs;
      while (Date.now() < deadline) {
        const raw = await Deno.readTextFile(resultPath).catch(() => "");
        if (raw.trim()) {
          const parsed = JSON.parse(raw) as Record<string, unknown>;
          const pastaPid = Number(parsed.pasta_pid);
          const nsPid = (await childrenOf(pastaPid))[0];
          const hostVmmPid = await descendantNamed(pastaPid, "firecracker");
          if (nsPid !== undefined) {
            netExec.set(spec.name, [
              ...asAccount, "nsenter", "-t", String(nsPid), "-U", "-n", "--preserve-credentials", "--keep-caps",
              "/bin/sh", "-c", GUEST_ROUTE_SCRIPT, "sh",
              spec.network.tap ?? DEFAULT_TAP, spec.network.guestIp, spec.network.pastaIp,
            ]);
          }
          const result: MicrovmResult = {
            name: String(parsed.name),
            fingerprint: typeof parsed.fingerprint === "string" ? parsed.fingerprint : "",
            vmmPid: hostVmmPid ?? Number(parsed.vmm_pid),
            pastaPid: Number(parsed.pasta_pid),
            guestIp: String(parsed.guest_ip),
            socket: String(parsed.socket),
            console: String(parsed.console),
            workDir: String(parsed.work_dir),
            container: unit,
          };
          opts.logger?.info("microvm_booted", {
            name: result.name, unit, guestIp: result.guestIp, vmmPid: result.vmmPid, vmmUid: slot.vmmUid,
            uidMap: await Deno.readTextFile(`/proc/${result.vmmPid}/uid_map`).then((m) => m.trim()).catch(() => ""),
          });
          return result;
        }
        const state = await unitState(unit);
        if (!state.running) {
          throw new Error(`the unit ${unit} that boots guest ${spec.name} stopped before it reported a guest:\n${await logTail(spec.workDir)}`);
        }
        await new Promise((r) => setTimeout(r, 300));
      }
      throw new Error(`guest ${spec.name} reported no result within ${bootTimeoutMs}ms:\n${await logTail(spec.workDir)}`);
    },
    inspect: unitState,
    guestNetExec(name: string): string[] | undefined {
      return netExec.get(name);
    },
    hostAddressForGuest(): Promise<string> {
      return Promise.resolve(hostAddress);
    },
    async stop(workDir: string): Promise<void> {
      const name = workDir.split("/").filter((p) => p !== "").pop() ?? "";
      if (!name) throw new Error(`cannot tell which guest works in ${workDir}`);
      const unit = unitOf(name);
      await systemctl(["stop", unit]);
      await systemctl(["reset-failed", unit]);
      const state = await unitState(unit);
      if (state.running) {
        throw new Error(`unit ${unit} is still running after stop, so its work directory ${workDir} is kept`);
      }
      await Deno.remove(workDir, { recursive: true }).catch((err: unknown) => {
        if (!(err instanceof Deno.errors.NotFound)) throw err;
      });
      usedSlots.delete(workDir);
      netExec.delete(name);
      opts.logger?.info("microvm_work_dir_removed", { unit, workDir });
    },
    watch(container: string, onExit: (exit: MicrovmExit) => void): () => void {
      let cancelled = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      const schedule = () => {
        if (cancelled) return;
        timer = setTimeout(check, watchIntervalMs);
        Deno.unrefTimer(Number(timer));
      };
      const check = async () => {
        timer = undefined;
        if (cancelled) return;
        const state = await unitState(container).catch(() => undefined);
        if (cancelled) return;
        if (state === undefined || state.running) return schedule();
        cancelled = true;
        onExit({ container, reason: state.exists ? "exited" : "removed", exitCode: state.exitCode, logs: "" });
      };
      schedule();
      return () => {
        cancelled = true;
        if (timer !== undefined) clearTimeout(timer);
      };
    },
  };
}
