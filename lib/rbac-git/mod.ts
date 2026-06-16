import type { StrongRef } from "@publicdomainrelay/compute-provider";

export interface GitRbacContext {
  teamUuid: string;
  rbacRepoRoot: string;
  digitaloceanBaseUrl: string;
  doToken: string;
  log?: (level: string, msg: string, meta?: Record<string, unknown>) => void;
}

const noopLog = (_l: string, _m: string, _e?: Record<string, unknown>) => {};

async function runProc(
  cmd: string[],
  cwd: string,
  log: (level: string, msg: string, meta?: Record<string, unknown>) => void,
): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = new Deno.Command(cmd[0], {
    args: cmd.slice(1),
    cwd,
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  });
  const out = await proc.output();
  const stdout = new TextDecoder().decode(out.stdout);
  const stderr = new TextDecoder().decode(out.stderr);
  if (out.code !== 0) {
    log("error", "subprocess failed", { cmd, code: out.code, stdout, stderr });
  }
  return { code: out.code, stdout, stderr };
}

async function isDir(p: string): Promise<boolean> {
  try { return (await Deno.stat(p)).isDirectory; } catch { return false; }
}

async function ensureGitRepo(
  rbac: string,
  digitaloceanBaseUrl: string,
  teamUuid: string,
  doToken: string,
  log: (level: string, msg: string, meta?: Record<string, unknown>) => void,
): Promise<void> {
  if (await isDir(`${rbac}/.git`)) return;

  await Deno.mkdir(rbac, { recursive: true });
  const home = Deno.env.get("HOME") ?? "/root";
  const credHelperDir = `${home}/.local/scripts`;
  const credHelperPath = `${credHelperDir}/git-credential-rbac-digitalocean.sh`;
  const credHelper = `#!/usr/bin/env bash

TOKEN="${doToken}"

while IFS='=' read -r key value; do
  if [[ -n "$key" && -n "$value" ]]; then
    if [[ "$key" == "protocol" || "$key" == "host" ]]; then
      echo "$key=$value"
    fi
  fi
done

echo "username=token"
echo "password=\${TOKEN}"
`;
  await Deno.mkdir(credHelperDir, { recursive: true });
  await Deno.writeTextFile(credHelperPath, credHelper);
  await Deno.chmod(credHelperPath, 0o700);

  const helperAbs = await Deno.realPath(credHelperPath);
  const cmds: string[][] = [
    ["git", "config", "--global", `credential.${digitaloceanBaseUrl}/_rbac/DigitalOcean/.helper`, `!${helperAbs}`],
    ["git", "init"],
    ["git", "remote", "add", "origin", `${digitaloceanBaseUrl}/_rbac/DigitalOcean/${teamUuid}`],
    ["git", "pull", "origin", "main"],
    ["git", "branch", "--set-upstream-to=origin/main"],
  ];
  for (const cmd of cmds) {
    log("info", "rbac git command", { cmd });
    const r = await runProc(cmd, rbac, log);
    if (r.code !== 0) {
      if (cmd[1] === "pull" && r.stderr.includes("couldn't find remote ref main")) continue;
      if (cmd[1] === "branch" && r.stderr.includes("no commit on branch")) continue;
      log("error", "rbac git command failed", { cmd, code: r.code });
    }
  }
}

export async function configureRbac(
  vm: { role: string; _uri?: string; _cid?: string },
  requesterDid: string,
  ctx: GitRbacContext,
): Promise<StrongRef> {
  const log = ctx.log ?? noopLog;
  const { teamUuid, rbacRepoRoot, digitaloceanBaseUrl, doToken } = ctx;
  const rbac = `${rbacRepoRoot}/${teamUuid}`;

  await ensureGitRepo(rbac, digitaloceanBaseUrl, teamUuid, doToken, log);

  const requesterPlc = requesterDid.split(":").slice(-1)[0];
  const slug = `${teamUuid}-${requesterPlc}-${vm.role}`;
  const roleName = `ex-${slug}`;
  const subject = `actx:${teamUuid}:plc:${requesterPlc}:role:${vm.role}`;

  const policyPath = `${rbac}/policies/ex-${slug}.hcl`;
  const policyEx = `path "/v1/oidc/issue" {
  capabilities = ["create"]
  allowed_parameters = {
    "aud" = "*"
    "sub" = "${subject}"
    "ttl" = 3600
  }
}
`;

  const rolePath = `${rbac}/droplet-roles/ex-${slug}.hcl`;
  const roleEx = `role "ex-${slug}" {
  aud      = "api://DigitalOcean?actx=${teamUuid}"
  sub      = "${subject}"
  policies = ["ex-${slug}"]
}
`;

  await Deno.mkdir(`${rbac}/policies`, { recursive: true });
  await Deno.mkdir(`${rbac}/droplet-roles`, { recursive: true });
  await Deno.writeTextFile(policyPath, policyEx);
  await Deno.writeTextFile(rolePath, roleEx);

  const commitCmds: string[][] = [
    ["git", "add", "-A"],
    ["git", "commit", "-m", "feat: rbac for compute-contract"],
    ["git", "push", "-u", "origin", "main"],
  ];
  for (const cmd of commitCmds) {
    log("info", "rbac git command", { cmd });
    const r = await runProc(cmd, rbac, log);
    if (r.code !== 0) {
      if (cmd[1] === "commit" && r.stdout.includes("nothing to commit")) continue;
      log("error", "rbac git command failed", { cmd, code: r.code });
    }
    log("info", "rbac git command exited", { cmd, code: r.code });
  }

  const commitLog = await runProc(
    ["git", "log", "--format=%H", "-1"],
    rbac,
    log,
  );
  const commitHash = commitLog.stdout.trim();

  return {
    $type: "com.atproto.repo.strongRef",
    uri: `${digitaloceanBaseUrl}/_rbac/DigitalOcean/${teamUuid}/-/commit/${commitHash}`,
    cid: commitHash,
  };
}
