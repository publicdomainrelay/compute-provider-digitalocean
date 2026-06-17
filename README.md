# compute-provider

DigitalOcean-compatible droplets API. Two backends — local Docker, real
DigitalOcean. One HTTP surface.

```
deno run -A hono-compute-provider/mod.ts --provider local --port 8080
```

## Providers

### local

Provision Docker containers on this host. Container mode (default) or QEMU VM.

Container mode: cloud-init + sshd directly in Docker. Systemctl-shim as PID 1.
Lightweight, no KVM needed.

QEMU mode: full VM with kernel/initrd/squashfs overlay via privileged Docker
container with /dev/kvm passthrough.

```
# Container mode (default)
deno run -A hono-compute-provider/mod.ts --provider local

# QEMU mode
deno run -A hono-compute-provider/mod.ts --provider local --no-container-mode

# Custom images
deno run -A hono-compute-provider/mod.ts --provider local \
  --vm-image my-qemu:latest \
  --container-image my-runner:latest
```

### digitalocean

Proxy to DigitalOcean-compatible API.

```
DO_TOKEN=xxx deno run -A hono-compute-provider/mod.ts \
  --provider digitalocean \
  --digitalocean-base-url https://droplet-oidc.its1337.com
```

## Options

Every option: CLI flag, env var, or cliffy default. Config resolution
order: `--flag` > `ENV_VAR` > default.

| Flag | Env | Default | Use |
|------|-----|---------|-----|
| `-p`, `--port` | `PORT` | `8080` | HTTP listen port |
| `--provider` | `COMPUTE_PROVIDER` | `local` | `local` or `digitalocean` |
| `--container-mode` | `CONTAINER_MODE` | `true` | Container (true) or QEMU (false). Local only |
| `--vm-image` | `VM_IMAGE` | `atcr.io/...ccripoc-qemu-runner` | QEMU Docker image. Local only |
| `--container-image` | `CONTAINER_IMAGE` | `container-runner-ubuntu:latest` | Container runner image. Local only |
| `--cache-dir` | `CACHE_DIR` | `~/.cache/pdr-local` | Temp files. Local only |
| `--issuer-url` | `ISSUER_URL` | `http://localhost:{port}` | OIDC issuer base URL |
| `--operator-handle` | `OPERATOR_HANDLE` | `did:plc:localhost` | Operator DID |
| `--self-did` | `SELF_DID` | `did:plc:localhost` | This host DID |
| `--digitalocean-base-url` | `DIGITALOCEAN_BASE_URL` | `https://droplet-oidc.its1337.com` | DO API base. DO only |
| `--do-token` | `DO_TOKEN` | (none) | DO API token. DO only. Required |

## API

All `/v2/*` routes: `Authorization: Bearer <token>` header required.

| Method | Path | What |
|--------|------|------|
| `GET` | `/v2/account` | Account info. Returns `{account: {team: {uuid}}}` |
| `POST` | `/v2/droplets` | Create droplet. Body: `{name, region?, size?, image?, user_data?, ssh_keys?, tags?}`. Returns 202 |
| `GET` | `/v2/droplets` | List droplets scoped to auth context |
| `GET` | `/v2/droplets/:id` | Get single droplet |
| `DELETE` | `/v2/droplets/:id` | Destroy droplet. Returns 204 |

OIDC endpoints (local provider only):

| Method | Path | What |
|--------|------|------|
| `GET` | `/.well-known/openid-configuration` | OIDC discovery |
| `GET` | `/.well-known/jwks` | Public JWKS |
| `POST` | `/v1/oidc/issue` | Issue scoped JWT. Body: `{sub, ttl?, aud?}` |
| `POST` | `/v1/oidc/prove` | SSH challenge -> scoped token. Body: `{sig, port}` |

## How local provisioning works

1. POST `/v2/droplets` hits factory
2. `ProvisioningData.create()` mints nonce + short-lived JWT + injects cloud-init
   runcmd scripts (provisioning-token.sh + systemd unit)
3. `spawnVM()` fires: write user-data, `docker run -d` with systemctl-shim mounted
4. Container boots: systemctl-shim starts sshd, runs cloud-init
5. runcmd runs `provisioning-token.sh`: SSH-signs provisioning JWT, calls
   `/v1/oidc/prove`, gets scoped OIDC token, writes to
   `/root/secrets/digitalocean.com/serviceaccount/token`
6. Container now has short-lived credential. Can call `/v1/oidc/issue` to mint
   more tokens

## How DO proxying works

1. POST `/v2/droplets` hits factory
2. If `gitRbac` configured: push HCL policy + role files to git RBAC repo
3. Factory proxies request to `{digitaloceanBaseUrl}/v2/droplets` with `DO_TOKEN`
4. Forwards `x-on-behalf-of` header with caller DID
5. Returns DO API response verbatim

## Packages

```
lib/common                        shared types (Logger, LoggerInterface)
lib/abc/compute-provider          ComputeProvider interface, VM, DropletSpec
lib/compute-provider-local        Docker/QEMU runner, systemctl-shim
lib/compute-provider-digitalocean DO API provider
lib/rbac-atproto                  atproto record RBAC (com.fedproxy.rbac)
lib/oidc-issuer                   OIDC Hono app, OIDCToken, ProvisioningData
lib/hono-factory-compute-provider-local      DO-compatible droplets API (local backend)
lib/hono-factory-compute-provider-digitalocean  DO-compatible droplets API (proxy backend)
hono-compute-provider             CLI entrypoint, cli-args-env.json
```

Dependency direction: `common <- abc <- impl <- hono-factory <- cli`
