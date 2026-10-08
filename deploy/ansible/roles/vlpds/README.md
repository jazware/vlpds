# roles/vlpds: a vlpds node

Deploys one [vlpds](../../../../README.md) node (an atproto PDS whose
durable state lives entirely in an S3-compatible bucket) under docker
compose, plus what its host needs around it: clock sync, kernel limits, a
firewall, security updates, the operator console and (when clustered) the
peer port on the tailnet. [`playbooks/vlpds.yml`](../../playbooks/vlpds.yml)
runs it between roles/common and roles/caddy + roles/alloy.

- Every variable, with its meaning: [`defaults/main.yml`](defaults/main.yml).
  The checked interface: [`meta/argument_specs.yml`](meta/argument_specs.yml).
- A worked inventory to copy: [`inventories/example`](../../inventories/example)
  and the kit's [README](../../README.md).
- The node's own procedures and alerts: `ops/RUNBOOK.md`,
  `ops/alerts.yml`, and the docs in `docs/operations/`.

## What it does

| Step | Tasks (tag) | Notes |
|---|---|---|
| Refuse bad config | `assert.yml` (`vlpds-assert`) | Pinned image, identity (service DID = `did:web:<hostname>`), bucket, secrets (>= 32 bytes, all distinct), KEK (local, or Cloud KMS with an optional service-account key), PLC key, email, log format, disk cache size, lease >= 10 s, stop grace >= 60 s, the peer TLS material when clustered, the Spaces knobs, and no dev mode or `--lexicon-authority-override` in `vlpds_extra_env` / `vlpds_extra_args`. Runs before anything changes. |
| Host prep | `host.yml` (`vlpds-host`) | chrony, sysctls (`/etc/sysctl.d/90-vlpds.conf`), ufw (SSH + 80/443 public, everything on `tailscale0`), unattended-upgrades (security only, **no automatic reboot**), an optional NVMe cache device. |
| Node | `deploy.yml` (`vlpds-deploy`) | Disk cache size and a free-space check, secret files (0400, uid 10001, read-only at `/run/vlpds`, passed as `VLPDS_*_FILE` so neither the compose file nor `docker inspect` shows a secret, and an emptied secret's file is removed), peer TLS files, `/opt/vlpds/docker-compose.yml` (0600), the `vlpds` docker network, image pull, optional bucket probe, then `compose up`. |
| Console | `console.yml` (`vlpds-console`) | `tailscale serve` on `vlpds_tailnet_console_port` for `/admin` (tailnet only). |
| Peer port | `peer.yml` (`vlpds-peer`) | Clustered only: `tailscale serve` forwards TCP `vlpds_peer_port` on the tailnet to the loopback-published peer port. |
| Verify | `verify.yml` (`vlpds-verify`) | `/xrpc/_health`, then `getClusterStatus` until the lease is valid and every shard is owned. `/tls-check` approves the hostname and refuses an unknown handle, and `/.well-known/did.json` is the service DID's. Then it prints the build, feature level, disk cache size and how the previous process ended. |

**Restarts are graceful and only when needed.** The node is recreated only
when its compose file, a secret file or the image changed (or with
`-e vlpds_force_restart=true`). Compose sends SIGTERM and waits
`vlpds_stop_grace_period` (90 s) before SIGKILL. The node hands its shards
back, fences its own log and exits 0, and the new process (same
`--node-id`) reclaims them. Peer TLS files are re-read by the running node
(renewals need no restart). A second run with nothing changed changes
nothing.

Docker compose rather than systemd, because compose gives what vlpds needs (restart on fail-stop
with backoff, SIGTERM + stop timeout, ulimits, per-container
`net.core.somaxconn`, a memory limit the node sizes its caches from,
json-file logs Alloy ships).

## Profiles

| | `tiny` | `standard` |
|---|---|---|
| For | a personal PDS on a small VM | 6-8 cores / 32 GB / NVMe |
| `--shards` (new prefix only) | 1 | 64 |
| `--lease-ttl-ms` | 60000 | 10000 |
| SlateDB manifest poll | 60 s | 10 s |
| container memory limit | 2.5 GiB (`vlpds_mem_limit_mb`) | 85% of RAM |
| disk cache | `/var/lib/vlpds-cache`, 4 GiB, needs that + 10 GiB free | `/data/vlpds/cache` on NVMe (`vlpds_cache_device` can format + mount it), `auto` = 80% of that filesystem |

The node sizes its caches from the container memory limit
(`docker exec vlpds vlpds --memory-plan` prints the plan). Tiny idles at
~0.12 Class A + ~0.41 Class B object-store requests a second (inside R2's
free tier). The price of its 60 s lease is that a restart after a crash
waits about one TTL before writing again (a graceful restart takes ~1 s).

## Object store

vlpds is only correct on a store with strongly consistent conditional writes
(`If-None-Match: *`, `If-Match`): AWS S3, GCS (S3 interop), Cloudflare R2.
Run the probe once per new bucket: `-e vlpds_preflight_probe=true` runs
`vlpds-bucket-probe` from the deployed image with the node's settings under a
throwaway prefix, and the role refuses to (re)start the node unless it
reports `SAFE for vlpds`. Add a lifecycle rule that aborts incomplete
multipart uploads after 1 day, and scope the key pair to the bucket. One
prefix (`vlpds_s3_prefix`) is one PDS: never point two deployments at it.

## First deploy

1. **Bucket**: create it, add the lifecycle rule, make the scoped key pair.
2. **Image**: pin a release of `ghcr.io/jazware/vlpds` (`:1.0.0`, never
   `:latest` or `:main`) in `vlpds_image`. To run your own build, build it
   from the repo root with `just docker-build <registry>/vlpds:<tag>` (or
   `docker buildx build --platform linux/amd64` for another platform), push
   it and pin that tag.
3. **Secrets** (the inventory's sops file, mapped onto the role variables in
   its `group_vars`): `openssl rand -hex 32` for `vlpds_jwt_secret`,
   `vlpds_admin_token`, `vlpds_internal_token` (three different values) and a
   local KEK (`vlpds_kek_hex`), or Cloud KMS (`vlpds_gcp_kms_key`, plus
   `vlpds_gcp_credentials_json` off GCE). Back the KEK up offline: it wraps
   every signing key and is not in the bucket.
4. **PLC rotation key**: `docker run --rm -i -e VLPDS_KEK <image>
   --wrap-plc-rotation-key </dev/null` prints the `vw1.…` key for
   `vlpds_plc_rotation_key` on stdout and its did:key on stderr. Record the
   did:key.
5. **DNS**: `A` for the hostname and `*.<handle domain>`. Prefer one wildcard
   certificate (`vlpds_caddy_wildcard_dns: cloudflare` +
   `vlpds_cloudflare_dns_token`) over per-handle on-demand ones.
6. **Email** (optional): `vlpds_email_smtp_url` (secret), or
   `vlpds_email_api_url` + `vlpds_email_api_token` (secret) where the
   provider blocks outbound SMTP, and
   `vlpds_email_from_address`, or `vlpds_email_required: false`.
7. **Run** (after `playbooks/bootstrap.yml` on a fresh VPS):

       ansible-playbook -i inventories/<inv>/hosts.yml playbooks/vlpds.yml --check --diff
       ansible-playbook -i inventories/<inv>/hosts.yml playbooks/vlpds.yml -e vlpds_preflight_probe=true

## Upgrades and rollback

A lone node means every restart is a short outage. The graceful stop takes
well under a second, the new process takes its first write ~1.3 s after it
starts, and Caddy retries the connection for up to 10 s in between
(`docs/operations/upgrades.md`). Set `vlpds_image` to the new tag and run `--tags
vlpds-deploy,vlpds-verify`. Until `vlpds admin cluster finalize --level L+1`
a rollback is a redeploy of the previous tag. After it, only forward fixes work.
RUNBOOK "Rolling upgrade, finalize, rollback" has the details. In a cluster
`playbooks/vlpds.yml` restarts one node at a time (`serial: 1`).

## Spaces

`vlpds_spaces: false` (the default) leaves Spaces off. Turned on, the node
gets `--spaces` and serves `com.atproto.space.*` and
`com.atproto.simplespace.*` itself. Read the checklist in
`docs/spaces/operating.md` ("Enabling on a single node")
first. The knobs only matter with it on, and empty keeps vlpds' default:

| Variable | Flag | Default |
|---|---|---|
| `vlpds_spaces` | `--spaces` | `false` |
| `vlpds_space_repo_max_records` | `--space-repo-max-records` | empty (vlpds: 100000) |
| `vlpds_space_oplog_retention` | `--space-oplog-retention` | empty (vlpds: `7d`, `off` keeps all) |
| `vlpds_max_import_mb` | `--max-import-mb` | empty (vlpds: 1024, and Caddy's importRepo cap is this + 64 MiB) |

Turning it on or off is a graceful restart. With it off again, space-only
blobs stay private and the space data stays in the bucket.

The role never runs a node in dev mode. `assert.yml` refuses
`VLPDS_DEV_MODE` / `--dev-mode` and `VLPDS_LEXICON_AUTHORITY_OVERRIDE` /
`--lexicon-authority-override` in the extras, and the compose file drops
those two env vars even with the assert skipped. The override lets a chosen
repo stand in for a lexicon's DNS authority, which could widen OAuth grants.

## Clustering

`vlpds_cluster_enabled: false` (the default) runs a lone node: no
`--peer-listen`, `--advertise-url` or `--peer-tls-dir`. Turned on, every node
gets them:

- `--peer-listen 0.0.0.0:2584` in the container, published on
  `127.0.0.1:vlpds_peer_host_port`. `tailscale serve` forwards
  `<tailnet address>:vlpds_peer_port` to it. TLS passes through, the peer
  port is never on a public interface, and Docker never has to bind a
  tailnet address at boot.
- `--advertise-url https://<vlpds_peer_host>:<vlpds_peer_port>`:
  `vlpds_peer_host` is the node's tailnet IPv4 (a DNS name works only if
  the containers can resolve it).
- `--peer-tls-dir /run/vlpds/peer-tls`: `ca.crt` (`vlpds_peer_tls_ca_cert`),
  `<node id>.crt` (`vlpds_peer_tls_cert`) and `<node id>.key`
  (`vlpds_peer_tls_key`, a secret) from `vlpds admin tls ca` / `tls issue
  --node-id <vlpds_node_id> --host <vlpds_peer_host>`. The CA key stays
  offline.

Every node needs the same bucket, prefix, jwt/admin/internal tokens, KEK (or
KMS key) and PLC rotation key, and its own `vlpds_node_id` (the inventory
hostname by default). The tailnet policy must allow node-to-node TCP on the
peer port. `playbooks/vlpds.yml` refuses to run two enabled nodes without
clustering, and skips nodes with `vlpds_node_enabled: false`. Turning
clustering on is a graceful restart of each node. The join and
decommission steps are in `docs/operations/scaling-and-clustering.md`
("With the Ansible role").

With wildcard handle certificates, `vlpds_caddy_hostname_dns01: true` makes
Caddy get the hostname's certificate by DNS-01 as well, so a node can hold it
before DNS points at it.

### More handle domains

vlpds serves handles under more domains than `vlpds_handle_domain` once an
operator adds them at runtime (`vlpds admin handle-domain add <domain>` or the
console's Domains & invites page). Ansible doesn't push that set. It only gets
Caddy the certificates:

- On-demand mode (`vlpds_caddy_wildcard_dns: ""`) needs only DNS. The site
  catches every other name and asks `/tls-check` before issuing, so an `A`
  record for `*.<domain>` pointing at the node is enough.
- Wildcard mode (`cloudflare`) needs each domain in
  `vlpds_extra_handle_domains`, which renders one `*.<domain>` site per
  domain. The DNS-01 token must have Zone:DNS:Edit on those zones too.

## Monitoring

- **Metrics**: `roles/alloy/templates/vlpds-monitoring.alloy.j2` scrapes
  `127.0.0.1:9583` as `job="vlpds"`, `instance=<node id>`, and remote_write adds
  `cluster=<deploy_env>`.
- **Alerts**: `ops/alerts.yml`, for Prometheus or vmalert on your
  monitoring stack. Scope them with a `cluster` matcher if other vlpds
  instances (bench nodes) report to the same place.
- **Dashboards**: `vlpds dashboards --out DIR --datasource-uid <uid>`
  writes both, bound to your Grafana's Prometheus, for file provisioning
  (without `--datasource-uid`: import-ready, as in
  `bench/obs/grafana/dashboards/`).
- **Logs**: JSON lines on stderr, read in Loki with `{container="vlpds"} | json`.

## Backups

Not built (DESIGN.md "Backups and restore"). The bucket's durability is all
there is. Back up by hand, offline, what isn't in the bucket: the KEK (or
KMS access), the wrapped PLC rotation key and the sops files' keys.
