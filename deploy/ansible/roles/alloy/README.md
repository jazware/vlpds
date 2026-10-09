# alloy

Grafana Alloy from the Grafana apt repository, configured from
`/etc/alloy/` (config.alloy plus one file per fragment in
`alloy_config_fragments`). Metrics go to your monitoring stack's Prometheus
remote_write endpoint (`alloy_remote_write_url`), logs to its Loki
(`alloy_loki_push_url`); both default to paths under `alloy_monitoring_url`,
with optional basic auth (`monitoring_basic_auth_user` /
`monitoring_basic_auth_password`; keep the password in an encrypted vars
file). Every series and log line carries `cluster=<deploy_env>` and
`hostname`. Variables and their types:
[`defaults/main.yml`](defaults/main.yml), [`meta/argument_specs.yml`](meta/argument_specs.yml).

## Fragments

| Fragment | What |
|----------|------|
| `host-monitoring` | node_exporter metrics, the systemd journal, `/var/log`, container logs (Docker discovery), and the remote_write / Loki endpoints the other fragments forward to: always keep it |
| `vlpds-monitoring` | the vlpds node's metrics port (`127.0.0.1:<vlpds_metrics_host_port>`) as `job="vlpds"`, `instance=<vlpds_node_id>` |
| `docker-monitoring` | per-container CPU/memory/network via cAdvisor; needs the raw socket and root, so not with the default proxy mode |

With `alloy_pyroscope_enabled`, Alloy also receives profiles on
`alloy_pyroscope_listen_port` (vlpds images built with profiling push there
with `vlpds_extra_env: {VLPDS_PYROSCOPE_URL: "http://host.docker.internal:<port>"}`)
and forwards them to `alloy_pyroscope_url`.

## Privilege modes

| Mode | Settings | Docker access |
|------|----------|---------------|
| proxy (default) | `alloy_docker_socket_proxy: true` | filtered, read-only proxy |
| docker group | `alloy_docker_socket_proxy: false` | raw socket via the `docker` group (`alloy_enable_docker_logs`) |
| root | `alloy_docker_socket_proxy: false`, `alloy_run_as_root: true` | raw socket, plus containerd for cAdvisor (`docker-monitoring`) |

The raw Docker socket is root-equivalent, and `docker inspect` returns every
container's environment, which is where secrets usually live (on a vlpds
node: its storage credentials and key-encryption settings). Keep the proxy
mode on a vlpds node.

### Proxy mode

`alloy_docker_socket_proxy: true`:

- Alloy runs as `alloy` with groups `alloy`, `adm` (`/var/log`) and
  `systemd-journal` (the journal). The role removes it from `docker`,
  drops the run-as-root override, and hands `/var/lib/alloy` back to
  `alloy` (it stops a root Alloy first).
- An `alloy-docker-proxy` container (nginx with njs, pinned by digest in
  `alloy_docker_proxy_image`) serves the Docker API on
  `/var/lib/alloy-docker-proxy/docker.sock`. The directory is
  `alloy-docker-proxy:alloy 0750`, so only the alloy group can connect. The
  container runs as the `alloy-docker-proxy` system user with the docker
  gid, with no network, a read-only root, no capabilities and
  `no-new-privileges`.
- The proxy allows only `GET`/`HEAD` on `/_ping`, `/version`, `/networks`,
  `/containers/json`, `/containers/{id}/json` and `/containers/{id}/logs`.
  Everything else (create, exec, archive, export, images, info, events and
  so on) returns 403. The list and inspect responses are cut down to an
  allowlist of fields (`files/docker-proxy-filter.js`): no `Env`, `Cmd`,
  `Args`, `Mounts`, `HostConfig` (beyond `NetworkMode`) or healthcheck
  output. That covers what `discovery.docker` and `loki.source.docker` read.
  The proxy logs only refused and failed requests (`docker logs
  alloy-docker-proxy`).
- `docker-monitoring` (cAdvisor) is refused in this mode: it needs the raw
  socket, and root for containerd.

Turning the mode off again doesn't remove the proxy container (`docker rm
-f alloy-docker-proxy`).

Container logs, by design, still pass through the proxy. Labels are passed
through too, because discovery exposes them.
