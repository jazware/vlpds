#!/usr/bin/env python3
"""Generates the vlpds Grafana dashboards, two copies of each:

    python3 bench/obs/grafana/gen_dashboard.py           (or: just dashboards)
    python3 bench/obs/grafana/gen_dashboard.py --check   (exit 1 if a copy is stale)

Dashboards:
- vlpds.json (uid `vlpds`, "vlpds"): the PDS operator's view, in their
  words (users, content, federation, moderation, email, cost); its panels
  are in gen_operator.py.
- vlpds-internals.json (uid `vlpds-internals`, "vlpds internals"): the
  engineer's view of every subsystem, built below.

Datasources are dashboard variables (`ds_prometheus`, `ds_pyroscope`) and
the scrape job is one too (`job`), so the dashboards fit any Grafana 10+.

Copies:
- bench/obs/grafana/dashboards/: the import-ready copy, which `vlpds
  dashboards` also prints (src/cli/dashboards.rs embeds it). `__inputs`
  makes the Import dialog ask for a Prometheus and write it into
  `ds_prometheus`. The bench stack provisions this same file: provisioning
  leaves the literal ${DS_PROMETHEUS}, no datasource has that uid, and
  Grafana selects the first Prometheus by name instead (the bench has one).
- deploy/ansible/roles/monitoring/files/dashboards/ in the monorepo this
  was developed in, when that directory exists: a deployment's Grafana, the
  Prometheus variable pre-set to its uid (PROD_PROM_UID below), no
  `__inputs`. That Grafana has no Pyroscope, so this copy leaves out the
  CPU profile row and its pickers.

VLPDS_PROM_UID (a uid, or `default`: the default datasource) /
VLPDS_PYRO_UID / VLPDS_DASH_OUT (a directory) render one extra pre-set copy
of both for some other Grafana instead (the default copies are then left
alone).

Internals layout: an always-open "Health" row read in seconds (stats
coloured by the ops/alerts.yml thresholds, alert timeline, nodes table, the
key series per node), then collapsed rows per subsystem. Queries use
[$__rate_interval] and aggregate before histogram_quantile, so a 1 s refresh
on the bench stays cheap.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH_DIR = os.path.join(HERE, "dashboards")
PROD_DIR = os.path.normpath(os.path.join(HERE, "../../../../../deploy/ansible/roles/monitoring/files/dashboards"))
# The Prometheus datasource uid of that deployment's Grafana.
PROD_PROM_UID = "P4169E866C3094E38"

PROM = {"type": "prometheus", "uid": "${ds_prometheus}"}
PYRO = {"type": "grafana-pyroscope-datasource", "uid": "${ds_pyroscope}"}
# the Import dialog replaces __inputs placeholders; file provisioning doesn't
DS_INPUT = "${DS_PROMETHEUS}"
# state-timeline and flamegraph panels
GRAFANA_MIN = "10.0.0"

RB = "https://github.com/jazware/vlpds/blob/main/ops/RUNBOOK.md"
ALERTS_URL = "https://github.com/jazware/vlpds/blob/main/ops/alerts.yml"
MONITORING_DOC = "https://github.com/jazware/vlpds/blob/main/docs/operations/monitoring.md"
# ALERTS has series only while an alert is pending or firing: "rules not loaded" and "all quiet" look the same
ALERTS_NOTE = ("Needs ops/alerts.yml loaded in the rule evaluator that writes ALERTS to this Prometheus; "
               f"without it this stays empty ([monitoring docs]({MONITORING_DOC})).")


def rb(anchor, text=None):
    """Markdown link into ops/RUNBOOK.md (alert sections are anchored by alert name)."""
    return f"[{text or anchor}]({RB}#{anchor.lower()})"


# Every query is scoped to the cluster variable (Alloy's remote_write adds
# cluster=<deploy_env>; the bench Prometheus has no cluster label, which the
# All value ".*" still matches) and the node variable ($instance; its values
# are instance labels, its text the node ids).
C = 'cluster=~"$cluster"'
I = C + ', instance=~"$instance"'
# up is the one series a down node keeps, and every target in the Prometheus
# has one: $job narrows it to the jobs that export vlpds_build_info
UP = f'up{{job=~"$job", {I}}}'
RI = "[$__rate_interval]"
# MinIO is scraped every 5 s: rate windows need >= 2 samples
MRI = "[20s]"
WRITE_METHODS = r"com\\.atproto\\.repo\\.(createRecord|putRecord|deleteRecord|applyWrites)"
READ_METHODS = r"com\\.atproto\\.(repo\\.(get|list|describe).*|sync\\.(get|list).*|identity\\.resolve.*)"
PROXY_METHODS = r"(app\\.bsky|chat\\.bsky|tools\\.ozone)\\..*|_proxy_or_unmatched"
# what VlpdsHttp5xxHigh counts: everything vlpds answers itself
OWN = 'method!="_proxy_or_unmatched"'

# Node legends: series keyed by instance get the node id from vlpds_build_info
# (prod: instance = node id already; bench: instance = 127.0.0.1:<port>).
NODE_JOIN = f" * on (instance) group_left (node_id) max by (instance, node_id) (vlpds_build_info{{{I}}})"


def by_node(expr):
    return f"({expr}){NODE_JOIN}"


# Fixed colours for series that recur across panels.
STATUS_COLORS = {"2xx": "green", "3xx": "blue", "4xx": "yellow", "429": "orange", "5xx": "red"}
# only bare quantile legends: "p99 {{stage}}" series must stay distinguishable
QUANTILE_COLORS = [("p50", "green"), ("p90", "yellow"), ("p99", "orange"), ("p99.9", "red")]


class Dash:
    def __init__(self):
        self.panels = []
        self._id = 0
        self.x = self.y = self.row_h = 0
        self.row = None

    def nid(self):
        self._id += 1
        return self._id

    def place(self, w, h):
        if self.x + w > 24:
            self.newline()
        pos = {"x": self.x, "y": self.y, "w": w, "h": h}
        self.x += w
        self.row_h = max(self.row_h, h)
        return pos

    def newline(self):
        if self.x:
            self.x = 0
            self.y += self.row_h
            self.row_h = 0

    def add_row(self, title, collapsed=True, desc=""):
        self.newline()
        r = {"type": "row", "id": self.nid(), "title": title, "collapsed": collapsed,
             "gridPos": {"x": 0, "y": self.y, "w": 24, "h": 1}, "panels": []}
        if desc:
            r["description"] = desc
        self.y += 1
        self.panels.append(r)
        self.row = r if collapsed else None

    def add(self, p):
        (self.row["panels"] if self.row else self.panels).append(p)


D = Dash()
row = D.add_row


def t(expr, legend="", **kw):
    return {"datasource": PROM, "expr": expr, "legendFormat": legend, "range": True, **kw}


def thresholds(steps, base="green"):
    return {"mode": "absolute", "steps": [{"color": base, "value": None}] + [{"color": c, "value": v} for v, c in steps]}


def color_overrides(targets):
    """Status-class and quantile series get the same colour on every panel."""
    out = []
    legends = {tg.get("legendFormat", "") for tg in targets}
    for name, color in STATUS_COLORS.items():
        if name in legends:
            out.append({"matcher": {"id": "byName", "options": name},
                        "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}}]})
    for name, color in QUANTILE_COLORS:
        if name in legends:
            out.append({"matcher": {"id": "byName", "options": name},
                        "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}}]})
    return out


def right_axis(name, unit):
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": "unit", "value": unit}, {"id": "custom.axisPlacement", "value": "right"}]}


def dashed(name, color="red"):
    """A reference line (a limit, a ceiling): dashed, unstacked, no fill."""
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [10, 10]}},
                           {"id": "custom.fillOpacity", "value": 0},
                           {"id": "custom.stacking", "value": {"mode": "none", "group": "A"}},
                           {"id": "color", "value": {"mode": "fixed", "fixedColor": color}}]}


def ts(title, targets, unit="short", w=8, h=8, stack=False, desc="", min0=True, overrides=None, log=False,
       bars=False, lines=None, max_=None, decimals=None, legend="list", empty=None, nonzero=False, soft_max=None):
    """Time series. `lines` = [(value, colour)]: dashed threshold lines (alert thresholds).
    `nonzero`: drop all-zero series (rare-event counters), and say `empty` instead of
    "No data" when nothing happened. `soft_max`: the y axis reaches at least this far
    (a flat-zero ratio otherwise gets Grafana's 0..100 = 0..10000%)."""
    for i, tg in enumerate(targets):
        tg["refId"] = chr(65 + i)
        if nonzero and not tg["expr"].rstrip().endswith("> 0"):
            tg["expr"] = f"({tg['expr']}) > 0"
    if nonzero and empty is None:
        empty = "none (good)"
    # stacked: fills only (a stack's top outline takes the last series' colour and reads as that series)
    custom = {"lineWidth": 0 if stack else 1, "fillOpacity": 70 if stack else 8, "showPoints": "never", "spanNulls": False,
              "gradientMode": "none", "stacking": {"mode": "normal" if stack else "none", "group": "A"},
              "axisSoftMin": 0 if (min0 and not log) else None, "axisSoftMax": soft_max}
    if bars:
        custom.update(drawStyle="bars", fillOpacity=80, lineWidth=0)
    if log:
        custom["scaleDistribution"] = {"type": "log", "log": 10}
    if lines:
        custom["thresholdsStyle"] = {"mode": "dashed"}
    custom = {k: v for k, v in custom.items() if v is not None}
    defaults = {"unit": unit, "custom": custom, "color": {"mode": "palette-classic"}}
    if lines:
        defaults["thresholds"] = thresholds(lines, base="transparent")
    if max_ is not None:
        defaults["max"] = max_
    if decimals is not None:
        defaults["decimals"] = decimals
    if empty:
        defaults["noValue"] = empty
    lg = {"displayMode": "list", "placement": "bottom", "showLegend": True}
    if legend == "table":
        lg = {"displayMode": "table", "placement": "right", "showLegend": True, "calcs": ["mean", "max"], "sortBy": "Max", "sortDesc": True}
    D.add({
        "type": "timeseries", "id": D.nid(), "title": title, "description": desc, "datasource": PROM,
        "gridPos": D.place(w, h), "targets": targets,
        "fieldConfig": {"defaults": defaults, "overrides": color_overrides(targets) + (overrides or [])},
        "options": {"legend": lg, "tooltip": {"mode": "multi", "sort": "desc"}},
    })


def stat(title, targets, unit="short", steps=None, w=3, h=4, desc="", decimals=None, no_value="-", mappings=None,
         overrides=None, text_mode="value", spark=True):
    """Health stat. With `steps` ([(value, colour)] above a green base) the background
    shows the state; without, it's a neutral figure."""
    if isinstance(targets, str):
        targets = [t(targets)]
    for i, tg in enumerate(targets):
        tg["refId"] = chr(65 + i)
    d = {"unit": unit, "color": {"mode": "thresholds"}, "noValue": no_value,
         "thresholds": thresholds(steps) if steps is not None else thresholds([], base="text")}
    if decimals is not None:
        d["decimals"] = decimals
    if mappings:
        d["mappings"] = mappings
    D.add({
        "type": "stat", "id": D.nid(), "title": title, "description": desc, "datasource": PROM, "gridPos": D.place(w, h),
        # min step: health stats read 30 s+ windows, not 4 s bench blips
        "interval": "30s", "targets": targets,
        "fieldConfig": {"defaults": d, "overrides": overrides or []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                    "graphMode": "area" if spark else "none",
                    "colorMode": "background" if steps is not None else "value", "textMode": text_mode,
                    "justifyMode": "center", "orientation": "horizontal", "wideLayout": True, "showPercentChange": False},
    })


def table(title, targets, w=24, h=6, desc="", transformations=None, overrides=None):
    for i, tg in enumerate(targets):
        tg["refId"] = chr(65 + i)
    D.add({
        "type": "table", "id": D.nid(), "title": title, "description": desc, "datasource": PROM, "gridPos": D.place(w, h),
        "targets": targets, "transformations": transformations or [],
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}}}, "overrides": overrides or []},
        "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
    })


def text(title, content, w=24, h=3):
    D.add({"type": "text", "id": D.nid(), "title": title, "gridPos": D.place(w, h),
           "options": {"mode": "markdown", "content": content}})


def instant_table(expr):
    return t(expr, instant=True, range=False, format="table")


def hq(q, metric, sel=I, by="", window=RI):
    grp = "le" + (f", {by}" if by else "")
    return f"histogram_quantile({q}, sum by ({grp}) (rate({metric}_bucket{{{sel}}}{window})))"


QNAME = {0.5: "p50", 0.9: "p90", 0.99: "p99", 0.999: "p99.9"}


def quantiles(metric, sel=I, by="", qs=(0.5, 0.9, 0.99, 0.999)):
    """histogram_quantile per q over sum by (le[,by])."""
    return [t(hq(q, metric, sel, by), f"{QNAME[q]}" + (f" {{{{{by}}}}}" if by else "")) for q in qs]


def node_quantile(q, metric, sel=I):
    """One quantile per node, legend = node id."""
    return t(by_node(hq(q, metric, sel, "instance")), "{{node_id}}")


def rate(metric, sel=I, by=None, legend=None):
    if by:
        return t(f"sum by ({by}) (rate({metric}{{{sel}}}{RI}))", legend or f"{{{{{by}}}}}")
    return t(f"sum(rate({metric}{{{sel}}}{RI}))", legend or metric.replace("vlpds_", ""))


def node_rate(metric, sel=I):
    return t(by_node(f"sum by (instance) (rate({metric}{{{sel}}}{RI}))"), "{{node_id}}")


def node_gauge(metric, sel=I, agg="sum"):
    return t(by_node(f"{agg} by (instance) ({metric}{{{sel}}})"), "{{node_id}}")


def mean(metric, sel=I, by=None, legend=None):
    b = f" by ({by})" if by else ""
    return t(f"sum{b} (rate({metric}_sum{{{sel}}}{RI})) / sum{b} (rate({metric}_count{{{sel}}}{RI}))",
             legend or (f"{{{{{by}}}}}" if by else "mean"))


def status_classes(sel):
    base = f"vlpds_http_requests_total{{{sel}"
    return [t(f'sum(rate({base}, status=~"2.."}}{RI}))', "2xx"),
            t(f'sum(rate({base}, status=~"3.."}}{RI}))', "3xx"),
            t(f'sum(rate({base}, status=~"4..", status!="429"}}{RI}))', "4xx"),
            t(f'sum(rate({base}, status="429"}}{RI}))', "429"),
            t(f'sum(rate({base}, status=~"5.."}}{RI}))', "5xx")]


# ============================================================== health
row("Health", collapsed=False)
# line 1: traffic, errors, latency
stat("Requests/s", f"sum(rate(vlpds_http_requests_total{{{I}}}{RI}))", "reqps",
     desc="Every request a node answered (XRPC, proxied, OAuth, ...), summed over the selected nodes.")
stat("5xx", f'(sum(rate(vlpds_http_requests_total{{{I}, {OWN}, status=~"5.."}}{RI})) or vector(0)) '
            f'/ sum(rate(vlpds_http_requests_total{{{I}, {OWN}}}{RI}))',
     "percentunit", [(0.01, "yellow"), (0.05, "red")], decimals=2, no_value="no traffic",
     desc="Share of requests answered 5xx, proxied/unmatched paths excluded (the AppView's errors aren't ours). "
          f"Red at 5%: the page threshold of {rb('VlpdsHttp5xxHigh')} (5 min sustained). "
          "Yellow at 1% (guess). Break it down in HTTP & proxy.")
stat("429", f'(sum(rate(vlpds_http_requests_total{{{I}, status="429"}}{RI})) or vector(0)) '
            f'/ sum(rate(vlpds_http_requests_total{{{I}}}{RI}))',
     "percentunit", [(0.01, "yellow"), (0.1, "red")], decimals=2, no_value="no traffic",
     desc="Share of requests refused with 429: rate limits, the proxy's per-account cap, the firehose per-IP cap. "
          "No alert: yellow 1% / red 10% are guesses. Who is limited: Auth & abuse row.")
stat("Read p99", hq(0.99, "vlpds_http_request_duration_seconds", f'{I}, method=~"{READ_METHODS}"') + " >= 0", "s",
     [(0.25, "yellow"), (1, "red")], no_value="idle",
     desc="p99 of repo/sync/identity reads served by vlpds itself (getRecord, listRecords, sync.get*, ...). "
          "No alert: 250 ms / 1 s are guesses. Proxied AppView reads are in HTTP & proxy.")
stat("Write p99", hq(0.99, "vlpds_http_request_duration_seconds", f'{I}, method=~"{WRITE_METHODS}"') + " >= 0", "s",
     [(0.5, "yellow"), (2, "red")], no_value="idle",
     desc="p99 of createRecord / putRecord / deleteRecord / applyWrites, forwarding to the shard owner included. "
          "Same thresholds as commit p99 (writes wait for their commit).")
stat("Commit p99", hq(0.99, "vlpds_commit_durable_seconds") + " >= 0", "s", [(0.5, "yellow"), (2, "red")], no_value="idle",
     desc="Commit enqueue to durable + applied + acked. Design: ~150 ms on S3 Standard. "
          f"Yellow 500 ms = {rb('VlpdsCommitLatencyHigh')}, red 2 s = {rb('VlpdsCommitLatencyCritical')} (page; the 3 s forward deadline is close).")
stat("Firehose lag p99", hq(0.99, "vlpds_firehose_emit_delay_seconds") + " >= 0", "s", [(2, "yellow"), (20, "red")], no_value="idle",
     desc="Seq assignment to firehose emit (the merger waits for every log's watermark). "
          f"Yellow 2 s = {rb('VlpdsFirehoseEmitDelayHigh')}, red 20 s = {rb('VlpdsFirehoseEmitDelayCritical')} (page).")
stat("Firehose subscribers", f"sum(vlpds_firehose_subscribers{{{I}}}) or (0 * count({UP} == 1))", "short",
     desc="Connected subscribeRepos clients. A sudden drop to 0 with relays expected = they were cut off: "
          "see Firehose → disconnects by reason.")
D.newline()
# line 2: cluster, store, lifecycle
stat("Nodes up", [t(f"count({UP} == 1) or vector(0)", "up"),
                  t(f"count(({UP} == 0) and on (instance) group by (instance) (last_over_time(vlpds_build_info{{{I}}}[1h]))) or vector(0)", "down")],
     "short", [(1, "red")], text_mode="value_and_name", spark=False,
     overrides=[{"matcher": {"id": "byName", "options": "up"},
                 "properties": [{"id": "thresholds", "value": thresholds([], base="green")}]}],
     desc="Scraped nodes up / down. Down counts only targets that exported vlpds_build_info in the last hour, "
          f"so idle bench ports don't count. Any down for 2 min pages: {rb('VlpdsNodeDown')}.")
stat("Shards", [t(f"sum(vlpds_owned_partitions{{{C}}})", "owned"),
                t(f"max(vlpds_shard_layout_shards{{{C}}}) - (sum(vlpds_owned_partitions{{{C}}}) or vector(0))", "unowned")],
     "short", [(1, "red")], text_mode="value_and_name", spark=False,
     overrides=[{"matcher": {"id": "byName", "options": "owned"},
                 "properties": [{"id": "thresholds", "value": thresholds([], base="blue")}]},
                {"matcher": {"id": "byName", "options": "unowned"},
                 "properties": [{"id": "thresholds", "value": {"mode": "absolute", "steps": [
                     {"color": "yellow", "value": None}, {"color": "green", "value": 0}, {"color": "red", "value": 1}]}}]}],
     desc="Whole cluster (ignores the node filter). unowned = layout shards - owned: any for 2 min pages "
          f"({rb('VlpdsShardsUnowned')}: their writes and reads fail); negative (yellow) = two owners claim a shard "
          f"({rb('VlpdsShardsOverOwned')}).")
stat("Lease renew/TTL", f"max({hq(0.99, 'vlpds_lease_renew_ttl_ratio', by='instance')})", "percentunit",
     [(0.2, "yellow"), (0.4, "red")], decimals=0, no_value="no renewals",
     desc="Worst node's p99 lease renewal round trip as a share of its TTL. Past 0.4 x TTL the node's validity "
          f"gaps and it fail-stops (exit 5). Yellow 0.2 = {rb('VlpdsLeaseRenewalNearCeiling')}, "
          f"red 0.4 = {rb('VlpdsLeaseRenewalAtCeiling')} (page; several nodes at once = a store brownout).")
stat("Store errors/s", f'sum(rate(vlpds_object_store_requests_total{{{I}, result=~"error|timeout"}}{RI})) or vector(0)', "reqps",
     [(0.01, "yellow"), (1, "red")], decimals=2,
     desc="vlpds' object-store requests that failed or timed out (all clients: log, state, control plane). "
          f"Red at 1/s on one component = {rb('VlpdsObjectStoreErrors')} (state_*: SlateDB) or {rb('VlpdsObjectStoreRequestErrors')} "
          f"(the rest); on 2+ nodes at once = {rb('VlpdsObjectStoreBrownout')}. Per client and component: Object store row.")
stat("Store permit waits/s", f"sum(rate(vlpds_object_store_permit_waits_total{{{I}}}{RI})) or vector(0)", "reqps",
     [(0.01, "yellow"), (1, "red")], decimals=2,
     desc="Object-store requests that found every in-flight permit of their pool (log / state / ctl) and lane taken and queued. "
          f"Red at 1/s = {rb('VlpdsObjectStorePermitsSaturated')}: the store got slower or the load outgrew the permits.")
stat("Restarts (1 h)", [t(f"sum(changes(vlpds_process_start_time_seconds{{{I}}}[1h])) or vector(0)", "all"),
                        t(f"max(changes(vlpds_process_start_time_seconds{{{I}}}[1h])) or vector(0)", "worst node")],
     "short", [(1, "yellow"), (3, "red")], spark=False, text_mode="value_and_name",
     overrides=[{"matcher": {"id": "byName", "options": "all"},
                 "properties": [{"id": "thresholds", "value": thresholds([(1, "yellow")])}]}],
     desc=f"Process restarts over the last hour: all selected nodes, and the node that restarted most. Any = {rb('VlpdsNodeRestarted')}; "
          f"3 on one node = {rb('VlpdsNodeCrashLooping')} (page). Why: the nodes table's last exit column.")
stat("Fail-stops (30 m)", f'count(vlpds_last_exit_reason_info{{{I}, reason!~"clean|none"}} == 1 '
                          f"and on (instance) (time() - vlpds_process_start_time_seconds{{{I}}}) < 1800) or vector(0)",
     "short", [(1, "red")], spark=False,
     desc="Nodes that started in the last 30 min after a fail-stop, crash or error exit "
          f"(vlpds_last_exit_reason_info, as {rb('VlpdsNodeFailStopped')}). The reason is in the nodes table; "
          f"exit codes: {rb('tools-endpoints-cli-logs-exit-codes', 'runbook exit codes')}.")
stat("Alerts firing", [t(f'count(ALERTS{{alertstate="firing", alertname=~"Vlpds.*", severity="page", {C}}}) or vector(0)', "page"),
                       t(f'count(ALERTS{{alertstate="firing", alertname=~"Vlpds.*", severity!="page", {C}}}) or vector(0)', "ticket")],
     "short", [(1, "red")], text_mode="value_and_name", spark=False,
     overrides=[{"matcher": {"id": "byName", "options": "ticket"},
                 "properties": [{"id": "thresholds", "value": thresholds([(1, "orange")])}]}],
     desc="Vlpds* alerts firing in this Prometheus, by severity. Which ones: the timeline below. "
          f"{ALERTS_NOTE} The bench stack doesn't load it.")
D.newline()
# row labels: alert name without "Vlpds", instance without the bench's 127.0.0.1 (prod instances are node ids)
ts("Alerts firing", [t('max by (alert, where) (label_replace(label_replace('
                       f'ALERTS{{alertstate="firing", alertname=~"Vlpds.*", {C}}}, "alert", "$1", "alertname", "Vlpds(.*)"), '
                       '"where", "$1", "instance", "(?:127\\\\.0\\\\.0\\\\.1)?(.*)"))', "{{alert}} {{where}}")],
   w=24, h=6, desc=f"Vlpds* alerts from ops/alerts.yml ({ALERTS_URL}); each one's runbook section is {RB}#<alertname>. "
                   f"Filtered by cluster only, not by node. Empty = nothing firing, or the rules aren't loaded. {ALERTS_NOTE}")
# state timeline instead of the generic time series
D.panels[-1].update(type="state-timeline", options={"showValue": "never", "rowHeight": 0.8, "mergeValues": True, "alignValue": "left",
                                                    "legend": {"showLegend": False, "displayMode": "list", "placement": "bottom"},
                                                    "tooltip": {"mode": "single", "sort": "none"}})
D.panels[-1]["fieldConfig"] = {"defaults": {"color": {"mode": "fixed", "fixedColor": "red"}, "noValue": "no Vlpds alerts firing",
                                            "custom": {"fillOpacity": 80, "lineWidth": 0},
                                            "mappings": [{"type": "value", "options": {"1": {"text": "firing", "color": "red"}}}]},
                               "overrides": []}
ts("Requests/s by status", status_classes(I), "reqps", stack=True,
   desc="Stacked by class; 4xx excludes 429, which has its own series. Same colours on every panel.")
# clamp: per-series rate extrapolation over short windows can put a new series' share past 100%
ts("Error ratio", [t(f'clamp_max((sum(rate(vlpds_http_requests_total{{{I}, {OWN}, status=~"5.."}}{RI})) or vector(0)) / sum(rate(vlpds_http_requests_total{{{I}, {OWN}}}{RI})), 1)', "5xx"),
                   t(f'clamp_max((sum(rate(vlpds_http_requests_total{{{I}, status="429"}}{RI})) or vector(0)) / sum(rate(vlpds_http_requests_total{{{I}}}{RI})), 1)', "429")],
   "percentunit", lines=[(0.05, "red")], soft_max=0.06,
   desc=f"5xx share (proxied paths excluded) and 429 share. Dashed: the 5% page threshold of {rb('VlpdsHttp5xxHigh')}.")
ts("p99: reads, writes, commit", [t(hq(0.99, "vlpds_http_request_duration_seconds", f'{I}, method=~"{READ_METHODS}"'), "read"),
                                  t(hq(0.99, "vlpds_http_request_duration_seconds", f'{I}, method=~"{WRITE_METHODS}"'), "write"),
                                  t(hq(0.99, "vlpds_commit_durable_seconds"), "commit")],
   "s", lines=[(0.5, "orange"), (2, "red")],
   desc="Dashed: the commit latency alerts (500 ms ticket, 2 s page). A write above its commit = forwarding or queueing in front of the commit.")
ts("Owned shards by node", [node_gauge("vlpds_owned_partitions"), t(f"max(vlpds_shard_layout_shards{{{C}}})", "layout")],
   stack=True, overrides=[dashed("layout", "text")],
   desc="Stacked per node; the dashed line is the layout's shard count, which the stack should reach exactly "
        f"({rb('VlpdsShardsUnowned')}, {rb('VlpdsOwnershipImbalanced')}).")
ts("Lease renew / TTL p99 by node", [node_quantile(0.99, "vlpds_lease_renew_ttl_ratio")], "percentunit",
   lines=[(0.2, "orange"), (0.4, "red")], soft_max=0.45,
   desc="Renewal round trip as a share of the lease TTL. Over 0.4 the node fail-stops; dashed at the two lease alerts. "
        f"{rb('VlpdsLeaseRenewalNearCeiling')}")
ts("Firehose lag p99 by node", [node_quantile(0.99, "vlpds_firehose_emit_delay_seconds")], "s", lines=[(2, "orange"), (20, "red")],
   desc=f"Seq assigned to emitted. One node high = its merger; all high = a slow log holds the min watermark. {rb('VlpdsFirehoseEmitDelayHigh')}")
ts("Object store: failures and permit waits", [t(f'sum(rate(vlpds_object_store_requests_total{{{I}, result=~"error|timeout"}}{RI})) or vector(0)', "failed"),
                                               t(f"sum(rate(vlpds_object_store_permit_waits_total{{{I}}}{RI})) or vector(0)", "permit waits"),
                                               t(f"sum(rate(vlpds_cluster_store_timeouts_total{{{I}}}{RI})) or vector(0)", "control-plane timeouts")],
   "reqps", soft_max=1, lines=[(1, "red")], desc=f"Failed requests, permit queueing, control-plane steps that hit their deadline; per pool and lane in the Object store row "
                 f"({rb('VlpdsControlPlaneTimeouts')}). On 2+ nodes at once: {rb('VlpdsObjectStoreBrownout')}.")
ts("CPU by node", [t(by_node(f"sum by (instance) (rate(vlpds_process_cpu_seconds_total{{{I}}}{RI}))"), "{{node_id}}")], "short",
   decimals=1, desc="CPU cores used (user + system). Tokio saturation is in Process / runtime.")
ts("Memory used / limit by node", [t(by_node(f"max by (instance) (vlpds_process_resident_bytes{{{I}}}) / max by (instance) (vlpds_memory_limit_bytes{{{I}}})"), "{{node_id}}")],
   "percentunit", lines=[(0.85, "orange"), (0.95, "red")],
   desc=f"RSS / vlpds_memory_limit_bytes (RAM or the cgroup limit). Dashed: {rb('VlpdsMemoryHigh')} (85%) and {rb('VlpdsMemoryCritical')} (95%, page).")
table("Nodes", [instant_table(f"max by (instance, node_id, rev) (vlpds_build_info{{{I}}})"),
                instant_table(f"max by (instance) ({UP}) and on (instance) group by (instance) (last_over_time(vlpds_build_info{{{I}}}[1h]))"),
                instant_table(f"max by (instance) (time() - vlpds_process_start_time_seconds{{{I}}})"),
                instant_table(f"sum by (instance) (vlpds_owned_partitions{{{I}}})"),
                instant_table(f"max by (instance, reason, code) (vlpds_last_exit_reason_info{{{I}}} == 1)")],
      h=6, desc="One row per node: id, git rev (-dirty = uncommitted changes; two revs for an hour = "
                f"{rb('VlpdsMixedVersions')}), up, uptime, owned shards, and how its previous process ended "
                "(clean, crash = SIGKILL/OOM/host loss, or a fail-stop reason; see the runbook's exit codes).",
      transformations=[
          {"id": "joinByField", "options": {"byField": "instance", "mode": "outer"}},
          {"id": "organize", "options": {
              "excludeByName": {"Time": True, "Time 1": True, "Time 2": True, "Time 3": True, "Time 4": True, "Time 5": True, "Value #A": True, "Value #E": True},
              "indexByName": {"node_id": 0, "instance": 1, "rev": 2, "Value #B": 3, "Value #C": 4, "Value #D": 5, "reason": 6, "code": 7},
              "renameByName": {"node_id": "node", "Value #B": "up", "Value #C": "uptime", "Value #D": "owned shards",
                               "reason": "last exit", "code": "exit code"}}}],
      overrides=[{"matcher": {"id": "byName", "options": "uptime"}, "properties": [{"id": "unit", "value": "dtdurations"}]},
                 {"matcher": {"id": "byName", "options": "up"}, "properties": [
                     {"id": "mappings", "value": [{"type": "value", "options": {"0": {"text": "DOWN", "color": "red"}, "1": {"text": "up", "color": "green"}}}]},
                     {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}}]},
                 {"matcher": {"id": "byName", "options": "last exit"}, "properties": [
                     {"id": "mappings", "value": [{"type": "regex", "options": {"pattern": "^(clean|none)$", "result": {"color": "green"}}},
                                                  {"type": "regex", "options": {"pattern": ".+", "result": {"color": "orange"}}}]},
                     {"id": "custom.cellOptions", "value": {"type": "color-text"}}]}])

# ============================================================== writes
row("Writes and commit pipeline")
ts("Write requests/s by method", [t(f'sum by (m) (label_replace(rate(vlpds_http_requests_total{{{I}, method=~"{WRITE_METHODS}|com\\\\.atproto\\\\.repo\\\\.uploadBlob"}}{RI}), '
                                    f'"m", "$1", "method", "com\\\\.atproto\\\\.repo\\\\.(.*)"))', "{{m}}")], "reqps")
ts("Write latency", quantiles("vlpds_http_request_duration_seconds", f'{I}, method=~"{WRITE_METHODS}"'), "s",
   desc="createRecord / putRecord / deleteRecord / applyWrites, server side, forwarding included. Buckets 0.1 ms .. 52 s, x2: "
        "quantiles are bucket-resolution estimates.")
ts("Commit latency (enqueue → durable + applied + acked)", quantiles("vlpds_commit_durable_seconds"), "s", lines=[(0.5, "orange"), (2, "red")],
   desc=f"Dashed: {rb('VlpdsCommitLatencyHigh')} (p99 500 ms) and {rb('VlpdsCommitLatencyCritical')} (2 s, page). "
        "Where the time goes: the stage panels below.")
ts("Commits/s and record ops/s", [rate("vlpds_commits_total", legend="commits"), rate("vlpds_ops_total", by="action", legend="ops {{action}}")], "ops")
ts("Coalescing", [mean("vlpds_commit_requests", legend="requests / commit"), mean("vlpds_commit_ops", legend="ops / commit"),
                  mean("vlpds_segment_events", legend="events / segment"), mean("vlpds_worker_batch_messages", legend="msgs / worker batch")],
   "short", decimals=1, desc="Means over the rate window: write requests per commit, ops per commit, firehose events per segment, worker messages per loop. "
                             "Higher = more batching (good under load).")
ts("Rejected and retried writes", [rate("vlpds_write_errors_total", by="kind", legend="error {{kind}}"), rate("vlpds_writes_shed_total", legend="shed (503)"),
                                   rate("vlpds_writes_abandoned_total", legend="abandoned (503 RepoLoading)"),
                                   rate("vlpds_write_retries_total", by="reason", legend="resent {{reason}}")], "ops", nonzero=True,
   desc=f"internal/unavailable errors: {rb('VlpdsWriteInternalErrors')}; shed = admission control ({rb('VlpdsWritesShed')}); "
        f"resent = the entry node retried after a not-applied 503 ({rb('VlpdsWriteResendsSustained')}). Client errors (invalid record, ...) are normal.")
ts("Mean time per stage (per segment)", [mean("vlpds_commit_stage_seconds", by="stage")], "s", stack=True,
   desc="seal_wait: oldest entry's enqueue → PUT start; put: PUT until durable (hedges/retries incl.); "
        "apply_lock: finalizer waiting for the shards' apply locks; apply: SlateDB batches; ack: acks + repo views. "
        "The stack approximates the commit latency of a segment's oldest entry.")
ts("Stage p99", quantiles("vlpds_commit_stage_seconds", by="stage", qs=(0.99,)), "s",
   desc="Which stage owns the tail. put high: the store (Log / segments); apply high: SlateDB (L0 stalls, backpressure).")
ts("Queues: sequencer, PUTs in flight, workers", [t(f"sum(vlpds_sequencer_queue_depth{{{I}}})", "sequencer queue"),
                                                 t(f"sum(vlpds_segment_puts_inflight{{{I}}})", "segment PUTs in flight"),
                                                 t(f"max(vlpds_worker_queue_depth{{{I}}})", "busiest worker queue")], "short",
   desc=f"Entries waiting while no segment becomes durable for 2 min = {rb('VlpdsCommitLogStalled')} (page).")
ts("Watermark lag by node", [t(by_node(f"max by (instance) (vlpds_watermark_lag_microseconds{{{I}}}) / 1e6"), "{{node_id}}")], "s", lines=[(2, "orange")],
   desc=f"now - the node's log watermark. ~one segment PUT under load, ~0 idle. Dashed: {rb('VlpdsWatermarkLagHigh')} (2 s). "
        "A lagging log holds back every node's firehose.")
ts("Commit build CPU (MST + sign)", quantiles("vlpds_commit_build_seconds", qs=(0.5, 0.99, 0.999)), "s")
ts("Commit size (block CAR)", quantiles("vlpds_commit_car_bytes", qs=(0.5, 0.99)), "bytes")

# ============================================================== log
row("Log, segments, retention")
ts("Segments/s by node", [node_rate("vlpds_segments_total")], "ops")
ts("Log bytes/s (raw vs stored)", [rate("vlpds_segment_bytes_total", legend="raw"), rate("vlpds_segment_stored_bytes_total", legend="stored (zstd)")], "Bps")
ts("Segment size and events", quantiles("vlpds_segment_bytes", qs=(0.5, 0.99)) + [mean("vlpds_segment_events", legend="events / segment")], "bytes",
   overrides=[right_axis("events / segment", "short")])
ts("Segment PUT latency (until durable)", quantiles("vlpds_segment_put_seconds"), "s", lines=[(0.25, "orange")],
   desc=f"Design ~25 ms; a hedge starts at 100 ms. Dashed: {rb('VlpdsSegmentPutLatencyHigh')} (p99 250 ms).")
ts("PUT attempts by result, hedges, stall seals", [rate("vlpds_segment_put_attempts_total", by="result", legend="attempt {{result}}"),
                                                   rate("vlpds_segment_put_hedges_total", legend="hedges"),
                                                   rate("vlpds_segment_stall_seals_total", legend="stall seals")], "ops",
   desc=f"already_exists = a conditional-PUT conflict (our own hedge winning, or a fence). error over 0.1/s: {rb('VlpdsSegmentPutErrors')}. "
        "stall seals: segments sealed early because the oldest PUT stalled.")
ts("SlateDB apply per segment / checkpoint per shard", quantiles("vlpds_state_apply_seconds", qs=(0.5, 0.99)) +
   [t(hq(0.99, "vlpds_checkpoint_shard_seconds"), "checkpoint p99")], "s",
   desc=f"Checkpoints (applied marker + memtable flush) that stop running: {rb('VlpdsCheckpointsStalled')}.")
ts("Retention: deleted/s", [rate("vlpds_retention_deleted_objects_total", by="log", legend="objects {{log}}"),
                            rate("vlpds_retention_deleted_bytes_total", by="log", legend="bytes {{log}}")], "ops", empty="nothing deleted yet",
   overrides=[{"matcher": {"id": "byRegexp", "options": "^bytes"}, "properties": [{"id": "unit", "value": "Bps"}, {"id": "custom.axisPlacement", "value": "right"}]}])
ts("Retention passes", [rate("vlpds_retention_ticks_total", by="result", legend="passes {{result}}"),
                        t(hq(0.99, "vlpds_retention_pass_seconds", window="[5m]"), "pass p99")], "ops",
   overrides=[right_axis("pass p99", "s")],
   desc=f"{rb('VlpdsRetentionFailing')}, {rb('VlpdsRetentionNotRunning')}")
ts("Dead logs and replay hold", [t(f"sum by (state) (vlpds_retention_dead_logs{{{I}}})", "dead logs {{state}}"),
                                 t(f"sum(vlpds_retention_replay_hold_segments{{{I}}})", "replay-hold segments")], "short",
   desc=f"unfenced for 30 min: {rb('VlpdsDeadLogUnfenced')}; a growing replay hold: {rb('VlpdsReplayBacklogHigh')}.")

# ============================================================== firehose
row("Firehose and sync exports")
ts("Events emitted / frames sent per s", [rate("vlpds_firehose_events_total", legend="events emitted"),
                                          rate("vlpds_firehose_frames_sent_total", legend="frames sent"),
                                          rate("vlpds_firehose_backfill_events_total", legend="backfill events sent")], "ops",
   desc=f"Commits flowing but no events = {rb('VlpdsFirehoseStalled')} (page).")
ts("Emit delay (seq assigned → emitted)", quantiles("vlpds_firehose_emit_delay_seconds", qs=(0.5, 0.99, 0.999)), "s", lines=[(2, "orange"), (20, "red")],
   desc=f"Dashed: {rb('VlpdsFirehoseEmitDelayHigh')} and {rb('VlpdsFirehoseEmitDelayCritical')}.")
ts("Subscribers by node, bytes sent", [node_gauge("vlpds_firehose_subscribers"), rate("vlpds_firehose_bytes_sent_total", legend="bytes sent/s")], "short",
   overrides=[right_axis("bytes sent/s", "Bps")])
ts("Disconnects and refusals", [rate("vlpds_firehose_disconnects_total", by="reason", legend="disconnect {{reason}}"),
                                rate("vlpds_firehose_rejected_total", by="reason", legend="refused {{reason}}")], "ops", nonzero=True,
   desc=f"too_slow = past --firehose-max-lag-mb ({rb('VlpdsFirehoseConsumersTooSlow')}); write_stalled = took no bytes for 30 s; "
        "refused per_ip = over --firehose-max-per-ip (429).")
ts("Cursor backfills", [t(f"sum by (state) (vlpds_firehose_backfills{{{I}}})", "{{state}}"),
                        rate("vlpds_firehose_backfill_gets_total", legend="segment GETs/s"),
                        rate("vlpds_firehose_backfill_retries_total", by="reason", legend="retries/s {{reason}}")], "short", empty="no cursor backfills",
   desc="running / waiting for a slot (--firehose-max-backfills, default 16). Waiting for long = raise the cap or the readahead is too slow.")
ts("Backfill segment cache hit ratio", [t(f'sum(rate(vlpds_firehose_backfill_cache_total{{{I}, result="hit"}}{RI})) / sum(rate(vlpds_firehose_backfill_cache_total{{{I}}}{RI}))', "hit ratio")],
   "percentunit", max_=1, empty="no cursor backfills")
ts("Merger queue vs budget, rings", [t(f"max(vlpds_firehose_merge_queue_bytes{{{I}}})", "merger queue (max node)"),
                                    t(f"min(vlpds_firehose_merge_queue_budget_bytes{{{I}}})", "merger budget"),
                                    t(f"max(vlpds_firehose_ring_bytes{{{I}}})", "firehose ring (max node)"),
                                    t(f"max(vlpds_log_live_ring_bytes{{{I}}})", "log live ring (max node)")], "bytes",
   overrides=[dashed("merger budget")],
   desc=f"Past the budget a log spills to S3 read-back. Over 80% for 10 min: {rb('VlpdsFirehoseMergeQueueNearBudget')}.")
ts("Spills, lagged peer streams", [rate("vlpds_firehose_merge_spills_total", legend="merger spills"),
                                   rate("vlpds_firehose_merge_spill_segments_total", legend="spill segments read"),
                                   rate("vlpds_log_stream_lagged_total", legend="lagged peer streams")], "ops", nonzero=True,
   desc=f"{rb('VlpdsFirehoseMergeSpilling')}, {rb('VlpdsPeerLogStreamLagging')}")
ts("getRepo exports", [t(f"sum by (state) (vlpds_sync_exports{{{I}}})", "{{state}}"),
                       rate("vlpds_sync_exports_ended_total", by="reason", legend="ended/s {{reason}}")], "short", empty="no getRepo exports",
   desc="streaming / waiting for a slot (--max-exports, default 32). shed = no slot within 10 s (503); stalled = the client read nothing for --export-stall-secs.")

# ============================================================== repo workers
row("Repo workers and caches")
ts("Repo lookups by result", [rate("vlpds_repo_cache_lookups_total", by="result")], "ops", stack=True,
   desc="hit: cached; miss: starts a cold load; loading: joins a load in flight.")
ts("Repo cache hit ratio by node", [t(by_node(f'sum by (instance) (rate(vlpds_repo_cache_lookups_total{{{I}, result="hit"}}{RI})) / sum by (instance) (rate(vlpds_repo_cache_lookups_total{{{I}}}{RI}))'), "{{node_id}}")],
   "percentunit", max_=1, desc=f"Mostly misses under steady load: {rb('VlpdsRepoCacheMissRateHigh')} (cache too small for the active set).")
ts("Cold loads by result, evictions", [rate("vlpds_repo_loads_total", by="result", legend="load {{result}}"),
                                       rate("vlpds_repo_evictions_total", legend="evictions"),
                                       t(f"sum(vlpds_repos_loading{{{I}}})", "loading now")], "ops", nonzero=True, empty="no cold loads",
   desc=f"stale = a load finished after its shard moved (dropped, reloaded). error: {rb('VlpdsRepoLoadErrors')}.")
ts("Cold load latency", quantiles("vlpds_repo_load_seconds", qs=(0.5, 0.99, 0.999)), "s", empty="no cold loads")
ts("Repo cache: share of byte budget, repos held", [t(by_node(f"sum by (instance) (vlpds_repo_cache_bytes{{{I}}}) / max by (instance) (vlpds_repo_cache_capacity_bytes{{{I}}} > 0)"), "{{node_id}}"),
                                                    t(f"sum(vlpds_cached_repos{{{I}}})", "cached repos (all)")], "percentunit",
   overrides=[right_axis("cached repos (all)", "short")],
   desc="Loaded MST paths per node over --repo-cache-mb. Near 100%, idle repos drop back to their roots, then the least recently used are evicted.")
ts("Memory plan (busiest node)", [t(f'max by (part) (vlpds_memory_budget_bytes{{{I}, part!="budget"}})', "{{part}}")], "bytes", stack=True,
   desc="The node's memory budget (its limit, or --memory-budget-mb) as fixed costs plus the pool for the SST metadata, SST block and repo "
        "caches (src/memory.rs). `vlpds --memory-plan` prints it.")
ts("Pool caches: target, capacity, used", [t(f'sum by (cache, kind) (vlpds_memory_cache_bytes{{{I}}})', "{{cache}} {{kind}}"),
                                           t(f"sum(vlpds_repo_cache_bytes{{{I}}})", "repo used"),
                                           t(f"sum(vlpds_meta_cache_shortfall_bytes{{{I}}})", "meta shortfall")], "bytes",
   overrides=[dashed("meta shortfall")],
   desc=f"meta target: the owned SSTs' decoded filters + indexes (vlpds_sst_meta_need_bytes) x N/(N-1) x 1.25; the block and repo caches split "
        f"the rest of the pool. Grows at once, shrinks after 5 min. A shortfall (the pool can't fit the target) is logged and feeds "
        f"{rb('VlpdsSstMetaCacheTooSmall')}.")
ts("Lazy MST", [rate("vlpds_lazy_mst_reads_total", by="kind", legend="reads {{kind}}"), rate("vlpds_lazy_mst_fetches_total", by="result", legend="fetches {{result}}"),
                rate("vlpds_lazy_mst_unloads_total", legend="unloads"), rate("vlpds_lazy_mst_fallbacks_total", by="reason", legend="fallback {{reason}}"),
                rate("vlpds_repo_preloads_total", by="result", legend="preload {{result}}")], "ops", nonzero=True, empty="idle",
   desc=f"fallback invalid = a persisted MST didn't match its root ({rb('VlpdsLazyMstInvalid')}).")
ts("In-memory caches: fill", [t(f"max by (cache) (vlpds_cache_entries{{{I}}} / (vlpds_cache_capacity_entries{{{I}}} > 0))", "{{cache}}")], "percentunit", max_=1,
   desc=f"Entries / entry cap per cache (busiest node). Pinned at 100% for hours: {rb('VlpdsCacheAtCapacity')}.")
ts("In-memory caches: bytes", [t(f"sum by (cache) (vlpds_cache_bytes{{{I}}})", "{{cache}}")], "bytes")
ts("Proxy fast-path cache", [rate("vlpds_proxy_cache_total", by="result")], "ops", stack=True, empty="no proxied lookups")

# ============================================================== HTTP / proxy
row("HTTP and proxy")
ts("Requests/s by method (top 12)", [t(f"topk(12, sum by (method) (rate(vlpds_http_requests_total{{{I}}}{RI})))", "{{method}}")], "reqps", w=12, h=9, legend="table")
ts("p99 latency by method (top 12)",
   [t(f"topk(12, histogram_quantile(0.99, sum by (le, method) (rate(vlpds_http_request_duration_seconds_bucket{{{I}}}{RI}))))", "{{method}}")],
   "s", w=12, h=9, legend="table")
ts("5xx/s by method", [t(f'topk(10, sum by (method) (rate(vlpds_http_requests_total{{{I}, status=~"5.."}}{RI})) > 0)', "{{method}}")], "reqps", empty="no 5xx (good)",
   desc="Which methods fail. _proxy_or_unmatched = proxied to the AppView (its errors) or unknown paths.")
ts("In flight", [t(f"sum(vlpds_http_requests_inflight{{{I}}})", "requests in flight"),
                 t(f"sum by (version) (vlpds_http_server_active_requests{{{I}}})", "awaiting head {{version}}")], "short")
ts("Connections", [t(f"sum(vlpds_http_server_connections_open{{{I}}})", "inbound open"),
                   rate("vlpds_http_server_connections_total", legend="inbound accepted/s"),
                   rate("vlpds_http_client_connects_total", by="role", legend="outbound connects/s {{role}}")], "short",
   desc="Outbound connects should stay flat under steady load (pooled h2 over mTLS to peers).")
ts("Proxied requests/s by status", status_classes(f'{I}, method=~"{PROXY_METHODS}"'), "reqps", stack=True, nonzero=True, empty="nothing proxied",
   desc="app.bsky / chat.bsky / tools.ozone and unmatched paths, proxied to the AppView or service.")
ts("Proxied latency", quantiles("vlpds_http_request_duration_seconds", f'{I}, method=~"{PROXY_METHODS}"', qs=(0.5, 0.99)), "s")
ts("Proxy upstream: pool waits, read-after-write", [rate("vlpds_http_client_pool_waits_total", by="role", legend="pool waits {{role}}"),
                                                    rate("vlpds_proxy_read_after_write_total", by="result", legend="RAW {{result}}")], "ops", nonzero=True, empty="none",
   desc="pool waits: proxied requests that waited for an upstream connection at the per-host cap. RAW: reads with an AppView rev and how our newer records were merged in.")

# ============================================================== auth and abuse
row("Auth and abuse: rate limits, shedding, caps")
ts("Rate-limit rejections by limiter", [rate("vlpds_rate_limit_rejections_total", by="limiter")], "reqps", nonzero=True, empty="no 429s",
   desc="Requests over a rate-limit bucket (429). One limiter dominating = one class of client; see the route panel.")
ts("Rate-limit rejections by route (top 10)", [t(f"topk(10, sum by (route) (rate(vlpds_rate_limit_rejections_total{{{I}}}{RI})) > 0)", "{{route}}")], "reqps",
   empty="no 429s")
ts("Rate-limit config version", [t(f"max(vlpds_rate_limit_config_version{{{I}}})", "max over nodes"),
                                 t(f"min(vlpds_rate_limit_config_version{{{I}}})", "min over nodes"),
                                 t(f'sum(increase(vlpds_rate_limit_config_loads_total{{{I}, result!="unchanged"}}[5m])) by (result) > 0', "loads {{result}} (5 m)"),
                                 t(f"sum(increase(vlpds_rate_limit_config_errors_total{{{I}}}[5m])) > 0", "rejected configs (5 m)")], "short", decimals=0,
   desc="min != max = nodes on different configs; a rejected config keeps the last good one in force. 0 = flag defaults.")
ts("Password hashing shed (Argon2)", [node_rate("vlpds_argon2_shed_total")], "reqps", lines=[(0.5, "orange")], nonzero=True,
   desc=f"createSession / createAccount / OAuth sign-in answered 503 because every Argon2 permit stayed busy 2 s. "
        f"Dashed: {rb('VlpdsPasswordHashingShed')} (0.5/s for 10 min): credential stuffing or a login storm.")
ts("Proxy refusals", [rate("vlpds_proxy_rejected_total", by="reason", legend="{{reason}}")], "reqps", lines=[(1, "orange")], nonzero=True,
   desc=f"Proxied requests refused before forwarding; account_cap = 429 at 64 in flight for one account. "
        f"Dashed: {rb('VlpdsProxyAccountCapSustained')} (1/s for 30 min).")
ts("Stalled bodies, accept errors, firehose per-IP", [rate("vlpds_http_stalled_bodies_total", legend="stalled bodies dropped"),
                                                      rate("vlpds_http_server_accept_errors_total", legend="accept errors"),
                                                      t(f'sum(rate(vlpds_firehose_rejected_total{{{I}, reason="per_ip"}}{RI}))', "firehose refused per IP"),
                                                      t(f'sum(rate(vlpds_sync_exports_ended_total{{{I}, reason=~"shed|stalled"}}{RI}))', "exports shed/stalled")], "ops", nonzero=True,
   desc="Stalled bodies: proxied/forwarded responses the client stopped reading for 30 s (slowloris-style). "
        "Accept errors: usually out of file descriptors (retried every 50 ms). "
        f"{rb('tools-endpoints-cli-logs-exit-codes', 'Serving limits')}")

# ============================================================== accounts
row("Accounts: scheduled deletion, sign-in security, OAuth scopes")
ts("Scheduled-deletion sweeps", [rate("vlpds_scheduled_deletion_passes_total", by="result", legend="passes {{result}}"),
                                 t(hq(0.99, "vlpds_scheduled_deletion_pass_seconds", window="[30m]"), "pass p99")], "ops",
   overrides=[right_axis("pass p99", "s")], empty="no sweeps (--delete-after false?)",
   desc=f"Every node sweeps its own shards' D/ rows every 10 min. error = a shard scan or an account's deletion "
        f"failed (retried next sweep). {rb('VlpdsScheduledDeletionFailing')}")
ts("Scheduled-deletion accounts", [t(f"sum by (result) (increase(vlpds_scheduled_deletion_accounts_total{{{I}}}[30m])) > 0", "{{result}} (30 m)"),
                                   t(f"sum by (state) (vlpds_scheduled_deletion_accounts{{{I}}})", "{{state}}")], "short",
   empty="nothing scheduled",
   desc="Per sweep outcome: deleted, finished (a deletion that stopped partway), raced (reactivated first; kept), failed. "
        "States as of each node's last sweep: scheduled (D/ rows), held (taken down or suspended), deferred (over the "
        f"100 per-pass cap: next sweep). A jump in scheduled: {rb('VlpdsScheduledDeletionsSurge')}")
ts("Sign-in factors and alerts", [rate("vlpds_sign_in_factors_total", by="method, factor", legend="{{method}} / {{factor}}"),
                                  t(f"sum by (result) (rate(vlpds_sign_in_alerts_total{{{I}}}{RI})) > 0", "new device: {{result}}")], "ops",
   empty="no sign-ins",
   desc="Successful sign-ins by method and second factor (trusted = a trusted browser skipped it), and new-device "
        f"sign-ins by what became of their alert mail. budget: {rb('VlpdsSignInAlertsSuppressed')}")
ts("Sign-in refusals and settings", [t(f'sum by (method, result) (rate(vlpds_logins_total{{{I}, result=~"inactive|oauth_required|app_passwords_blocked|passkey_required"}}{RI})) > 0', "{{method}} {{result}}"),
                                     t(f"sum by (setting, value) (rate(vlpds_sign_in_settings_total{{{I}}}{RI})) > 0", "{{setting}} -> {{value}}"),
                                     t(f"sum by (event) (rate(vlpds_trusted_browsers_total{{{I}}}{RI})) > 0", "trusted browser {{event}}")], "ops",
   empty="none", desc="createSession refused by the account (taken down, OAuth-only, app passwords off, passkey_required: "
                      "a passkey is its only strong factor), and owners changing those settings.")
ts("Passkeys", [t(f"sum by (event) (rate(vlpds_passkeys_total{{{I}}}{RI})) > 0", "{{event}}"),
                t(f"sum by (reason) (rate(vlpds_passkey_failures_total{{{I}}}{RI})) > 0", "refused: {{reason}}"),
                t(f"sum by (result) (rate(vlpds_passkey_counter_regressions_total{{{I}}}{RI})) > 0", "counter back: {{result}}"),
                t(f'sum by (result) (rate(vlpds_logins_total{{{I}, method="passkey"}}{RI})) > 0', "passwordless {{result}}")], "ops",
   empty="no passkey activity",
   desc="Passkeys registered, removed and reset by the operator; registrations and assertions refused by the check "
        "that failed (origin / rp_id from another site, challenge = expired or another flow's, replay = a challenge "
        "used twice, unknown_credential = not one of the account's); signature counters that went backwards "
        "(refused = a hardware key, now flagged; accepted = a synced passkey); passwordless sign-ins by result. "
        f"{rb('a-passkey-flagged-as-copied', 'A passkey flagged as copied')}")
ts("Scope rejections (ScopeMissingError)", [t(f"sum by (credential, kind) (rate(vlpds_scope_rejections_total{{{I}}}{RI})) > 0", "{{credential}} {{kind}}")], "reqps",
   empty="none",
   desc="403s for a scope the OAuth token or scoped app password lacks, by the missing scope's kind. A steady rate from "
        "one kind is usually one client asking for less than it uses; the access log's route and client tell which.")
ts("OAuth consents, handle checks", [t(f"sum by (result) (rate(vlpds_oauth_consents_total{{{I}}}{RI})) > 0", "consent {{result}}"),
                                     t(f"sum by (kind, status) (rate(vlpds_handle_checks_total{{{I}}}{RI})) > 0", "checkHandle {{kind}} {{status}}"),
                                     t(f'sum by (limiter) (rate(vlpds_rate_limit_rejections_total{{{I}, limiter=~"vlpds.identity.checkHandle-.*"}}{RI})) > 0', "429 {{limiter}}")], "ops",
   empty="none",
   desc="Consent page answers (narrowed = some scopes unticked; refused = a forged post without atproto), and "
        "vlpds.identity.checkHandle answers with its per-DID rate-limit rejections.")

# ============================================================== spaces
# vlpds_space_* series are registered on first use, so nodes without --spaces export none
row("Spaces (--spaces): writes, notify outbox and fan-out, sync reads, credentials")
SPACE_NOTIFY = "vlpds_space_notify_total"
ts("Space writes by method and result", [rate("vlpds_space_writes_total", by="op, result", legend="{{op}} {{result}}")], "reqps",
   empty="no space writes",
   desc="createRecord / putRecord / deleteRecord / applyWrites into space repos. refused = a 4xx (validation, scope, an inactive account); "
        "error = a 5xx.")
ts("Write → notify ack", quantiles("vlpds_space_notify_ack_seconds", qs=(0.5, 0.99)), "s", empty="no notifies to other authorities",
   desc="A space write's ack to its authority's 200 for the notifyWrite. Writes into the author's own space carry the authority's "
        "rows in the write's entry, so they send nothing and aren't counted here.")
ts("notifyWrite outbox rows by node", [node_gauge("vlpds_space_outbox_rows")], "short", empty="no outbox rows",
   desc="One row per (repo, space) this node still owes its authority a notify for. Writes made while a send is in flight only "
        "move their row's rev, so the count follows the active (repo, space) pairs, not the write rate.")
ts("notifyWrite outbox oldest row", [node_gauge("vlpds_space_outbox_oldest_seconds", agg="max")], "s", lines=[(3600, "orange")],
   empty="no outbox rows",
   desc=f"Age of each node's oldest undelivered row. Retries back off from 1 min to 1 h and give up 24 h after the write. "
        f"Dashed: {rb('VlpdsSpaceOutboxBacklog')} (1 h).")
ts("notifyWrite by hop and result", [rate(SPACE_NOTIFY, by="hop, result", legend="{{hop}} {{result}}")], "ops", empty="no notifies",
   desc="out = this node's writes to their authorities; in = notifies received as an authority; fanout = forwarded to "
        "registered syncers. ok = 200; retry = backing off; wait = the writer's account is inactive; refused / gone / "
        "expired = the row was dropped. in same_rev_unverified / same_rev_capped = a remote writer's same-rev, new-hash "
        "notify (a record takedown) its host didn't confirm, or over 3 per writer and space in 10 min: dropped, left to polls.")
ts("notifyWrite failure ratio by hop",
   [t(f'sum by (hop) (rate({SPACE_NOTIFY}{{{I}, result!="ok"}}{RI})) / sum by (hop) (rate({SPACE_NOTIFY}{{{I}}}{RI}))', "{{hop}}")],
   "percentunit", max_=1, lines=[(0.5, "orange")], empty="no notifies",
   desc=f"Dashed: {rb('VlpdsSpaceNotifyFanoutFailing')} (fanout over 50%). A dead syncer or a remote authority that's down "
        "shows up here first.")
ts("listRepoOps: at-head polls vs scans", [rate("vlpds_space_list_repo_ops_total", by="path")], "reqps", stack=True,
   empty="no listRepoOps",
   desc="noop = since was the head, answered from the in-memory head with no state read (most syncer polls). scan = an oplog range scan.")
ts("listRepoOps server time", [t(hq(q, "vlpds_space_list_repo_ops_seconds", by="path"), f"{QNAME[q]} {{{{path}}}}") for q in (0.5, 0.99)],
   "s", empty="no listRepoOps",
   desc="Handler time after auth, the commit signature included. Targets: noop well under 1 ms, a typical delta a few ms.")
ts("Space reads by method and auth", [rate("vlpds_space_reads_total", by="method, auth", legend="{{method}} {{auth}}")], "reqps",
   empty="no space reads",
   desc="credential = an Atproto-Space credential (another member or a syncer). oauth = the account reading its own repo.")
ts("Credential cache hit ratio",
   [t(f'sum(rate(vlpds_space_credential_cache_total{{{I}, result="hit"}}{RI})) / sum(rate(vlpds_space_credential_cache_total{{{I}}}{RI}))', "hit ratio")],
   "percentunit", max_=1, empty="no credential reads",
   desc="A hit costs a hash lookup and the request's P-256 signature check. A miss verifies the whole chain and resolves the "
        "authority's key. Low under steady polling means credentials churn faster than they expire, or the cache is too small.")
ts("Credential checks by result", [rate("vlpds_space_credential_checks_total", by="result")], "reqps", stack=True,
   empty="no credential reads",
   desc=f"ok, or why a credential read was refused (bad_sig, expired, revoked, audience, space). {rb('VlpdsSpaceCredentialRejectsHigh')}")
ts("Credentials and delegations issued", [rate("vlpds_space_credentials_issued_total", by="result", legend="credentials {{result}}"),
                                         rate("vlpds_space_delegations_total", legend="delegation tokens")], "ops",
   empty="none issued",
   desc="getSpaceCredential answers as an authority (bad_token = the delegation token didn't verify), and delegation tokens "
        "minted for this node's accounts.")
ts("Fan-out queue depth and drops", [t(f"sum(vlpds_space_fanout_queue_depth{{{I}}})", "queued"),
                                     rate("vlpds_space_fanout_dropped_total", by="reason", legend="dropped/s {{reason}}")], "short",
   overrides=[right_axis("queued", "short")], empty="no fan-out",
   desc="Notifies waiting for a syncer, and the ones dropped (a newer one for the same syncer superseded it, or a host's "
        "queue was full). Superseded drops are normal. The syncer pulls from its last rev either way.")
ts("Revocations held, blocks, digest mismatches",
   [t(f"max(vlpds_space_revocations{{{I}}})", "revocations held"),
    t(f"sum(increase(vlpds_space_digest_mismatch_total{{{I}}}[1h])) > 0", "digest mismatches (1 h)"),
    t(f"max by (kind) (vlpds_space_revocation_blocks{{{I}}})", "blocked {{kind}}s"),
    t(f"max(vlpds_space_revocations_saturated{{{I}}}) > 0", "saturated (remote authorities refused)")],
   "short", decimals=0, empty="none",
   desc=f"Revoked credential ids still in force (kept until their credential could have expired). Blocks: spaces and authorities "
        f"refused because a revocation of theirs couldn't be stored; saturated: every remote authority refused "
        f"({rb('VlpdsSpaceRevocationsSaturated')}). Mismatches: {rb('VlpdsSpaceDigestMismatch')}.")

# ============================================================== cluster: leases and ownership
row("Cluster: leases, ownership, failover")
ts("Lease renewal round trip by node (p99)", [node_quantile(0.99, "vlpds_lease_renew_seconds"),
                                              t(f"0.4 * min(vlpds_lease_ttl_seconds{{{I}}})", "fail-stop ceiling (0.4 x TTL)")], "s",
   overrides=[dashed("fail-stop ceiling (0.4 x TTL)")],
   desc="One CAS PUT of nodes/{node_id} every TTL/5. A round trip over 0.4 x TTL (4 s at the default 10 s TTL) lapses the lease and the "
        f"node fail-stops (exit 5). p99 over 500 ms for 10 min: {rb('VlpdsLeaseRenewalSlow')}.")
ts("Lease validity left by node", [t(f"min by (node_id) (vlpds_lease_validity_seconds{{{I}}})", "{{node_id}}"),
                                   t(f"0.4 * min(vlpds_lease_ttl_seconds{{{I}}})", "low (0.4 x TTL)")], "s",
   overrides=[dashed("low (0.4 x TTL)", "orange")],
   desc="Seconds until each node's lease validity ends, at scrape: a sawtooth between TTL - skew - one renew interval and TTL - skew. "
        f"Dips toward 0 = renewals overdue; below the dashed line: {rb('VlpdsLeaseValidityLow')}.")
ts("Renew errors, takeovers", [rate("vlpds_lease_renew_errors_total", by="kind", legend="renew {{kind}}"),
                               rate("vlpds_peer_takeovers_total", by="reason", legend="takeover {{reason}}")], "ops",
   nonzero=True,
   desc=f"renew conflict/lapsed = fail-stop; timeout/error retry ({rb('VlpdsLeaseRenewErrors')}). takeover peer: a dead peer's log fenced "
        f"before taking its shards; restart: our own previous incarnation's at startup ({rb('VlpdsUncleanNodeExit')}).")
ts("Lease events/s", [rate("vlpds_lease_events_total", by="event")], "ops", nonzero=True, empty="no shard moves",
   desc=f"opened/closed: shard moves (many per hour: {rb('VlpdsOwnershipFlapping')}); peer_refused: a peer presumed dead "
        f"({rb('VlpdsPeerPresumedDead')}); history_full: a shard not taken because its history is at its span cap with no clean open "
        "(investigate: its log can't be trimmed); lost / shutdown_fence_failed: fail-stop paths.")
ts("Shard opens (time to serve, p99)", [t(hq(0.99, "vlpds_shard_open_seconds", by="kind"), "{{kind}}"),
                                        t(hq(0.99, "vlpds_recovery_replay_seconds"), "replay step")], "s", empty="no shard opens",
   desc=f"replay: the batch replayed a dead owner's log tail (takeover after a crash; over 20 s: {rb('VlpdsTakeoverReplaySlow')}); "
        "clean: nothing to replay (handback).")
ts("Shards opened / segments replayed per s", [rate("vlpds_shards_opened_total", by="result", legend="opened {{result}}"),
                                               rate("vlpds_recovery_replayed_segments_total", legend="segments replayed")], "ops", nonzero=True, empty="no shard opens",
   desc=f"opened error: {rb('VlpdsShardOpenErrors')}.")
table("Exit state and versions", [instant_table(f"max by (instance, reason, code) (vlpds_last_exit_reason_info{{{I}}} == 1)"),
                                  instant_table(f"max by (instance) (vlpds_last_exit_time_seconds{{{I}}} > 0) * 1000"),
                                  instant_table(f'max by (instance) (vlpds_feature_level{{{I}, kind="active"}})'),
                                  instant_table(f'max by (instance) (vlpds_feature_level{{{I}, kind="binary_max"}})'),
                                  instant_table(f"max by (instance) (vlpds_shard_layout_version{{{I}}})"),
                                  instant_table(f"max by (instance, node_id) (vlpds_build_info{{{I}}})")],
      w=16, h=7, desc="Per node: how its previous process ended and when, the cluster feature level it last read and the max this build "
                      f"runs (binary max > active everywhere = a finalize is available: {rb('VlpdsFeatureLevelUnfinalized')}), shard layout version.",
      transformations=[{"id": "joinByField", "options": {"byField": "instance", "mode": "outer"}},
                       {"id": "organize", "options": {
                           "excludeByName": {"Time": True, "Time 1": True, "Time 2": True, "Time 3": True, "Time 4": True, "Time 5": True, "Time 6": True,
                                             "Value #A": True, "Value #F": True},
                           "indexByName": {"node_id": 0, "instance": 1, "reason": 2, "code": 3, "Value #B": 4, "Value #C": 5, "Value #D": 6, "Value #E": 7},
                           "renameByName": {"node_id": "node", "reason": "last exit", "code": "code", "Value #B": "exited", "Value #C": "level active",
                                            "Value #D": "level binary max", "Value #E": "layout version"}}}],
      overrides=[{"matcher": {"id": "byName", "options": "exited"}, "properties": [{"id": "unit", "value": "dateTimeFromNow"}]}])
ts("Integrity: format errors, signature faults", [rate("vlpds_format_errors_total", by="format", legend="format error {{format}}"),
                                                 rate("vlpds_signature_verify_failures_total", by="purpose", legend="signature fault {{purpose}}")], "ops", w=8, h=7,
   nonzero=True,
   desc=f"Should be empty. Format errors: a newer-level node writing early, or corruption ({rb('VlpdsFormatErrors')}, page). "
        f"Signature faults: suspect hardware ({rb('VlpdsSignatureFault')}, page).")

ts("Peer TLS: days until certificate expiry", [t(by_node(f"(vlpds_peer_tls_cert_expiry_seconds{{{I}}} - time()) / 86400"), "{{node_id}} {{cert}}")],
   "d", w=8, h=7, decimals=1, empty="TLS not enabled", lines=[(3, "red"), (14, "orange")],
   desc="Per node, its own server certificate (cert=node) and the CA it trusts (cert=ca), as days until notAfter. Only nodes running "
        "peer TLS export it. An expired node cert is refused by every peer and the node won't start or reload with one. Dashed: "
        f"14 days = {rb('VlpdsPeerTlsCertExpiring')} (ticket); 3 days = out of time, renew now (renewal procedure in the same section).")
ts("Peer TLS: handshake failures/s by side", [rate("vlpds_peer_tls_handshake_failures_total", by="side", legend="{{side}}")], "ops",
   w=8, h=7, empty="TLS not enabled",
   desc="Peer connections refused at the TLS handshake: server = a peer was refused by this node, client = this node was refused by (or "
        "refused) a peer. Cause: a cert from another CA, an expired cert, or an address whose lease names another node. Over 0.1/s for "
        f"10 min: {rb('VlpdsPeerTlsHandshakeFailures')}.")
ts("Peer TLS: certificate reloads by result", [rate("vlpds_peer_tls_reloads_total", by="result", legend="{{result}}")], "ops",
   w=8, h=7, empty="TLS not enabled",
   desc="Reloads of the CA/cert/key set (file change or SIGHUP). error = the new set failed to load and the node keeps the previous "
        f"one, which the rotation meant to replace: {rb('VlpdsPeerTlsReloadFailing')}.")

# ============================================================== cluster: forwarding and control plane
row("Cluster: forwarding, control plane, resharding")
ts("Forwards/s by owner status", [rate("vlpds_forwards_total", by="result", legend="{{result}}")], "reqps",
   desc=f"5xx includes owner unreachable / past its TTFB deadline (503 PartitionUnavailable). Over 5%: {rb('VlpdsForwardErrorsHigh')}.")
ts("Forward latency (to the owner's response head)", quantiles("vlpds_forward_seconds", qs=(0.5, 0.99, 0.999)), "s", lines=[(1, "orange")],
   desc=f"Deadline 3 s. Dashed: {rb('VlpdsForwardLatencyHigh')} (p99 1 s).")
ts("Forwards/s by node", [node_rate("vlpds_forwards_total")], "reqps")
ts("Control-plane requests/s by op", [rate("vlpds_cluster_store_requests_total", by="op")], "reqps")
ts("Control-plane latency", [t(hq(q, "vlpds_object_store_request_seconds", f'{I}, component=~"ctl_.*"'), QNAME[q]) for q in (0.5, 0.99)], "s", lines=[(1, "orange")],
   desc=f"Lease, assignment and fence reads/writes. Dashed: {rb('VlpdsControlPlaneLatencyHigh')} (p99 1 s).")
ts("Control-plane timeouts, nudges, lone skips", [rate("vlpds_cluster_store_timeouts_total", by="op", legend="timeout {{op}}"),
                                                  rate("vlpds_cluster_nudges_total", by="dir", legend="nudges {{dir}}"),
                                                  rate("vlpds_cluster_lone_skips_total", by="list", legend="lone skip {{list}}")], "ops", nonzero=True,
   desc=f"Timeouts: {rb('VlpdsControlPlaneTimeouts')}.")
ts("Resharding", [rate("vlpds_reshard_events_total", by="event", legend="{{event}}"), t(f"max(vlpds_shard_layout_shards{{{I}}})", "layout shards")], "short",
   overrides=[right_axis("layout shards", "short")])
ts("Retired-state GC", [rate("vlpds_reshard_gc_passes_total", by="result", legend="passes {{result}}"),
                        t(f"max by (state) (vlpds_reshard_gc_retired_dirs{{{I}}})", "retired dirs {{state}}"),
                        t(f"max(vlpds_reshard_gc_orphan_assign_records{{{I}}})", "orphan assign records")], "short", nonzero=True,
   empty="nothing retired",
   desc=f"{rb('VlpdsReshardGcFailing')}; retired dirs referenced > 0: {rb('VlpdsRetiredStateReferenced')}.")
ts("Forced compactions, inherited SSTs", [rate("vlpds_forced_compactions_total", by="kind, result", legend="{{kind}} {{result}}"),
                                         t(f"sum(vlpds_shards_with_inherited_ssts{{{I}}})", "shards with inherited SSTs")], "short", nonzero=True,
   empty="none (no split/merge parents)",
   desc=f"{rb('VlpdsForcedDetachFailing')}")

# ============================================================== object store
row("Object store (vlpds clients, per pool and lane)")
ts("Permits in use / limit", [t(f"max by (client, lane) (vlpds_object_store_inflight{{{I}}} / (vlpds_object_store_inflight_limit{{{I}}} > 0))", "{{client}}/{{lane}}")],
   "percentunit", max_=1, lines=[(0.8, "orange")],
   desc="Busiest node's in-flight requests per pool (log, state, ctl) and lane (main; reserved = log writes / ctl lease writes) over its permits "
        f"(--store-inflight, --log-store-inflight). At 100% requests queue: {rb('VlpdsObjectStorePermitsSaturated')}.")
ts("Permit waits/s", [t(f"sum by (client, lane) (rate(vlpds_object_store_permit_waits_total{{{I}}}{RI}))", "{{client}}/{{lane}}")], "reqps", lines=[(1, "red")],
   soft_max=1.2, desc=f"Dashed: {rb('VlpdsObjectStorePermitsSaturated')} (1/s per pool and lane for 10 min).")
ts("Permit wait p99", [t(hq(0.99, "vlpds_object_store_permit_wait_seconds", by="client, lane") + " > 0", "{{client}}/{{lane}}")], "s",
   empty="no permit waits")
ts("Requests/s by client", [t(f"sum by (client) (rate(vlpds_object_store_requests_total{{{I}}}{RI}))", "{{client}}")], "reqps", stack=True)
ts("Requests/s by op", [t(f"sum by (op) (rate(vlpds_object_store_requests_total{{{I}}}{RI})) > 0", "{{op}}")], "reqps", stack=True,
   desc="Billable ops (put, put_cas, get, get_range, head, list pages, delete, ...): cost tracks this mix.")
ts("Non-ok results/s", [t(f'sum by (result, client) (rate(vlpds_object_store_requests_total{{{I}, result!="ok"}}{RI})) > 0', "{{result}} {{client}}")], "reqps",
   desc="not_found / precondition are normal answers (misses, lost CAS races); timeout / error failed; cancelled = the caller gave up.")
ts("Throttled answers/s (429, 503 SlowDown)", [rate("vlpds_object_store_throttled_total", by="kind", legend="{{kind}}")], "reqps", nonzero=True,
   empty="no throttling",
   desc="Every 429 or 503 SlowDown the store answered, retries included (object_store retries them inside its client, so the request "
        "counters see only the final result). lease = node leases, assignments, writer claims and the cluster version (LISTs by prefix; "
        "bulk deletes count as other). R2 takes about one write a second per key, and node lease writes retry 1-4 s apart. "
        f"{rb('VlpdsObjectStoreThrottled')}.")
ts("p99 latency by component", [t(hq(0.99, "vlpds_object_store_request_seconds", by="component") + " > 0", "{{component}}")], "s", w=12, legend="table",
   desc=f"To the response head (GET), first page (LIST); deletes are not timed. {rb('VlpdsObjectStoreLatencyHigh')}")
ts("Bytes/s by client and direction", [t(f"sum by (client, dir) (rate(vlpds_object_store_bytes_total{{{I}}}{RI}))", "{{client}} {{dir}}")], "Bps", w=12)

# ============================================================== slatedb
row("SlateDB (summed over each node's shard DBs)")
ts("Block cache hit rate by entry kind",
   [t(f'sum by (entry_kind) (rate(slatedb_db_cache_access_count_total{{{I}, result="hit"}}{RI})) / sum by (entry_kind) (rate(slatedb_db_cache_access_count_total{{{I}}}{RI}))', "{{entry_kind}}")],
   "percentunit", max_=1)
ts("DB requests/s", [rate("slatedb_db_request_count_total", by="op"), rate("slatedb_db_write_batch_count_total", legend="write batches"),
                     rate("slatedb_db_write_ops_total", legend="write ops")], "ops")
ts("Memtables / L0", [t(f"sum(slatedb_db_total_mem_size_bytes{{{I}}})", "memtable bytes"), t(f"sum(slatedb_db_l0_sst_count{{{I}}})", "L0 SSTs")], "bytes",
   overrides=[right_axis("L0 SSTs", "short")])
ts("Flushes, backpressure, stalls", [rate("slatedb_db_immutable_memtable_flushes_total", legend="memtable flushes"),
                                     rate("slatedb_db_backpressure_count_total", legend="backpressure"),
                                     rate("slatedb_db_l0_stall_count_total", by="type", legend="L0 stall {{type}}"),
                                     rate("vlpds_compaction_poll_switches_total", by="mode", legend="compactor polls → {{mode}}")], "ops",
   desc=f"L0 stalls block writes: {rb('VlpdsSlateDbL0Stalls')}.")
ts("Flush / compaction bytes/s", [rate("slatedb_db_l0_flush_bytes_total", legend="L0 flush"), rate("slatedb_db_memtable_write_bytes_total", legend="memtable writes"),
                                  rate("slatedb_compactor_bytes_compacted_total", legend="compacted")], "Bps")
ts("Object store requests/s and errors (SlateDB)", [t(f"sum by (api) (rate(slatedb_object_store_request_count_total{{{I}}}{RI})) > 0", "{{api}}"),
                                                    t(f"sum(rate(slatedb_object_store_error_count_total{{{I}}}{RI}))", "errors (incl. not found)")], "reqps",
   overrides=[{"matcher": {"id": "byName", "options": "errors (incl. not found)"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}]}],
   desc="SlateDB's own view of its store calls. Its error count includes normal answers (GETs of objects that don't exist yet, "
        "e.g. compactor polls; lost CAS races), so a steady rate here is not trouble by itself: real failures are result=error|timeout "
        f"in the Object store row, where {rb('VlpdsObjectStoreErrors')} counts them for the state_* components (no alert reads this counter).")

# ============================================================== process
row("Process and runtime")
ts("CPU by mode", [t(f"sum by (mode) (rate(vlpds_process_cpu_seconds_total{{{I}}}{RI}))", "{{mode}}")], "short", stack=True, decimals=1,
   desc="CPU cores, summed over the selected nodes.")
ts("RSS by node", [t(by_node(f"max by (instance) (vlpds_process_resident_bytes{{{I}}})"), "{{node_id}}")], "bytes",
   desc="Resident set size. As a share of the node's memory limit: Health → Memory used / limit.")
ts("jemalloc", [t(f'sum by (stat) (vlpds_jemalloc_bytes{{{I}}})', "{{stat}}")], "bytes",
   desc="allocated = live heap; resident - allocated = fragmentation and retained pages.")
ts("Tokio worker utilization by node", [t(by_node(f"sum by (instance) (rate(vlpds_tokio_busy_seconds_total{{{I}}}{RI})) / sum by (instance) (vlpds_tokio_workers{{{I}}})"), "{{node_id}}")],
   "percentunit", max_=1, lines=[(0.9, "orange")],
   desc=f"Busy / workers. Dashed: {rb('VlpdsRuntimeSaturated')} (90% for 15 min).")
ts("Runtime lateness by node", [t(by_node(f"sum by (instance) (rate(vlpds_runtime_late_seconds_total{{{I}}}{RI}))"), "{{node_id}}")], "percentunit",
   lines=[(0.05, "orange")],
   desc=f"Share of time a 10 ms ticker woke late: ready tasks waited for a worker (blocking code on the runtime, or CPU starvation). "
        f"Dashed: {rb('VlpdsRuntimeStalls')} (5%).")
ts("Tasks, injection queue, threads", [t(f"sum(vlpds_tokio_alive_tasks{{{I}}})", "alive tasks"),
                                       t(f"sum(vlpds_tokio_global_queue_depth{{{I}}})", "injection queue"),
                                       t(f"sum(vlpds_process_threads{{{I}}})", "OS threads")], "short")

# ============================================================== identity services
row("Key service, PLC directory, mail")
ts("KMS requests/s by result", [t(f"sum by (backend, op, result) (rate(vlpds_kms_requests_total{{{I}}}{RI}))", "{{backend}} {{op}} {{result}}")], "reqps",
   desc=f"unavailable: {rb('VlpdsKeyServiceUnavailable')} (page: cold writes fail); unwrap rejected: {rb('VlpdsSecretUnwrapRejected')}.")
ts("KMS latency p99, signing-key cache", [t(hq(0.99, "vlpds_kms_request_seconds", by="op"), "p99 {{op}}"),
                                          t(f'sum(rate(vlpds_signing_key_cache_total{{{I}, result="hit"}}{RI})) / sum(rate(vlpds_signing_key_cache_total{{{I}}}{RI}))', "key cache hit ratio")], "s",
   overrides=[right_axis("key cache hit ratio", "percentunit")], empty="no KMS calls")
ts("PLC directory requests/s", [t(f"sum by (op, result) (rate(vlpds_plc_requests_total{{{I}}}{RI}))", "{{op}} {{result}}"),
                                t(hq(0.99, "vlpds_plc_request_seconds"), "p99")], "reqps",
   overrides=[right_axis("p99", "s")], empty="no PLC calls (did:web / dev)",
   desc=f"Write ops unavailable: {rb('VlpdsPlcDirectoryUnavailable')} (page); rejected: {rb('VlpdsPlcOpsRejected')}.")
ts("Mail", [t(f"sum by (result, purpose) (rate(vlpds_mail_messages_total{{{I}}}{RI}))", "{{result}} {{purpose}}"),
            rate("vlpds_mail_retries_total", legend="retries"), t(f"sum(vlpds_mail_queue_depth{{{I}}})", "queued")], "short",
   empty="no mail (SMTP not configured, or nothing sent)")

# ============================================================== minio
row("MinIO (bench only; 5 s scrape)")
ts("S3 requests/s by API", [t(f"sum by (api) (rate(minio_s3_requests_total{{{C}}}{MRI})) > 0", "{{api}}")], "reqps")
ts("S3 TTFB p99 by API", [t(f"histogram_quantile(0.99, sum by (le, api) (rate(minio_s3_requests_ttfb_seconds_distribution{{{C}}}{MRI}))) < +Inf", "{{api}}")], "s")
ts("S3 traffic", [t(f"sum(rate(minio_s3_traffic_received_bytes{{{C}}}{MRI}))", "received"), t(f"sum(rate(minio_s3_traffic_sent_bytes{{{C}}}{MRI}))", "sent")], "Bps")
ts("S3 errors / in flight", [t(f"sum(rate(minio_s3_requests_errors_total{{{C}}}{MRI}))", "errors/s"), t(f"sum(minio_s3_requests_inflight_total{{{C}}})", "in flight"),
                             t(f"sum(minio_s3_requests_waiting_total{{{C}}})", "waiting")], "short")
ts("Bucket usage", [t(f"sum by (instance) (minio_cluster_usage_total_bytes{{{C}}})", "{{instance}}")], "bytes")

# ============================================================== profiles
PROFILE_ROWS_FROM = len(D.panels)
row("CPU profile (Pyroscope; nodes run with --pyroscope-url)")
D.add({
    "type": "flamegraph", "id": D.nid(), "title": "CPU flamegraph (dashboard time range, selected nodes)", "datasource": PYRO, "gridPos": D.place(24, 16),
    "description": "Needs a Pyroscope datasource (the Pyroscope picker at the top) and nodes started with --pyroscope-url.",
    "targets": [{"datasource": PYRO, "refId": "A", "queryType": "profile", "groupBy": [],
                 "profileTypeId": "process_cpu:cpu:nanoseconds:cpu:nanoseconds",
                 "labelSelector": '{service_name="vlpds", node_id=~"$node"}'}],
    "options": {},
})



INTERNALS_PANELS = D.panels


def var(name, label, query, hide=0, regex="", multi=True, all_value=".*"):
    v = {"name": name, "label": label, "type": "query", "datasource": PROM, "hide": hide,
         "query": {"query": query, "refId": name, "qryType": 3 if query.startswith("query_result") else 1},
         "definition": query, "refresh": 2, "multi": multi, "includeAll": True, "regex": regex,
         "allValue": all_value, "current": {"selected": True, "text": ["All"], "value": ["$__all"]}, "sort": 1}
    if all_value is None:
        del v["allValue"]
    return v


def ds_var(name, label, plugin):
    """Datasource picker; render() sets which one is selected."""
    return {"name": name, "label": label, "type": "datasource", "query": plugin, "hide": 0, "refresh": 1,
            "regex": "", "multi": False, "includeAll": False, "options": []}


def job_var():
    # no custom All value: All = the jobs found, not ".*" (which would count every target's up)
    return var("job", "job", f"label_values(vlpds_build_info{{{C}}}, job)", hide=2, all_value=None)


PLUGIN_NAMES = {"prometheus": "Prometheus", "grafana-pyroscope-datasource": "Grafana Pyroscope", "row": "Row",
                "stat": "Stat", "table": "Table", "text": "Text", "timeseries": "Time series",
                "state-timeline": "State timeline", "flamegraph": "Flame Graph"}


def without_profiles(d):
    """For a Grafana with no Pyroscope: the profile row goes, with the pickers
    only it reads (`node` exists for the flamegraph's label selector)."""
    if d["uid"] == "vlpds-internals":
        d["panels"] = d["panels"][:PROFILE_ROWS_FROM]
    d["templating"]["list"] = [v for v in d["templating"]["list"] if v["name"] not in ("ds_pyroscope", "node")]
    assert PYRO["type"] not in json.dumps(d), "a Pyroscope panel outside the profile row"
    return d


def render(template, prom_uid=None, pyro_uid=None, profiles=True):
    """prom_uid None: the import-ready copy (__inputs). Otherwise both pickers
    are pre-set (a uid, or `default`); an unset Pyroscope picker selects the
    first Pyroscope datasource."""
    d = template()
    if not profiles:
        d = without_profiles(d)
    for v in d["templating"]["list"]:
        uid = {"ds_prometheus": prom_uid or DS_INPUT, "ds_pyroscope": pyro_uid}.get(v["name"]) if v["type"] == "datasource" else None
        if uid:
            v["current"] = {"selected": False, "text": uid, "value": uid}
    kinds = {p["type"] for p in d["panels"]} | {q["type"] for p in d["panels"] for q in p.get("panels", [])}
    datasources = {v["query"] for v in d["templating"]["list"] if v["type"] == "datasource"}
    head = {"__requires": [{"type": "grafana", "id": "grafana", "name": "Grafana", "version": GRAFANA_MIN}]
            + [{"type": "datasource", "id": k, "name": PLUGIN_NAMES[k], "version": ""} for k in sorted(datasources)]
            + [{"type": "panel", "id": k, "name": PLUGIN_NAMES[k], "version": ""} for k in sorted(kinds - {"row"})]}
    if prom_uid is None:
        # Pyroscope stays out: the Import dialog requires every datasource input
        head = {"__inputs": [{"name": DS_INPUT[2:-1], "label": "Prometheus", "type": "datasource", "pluginId": "prometheus",
                              "pluginName": "Prometheus", "description": "Pick the Prometheus that scrapes vlpds /metrics"}], **head}
    return json.dumps({**head, **d}, indent=1) + "\n"


def internals_template():
    return {
        "uid": "vlpds-internals",
        "title": "vlpds internals",
        "description": "vlpds internals, for engineers debugging the PDS cluster: health first, then one collapsed row "
                       "per subsystem. The operator's view is the 'vlpds' dashboard. Generated by "
                       "bench/obs/grafana/gen_dashboard.py (also printed by `vlpds dashboards`).",
        "tags": ["vlpds"],
        "timezone": "browser",
        "editable": True,
        "graphTooltip": 1,
        "refresh": "10s",
        "time": {"from": "now-1h", "to": "now"},
        "timepicker": {"refresh_intervals": ["1s", "2s", "5s", "10s", "30s", "1m", "5m"]},
        "schemaVersion": 39,
        "version": 1,
        "links": [
            {"title": "Operator dashboard", "type": "link", "url": "/d/vlpds", "icon": "dashboard", "keepTime": True,
             "tooltip": "The PDS operator's view: users, content, federation, cost"},
            {"title": "Runbook", "type": "link", "url": RB, "icon": "doc", "targetBlank": True, "tooltip": "ops/RUNBOOK.md: one section per alert"},
            {"title": "Alert rules", "type": "link", "url": ALERTS_URL, "icon": "bolt", "targetBlank": True, "tooltip": "ops/alerts.yml"},
        ],
        "annotations": {"list": [
            {"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"}, "enable": True, "hide": True,
             "iconColor": "rgba(0, 211, 255, 1)", "name": "Annotations & Alerts", "type": "dashboard"},
            # off by default: page regions shade every panel; the Health timeline is the main view
            {"datasource": PROM, "enable": False, "iconColor": "red", "name": "Paging alerts",
             "expr": f'max by (alertname, severity) (ALERTS{{alertstate="firing", alertname=~"Vlpds.*", severity="page", {C}}})',
             "step": "30s", "titleFormat": "{{alertname}}", "textFormat": "{{severity}}", "tagKeys": "severity", "useValueForTime": False},
            {"datasource": PROM, "enable": True, "iconColor": "purple", "name": "Restarts",
             "expr": f"max by (instance) (changes(vlpds_process_start_time_seconds{{{I}}}[2m])) > 0",
             "step": "1m", "titleFormat": "restart", "textFormat": "{{instance}}", "tagKeys": "instance", "useValueForTime": False},
            {"datasource": {"type": "grafana", "uid": "-- Grafana --"}, "enable": True, "iconColor": "#FF9830",
             "name": "bench steps", "target": {"type": "tags", "tags": ["vlpds-bench"], "matchAny": True, "limit": 500}},
        ]},
        "templating": {"list": [
            ds_var("ds_prometheus", "Prometheus", "prometheus"),
            ds_var("ds_pyroscope", "Pyroscope", "grafana-pyroscope-datasource"),
            var("cluster", "cluster", "label_values(vlpds_build_info, cluster)"),
            job_var(),
            # text = node id, value = instance label (prod: the same; bench: 127.0.0.1:<port>)
            var("instance", "node", f'query_result(max by (instance, node_id) (vlpds_build_info{{{C}}}))',
                # query_result prints labels sorted: instance before node_id
                regex='/instance="(?<value>[^"]+)".*node_id="(?<text>[^"]+)"/'),
            # node ids of the selected nodes, for the Pyroscope flamegraph
            var("node", "node id", f'label_values(vlpds_build_info{{{I}}}, node_id)', hide=2),
        ]},
        "panels": INTERNALS_PANELS,
    }


def count(panels):
    return sum(1 for p in panels if p["type"] != "row") + \
        sum(len(p.get("panels", [])) for p in panels if p["type"] == "row")


def main():
    sys.path.insert(0, HERE)
    import gen_operator
    operator_panels = gen_operator.build(sys.modules[__name__])
    dashboards = [("vlpds.json", lambda: gen_operator.template(sys.modules[__name__], operator_panels), operator_panels),
                  ("vlpds-internals.json", internals_template, INTERNALS_PANELS)]
    check = "--check" in sys.argv[1:]
    if os.environ.get("VLPDS_PROM_UID") or os.environ.get("VLPDS_PYRO_UID") or os.environ.get("VLPDS_DASH_OUT"):
        out = os.environ.get("VLPDS_DASH_OUT", "")
        if not out or os.path.abspath(out) == BENCH_DIR:
            sys.exit("VLPDS_DASH_OUT: a directory other than the import-ready copy's (bench/obs/grafana/dashboards)")
        outs = [(out, os.environ.get("VLPDS_PROM_UID", "default"), os.environ.get("VLPDS_PYRO_UID"), True)]
    else:
        outs = [(BENCH_DIR, None, None, True)]
        if os.path.isdir(PROD_DIR):
            outs.append((PROD_DIR, PROD_PROM_UID, None, False))
    stale = []
    for out_dir, prom_uid, pyro_uid, profiles in outs:
        for name, template, panels in dashboards:
            path = os.path.join(out_dir, name)
            body = render(template, prom_uid, pyro_uid, profiles)
            old = open(path).read() if os.path.exists(path) else None
            if check:
                if old != body:
                    stale.append(path)
                continue
            if old != body:
                with open(path, "w") as f:
                    f.write(body)
            print(f"{'wrote' if old != body else 'unchanged'} {os.path.relpath(path)}: {count(json.loads(body)['panels'])} panels")
    if stale:
        print("stale (run python3 bench/obs/grafana/gen_dashboard.py):\n  " + "\n  ".join(stale), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
