---
title: Operations
section: Operations
order: 100
status: ready
summary: "Running vlpds: deploying a node, configuring it, watching it, and what to do when something goes wrong."
---

```hero
diagram:
  caption: An operator's loop. Deploy points a node at a bucket; monitoring scrapes it; an alert names its runbook section. Upgrades and scaling are restarts and joins of the same binary on the same bucket.
  nodes:
    - { id: bucket, label: Object store, sub: bucket + prefix, at: [0, 0.2], size: [8, 2.6], shape: store, tone: amber }
    - { id: keys, label: Secrets, sub: "KEK · PLC key · tokens", at: [0, 5.2], size: [8, 2.6], tone: muted }
    - { id: deploy, label: Deploy, sub: Ansible · compose, at: [12, 2.6], size: [8, 3], tone: accent }
    - { id: watch, label: Monitoring, sub: "metrics · 92 alerts", at: [24, 2.6], size: [8, 3], tone: blue }
    - { id: runbook, label: Runbook, sub: one section per alert, at: [36, 2.6], size: [8, 3], tone: danger }
    - { id: upgrade, label: Upgrades, sub: SIGTERM · roll · finalize, at: [12, 9], size: [8, 3], tone: accent }
    - { id: scale, label: Scaling, sub: "add nodes · split shards", at: [24, 9], size: [8, 3], tone: accent }
    - { id: backup, label: Backups, sub: "bucket durability · offline keys", at: [36, 9], size: [8, 3], shape: note, tone: muted }
  edges:
    - "bucket.r -> deploy.l30"
    - "keys.r -> deploy.l70"
    - "deploy -> watch: scrape"
    - "watch -> runbook: alert"
    - { from: deploy.b, to: upgrade.t, label: new image }
    - { from: watch.b, to: scale.t, label: busy cores }
    - { from: runbook.b, to: backup.t, label: last resort, dash: true }
facts:
  - { value: "1", unit: binary, label: and one bucket per PDS, note: "the web UI and the admin CLI are in the same binary" }
  - { value: "92", unit: alerts, label: each with a runbook section, note: "18 page, 74 ticket (ops/alerts.yml)", tone: blue }
  - { value: "≥ 60 s", label: stop grace for SIGTERM, note: "a graceful stop hands shards over in ~0.2 s each; never SIGKILL", tone: amber }
  - { value: "2", unit: keys, label: to copy offline, note: "the KEK and the PLC rotation key; durability is the bucket's own", tone: rust }
```


These pages are for whoever runs a vlpds server, from a personal PDS on a small VM to a cluster.
Read [Deploy](deploy.md) first, then read [Monitoring](monitoring.md) and the
[Runbook](runbook.md) before you need them. The [Overview](../overview.md) explains the design in
one screen.

Operationally, two things set vlpds apart from the reference PDS. First, the bucket is the
database. A node's disk is a cache, so losing a host only costs you warm caches. Second, a node
exits when it can't be sure it's allowed to write. Restarts with exit codes 2 to 9 are the safety
mechanism, so the supervisor must restart the process on any of them.

```pages
{}
```
