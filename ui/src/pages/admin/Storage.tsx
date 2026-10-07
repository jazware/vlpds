import { DataTable } from '../../components/console/DataTable'
import { Banners, Chip, ErrorState, Glyph, KV, Loading, Meter, Mini, Minis, NeedsVersion, PageHead, Panel, PanelBody, Spark, Src, Swatch, Tiles, type BannerSpec } from '../../components/console/kit'
import { registerPalette } from '../../components/console/Palette'
import { useClusterView } from '../../lib/console/cluster'
import { ago, fmtBytes, fmtMs, fmtNum, fmtSi } from '../../lib/console/fmt'
import { configPoll, storageStatsPoll, maxLatest, nodeSeries, sumLatest, sumSeries, useNodeMetrics, worstSeries, type NodeSeries, type StorageStats } from '../../lib/console/sys'
import { navigate } from '../../lib/router'

// Object store: request rates by billing class (A: writes, lists, CAS; B: reads), by key component
// and by node, and segment PUT latency. What's stored per component comes from getStorageStats:
// counters every node keeps from its own PUTs and DELETEs, seeded by one operator-run backfill; the
// console itself never lists the bucket.

/** Last backfill, a run in progress, and why the counts aren't exact. */
function storageFoot(s: StorageStats) {
  const b = s.backfill
  const run =
    b && b.phase !== 'done'
      ? `Backfill ${b.phase === 'capped' ? 'stopped at its budget' : b.phase}: ${fmtNum(b.keys)} keys in ${fmtNum(b.requests)} LISTs${b.phase === 'capped' ? '; another call resumes it' : ''}${b.error ? ` (${b.error})` : ''}.`
      : undefined
  return (
    <span>
      {s.lastBackfillAt ? `Backfilled ${ago(s.lastBackfillAt)}.` : 'Never backfilled: the counts are changes since the nodes started counting.'}
      {run ? ` ${run}` : ''}
      {s.inexactBecause.length ? ` Approximate: ${s.inexactBecause.join('; ')}.` : !s.exact ? ` Approximate: ${fmtNum(s.uncertainChanges)} changes since were guessed (≈ rows).` : ''}
    </span>
  )
}

/** The provider an endpoint belongs to; MinIO and the rest are "S3-compatible". */
export function providerOf(endpoint?: string) {
  const e = endpoint ?? ''
  if (/r2\.cloudflarestorage\.com/.test(e)) return 'Cloudflare R2'
  if (/amazonaws\.com/.test(e)) return 'AWS S3'
  if (/storage\.googleapis\.com/.test(e)) return 'Google Cloud Storage'
  return 'S3-compatible'
}

export const COMPONENTS: Record<string, { name: string; what: string }> = {
  log_segment: { name: 'Log segments', what: 'a PUT per batch of commits; GETs for replay and cursor backfill' },
  retention_report: { name: 'Log retention', what: 'retention passes and their reports' },
  ctl_lease: { name: 'Node leases', what: 'each node renews its lease by CAS every TTL/5' },
  ctl_assign: { name: 'Shard assignments', what: 'owners and the slot layout, by CAS' },
  ctl_writer: { name: 'Writer claims', what: 'the writer byte each log signs seqs with' },
  ctl_stats: { name: 'Storage stats', what: 'these counts, folded by each node every 5 minutes, and the backfill\'s place' },
  ctl_version: { name: 'Feature level', what: 'the cluster version object' },
  account_index: { name: 'Handle and email index', what: 'uniqueness claims for handles and emails' },
  blob: { name: 'Blobs', what: 'uploads (multipart when large), reads, GC' },
  state_manifest: { name: 'SlateDB manifests', what: 'every shard re-reads its manifest (--slatedb-manifest-poll)' },
  state_sst: { name: 'SlateDB SSTs', what: 'memtable flushes, compaction, reads that miss the caches' },
  state_wal: { name: 'SlateDB WAL', what: 'write-ahead log objects of the shard DBs' },
  state_compactions: { name: 'SlateDB compactions', what: 'compaction state each compactor polls' },
  state_gc_boundary: { name: 'SlateDB GC boundary', what: 'read with every latest-manifest and compactions read' },
  state_other: { name: 'SlateDB, other', what: 'checkpoints and the rest of a shard DB' },
  other: { name: 'Everything else', what: 'config, mail budget, moderation, spaces' },
}
export const componentName = (c: string) => COMPONENTS[c]?.name ?? c

export type ComponentRow = { component: string; a: number; b: number; byNode: { node: string; a: number; b: number }[] }
/** storeComponents summed over the nodes that answered. */
export function componentRows(nodes: NodeSeries[]): ComponentRow[] {
  const m = new Map<string, ComponentRow>()
  for (const n of nodes) {
    for (const c of n.raw.storeComponents ?? []) {
      const r = m.get(c.component) ?? { component: c.component, a: 0, b: 0, byNode: [] }
      r.a += c.classAPerSec
      r.b += c.classBPerSec
      r.byNode.push({ node: n.node, a: c.classAPerSec, b: c.classBPerSec })
      m.set(c.component, r)
    }
  }
  return [...m.values()]
}

registerPalette({
  items: () => [
    { group: 'Go to', title: 'Object store requests', desc: 'class A and B by component and node', glyph: '◫', run: () => navigate('/admin/storage') },
    ...Object.entries(COMPONENTS).map(([k, v]) => ({ group: 'Go to', title: `Object store: ${v.name}`, desc: v.what, hay: k, glyph: '◫', run: () => navigate(`/admin/storage?open=storecomp:${k}`) })),
  ],
})

export function Storage() {
  const { view } = useClusterView()
  const m = useNodeMetrics()
  const cfg = configPoll.use()
  const stats = storageStatsPoll.use()
  const counts = stats.data?.supported ? stats.data.data : undefined
  const self = cfg.data?.find((x) => x.config && x.self)?.config ?? cfg.data?.find((x) => x.config)?.config
  const setting = (f: string) => self?.settings.find((s) => s.flag === f)?.value
  const endpoint = setting('--s3-endpoint')
  const provider = providerOf(endpoint)
  const color = (node: string) => view?.nodes.find((n) => n.node === node)?.color

  if (m.status === 'unsupported')
    return (
      <>
        <PageHead title="Object store" />
        <Panel>
          <NeedsVersion what="Object-store request rates" nsid="vlpds.admin.getNodeMetrics" />
        </Panel>
      </>
    )
  if (m.status === 'pending') return <Loading label="Asking every node…" />
  if (m.status === 'error' && !m.nodes.length) return <ErrorState error={m.error} />

  const nodes = m.nodes.filter((n) => n.reachable)
  const aNow = sumLatest(nodes, 'classAPerSec')
  const bNow = sumLatest(nodes, 'classBPerSec')
  const errNow = sumLatest(nodes, 'storeErrorsPerSec') ?? 0
  const reqs = (r: { a: number; b: number }) => r.a + r.b
  const comps = componentRows(nodes).sort((x, y) => reqs(y) - reqs(x))
  const reqsAll = comps.reduce((t, r) => t + reqs(r), 0) || 1
  const stored = counts ? [...counts.components].sort((x, y) => y.bytes - x.bytes) : []
  const bytesAll = stored.reduce((t, r) => t + r.bytes, 0) || 1
  const windowMin = Math.round((nodes[0]?.raw.storeWindowMs ?? 0) / 60000)
  const putP99 = maxLatest(nodes, 'putP99Ms')

  const banners: BannerSpec[] = []
  if (m.unreachable.length) banners.push({ id: 'unreach', tone: 'warn', title: `${m.unreachable.join(', ')} didn't answer`, desc: 'Rates leave out what those nodes send.' })
  if (errNow > 0) banners.push({ id: 'err', tone: 'err', title: `${fmtSi(errNow)} object-store errors or timeouts a second`, desc: 'Timeouts and errors after the client’s retries, all nodes, last 10 s.' })

  const byNode = nodes.map((n) => ({
    n,
    a: n.latest?.classAPerSec ?? 0,
    b: n.latest?.classBPerSec ?? 0,
    err: n.latest?.storeErrorsPerSec ?? 0,
    put: n.latest?.putP99Ms,
  }))

  return (
    <>
      <PageHead
        title="Object store"
        sub={
          <>
            <span>{provider}</span>
            {self && (
              <span className="mono">
                {setting('--s3-bucket')}/{setting('--prefix') ?? ''}
                {setting('--prefix') ? '/' : ''}
              </span>
            )}
            {endpoint && <span className="mono muted">{endpoint.replace(/^https?:\/\//, '')}</span>}
          </>
        }
      />
      <Banners items={banners} />
      <Tiles
        boxed
        tiles={[
          { label: 'Class A requests / s', right: 'PUT · LIST · CAS', value: aNow === undefined ? '—' : fmtSi(aNow), spark: <Spark data={sumSeries(nodes, 'classAPerSec')} color="c3" /> },
          { label: 'Class B requests / s', right: 'GET · HEAD', value: bNow === undefined ? '—' : fmtSi(bNow), spark: <Spark data={sumSeries(nodes, 'classBPerSec')} color="c6" /> },
          {
            label: 'Stored',
            right: counts ? (counts.seeded ? (counts.exact ? 'exact' : 'approximate') : 'not backfilled') : undefined,
            value: counts ? fmtBytes(counts.totalBytes) : '—',
            sec: counts ? `${fmtSi(counts.totalObjects)} objects` : undefined,
          },
          { label: 'Errors · timeouts / s', right: 'after retries', value: errNow ? fmtSi(errNow) : '0', spark: <Spark data={sumSeries(nodes, 'storeErrorsPerSec')} color="warn" /> },
          { label: 'Segment PUT p99', right: 'worst node · p50 dashed', value: fmtMs(putP99), spark: <Spark data={worstSeries(nodes, 'putP99Ms')} l2={worstSeries(nodes, 'putP50Ms')} color="amber" /> },
        ]}
      />
      <div className="cx-grid2 cx-mt">
        <div className="cx-stack">
          <Panel
            title="Requests by component"
            src={<Src>getNodeMetrics · storeComponents</Src>}
            right={<span className="muted sm">last {windowMin || 3} min · all nodes</span>}
            foot="Requests follow nodes and shards more than traffic: every shard polls its SlateDB manifest and every node renews its lease, idle or not."
          >
            <DataTable
              compact
              rows={comps}
              rowKey={(r) => r.component}
              open={(r) => ({ type: 'storecomp', id: r.component })}
              empty={<div className="cx-empty">No requests counted yet.</div>}
              cols={[
                {
                  id: 'c',
                  label: 'Component',
                  render: (r) => (
                    <span title={COMPONENTS[r.component]?.what}>
                      <b>{componentName(r.component)}</b> <span className="muted mono sm">{r.component}</span>
                    </span>
                  ),
                },
                { id: 'a', label: 'A/s', r: true, sort: (x, y) => x.a - y.a, render: (r) => <span className="mono">{fmtNum(r.a, 2)}</span> },
                { id: 'b', label: 'B/s', r: true, sort: (x, y) => x.b - y.b, render: (r) => <span className="mono">{fmtNum(r.b, 2)}</span> },
                {
                  id: 'share',
                  label: 'Share of requests',
                  sort: (x, y) => reqs(x) - reqs(y),
                  render: (r) => (
                    <span className="cx-cellid">
                      <Meter v={reqs(r)} max={reqsAll} k="info" />
                      <span className="mono sm">{Math.round((reqs(r) / reqsAll) * 100)}%</span>
                    </span>
                  ),
                },
              ]}
            />
          </Panel>
          <Panel title="Latency" src={<Src>getNodeMetrics · putP50Ms, putP99Ms</Src>} foot="Segment PUTs run until durable, hedges and retries included. A commit is acked only once its segment is.">
            <Minis n={Math.min(3, Math.max(1, nodes.length))}>
              {nodes.map((n) => (
                <Mini
                  key={n.node}
                  label={
                    <>
                      <Swatch color={color(n.node)} /> {n.node} PUT p99
                    </>
                  }
                  value={fmtMs(n.latest?.putP99Ms)}
                >
                  <Spark data={nodeSeries(n, 'putP99Ms')} l2={nodeSeries(n, 'putP50Ms')} color="amber" />
                </Mini>
              ))}
            </Minis>
          </Panel>
        </div>
        <div className="cx-stack">
          <Panel
            title="Stored by component"
            src={<Src isNew={!counts}>getStorageStats · 60 s</Src>}
            right={
              counts ? (
                <span className="cx-cellid end">
                  <span className="muted sm">{fmtBytes(counts.totalBytes)} in all</span>
                  <Chip k={counts.exact ? 'ok' : 'warn'}>{counts.exact ? 'exact' : 'approximate'}</Chip>
                </span>
              ) : undefined
            }
            foot={counts ? storageFoot(counts) : undefined}
          >
            {stats.data && !stats.data.supported ? (
              <NeedsVersion what="Objects and bytes by component" nsid="vlpds.admin.getStorageStats" />
            ) : stats.error ? (
              <ErrorState error={stats.error} retry={storageStatsPoll.refresh} />
            ) : !counts ? (
              <Loading />
            ) : (
              <DataTable
                compact
                rows={stored}
                rowKey={(r) => r.component}
                open={(r) => ({ type: 'storecomp', id: r.component })}
                empty={<div className="cx-empty">Nothing counted yet.</div>}
                cols={[
                  { id: 'c', label: 'Component', render: (r) => <b>{componentName(r.component)}</b> },
                  { id: 'o', label: 'Objects', r: true, render: (r) => <span className="mono">{fmtNum(r.objects)}</span> },
                  {
                    id: 'b',
                    label: 'Size',
                    r: true,
                    render: (r) => (
                      <span className="mono" title={r.exact ? undefined : `${fmtNum(r.uncertain)} guessed changes since the backfill`}>
                        {r.exact ? '' : '≈ '}
                        {fmtBytes(r.bytes)}
                      </span>
                    ),
                  },
                  {
                    id: 'share',
                    label: 'Share of bytes',
                    render: (r) => (
                      <span className="cx-cellid">
                        <Meter v={r.bytes} max={bytesAll} k="info" />
                        <span className="mono sm">{Math.round((r.bytes / bytesAll) * 100)}%</span>
                      </span>
                    ),
                  },
                ]}
              />
            )}
          </Panel>
          <Panel title="By node" src={<Src>getNodeMetrics · latest 10 s</Src>}>
            <DataTable
              compact
              rows={byNode}
              rowKey={(r) => r.n.node}
              open={(r) => ({ type: 'node', id: r.n.node })}
              cols={[
                {
                  id: 'n',
                  label: 'Node',
                  render: (r) => (
                    <span className="cx-cellid">
                      <Swatch color={color(r.n.node)} />
                      <span className="mono">{r.n.node}</span>
                    </span>
                  ),
                },
                { id: 'a', label: 'A/s', r: true, sort: (x, y) => x.a - y.a, render: (r) => <span className="mono">{fmtNum(r.a, 2)}</span> },
                { id: 'b', label: 'B/s', r: true, sort: (x, y) => x.b - y.b, render: (r) => <span className="mono">{fmtNum(r.b, 2)}</span> },
                {
                  id: 'e',
                  label: 'Errors/s',
                  r: true,
                  render: (r) =>
                    r.err > 0 ? (
                      <span className="s-err">
                        <Glyph k="err" /> {fmtSi(r.err)}
                      </span>
                    ) : (
                      <span className="muted">0</span>
                    ),
                },
                { id: 'p', label: 'PUT p99', r: true, render: (r) => <span className="mono">{fmtMs(r.put)}</span> },
              ]}
            />
          </Panel>
          <Panel title="Bucket">
            <PanelBody>
              <KV
                rows={[
                  ['Provider', provider],
                  ['Endpoint', endpoint ? <span className="mono sm">{endpoint}</span> : '—'],
                  ['Bucket', <span className="mono">{setting('--s3-bucket') ?? '—'}</span>],
                  ['Prefix', <span className="mono">{setting('--prefix') ?? '(none)'}</span>],
                  ['Region', <span className="mono">{setting('--s3-region') ?? '—'}</span>],
                  ['Log retention', <span className="mono">{setting('--log-retention') ?? '—'}</span>],
                  ['Hedge after', <span className="mono">{setting('--hedge-after-ms') ? `${setting('--hedge-after-ms')} ms` : '—'}</span>],
                ]}
              />
              <p className="muted sm" style={{ margin: '10px 0 0' }}>
                The console never lists the bucket. Never edit or delete objects by hand: <span className="mono">assign/</span> and{' '}
                <span className="mono">nodes/</span> are how nodes agree on ownership.
              </p>
            </PanelBody>
          </Panel>
        </div>
      </div>
    </>
  )
}
