import { useMemo, useState, type ReactNode } from 'react'
import { DataTable, type Col } from '../../components/console/DataTable'
import { Banners, Chip, ErrorState, KV, Loading, NeedsVersion, PageHead, Panel, PanelBody, SearchInput, Seg, Src, Swatch, type BannerSpec, type ChipKind } from '../../components/console/kit'
import { openPanel } from '../../components/console/nav'
import { registerPalette } from '../../components/console/Palette'
import { useClusterView } from '../../lib/console/cluster'
import { ago, plural } from '../../lib/console/fmt'
import { configQ, missing, type NodeConfigResult } from '../../lib/console/sys'
import type { Setting } from '../../lib/adminApi'

// Config: every flag each node runs with, where its value came from, secrets as set or unset
// with a fingerprint, the settings stored in the bucket, and anything that differs between nodes.

/** Flags that differ between nodes on purpose (addresses, the node's own name). */
export const PER_NODE = new Set(['--node-id', '--listen', '--public-url', '--peer-listen', '--advertise-url', '--metrics-listen', '--admin-listen', '--exit-state-file'])

const GROUPS: [string, RegExp][] = [
  ['Storage', /^--(s3-|prefix$|memory$|inject-|cache-dir|disk-cache|block-cache|meta-cache|sst-|compaction|slatedb-|log-compression|log-retention|fence-|max-segment|log-inflight|store-inflight|log-store-inflight|hedge-|checkpoint|full-compaction|reshard|forced-detach|blob-|max-blob)/],
  ['Cluster & capacity', /^--(shards$|workers|io-threads|cache-per-worker|repo-cache|memory-budget|memory-plan|lazy-mst|live-ring|node-id|advertise-url|lease-ttl|peer-|max-queued|max-inflight|forwarded-|retry-unapplied|preload-|exit-state|cache-budget|cache-entries|max-exports|export-stall|import-|max-import)/],
  ['Firehose & relays', /^--(firehose-|backfill-|crawl|asn-lookup)/],
  ['Keys & secrets at rest', /^--(kek|gcp-|vault-|kms-|plc-rotation|wrap-plc|generate-did-key|jwt-secret|admin-token|internal-token|rate-limit-bypass)/],
  ['Mail & moderation', /^--(email-|moderation-|mail-|mod-service|report-service|trusted-device|delete-after|no-rate-limits)/],
  ['Spaces', /^--(spaces$|space-)/],
  ['Identity & listeners', /^--(listen|metrics-listen|admin-|max-connections|public-url|handle-domain|service-did|trusted-proxies|appview|bsky-|plc-|invite-|privacy|terms|contact|lexicon|resolve-lexicons|dev-mode|ui-dir|log-format|pyroscope|allow-bulk)/],
]
export const groupOf = (flag: string) => GROUPS.find(([, re]) => re.test(flag))?.[0] ?? 'Other'
const ORDER = ['Identity & listeners', 'Storage', 'Cluster & capacity', 'Firehose & relays', 'Mail & moderation', 'Spaces', 'Keys & secrets at rest', 'Other']

export const SOURCE_KIND: Record<Setting['source'], ChipKind> = { flag: 'plain', env: 'info', file: 'acc', default: 'idle', unset: 'idle' }
export const sourceChip = (s?: Setting) => (s ? <Chip k={SOURCE_KIND[s.source]} glyph={false}>{s.source}</Chip> : <span className="muted">—</span>)

/** What a node shows for a flag, for comparing nodes: a secret by its fingerprint. */
export const shown = (s?: Setting) => (!s ? '' : s.secret ? (s.source === 'unset' ? 'unset' : (s.fingerprint ?? 'set')) : (s.value ?? ''))

export type FlagRow = {
  flag: string
  group: string
  /** By node id. */
  per: Map<string, Setting | undefined>
  help?: string
  env?: string
  secret: boolean
  differs: boolean
  byDesign: boolean
}

/** One row per flag across every node that answered. */
export function flagRows(results: NodeConfigResult[]): FlagRow[] {
  const ok = results.filter((r) => r.config)
  const flags = new Map<string, FlagRow>()
  for (const r of ok) {
    for (const s of r.config!.settings) {
      let row = flags.get(s.flag)
      if (!row) {
        row = { flag: s.flag, group: groupOf(s.flag), per: new Map(), help: s.help, env: s.env, secret: !!s.secret, differs: false, byDesign: PER_NODE.has(s.flag) }
        flags.set(s.flag, row)
      }
      row.per.set(r.node, s)
    }
  }
  for (const row of flags.values()) {
    const vals = new Set(ok.map((r) => `${row.per.get(r.node)?.source === 'unset' ? 'unset' : 'set'}|${shown(row.per.get(r.node))}`))
    row.differs = vals.size > 1
  }
  return [...flags.values()]
}

registerPalette({
  items: (q) => {
    if (q.length < 2) return []
    const d = configQ.get().data
    if (!d) {
      // loaded on first use, so the next keystroke can list flags
      if (!configQ.get().error) void configQ.prefetch()
      return []
    }
    return flagRows(d)
      .filter((r) => r.flag.includes(q.toLowerCase().replace(/^-*/, '--')) || r.flag.includes(q.toLowerCase()))
      .slice(0, 12)
      .map((r) => {
        const s = [...r.per.values()][0]
        return {
          group: 'Go to',
          title: r.flag,
          desc: r.secret ? (s?.source === 'unset' ? 'secret · unset' : 'secret · set') : `${s?.value ?? 'unset'} · ${s?.source}`,
          hay: `${r.env ?? ''} ${r.help ?? ''}`,
          glyph: '⚙',
          run: () => openPanel('cfg', r.flag),
        }
      })
  },
})

type Filter = 'set' | 'all' | 'differs'

// getConfig's peerTls (the node's certificate) and secretFiles (when each `-file` secret last
// changed); an older vlpds answers without them and the Builds panel says so.
export function certExpiry(c?: NodeConfigResult['config']): number | undefined {
  return c?.peerTls?.notAfter ?? undefined
}
/** When the file behind a secret flag (`--x` read from `--x-file`) last changed. */
export function secretSetAt(c: NodeConfigResult['config'] | undefined, flag: string): number | undefined {
  return c?.secretFiles?.find((f) => f.flag === `${flag}-file`)?.modifiedAt ?? undefined
}

export function Config() {
  const cfg = configQ.use()
  const { view } = useClusterView()
  const [node, setNode] = useState<string>()
  const [filter, setFilter] = useState<Filter>('set')
  const [q, setQ] = useState('')
  const results = cfg.data
  const rows = useMemo(() => (results ? flagRows(results) : []), [results])
  if (!results) return cfg.error ? <ErrorState error={cfg.error} retry={configQ.refresh} /> : <Loading label="Asking every node…" />
  const okNodes = results.filter((r) => r.config)
  if (!okNodes.length && results.some((r) => missing(r.error)))
    return (
      <>
        <PageHead title="Config" />
        <Panel>
          <NeedsVersion what="Effective config" nsid="vlpds.admin.getConfig" />
        </Panel>
      </>
    )
  const cur = okNodes.find((r) => r.node === node) ?? okNodes.find((r) => r.self) ?? okNodes[0]
  const color = (n: string) => view?.nodes.find((x) => x.node === n)?.color
  const failed = results.filter((r) => !r.config)
  const differ = rows.filter((r) => r.differs && !r.byDesign)
  const revs = new Set(okNodes.map((r) => r.config!.rev))
  const multi = okNodes.length > 1
  const hasCert = okNodes.some((r) => certExpiry(r.config) !== undefined)
  const hasAge = rows.some((r) => r.secret && okNodes.some((n) => secretSetAt(n.config, r.flag) !== undefined))
  const olderBuild = okNodes.some((r) => r.config!.peerTls === undefined || r.config!.secretFiles === undefined)
  const soon = okNodes.filter((r) => {
    const e = certExpiry(r.config)
    return e !== undefined && e - Date.now() < 14 * 86400_000
  })

  const banners: BannerSpec[] = []
  if (failed.length) banners.push({ id: 'fail', tone: 'warn', title: `${failed.map((f) => f.node).join(', ')} didn't answer getConfig`, desc: 'Differences below leave those nodes out.' })
  if (revs.size > 1)
    banners.push({ id: 'revs', tone: 'warn', title: 'Mixed builds', desc: okNodes.map((r) => `${r.node} ${r.config!.rev.slice(0, 12)}`).join(' · ') })
  if (multi)
    banners.push(
      differ.length
        ? {
            id: 'diff',
            tone: 'warn',
            title: `${plural(differ.length, 'setting')} differ between nodes`,
            desc: differ
              .slice(0, 6)
              .map((r) => r.flag)
              .join(', ') + (differ.length > 6 ? ' …' : ''),
            right: (
              <button type="button" className="cx-btn sm" onClick={() => setFilter('differs')}>
                Show them
              </button>
            ),
          }
        : { id: 'agree', tone: 'info', title: `All ${okNodes.length} nodes agree`, desc: 'apart from their addresses and --node-id. Secrets show whether they’re set and a fingerprint, never their value.' },
    )
  if (soon.length) banners.push({ id: 'cert', tone: 'err', title: `Peer certificate expires within 14 days on ${soon.map((r) => r.node).join(', ')}`, desc: 'Nodes stop talking to each other when it lapses. Reissue it from the cluster CA.' })
  if (cur && !cur.config!.recorded) banners.push({ id: 'norec', tone: 'info', title: `${cur.node} recorded no command line`, desc: 'A test or embedded node: its flags aren’t known.' })

  const ql = q.trim().toLowerCase()
  const want = (r: FlagRow) => {
    const s = r.per.get(cur?.node ?? '')
    if (filter === 'set' && !(s && (s.source === 'flag' || s.source === 'env' || s.source === 'file')) && !r.differs) return false
    if (filter === 'differs' && !(r.differs && !r.byDesign)) return false
    if (ql && !r.flag.includes(ql) && !(r.env ?? '').toLowerCase().includes(ql) && !(r.help ?? '').toLowerCase().includes(ql) && !(s?.value ?? '').toLowerCase().includes(ql)) return false
    return true
  }
  const plain = rows.filter((r) => !r.secret && want(r))
  const secrets = rows.filter((r) => r.secret && (filter !== 'differs' || r.differs) && (!ql || r.flag.includes(ql) || (r.env ?? '').toLowerCase().includes(ql)))
  const groups = ORDER.map((g) => [g, plain.filter((r) => r.group === g)] as const).filter(([, xs]) => xs.length)
  const half = Math.ceil(groups.reduce((t, [, xs]) => t + xs.length, 0) / 2)
  const left: (typeof groups)[number][] = []
  const right: (typeof groups)[number][] = []
  let n = 0
  for (const g of groups) {
    ;(n < half ? left : right).push(g)
    n += g[1].length
  }
  const nSet = rows.filter((r) => {
    const s = r.per.get(cur?.node ?? '')
    return s && (s.source === 'flag' || s.source === 'env' || s.source === 'file')
  }).length

  const valueCol = (r: FlagRow): ReactNode => {
    const s = r.per.get(cur?.node ?? '')
    if (!s || s.source === 'unset') return <span className="muted">unset</span>
    return <span className="mono sm" style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{s.value ?? ''}</span>
  }
  const cols: Col<FlagRow>[] = [
    { id: 'f', label: 'Flag', style: { width: '38%' }, render: (r) => <span className="mono sm">{r.flag}</span> },
    { id: 'v', label: 'Value', className: 'wrap', render: valueCol },
    {
      id: 's',
      label: 'Source',
      r: true,
      render: (r) => (
        <span className="cx-cellid end">
          {r.differs && !r.byDesign && <Chip k="warn">differs</Chip>}
          {r.differs && r.byDesign && <Chip k="plain" glyph={false}>per node</Chip>}
          {sourceChip(r.per.get(cur?.node ?? ''))}
        </span>
      ),
    },
  ]

  const panel = ([g, xs]: (typeof groups)[number]) => (
    <Panel key={g} title={g} right={<span className="muted sm">{xs.length}</span>}>
      <DataTable compact rows={xs} cols={cols} rowKey={(r) => r.flag} open={(r) => ({ type: 'cfg', id: r.flag })} dim={(r) => r.per.get(cur?.node ?? '')?.source === 'unset'} />
    </Panel>
  )
  const st = cur?.config?.stored

  return (
    <>
      <PageHead
        title="Effective config"
        sub={
          <>
            <span>
              what <span className="mono">{cur?.node}</span> runs with
            </span>
            {cur?.config && <span className="mono">{cur.config.version}</span>}
            <span>flags, env, defaults and settings stored in the bucket</span>
          </>
        }
        updated={cfg.at}
        actions={
          multi && (
            <Seg
              label="Node"
              value={cur?.node ?? ''}
              onChange={setNode}
              options={okNodes.map((r) => ({
                v: r.node,
                label: (
                  <>
                    <Swatch color={color(r.node)} /> {r.node}
                  </>
                ),
              }))}
            />
          )
        }
      />
      <Banners items={banners} />
      <div className="cx-toolbar" style={{ border: 0, padding: '0 0 12px' }}>
        <SearchInput value={q} onChange={setQ} placeholder="filter flags, env vars, values, help" mono style={{ flex: '1 1 240px', maxWidth: 420 }} />
        <Seg
          label="Show"
          value={filter}
          onChange={setFilter}
          options={[
            { v: 'set', label: 'Set here', n: nSet },
            { v: 'all', label: 'All', n: rows.length },
            ...(multi ? [{ v: 'differs' as Filter, label: 'Differs', n: differ.length }] : []),
          ]}
        />
        <Src>vlpds.admin.getConfig · every node</Src>
      </div>
      <div className="cx-grid2">
        <div className="cx-stack">
          {left.map(panel)}
          {!groups.length && (
            <Panel>
              <div className="cx-empty">Nothing matches.</div>
            </Panel>
          )}
        </div>
        <div className="cx-stack">
          <Panel title="Secrets" right={<span className="muted sm">set or unset · fingerprint of the value in use</span>}>
            <DataTable
              compact
              rows={secrets}
              rowKey={(r) => r.flag}
              open={(r) => ({ type: 'cfg', id: r.flag })}
              empty={<div className="cx-empty">No secrets match.</div>}
              cols={[
                { id: 'f', label: 'Flag', render: (r) => <span className="mono sm">{r.flag}</span> },
                {
                  id: 's',
                  label: 'State',
                  render: (r) => {
                    const s = r.per.get(cur?.node ?? '')
                    return s && s.source !== 'unset' ? <Chip k="ok">set · {s.source}</Chip> : <Chip k="idle">unset</Chip>
                  },
                },
                { id: 'fp', label: 'Fingerprint', render: (r) => <span className="mono sm t2">{r.per.get(cur?.node ?? '')?.fingerprint ?? ''}</span> },
                ...(hasAge
                  ? [
                      {
                        id: 'age',
                        label: 'File changed',
                        r: true,
                        render: (r: FlagRow) => {
                          const at = secretSetAt(cur?.config, r.flag)
                          return at ? <span className="t2 sm">{ago(at)}</span> : null
                        },
                      },
                    ]
                  : []),
                { id: 'd', label: '', r: true, render: (r) => (r.differs ? <Chip k="warn">differs</Chip> : null) },
              ]}
            />
          </Panel>
          {st && (
            <Panel title="Stored in the bucket" src={<Src>getConfig · stored</Src>} foot="Changed from this console, not by flags: every node reads the same copy.">
              <PanelBody>
                <KV
                  rows={[
                    ['Handle domains', st.handleDomains.length ? st.handleDomains.map((d) => <div key={d.domain} className="mono sm">.{d.domain}{d.added_at ? <span className="muted"> · added {ago(Date.parse(d.added_at))}{d.added_by ? ` by ${d.added_by}` : ''}</span> : <span className="muted"> · primary</span>}</div>) : '—'],
                    ['Rate limits', st.rateLimitsVersion ? <>config version {st.rateLimitsVersion}</> : 'built-in defaults'],
                    ['Shard layout', st.shardLayout ? `${st.shardLayout.shards} shards · layout v${st.shardLayout.version}` : 'single node'],
                    ['Feature level', st.featureLevel ?? '—'],
                  ]}
                />
              </PanelBody>
            </Panel>
          )}
          <Panel
            title="Builds"
            foot={olderBuild ? <span>Peer certificate expiry and secret file ages need a newer vlpds (getConfig adds them).</span> : undefined}
          >
            <DataTable
              compact
              rows={results}
              rowKey={(r) => r.node}
              cols={[
                {
                  id: 'n',
                  label: 'Node',
                  render: (r) => (
                    <span className="cx-cellid">
                      <Swatch color={color(r.node)} />
                      <span className="mono">{r.node}</span>
                      {r.self && <Chip k="acc">this node</Chip>}
                    </span>
                  ),
                },
                { id: 'v', label: 'Version', render: (r) => (r.config ? <span className="mono sm">{r.config.version}</span> : <Chip k="err">no answer</Chip>) },
                { id: 'r', label: 'Rev', render: (r) => <span className="mono sm t2">{r.config?.rev.slice(0, 12) ?? '—'}</span> },
                ...(hasCert
                  ? [
                      {
                        id: 'cert',
                        label: 'Peer cert',
                        r: true,
                        render: (r: NodeConfigResult) => {
                          const exp = certExpiry(r.config)
                          if (!exp) return <span className="muted">—</span>
                          const days = (exp - Date.now()) / 86400_000
                          return <Chip k={days < 14 ? 'err' : days < 45 ? 'warn' : 'ok'}>{days < 0 ? 'expired' : `expires in ${Math.floor(days)}d`}</Chip>
                        },
                      },
                    ]
                  : []),
              ]}
            />
          </Panel>
          {right.map(panel)}
        </div>
      </div>
    </>
  )
}
