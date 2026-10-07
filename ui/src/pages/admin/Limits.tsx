import { useMemo, useState, type ReactNode } from 'react'
import { DataTable, type Col } from '../../components/console/DataTable'
import { detailKind } from '../../components/console/Drawer'
import { Banners, Chip, Empty, ErrorState, Glyph, Loading, Mini, Minis, NeedsVersion, PageHead, Panel, PanelBody, Sec, SearchInput, Spark, Src, Tiles, Toggle, type BannerSpec } from '../../components/console/kit'
import { useClusterView } from '../../lib/console/cluster'
import { ago, fmtNum, fmtSi, plural } from '../../lib/console/fmt'
import {
  FACTOR_LABEL,
  KEY_LABEL,
  KEY_SHORT,
  busiest,
  fmtWindow,
  held,
  rate429Poll,
  rejectionHistory,
  rlPoll,
  shortName,
  totalRate,
  type Consumer,
  type Loaded,
  type OverrideCfg,
} from '../../lib/console/ratelimits'
import type { Lockout } from '../../lib/adminApi'
import { lockoutsPoll } from '../../lib/console/polls'
import { addOverrideDialog, addRouteDialog, bucketRows, clearLock, KeyId, KeyUse, KeyWho, overrideFor, toggleEnforcement, type BucketRow } from './limitsUi'
import { AccountLink, openAccount } from './peopleUi'

// Limits & lockouts: who is locked out now, the cluster's 429s, every bucket with its busiest
// key, overrides and the config's change history. Edits go through limitsUi's diff dialog.

export function Limits() {
  const s = rlPoll.use()
  const d = s.data
  if (!d) return s.error ? <ErrorState error={s.error} retry={rlPoll.refresh} /> : <Loading label="Asking every node…" />
  return <Page d={d} stale={!!s.error} />
}

function Page({ d, stale }: { d: Loaded; stale: boolean }) {
  const locks = lockoutsPoll.use()
  const rate = rate429Poll.use()
  const { view } = useClusterView()
  const rows = useMemo(() => bucketRows(d), [d])
  const hist = rejectionHistory()

  const reachable = d.nodes.filter((n) => n.reachable)
  const onVersion = reachable.filter((n) => n.configVersion === d.configVersion).length
  const versions = [...new Set(reachable.map((n) => n.configVersion))]
  const last1m = d.rejections.reduce((a, r) => a + r.last1m, 0)
  const last15m = d.rejections.reduce((a, r) => a + r.last15m, 0)
  const overrides = d.config?.overrides ?? []
  const factorLocks = locks.data?.supported ? locks.data.data : []
  const heldKeys = rows.flatMap((b) => b.top.filter(held).map((c) => ({ b, c })))
  const total = rate.data?.supported ? totalRate(rate.data) : hist.total
  const enabled = d.config?.enabled ?? true

  const banners: BannerSpec[] = []
  if (stale) banners.push({ id: 'stale', tone: 'warn', title: 'Not updating', desc: 'getRateLimits is failing; showing the last answer.' })
  for (const n of d.nodes.filter((n) => n.configError))
    banners.push({
      id: `err-${n.node}`,
      tone: 'err',
      title: `${n.node} rejected config${n.configError!.version != null ? ` v${n.configError!.version}` : ''}`,
      desc: `${ago(n.configError!.atMs)}; it keeps running v${n.configVersion}`,
      body: <span className="mono sm">{n.configError!.message}</span>,
      open: true,
    })
  if (versions.length > 1)
    banners.push({ id: 'versions', tone: 'warn', title: 'Nodes disagree on the config version', desc: `${reachable.map((n) => `${n.node} v${n.configVersion}`).join(' · ')} · they re-read every ${d.refreshSecs} s` })
  const flagOff = reachable.filter((n) => n.enabledByFlag === false)
  if (flagOff.length) banners.push({ id: 'flag', tone: 'warn', title: `${flagOff.map((n) => n.node).join(', ')} ${flagOff.length === 1 ? 'runs' : 'run'} with --no-rate-limits`, desc: 'the config is kept there but nothing is counted or limited' })
  if (!enabled) banners.push({ id: 'off', tone: 'warn', title: 'Rate limiting is off', desc: 'nothing is counted or limited on any node', right: <button type="button" className="cx-btn sm" onClick={() => toggleEnforcement(true)}>Turn on…</button> })
  if (d.unreachableNodes?.length) banners.push({ id: 'unreach', tone: 'warn', title: `${plural(d.unreachableNodes.length, 'node')} didn’t answer`, desc: `${d.unreachableNodes.join(', ')}: their keys and 429s are missing` })

  const ipOv = overrides.filter((o) => o.ip).length
  const top3 = [...rows].filter((b) => b.m15).sort((a, b) => b.m1 - a.m1 || b.m15 - a.m15).slice(0, 3)

  return (
    <>
      <PageHead
        title="Rate limits & lockouts"
        sub={
          <>
            <span>{d.configVersion ? <>config v{d.configVersion} in <span className="mono">config/ratelimits.json</span></> : 'built-in defaults (no config saved yet)'}</span>
            <span>
              applied on {onVersion}/{d.nodes.length} nodes · re-read every {d.refreshSecs} s
            </span>
          </>
        }
        actions={
          <span className="cx-cellid sm t2">
            Rate limiting <Toggle on={enabled} label={enabled ? 'Turn rate limiting off' : 'Turn rate limiting on'} onChange={(on) => toggleEnforcement(on)} />
          </span>
        }
      />
      <Banners items={banners} />
      <Tiles
        boxed
        tiles={[
          { label: '429s, last minute', right: 'cluster-wide', value: fmtNum(last1m), spark: <Spark data={total} color="warn" min={0.05} /> },
          { label: '429s, last 15 minutes', value: fmtNum(last15m) },
          { label: 'Locked out', right: 'accounts', value: locks.data?.supported ? factorLocks.length : '—', sec: heldKeys.length ? `+${plural(heldKeys.length, 'key')} held` : undefined },
          { label: 'Overrides', right: overrides.length ? `${ipOv} IP · ${overrides.length - ipOv} DID` : undefined, value: overrides.length },
        ]}
      />
      <div className="cx-grid2 cx-mb">
        <LockedOut d={d} factorLocks={factorLocks} supported={locks.data ? locks.data.supported : true} heldKeys={heldKeys} />
        <Panel
          title="429s per second"
          src={<Src>{rate.data?.supported ? 'getNodeMetrics' : 'getRateLimits · totals'}</Src>}
          right={<span className="muted sm">cluster-wide</span>}
        >
          <PanelBody>
            <Spark data={total} color="warn" size="big" min={0.05} title="429s per second, cluster-wide" />
            <div className="cx-legend" style={{ marginTop: 8 }}>
              <span>
                <i style={{ background: 'var(--warn)' }} />
                all buckets, now {fmtSi(total[total.length - 1] ?? 0)}/s
              </span>
              <span className="muted">{top3.length ? `top: ${top3.map((b) => shortName(b.name)).join(', ')}` : 'no 429s in the last 15 minutes'}</span>
            </div>
          </PanelBody>
          {rate.data?.supported && rate.data.nodes.length > 1 && (
            <Minis n={Math.min(3, rate.data.nodes.length)}>
              {rate.data.nodes.map((n) => {
                const c = view?.nodes.find((x) => x.node === n.node)?.color?.match(/--(c\d)/)?.[1] ?? 'warn'
                return (
                  <Mini key={n.node} label={<span className="mono">{n.node}</span>} value={`${fmtSi(n.points[n.points.length - 1]?.v ?? 0)}/s`}>
                    <Spark data={n.points.map((p) => p.v)} color={c} min={0.05} />
                  </Mini>
                )
              })}
            </Minis>
          )}
          {rate.data && !rate.data.supported && (
            <PanelBody>
              <span className="muted sm">From the change in each bucket’s 429 total between polls (this server has no getNodeMetrics).</span>
            </PanelBody>
          )}
        </Panel>
      </div>
      <Buckets rows={rows} />
      <div className="cx-grid2 cx-mt">
        <Overrides overrides={overrides} />
        <div className="cx-stack">
          <History d={d} />
          <Nodes d={d} />
        </div>
      </div>
    </>
  )
}

// ---------------------------------------------------------------- locked out now

type LockRow = { id: string; factor?: Lockout; key?: { b: BucketRow; c: Consumer } }

function LockedOut({ d, factorLocks, supported, heldKeys }: { d: Loaded; factorLocks: Lockout[]; supported: boolean; heldKeys: { b: BucketRow; c: Consumer }[] }) {
  const rows: LockRow[] = [...factorLocks.map((l) => ({ id: `f:${l.did}:${l.factor}`, factor: l })), ...heldKeys.map((k) => ({ id: `k:${k.b.name}:${k.c.key}`, key: k }))]
  const account = !!detailKind('account')
  const cols: Col<LockRow>[] = [
    {
      id: 'who',
      label: 'Who',
      className: 'trunc',
      style: { maxWidth: 150 },
      render: (r) => (r.factor ? <AccountLink did={r.factor.did} handle={r.factor.handle} /> : <KeyWho kind={r.key!.b.key} k={r.key!.c.key} w={150} />),
    },
    { id: 'by', label: 'Held by', className: 'trunc', style: { maxWidth: 130 }, render: (r) => (r.factor ? <span className="t2">{FACTOR_LABEL[r.factor.factor] ?? r.factor.factor}</span> : <span className="mono sm">{shortName(r.key!.b.name)}</span>) },
    { id: 'used', label: 'Used', r: true, render: (r) => (r.factor ? <span className="mono sm">{plural(r.factor.failures, 'wrong code')}</span> : <KeyUse c={r.key!.c} />) },
    { id: 'clears', label: 'Clears', r: true, render: (r) => ago(r.factor ? r.factor.lockedUntil : r.key!.c.resetMs) },
    {
      id: 'act',
      label: '',
      r: true,
      render: (r) => {
        if (r.factor)
          return (
            <button type="button" className="cx-btn sm" onClick={() => clearLock(r.factor!.did, r.factor!.handle, r.factor!.factor)}>
              Clear…
            </button>
          )
        const ov = overrideFor(r.key!.b, r.key!.c.key)
        return ov ? (
          <button type="button" className="cx-btn sm" onClick={() => addOverrideDialog({ ...ov, note: `lifted ${new Date().toISOString().slice(0, 10)}` })}>
            Exempt…
          </button>
        ) : (
          <span className="muted sm">{KEY_SHORT[r.key!.b.key]}</span>
        )
      },
    },
  ]
  return (
    <Panel
      title="Locked out now"
      src={
        <>
          <Src>listLockouts</Src> <Src>getRateLimits · topKeys</Src>
        </>
      }
      right={rows.length ? <Chip k="warn">{rows.length}</Chip> : undefined}
      foot="Live sessions keep working while sign-in is held. A held key clears when its window ends; an override lifts it sooner."
    >
      {!supported && <NeedsVersion what="Factor lockouts" nsid="vlpds.admin.listLockouts" />}
      <DataTable
        rows={rows}
        cols={cols}
        rowKey={(r) => r.id}
        label="Locked out now"
        open={(r) => (r.key ? { type: 'bucket', id: r.key.b.name } : account ? { type: 'account', id: r.factor!.did } : undefined)}
        onRow={(r) => r.factor && openAccount(r.factor.did)}
        empty={<Empty>Nobody is locked out, and no key is at its limit.</Empty>}
      />
      {d.unreachableNodes?.length ? <div className="cx-pn-b muted sm">Keys counted on {d.unreachableNodes.join(', ')} are missing.</div> : null}
    </Panel>
  )
}

// ---------------------------------------------------------------- buckets

function Buckets({ rows }: { rows: BucketRow[] }) {
  const [q, setQ] = useState('')
  const [all, setAll] = useState(false)
  const hist = rejectionHistory()
  const f = q.trim().toLowerCase()
  const busy = (b: BucketRow) => b.top.length > 0 || b.m15 > 0 || b.changed || !!b.route || !b.enabled
  const shown = rows
    .filter((b) => (f ? b.name.toLowerCase().includes(f) || b.scope.toLowerCase().includes(f) : all || busy(b)))
    .sort((a, b) => b.m1 - a.m1 || b.m15 - a.m15 || frac(b) - frac(a) || Number(!!b.route) - Number(!!a.route) || Number(b.changed) - Number(a.changed) || a.name.localeCompare(b.name))
  const cols: Col<BucketRow>[] = [
    {
      id: 'name',
      label: 'Bucket',
      sort: (a, b) => b.name.localeCompare(a.name),
      render: (b) => (
        <span className="cx-cellid">
          <b className="mono" title={`${b.name}\n${b.scope}`}>
            {shortName(b.name)}
          </b>
          {b.route && <Chip k="plain" glyph={false}>added</Chip>}
          {b.changed && <Chip k="info">changed</Chip>}
        </span>
      ),
    },
    { id: 'key', label: 'Keyed by', style: { width: '100%' }, render: (b) => <span className="t2" title={KEY_LABEL[b.key]}>{KEY_SHORT[b.key]}</span> },
    { id: 'limit', label: 'Limit', r: true, sort: (a, b) => a.points - b.points, render: (b) => <span className="mono">{fmtNum(b.points)}</span> },
    { id: 'win', label: 'Window', className: 'cxp-win', sort: (a, b) => a.windowSecs - b.windowSecs, render: (b) => <span className="t2">{fmtWindow(b.windowSecs)}</span> },
    {
      id: 'busy',
      label: 'Busiest key',
      render: (b) => {
        const c = busiest(b.top)
        return c ? <KeyId k={c.key} w={190} /> : <span className="muted">—</span>
      },
    },
    {
      id: 'used',
      label: 'Used',
      r: true,
      title: 'What the busiest node counted for that key in its current window',
      sort: (a, b) => frac(a) - frac(b),
      render: (b) => {
        const c = busiest(b.top)
        return c ? <KeyUse c={c} of={b.points} /> : <span className="muted">—</span>
      },
    },
    {
      id: 'keys',
      label: 'Keys',
      r: true,
      title: 'Keys counted in their current window (the ten busiest are listed)',
      render: (b) => <span className={`mono${b.top.length ? '' : ' muted'}`}>{b.top.length >= TOP ? `${TOP}+` : b.top.length || '—'}</span>,
    },
    { id: 'm1', label: '429s 1m', r: true, sort: (a, b) => a.m1 - b.m1, render: (b) => <span className={`mono ${b.m1 ? 's-warn' : 'muted'}`}>{fmtNum(b.m1)}</span> },
    { id: 'm15', label: '15m', r: true, sort: (a, b) => a.m15 - b.m15, render: (b) => <span className={`mono ${b.m15 ? '' : 'muted'}`}>{fmtNum(b.m15)}</span> },
    {
      id: 'spark',
      label: '429/s',
      r: true,
      title: 'Since this console opened',
      render: (b) => {
        const h = hist.byBucket.get(b.name) ?? []
        return h.some((v) => v > 0) ? <Spark data={h} color={b.m1 ? 'warn' : 'ink3'} size="inline" min={0.05} /> : <span className="muted" title="No 429s since this console opened">—</span>
      },
    },
    { id: 'on', label: 'On', render: (b) => (b.enabled ? <Glyph k="ok" title="on" /> : <Glyph k="idle" title="off" />) },
  ]
  return (
    <Panel
      title="Buckets"
      src={<Src>getRateLimits · updateRateLimits</Src>}
      right={
        <>
          <SearchInput value={q} onChange={setQ} placeholder="Filter buckets" style={{ height: 26, width: 200, maxWidth: '100%' }} />
          <button type="button" className="cx-btn sm" onClick={addRouteDialog}>
            Add method bucket…
          </button>
        </>
      }
      foot={
        <>
          <span>
            {shown.length} of {rows.length} buckets{f ? '' : all ? ', busiest first' : ': the ones counting something and the ones changed'}. Each node counts on its own except cluster buckets.
          </span>
          {!f && (
            <button type="button" className="cx-linklike" style={{ marginLeft: 'auto' }} onClick={() => setAll((v) => !v)}>
              {all ? 'Show the busy ones' : `Show all ${rows.length}`}
            </button>
          )}
        </>
      }
    >
      <DataTable compact rows={shown} cols={cols} rowKey={(b) => b.name} open={(b) => ({ type: 'bucket', id: b.name })} dim={(b) => !b.enabled} label="Buckets" empty={<Empty>{f ? `No bucket matches “${q}”.` : 'No bucket is counting anything right now.'}</Empty>} />
    </Panel>
  )
}

/** getRateLimits' `top`: keys listed per bucket. */
const TOP = 10

const frac = (b: BucketRow) => {
  const c = busiest(b.top)
  return c?.limit ? c.maxNodeUsed / c.limit : 0
}

// ---------------------------------------------------------------- overrides, history, nodes

function Overrides({ overrides }: { overrides: OverrideCfg[] }) {
  const rows = overrides.map((o, i) => ({ o, i }))
  return (
    <Panel
      title="Overrides"
      src={<Src>config/ratelimits.json · overrides</Src>}
      right={
        <button type="button" className="cx-btn sm" onClick={() => addOverrideDialog()}>
          Add override…
        </button>
      }
    >
      <DataTable
        compact
        rows={rows}
        rowKey={(r) => String(r.i)}
        open={(r) => ({ type: 'override', id: String(r.i) })}
        label="Overrides"
        empty={<Empty>No overrides: every client gets the bucket limits.</Empty>}
        cols={[
          { id: 'kind', label: 'Match', render: ({ o }) => <span className="t2">{o.ip ? 'IP' : 'DID'}</span> },
          { id: 'match', label: <span className="sr">Value</span>, render: ({ o }) => <KeyId k={(o.ip ?? o.did)!} w={200} /> },
          {
            id: 'b',
            label: 'Buckets',
            render: ({ o }) => {
              const t = o.limiters?.length ? o.limiters.map(shortName).join(', ') : 'all'
              return (
                <span className="sm t2 mono trunc cxp-fixed" style={{ width: 170 }} title={t}>
                  {t}
                </span>
              )
            },
          },
          { id: 'a', label: 'Limit', r: true, render: ({ o }) => (o.exempt ? <Chip k="info">exempt</Chip> : <span className="mono">{fmtNum(o.points)}</span>) },
          { id: 'n', label: 'Note', style: { width: '100%' }, render: ({ o }) => <span className="t2 sm">{o.note ?? ''}</span> },
        ]}
      />
    </Panel>
  )
}

function History({ d }: { d: Loaded }) {
  const h = [...(d.config?.history ?? [])].reverse()
  const latest = h[0]
  return (
    <Sec title="Change history" digest={latest ? `v${latest.version} by ${latest.by}, ${ago(Date.parse(latest.at))}` : 'no changes: built-in defaults'} open flush>
      {h.length ? (
        <div className="cx-tw" style={{ maxHeight: 360 }}>
          <table className="cx-t compact">
            <tbody>
              {h.map((a) => (
                <tr key={a.version}>
                  <td className="mono" style={{ verticalAlign: 'top' }}>
                    v{a.version}
                  </td>
                  <td style={{ verticalAlign: 'top' }} title={a.at}>
                    {ago(Date.parse(a.at))}
                  </td>
                  <td style={{ verticalAlign: 'top' }}>
                    {a.by}
                    <div className="muted mono sm">{a.node}</div>
                  </td>
                  <td className="wrap t2">
                    {a.changes.map((x, i) => (
                      <div key={i} className="mono sm">
                        {x}
                      </div>
                    ))}
                    {a.note && <div className="sm">“{a.note}”</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="cx-empty">No changes yet. The built-in defaults are in force.</div>
      )}
    </Sec>
  )
}

function Nodes({ d }: { d: Loaded }) {
  return (
    <Sec title="Nodes" digest={`each re-reads the config every ${d.refreshSecs} s`} flush>
      <div className="cx-tw">
        <table className="cx-t compact">
          <thead>
            <tr>
              <th>Node</th>
              <th>Config</th>
              <th className="r">Applied</th>
              <th className="r">Checked</th>
              <th className="r">Windows</th>
            </tr>
          </thead>
          <tbody>
            {d.nodes.map((n) => {
              let c: ReactNode
              if (!n.reachable) c = <Chip k="err">unreachable</Chip>
              else if (n.configError) c = <Chip k="err">v{n.configVersion}, rejected newer</Chip>
              else c = <Chip k={n.configVersion === d.configVersion ? 'ok' : 'warn'}>v{n.configVersion}</Chip>
              return (
                <tr key={n.node}>
                  <td className="mono">
                    {n.node}
                    {n.self && <span className="muted"> · this</span>}
                  </td>
                  <td>
                    {c}
                    {n.enabledByFlag === false && <Chip k="warn">--no-rate-limits</Chip>}
                  </td>
                  <td className="r muted">{n.loadedAtMs ? ago(n.loadedAtMs) : '—'}</td>
                  <td className="r muted">{n.checkedAtMs ? ago(n.checkedAtMs) : '—'}</td>
                  <td className="r">{fmtNum(n.liveWindows)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Sec>
  )
}
