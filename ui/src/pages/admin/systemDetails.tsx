import { confirmAction } from '../../components/console/dialogs'
import { registerDetail } from '../../components/console/Drawer'
import { Chip, Copy, KV, Mini, Minis, Sec, Spark, Src, Strip, Swatch } from '../../components/console/kit'
import { closePanel } from '../../components/console/nav'
import { useClusterView } from '../../lib/console/cluster'
import { ago, clock, fmtMs, fmtNum } from '../../lib/console/fmt'
import { configPoll, crawlersPoll, mailPoll, setCrawlers, sumSeries, useNodeMetrics } from '../../lib/console/sys'
import { flagRows, groupOf, PER_NODE, shown, sourceChip } from './Config'
import { crawlNow, RelayResult } from './Firehose'
import { MailChip, mailId } from './Mail'
import { COMPONENTS, componentName, componentRows } from './Storage'

// Slide-over / full-page details for the system sections: relay, mail, setting, object-store
// component. Spaces registers its own kind in Spaces.tsx. Registered on import (AdminApp).

const SOURCE_TEXT: Record<string, string> = {
  flag: 'the command line',
  env: 'its VLPDS_ environment variable',
  file: 'its -file flag (a file holding the secret)',
  default: 'the built-in default',
  unset: 'not set, and it has no default',
}

registerDetail('relay', {
  kind: 'Relay',
  section: 'firehose',
  use: (id) => {
    const cr = crawlersPoll.use()
    const r = cr.data?.relays.find((x) => x.relay === id)
    if (!cr.data) return { title: id, body: null, loading: true }
    if (!r) return { title: <span className="mono">{id}</span>, body: null, missing: 'This relay is no longer on the list.' }
    const s = r.status
    const list = cr.data.relays.map((x) => x.relay)
    return {
      title: <span className="mono">{r.relay}</span>,
      chip: <RelayResult r={r} />,
      foot: <Src>getCrawlers · requestCrawl · setCrawlers</Src>,
      body: (
        <>
          <Strip items={[['asked', s ? ago(s.lastAttemptMs) : '—'], ['accepted', s?.lastSuccessMs ? ago(s.lastSuccessMs) : '—'], ['by', s?.node.replace(/^vlpds-/, '') ?? '—']]} />
          <Sec title="Last crawl request" digest={s ? (s.ok ? 'accepted' : 'refused') : 'not asked yet'} open>
            <KV
              rows={[
                ['URL', <span className="mono sm" style={{ overflowWrap: 'anywhere' }}>{r.url.replace(/\/$/, '')}/xrpc/com.atproto.sync.requestCrawl</span>],
                ['Hostname sent', <span className="mono">{cr.data.hostname}</span>],
                ['Result', s ? (s.ok ? `${s.httpStatus ?? ''} accepted` : `${s.httpStatus ?? 'no answer'} ${s.error ?? ''}`) : '—'],
                ['Asked by', s ? <span className="mono">{s.node}</span> : '—'],
                ['Last accepted', s?.lastSuccessMs ? ago(s.lastSuccessMs) : '—'],
                ['Interval', `at most once every ${cr.data.intervalSecs % 60 ? `${cr.data.intervalSecs} s` : `${cr.data.intervalSecs / 60} min`} after new activity`],
              ]}
            />
          </Sec>
          <Sec title="Actions" open flush>
            <div className="cx-acts">
              <div className="cx-act">
                <div className="ad">
                  <b>Crawl now</b>Sends requestCrawl at once, whatever the interval.
                </div>
                <button type="button" className="cx-btn sm" onClick={() => crawlNow([r.relay])}>
                  Crawl now
                </button>
              </div>
              <div className="cx-act">
                <div className="ad">
                  <b>Remove</b>Stops telling this relay about the PDS. It keeps what it has crawled.
                </div>
                <button
                  type="button"
                  className="cx-btn sm danger"
                  onClick={() =>
                    confirmAction({
                      tone: 'warn',
                      title: `Remove ${r.relay}?`,
                      items: ['No more crawl requests go to it.', cr.data!.relaysSource === 'flags' ? 'The list gets stored in the bucket and overrides --crawlers from now on.' : 'The stored list is updated for every node.'],
                      action: 'Remove',
                      call: `vlpds.admin.setCrawlers {"relays": [${list.filter((x) => x !== r.relay).map((x) => `"${x}"`).join(', ')}]}`,
                      run: async () => {
                        await setCrawlers({ relays: list.filter((x) => x !== r.relay) })
                        crawlersPoll.refresh()
                        closePanel()
                      },
                      done: `Removed ${r.relay}`,
                    })
                  }
                >
                  Remove…
                </button>
              </div>
            </div>
          </Sec>
        </>
      ),
    }
  },
})

registerDetail('mail', {
  kind: 'Mail',
  section: 'mail',
  use: (id) => {
    const ml = mailPoll.use()
    const { view } = useClusterView()
    const m = ml.data?.mail.find((x) => mailId(x) === id)
    if (!ml.data) return { title: id, body: null, loading: true }
    if (!m) return { title: <span className="mono">{id}</span>, body: null, missing: 'This mail has dropped out of the log (each node keeps its last 200).' }
    const color = view?.nodes.find((n) => n.node === m.node)?.color
    return {
      title: <span className="mono">{m.purpose}</span>,
      chip: <MailChip m={m} />,
      foot: <Src>vlpds.admin.listMail</Src>,
      body: (
        <>
          <Strip items={[['attempts', `${m.attempts} of 3`], ['queued', ago(m.at)], ['send', fmtMs(m.sendMs)]]} />
          <Sec title="Delivery" digest={m.status} open>
            <KV
              rows={[
                ['To', <>…@{m.toDomain} <span className="muted">(only the domain is kept)</span></>],
                ['Queued', <>{new Date(m.at).toISOString().replace('T', ' ').slice(0, 19)}Z · {clock(m.at)} here</>],
                ['Node', <span className="cx-cellid"><Swatch color={color} /><span className="mono">{m.node}</span></span>],
                ['Finished', m.doneAt ? ago(m.doneAt) : 'not yet'],
                ...(m.error ? [['Provider said', <span className="mono sm" style={{ overflowWrap: 'anywhere' }}>{m.error}</span>] as [string, React.ReactNode]] : []),
                ...(m.reason ? [['Suppressed by', <span className="mono">{m.reason}</span>] as [string, React.ReactNode]] : []),
              ]}
            />
          </Sec>
          <p className="muted sm" style={{ margin: 0 }}>
            Bodies, codes and addresses are never stored: only the purpose, the recipient's domain and the outcome. An error loses every word with an @ in it.
          </p>
        </>
      ),
    }
  },
})

registerDetail('cfg', {
  kind: 'Setting',
  section: 'config',
  use: (flag) => {
    const cfg = configPoll.use()
    const { view } = useClusterView()
    if (!cfg.data) return { title: <span className="mono">{flag}</span>, body: null, loading: true }
    const row = flagRows(cfg.data).find((r) => r.flag === flag)
    if (!row) return { title: <span className="mono">{flag}</span>, body: null, missing: 'No node reports this flag: it may be from another build.' }
    const any = [...row.per.values()].find(Boolean)
    const color = (n: string) => view?.nodes.find((x) => x.node === n)?.color
    return {
      title: <span className="mono">{row.flag}</span>,
      chip: row.differs && !row.byDesign ? <Chip k="warn">differs</Chip> : sourceChip(any),
      foot: <Src>vlpds.admin.getConfig · every node</Src>,
      body: (
        <>
          {row.help && <p style={{ margin: 0 }}>{row.help}</p>}
          <Sec title="On each node" digest={row.byDesign ? 'differs by design' : row.differs ? 'not the same everywhere' : 'same everywhere'} open flush>
            <div className="cx-tw">
              <table className="cx-t compact">
                <tbody>
                  {cfg.data.map((r) => {
                    const s = row.per.get(r.node)
                    return (
                      <tr key={r.node}>
                        <td>
                          <span className="cx-cellid">
                            <Swatch color={color(r.node)} />
                            <span className="mono sm">{r.node}</span>
                          </span>
                        </td>
                        <td className="mono sm" style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>
                          {!r.config ? <span className="muted">no answer</span> : row.secret ? (s?.source === 'unset' ? <span className="muted">unset</span> : (s?.fingerprint ?? 'set')) : s?.source === 'unset' ? <span className="muted">unset</span> : shown(s)}
                        </td>
                        <td className="r">{sourceChip(s)}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </Sec>
          <Sec title="Where it comes from" digest={groupOf(row.flag)} open>
            <KV
              rows={[
                ['Source', any ? SOURCE_TEXT[any.source] : '—'],
                ['Environment', row.env ? <Copy text={row.env} /> : '—'],
                ...(row.secret ? [['Secret', 'Never returned. The fingerprint is sha256 of the value in use, 8 hex digits: enough to tell two nodes apart.'] as [string, React.ReactNode]] : []),
                ...(PER_NODE.has(row.flag) ? [['Per node', 'Each node has its own value: an address or its name.'] as [string, React.ReactNode]] : []),
                ['Changes take effect', 'on the node’s next start (a rolling deploy)'],
              ]}
            />
          </Sec>
        </>
      ),
    }
  },
})

registerDetail('storecomp', {
  kind: 'Object-store component',
  section: 'storage',
  use: (id) => {
    const m = useNodeMetrics()
    const { view } = useClusterView()
    const rows = componentRows(m.nodes.filter((n) => n.reachable))
    const r = rows.find((x) => x.component === id)
    const c = COMPONENTS[id]
    if (m.status === 'pending') return { title: componentName(id), body: null, loading: true }
    const color = (n: string) => view?.nodes.find((x) => x.node === n)?.color
    return {
      title: (
        <>
          {componentName(id)} <span className="muted mono sm">{id}</span>
        </>
      ),
      foot: <Src>getNodeMetrics · storeComponents</Src>,
      body: (
        <>
          {c && <p style={{ margin: 0 }}>{c.what[0].toUpperCase() + c.what.slice(1)}.</p>}
          <Strip
            items={[
              ['class A / s', r ? fmtNum(r.a, 2) : '0'],
              ['class B / s', r ? fmtNum(r.b, 2) : '0'],
              ['of all requests', r ? `${Math.round(((r.a + r.b) / (rows.reduce((t, x) => t + x.a + x.b, 0) || 1)) * 100)}%` : '0%'],
            ]}
          />
          <Sec title="By node" digest={`over the last ${Math.round((m.nodes[0]?.raw.storeWindowMs ?? 0) / 60000) || 3} min`} open flush>
            <div className="cx-tw">
              <table className="cx-t compact">
                <thead>
                  <tr>
                    <th>Node</th>
                    <th className="r">A/s</th>
                    <th className="r">B/s</th>
                  </tr>
                </thead>
                <tbody>
                  {(r?.byNode ?? []).map((n) => (
                    <tr key={n.node}>
                      <td>
                        <span className="cx-cellid">
                          <Swatch color={color(n.node)} />
                          <span className="mono sm">{n.node}</span>
                        </span>
                      </td>
                      <td className="r mono">{fmtNum(n.a, 2)}</td>
                      <td className="r mono">{fmtNum(n.b, 2)}</td>
                    </tr>
                  ))}
                  {!r && (
                    <tr>
                      <td colSpan={3} className="muted">
                        No requests in the window.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Sec>
          <Minis n={2} style={{ padding: 0 }}>
            <Mini label="all class A / s, every component" value={fmtNum(m.nodes.reduce((t, n) => t + (n.latest?.classAPerSec ?? 0), 0), 1)}>
              <Spark data={sumSeries(m.nodes, 'classAPerSec')} color="c3" />
            </Mini>
            <Mini label="all class B / s, every component" value={fmtNum(m.nodes.reduce((t, n) => t + (n.latest?.classBPerSec ?? 0), 0), 1)}>
              <Spark data={sumSeries(m.nodes, 'classBPerSec')} color="c6" />
            </Mini>
          </Minis>
        </>
      ),
    }
  },
})
