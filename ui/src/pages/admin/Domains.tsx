import { useEffect, useState } from 'react'
import { DataTable, type Col } from '../../components/console/DataTable'
import { Banners, Chip, Empty, ErrorState, Loading, Meter, PageHead, Panel, Seg, Src, type BannerSpec } from '../../components/console/kit'
import { ago, fmtNum, plural } from '../../lib/console/fmt'
import { addDomainDialog, createInvitesDialog, disableCodes, domainsPoll, InviteStatus, loadInvites, usable, useInvites, usesLeft, type Code, type Domain } from './domainsUi'
import { AccountLink, Who } from './peopleUi'

// Domains & invites: the handle domains accounts can take a handle under, and invite codes.

type Filter = 'usable' | 'used' | 'disabled' | 'all'
const FILTERS: Record<Filter, (c: Code) => boolean> = {
  usable,
  used: (c) => !c.disabled && usesLeft(c) === 0,
  disabled: (c) => c.disabled,
  all: () => true,
}

export function Domains() {
  const doms = domainsPoll.use()
  const inv = useInvites()
  useEffect(() => {
    loadInvites()
  }, [])
  const d = doms.data
  const nUsable = inv.codes.filter(usable).length
  const banners: BannerSpec[] = []
  if (d?.countsPartial) banners.push({ id: 'partial', tone: 'warn', title: 'Account counts may be low', desc: 'some nodes or shards didn’t answer or are still loading their totals; removing a domain needs “force” until they do' })
  if (d?.unreachableNodes?.length) banners.push({ id: 'unreach', tone: 'warn', title: `${plural(d.unreachableNodes.length, 'node')} didn’t answer`, desc: d.unreachableNodes.join(', ') })
  if (inv.unreachableNodes?.length) banners.push({ id: 'inv-unreach', tone: 'warn', title: 'Some invite codes may be missing', desc: `${inv.unreachableNodes.join(', ')} didn’t answer` })
  return (
    <>
      <PageHead
        title="Handle domains & invites"
        sub={
          <>
            {d && (
              <span>
                primary <span className="mono">.{d.primary}</span>
              </span>
            )}
            {d && <span>{plural(d.domains.length, 'handle domain')}</span>}
            {inv.loaded && <span>{plural(nUsable, 'usable code')}{inv.cursor ? '+' : ''}</span>}
          </>
        }
      />
      <Banners items={banners} />
      <div className="cx-grid2 cxp-domgrid">
        <Panel
          title="Handle domains"
          src={<Src>listHandleDomains · 5 s</Src>}
          right={
            <button type="button" className="cx-btn sm" onClick={addDomainDialog}>
              Add domain…
            </button>
          }
          foot={d ? `Each needs a wildcard DNS record pointing at the PDS and certificates for it. Every node picks up a change within ${d.refreshSecs} s.` : undefined}
        >
          {!d ? doms.error ? <ErrorState error={doms.error} retry={domainsPoll.refresh} /> : <Loading /> : <DomainsTable domains={d.domains} />}
        </Panel>
        <Invites />
      </div>
    </>
  )
}

function DomainsTable({ domains }: { domains: Domain[] }) {
  const total = domains.reduce((a, x) => a + (x.accounts ?? 0), 0)
  const cols: Col<Domain>[] = [
    {
      id: 'd',
      label: 'Domain',
      render: (x) => (
        <span className="cx-cellid">
          <b className="mono">.{x.domain}</b>
          {x.primary && <Chip k="acc">primary</Chip>}
        </span>
      ),
    },
    { id: 'n', label: 'Accounts', r: true, sort: (a, b) => (a.accounts ?? -1) - (b.accounts ?? -1), render: (x) => (x.accounts === null ? <span className="muted" title="Couldn’t be counted">—</span> : <span className="mono">{fmtNum(x.accounts)}</span>) },
    { id: 's', label: 'Share', render: (x) => <Meter v={x.accounts ?? 0} max={total} /> },
    { id: 'a', label: 'Added', render: (x) => (x.primary ? <span className="muted">from --handle-domain</span> : x.addedAt ? <span className="t2">{ago(Date.parse(x.addedAt))}{x.addedBy && <span className="muted"> by {x.addedBy}</span>}</span> : <span className="muted">—</span>) },
  ]
  return <DataTable rows={domains} cols={cols} rowKey={(x) => x.domain} open={(x) => ({ type: 'domain', id: x.domain })} label="Handle domains" />
}

function Invites() {
  const inv = useInvites()
  const [f, setF] = useState<Filter>('usable')
  const [sel, setSel] = useState<Set<string>>(new Set())
  const list = inv.codes.filter(FILTERS[f])
  const selectable = list.filter((c) => !c.disabled)
  const allOn = selectable.length > 0 && selectable.every((c) => sel.has(c.code))
  const flip = (code: string) =>
    setSel((s) => {
      const n = new Set(s)
      if (n.has(code)) n.delete(code)
      else n.add(code)
      return n
    })
  const cols: Col<Code>[] = [
    {
      id: 'sel',
      label: <input type="checkbox" aria-label="Select all shown" checked={allOn} disabled={!selectable.length} onChange={() => setSel(allOn ? new Set() : new Set(selectable.map((c) => c.code)))} />,
      render: (c) => <input type="checkbox" aria-label={`Select ${c.code}`} checked={sel.has(c.code)} disabled={c.disabled} onChange={() => flip(c.code)} />,
    },
    { id: 'code', label: 'Code', render: (c) => <span className="mono sm">{c.code}</span> },
    { id: 'uses', label: 'Uses', r: true, render: (c) => <span className="mono">{c.uses.length}/{c.available}</span> },
    { id: 'created', label: 'Created', sort: (a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt), render: (c) => ago(Date.parse(c.createdAt)) },
    { id: 'for', label: 'For', render: (c) => (c.forAccount.startsWith('did:') ? <AccountLink did={c.forAccount} /> : <span className="t2 sm">{c.forAccount}</span>) },
    {
      id: 'by',
      label: 'Used by',
      className: 'trunc',
      style: { maxWidth: 170 },
      render: (c) =>
        c.uses.length ? (
          <span className="sm">
            <Who did={c.uses[0].usedBy} />
            {c.uses.length > 1 && <span className="muted"> +{c.uses.length - 1}</span>}
          </span>
        ) : (
          <span className="muted">—</span>
        ),
    },
    { id: 'st', label: 'Status', render: (c) => <InviteStatus c={c} /> },
  ]
  const chosen = [...sel].filter((c) => inv.codes.some((x) => x.code === c && !x.disabled))
  return (
    <Panel
      title="Invite codes"
      src={<Src>getInviteCodes · createInviteCodes · disableInviteCodes</Src>}
      right={
        <>
          <Seg<Filter> label="Filter" value={f} onChange={setF} options={(Object.keys(FILTERS) as Filter[]).map((k) => ({ v: k, label: k, n: inv.codes.filter(FILTERS[k]).length }))} />
          <button type="button" className="cx-btn sm primary" onClick={createInvitesDialog}>
            Create codes…
          </button>
        </>
      }
      foot={
        <>
          <span>{chosen.length ? `${chosen.length} selected · ` : ''}</span>
          <button type="button" className="cx-linklike" disabled={!chosen.length} onClick={() => disableCodes(chosen, () => setSel(new Set()))}>
            Disable selected…
          </button>
          {inv.cursor && (
            <button type="button" className="cx-linklike" style={{ marginLeft: 'auto' }} disabled={inv.busy} onClick={() => loadInvites(true)}>
              Load 100 more
            </button>
          )}
        </>
      }
    >
      {!inv.loaded ? (
        inv.error ? (
          <ErrorState error={inv.error} retry={() => loadInvites()} />
        ) : (
          <Loading />
        )
      ) : (
        <DataTable
          compact
          rows={list}
          cols={cols}
          rowKey={(c) => c.code}
          open={(c) => ({ type: 'invite', id: c.code })}
          dim={(c) => c.disabled}
          label="Invite codes"
          empty={<Empty>{inv.codes.length ? `No ${f} codes.` : 'No invite codes yet.'}</Empty>}
        />
      )}
    </Panel>
  )
}
