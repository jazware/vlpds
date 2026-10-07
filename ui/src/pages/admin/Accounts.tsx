import { useInfiniteQuery, useQueries } from '@tanstack/react-query'
import { useEffect, useMemo, useState } from 'react'
import { DataTable, type Col } from '../../components/console/DataTable'
import { Banners, Chip, ErrorState, Kbd, Loading, NeedsVersion, PageHead, Panel, Seg, Spinner, Src, Swatch, type BannerSpec } from '../../components/console/kit'
import { openPanel } from '../../components/console/nav'
import { SECTION } from '../../components/console/sections'
import * as api from '../../lib/adminApi'
import type { AccountFilter, AccountRow } from '../../lib/adminApi'
import { withAdmin } from '../../lib/console/adminAdapter'
import { useClusterView, type ClusterView } from '../../lib/console/cluster'
import { ago, fmtBytes, fmtNum, plural, shortDid } from '../../lib/console/fmt'
import { K } from '../../lib/console/keys'
import { isUnsupported } from '../../lib/console/live'
import { every, hydrate, queryClient } from '../../lib/console/query'
import { accountTone } from '../../lib/console/status'
import { Link } from '../../lib/router'
import { createAccount } from './accountActions'
import './accountDetail'
import './accounts.css'

// Accounts: every account across every node's shards, most recently active first, searchable by
// handle prefix, email prefix or DID (vlpds.admin.listAccounts). A row opens the account in the
// slide-over (accountDetail.tsx).

const FILTERS: { v: AccountFilter; label: string }[] = [
  { v: 'all', label: 'All' },
  { v: 'attention', label: 'Needs attention' },
  { v: 'deactivated', label: 'Deactivated' },
  { v: 'takendown', label: 'Taken down' },
  { v: 'no2fa', label: 'No second factor' },
  { v: 'unconfirmed', label: 'Email unconfirmed' },
]

const PAGE = 50

/** Which of listAccounts' counts each filter shows; attention has none (quotas and lockouts aren't counted). */
const COUNT_OF: Partial<Record<AccountFilter, keyof api.AccountCounts>> = {
  all: 'total',
  deactivated: 'deactivated',
  takendown: 'takendown',
  no2fa: 'no2fa',
  unconfirmed: 'unconfirmed',
}

function filterOptions(counts?: api.AccountCounts) {
  return FILTERS.map((f) => {
    const k = COUNT_OF[f.v]
    const n = counts && k ? (counts[k] as number) : undefined
    return { ...f, n: n === undefined ? undefined : `${counts?.approximate ? '≈' : ''}${fmtNum(n)}` }
  })
}

/** The account's state as a chip: tone and word (the console's one vocabulary, status.ts). */
export const accountState = accountTone

export function TwoFactor({ f }: { f: AccountRow['secondFactors'] }) {
  return (
    <span className="cx-2fa">
      <span className={f.passkeys ? 'on' : ''} title={plural(f.passkeys, 'passkey')}>
        PK{f.passkeys > 1 ? f.passkeys : ''}
      </span>
      <span className={f.totp ? 'on' : ''} title={f.totp ? 'Authenticator app on' : 'No authenticator app'}>
        TOTP
      </span>
      <span className={f.emailCode ? 'on' : ''} title={f.emailCode ? 'Email sign-in codes on' : 'No email sign-in codes'}>
        @
      </span>
    </span>
  )
}

/** The node a row's shard belongs to, as its colour square. */
const ownerSwatch = (view: ClusterView | undefined, node: string) => {
  const n = view?.nodes.find((x) => x.node === node)
  return <Swatch color={n?.color} title={node} />
}

function cols(view: ClusterView | undefined): Col<AccountRow>[] {
  return [
    {
      id: 'handle',
      label: 'Handle',
      sort: (a, b) => b.handle.localeCompare(a.handle),
      render: (a) => (
        <span className="cx-cellid">
          <span className="cx-handle">@{a.handle}</span>
        </span>
      ),
    },
    { id: 'did', label: 'DID', render: (a) => <span className="cx-did" title={a.did}>{shortDid(a.did)}</span> },
    {
      id: 'email',
      label: 'Email',
      render: (a) =>
        a.email ? (
          <span className="t2">
            {a.email} {!a.emailConfirmed && <Chip k="warn">unconfirmed</Chip>}
          </span>
        ) : (
          <span className="muted">—</span>
        ),
    },
    {
      id: 'shard',
      label: 'Shard',
      title: 'Shard, coloured by the node that owns it',
      sort: (a, b) => a.shard - b.shard,
      render: (a) => (
        <span className="cx-cellid">
          {ownerSwatch(view, a.node)}
          <span className="mono sm t2">{String(a.shard).padStart(2, '0')}</span>
        </span>
      ),
    },
    { id: 'records', label: 'Records', r: true, sort: (a, b) => (a.records ?? 0) - (b.records ?? 0), render: (a) => <span className="mono">{a.records === undefined ? '—' : fmtNum(a.records)}</span> },
    {
      id: 'repo',
      label: 'Repo',
      r: true,
      title: 'Record and MST blocks: what a getRepo CAR carries',
      sort: (a, b) => (a.repoBytes ?? 0) - (b.repoBytes ?? 0),
      render: (a) => <span className="mono">{a.repoBytes === undefined ? '—' : fmtBytes(a.repoBytes)}</span>,
    },
    {
      id: 'blobs',
      label: 'Blobs',
      r: true,
      sort: (a, b) => a.blobBytes - b.blobBytes,
      render: (a) => (
        <span className="mono" title={a.blobs !== undefined ? plural(a.blobs, 'blob') : undefined}>
          {fmtBytes(a.blobBytes)}
        </span>
      ),
    },
    { id: 'last', label: 'Last commit', r: true, sort: (a, b) => (a.lastCommitAt ?? 0) - (b.lastCommitAt ?? 0), render: (a) => (a.lastCommitAt ? ago(a.lastCommitAt) : <span className="muted">never</span>) },
    { id: '2fa', label: '2FA', render: (a) => <TwoFactor f={a.secondFactors} /> },
    {
      id: 'state',
      label: 'State',
      render: (a) => {
        const [k, t] = accountState(a)
        return (
          <span className="cx-acc-chips">
            <Chip k={k}>{t}</Chip>
            {a.overQuota && <Chip k="warn">over quota</Chip>}
          </span>
        )
      },
    },
  ]
}

/**
 * One page of listAccounts; each row also becomes the account's own `['account', did, 'row']`,
 * which is what the table draws, so an action or the drawer updating a row shows here at once.
 */
async function fetchPage(p: { q?: string; filter: AccountFilter }, cursor: string | undefined, signal: AbortSignal) {
  const at = Date.now()
  const r = await withAdmin((c) => api.listAccounts(c, { q: p.q, filter: p.filter, cursor, limit: PAGE }, signal))
  for (const a of r.accounts) hydrate(K.accountRow(a.did), a, at)
  return r
}

/** The rows as their per-account copies hold them now (absent: the list's own). */
function useRows(rows: AccountRow[]): AccountRow[] {
  const copies = useQueries({
    queries: rows.map((r) => ({ queryKey: K.accountRow(r.did), queryFn: () => queryClient.getQueryData<AccountRow | null>(K.accountRow(r.did)) ?? r, enabled: false })),
  })
  return useMemo(() => rows.flatMap((r, i) => (copies[i]?.data === null ? [] : [copies[i]?.data ?? r])), [rows, copies])
}

export function Accounts() {
  const { view } = useClusterView()
  const [q, setQ] = useState('')
  const [qq, setQq] = useState('')
  const [filter, setFilter] = useState<AccountFilter>('all')

  // debounce the search box
  useEffect(() => {
    const t = setTimeout(() => setQq(q.trim()), 220)
    return () => clearTimeout(t)
  }, [q])

  const params = { q: qq || undefined, filter }
  const list = useInfiniteQuery({
    queryKey: K.accounts(params),
    queryFn: ({ pageParam, signal }) => fetchPage(params, pageParam, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.cursor,
    refetchInterval: every(60_000),
    placeholderData: (prev) => prev,
  })
  const pages = list.data?.pages
  const listed = useMemo(() => pages?.flatMap((p) => p.accounts) ?? [], [pages])
  const rows = useRows(listed)
  const last = pages?.[pages.length - 1]
  const counts = pages?.find((p) => p.counts)?.counts
  const busy = list.isFetching
  const error = list.error
  const unsupported = isUnsupported(error)
  const page = pages ? { cursor: list.hasNextPage ? last?.cursor : undefined } : undefined
  const load = (cursor?: string) => (cursor ? list.fetchNextPage() : list.refetch())

  if (unsupported)
    return (
      <>
        <PageHead title="Accounts" />
        <Panel>
          <NeedsVersion what="The account list" nsid="vlpds.admin.listAccounts" />
        </Panel>
      </>
    )

  const banners: BannerSpec[] = []
  if (last?.unreachableNodes?.length)
    banners.push({ id: 'unreach', tone: 'warn', title: 'Some nodes didn’t answer', desc: `${last.unreachableNodes.join(', ')}: their shards’ accounts are missing from this list` })
  if (last?.missingShards?.length) banners.push({ id: 'missing', tone: 'warn', title: `${plural(last.missingShards.length, 'shard')} without an owner`, desc: `shards ${last.missingShards.join(', ')} are mid-move: their accounts are missing` })
  if (last?.unsupportedNodes?.length) banners.push({ id: 'old', tone: 'info', title: 'Older builds in the cluster', desc: `${last.unsupportedNodes.join(', ')} can't list accounts yet` })

  const sorting = last?.sort === 'slot' ? 'in shard order' : 'most recently active first'
  return (
    <>
      <PageHead
        title="Accounts"
        sub={
          <>
            <span>{page ? `${fmtNum(rows.length)}${page.cursor ? '+' : ''} ${qq || filter !== 'all' ? 'matching' : 'shown'}` : '…'}</span>
            <span>{sorting}</span>
            {view && <span>{plural(view.table.length, 'shard')}</span>}
          </>
        }
        updated={list.dataUpdatedAt || undefined}
        actions={
          <>
            <button type="button" className="cx-btn" onClick={() => createAccount()}>
              Create account…
            </button>
            <Link className="cx-btn" to={SECTION.domains.path}>
              Invite codes ›
            </Link>
          </>
        }
      />
      <Banners items={banners} />
      <Panel
        title={qq ? `Matching “${qq}”` : FILTERS.find((f) => f.v === filter)!.label === 'All' ? 'Most recently active' : FILTERS.find((f) => f.v === filter)!.label}
        src={<Src>listAccounts · every node’s shards</Src>}
        right={busy ? <Spinner /> : undefined}
        foot={
          <>
            <span>
              <Kbd k="/" /> search · <Kbd k={['j', 'k']} /> move · <Kbd k="↵" /> open · <Kbd k="o" /> full page
            </span>
            {page?.cursor && (
              <span className="cx-acc-more">
                <button type="button" className="cx-btn sm" disabled={busy} onClick={() => load(page.cursor)}>
                  {busy && <Spinner />}
                  Load {PAGE} more
                </button>
              </span>
            )}
          </>
        }
      >
        <form
          className="cx-toolbar"
          onSubmit={(e) => {
            e.preventDefault()
            setQq(q.trim())
            if (rows.length === 1) openPanel('account', rows[0].did)
          }}
        >
          <input
            className="cx-inp"
            data-search
            value={q}
            placeholder="Handle, DID or email   ( / )"
            aria-label="Search accounts by handle, DID or email"
            spellCheck={false}
            autoComplete="off"
            autoCapitalize="none"
            onChange={(e) => setQ(e.target.value)}
          />
          <Seg value={filter} options={filterOptions(counts)} onChange={setFilter} label="Filter accounts" />
        </form>
        {error && !pages ? (
          <ErrorState error={error} retry={() => load()} />
        ) : !page ? (
          <Loading label="Asking every node…" />
        ) : (
          <DataTable
            label="Accounts"
            rows={rows}
            cols={cols(view)}
            rowKey={(a) => a.did}
            open={(a) => ({ type: 'account', id: a.did })}
            dim={(a) => a.status === 'takendown' || a.status === 'deleted'}
            empty={
              <div className="cx-empty">
                {qq ? (
                  <>
                    No account here matches “{qq}”. Search takes a handle or email prefix, or a whole DID.
                  </>
                ) : (
                  'No accounts match this filter.'
                )}
              </div>
            }
          />
        )}
      </Panel>
    </>
  )
}
