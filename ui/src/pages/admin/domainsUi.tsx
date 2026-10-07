import { useInfiniteQuery, type InfiniteData } from '@tanstack/react-query'
import { useState } from 'react'
import { confirmAction, FormDialog, openDialog } from '../../components/console/dialogs'
import { registerDetail } from '../../components/console/Drawer'
import { Chip, Copy, KV, RRow, Sec, Src, Strip } from '../../components/console/kit'
import { panelParam } from '../../components/console/nav'
import { registerPalette } from '../../components/console/Palette'
import { toast } from '../../components/console/toast'
import { clusterQ } from '../../lib/console/cluster'
import { ago, fmtNum, plural } from '../../lib/console/fmt'
import { K } from '../../lib/console/keys'
import { mutate } from '../../lib/console/mutate'
import { every, queryClient, shared } from '../../lib/console/query'
import { inviteTone } from '../../lib/console/status'
import { useAction } from '../../lib/hooks'
import { navigate } from '../../lib/router'
import { admin, call, errText } from '../../lib/xrpc'
import { AccountLink } from './peopleUi'

// Domains & invites: the handle-domain list, invite codes (paged), their slide-overs, dialogs and
// ⌘K entries. Both are queries the change feed refreshes (`domain`, `invite`).

// ---------------------------------------------------------------- handle domains

export type Domain = { domain: string; primary: boolean; accounts: number | null; addedAt?: string | null; addedBy?: string | null }
export type DomainList = { primary: string; domains: Domain[]; updatedAt?: string | null; refreshSecs: number; countsPartial?: boolean; unreachableNodes?: string[] }

export const domainsQ = shared({ key: K.domains, fn: (signal) => admin<DomainList>('vlpds.admin.listHandleDomains', { signal }), poll: 30_000 })

type Applied = { nodes?: { node: string; ok: boolean; error?: string }[] }
const appliedText = (r: Applied) => {
  const n = r.nodes ?? []
  const ok = n.filter((x) => x.ok).length
  return n.length ? ` Every node picks it up within seconds (${ok} of ${n.length} told now).` : ''
}

export function addDomainDialog() {
  openDialog((close) => <AddDomain close={close} />)
}

function AddDomain({ close }: { close: () => void }) {
  const [v, setV] = useState('')
  const typed = v.trim().toLowerCase().replace(/^\.+/, '')
  const add = useAction(async () => {
    const r = await mutate({ run: () => admin<Applied>('vlpds.admin.addHandleDomain', { body: { domain: typed } }), changes: [{ kind: 'domain', id: typed }] })
    close()
    toast(`Added ${typed}.${appliedText(r)}`)
  })
  return (
    <FormDialog title="Add a handle domain" call="vlpds.admin.addHandleDomain → every node" action="Add domain" busy={add.busy} disabled={!typed.includes('.')} error={add.error} onSubmit={() => add.run()} onCancel={close}>
      <div>
        <label className="cx-lbl" htmlFor="dom-n">
          Domain
        </label>
        <input id="dom-n" className="cx-inp mono" autoFocus value={v} onChange={(e) => setV(e.target.value)} placeholder="at.example.org" autoCapitalize="none" spellCheck={false} />
      </div>
      <p className="t2" style={{ margin: 0 }}>
        Handles will look like <span className="mono">alice.{typed || 'example.org'}</span>. Set up its DNS first: a wildcard record (<span className="mono">*.{typed || 'example.org'}</span>) pointing at the PDS, and certificates for it (on-demand TLS, or a wildcard certificate).
      </p>
    </FormDialog>
  )
}

export function removeDomain(d: Domain) {
  const inUse = d.accounts !== 0
  return confirmAction({
    tone: 'err',
    title: `Remove ${d.domain}?`,
    items: [
      'New accounts can no longer take a handle under it.',
      d.accounts ? `${plural(d.accounts, 'account')} still ${d.accounts === 1 ? 'has' : 'have'} a handle under it. Those handles stop verifying (/.well-known/atproto-did answers 404), so other services stop resolving them, and no new certificates are issued for it.` : d.accounts === null ? 'Its account count isn’t known right now.' : 'No account has a handle under it.',
      ...(inUse ? ['Accounts left under it should pick a new handle; you can rename them with updateAccountHandle.'] : []),
    ],
    fields: inUse ? [{ id: 'force', type: 'checkbox', label: 'Remove it even though accounts still use it' }] : [],
    word: d.domain,
    action: 'Remove domain',
    call: `vlpds.admin.removeHandleDomain {domain${inUse ? ', force' : ''}}`,
    run: (v) =>
      mutate({
        run: () => admin<{ accounts?: number }>('vlpds.admin.removeHandleDomain', { body: { domain: d.domain, force: v.force ? true : undefined } }),
        changes: [{ kind: 'domain', id: d.domain }],
      }),
    done: (r) => {
      const n = (r as { accounts?: number }).accounts
      return n ? `Removed ${d.domain}. ${plural(n, 'account')} still under it.` : `Removed ${d.domain}`
    },
  })
}

registerDetail('domain', {
  kind: 'Handle domain',
  section: 'domains',
  use: (id) => {
    const s = domainsQ.use()
    const d = s.data?.domains.find((x) => x.domain === id)
    if (!s.data) return { title: id, body: null, loading: !s.error, missing: s.error ? errText(s.error) : undefined }
    if (!d) return { title: <span className="mono">.{id}</span>, body: null, missing: `${id} isn’t a handle domain here (any more).` }
    const total = s.data.domains.reduce((a, x) => a + (x.accounts ?? 0), 0)
    return {
      title: <span className="mono">.{d.domain}</span>,
      chip: d.primary ? <Chip k="acc">primary</Chip> : <Chip k="ok">served</Chip>,
      updated: s.at,
      foot: <Src>listHandleDomains</Src>,
      body: (
        <>
          <Strip
            items={[
              ['accounts', d.accounts === null ? '—' : fmtNum(d.accounts)],
              ['share', d.accounts !== null && total ? `${Math.round((d.accounts / total) * 100)}%` : '—'],
              ['added', d.primary ? 'flag' : d.addedAt ? ago(Date.parse(d.addedAt)) : '—'],
              ['by', d.primary ? '--handle-domain' : (d.addedBy ?? '—')],
            ]}
          />
          <Sec title="DNS and TLS" digest={`wildcard → this PDS`} open>
            <KV
              rows={[
                ['Record', <span className="mono">*.{d.domain} → the PDS</span>],
                ['TLS', 'on-demand certificates (the proxy asks vlpds first), or a wildcard certificate with the DNS-01 token'],
                ['Handles', <span className="mono">alice.{d.domain}</span>],
                ['Source', d.primary ? <>the <span className="mono">--handle-domain</span> flag; always served</> : 'stored in the bucket, changed in this console'],
              ]}
            />
          </Sec>
          {!d.primary && (
            <Sec title="Remove" digest={d.accounts ? 'refused while it has accounts, unless forced' : 'no accounts under it'} danger open>
              <button type="button" className="cx-btn sm danger" onClick={() => removeDomain(d)}>
                Remove domain…
              </button>
            </Sec>
          )}
        </>
      ),
    }
  },
})

// ---------------------------------------------------------------- invite codes

/** `available` is the code's total uses, as the reference PDS reports it. */
export type Code = { code: string; available: number; disabled: boolean; forAccount: string; createdBy: string; createdAt: string; uses: { usedBy: string; usedAt: string }[] }
export const usesLeft = (c: Code) => Math.max(0, c.available - c.uses.length)
export const usable = (c: Code) => !c.disabled && usesLeft(c) > 0

type CodePage = { codes: Code[]; cursor?: string; unreachableNodes?: string[] }

/** Every loaded code, newest first, across the pages fetched so far. */
const codesOf = (d?: InfiniteData<CodePage>) => d?.pages.flatMap((p) => p.codes) ?? []
export const cachedCodes = () => codesOf(queryClient.getQueryData<InfiniteData<CodePage>>(K.invites))

/** Invite codes, 100 a page; the change feed's `invite` refetches the pages loaded. */
export function useInvites() {
  const q = useInfiniteQuery({
    queryKey: K.invites,
    queryFn: ({ pageParam, signal }) =>
      admin<CodePage>('com.atproto.admin.getInviteCodes', { params: { sort: 'recent', limit: 100, cursor: pageParam }, signal }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.cursor,
    refetchInterval: every(60_000),
  })
  const pages = q.data?.pages
  return {
    codes: codesOf(q.data),
    cursor: q.hasNextPage ? pages?.[pages.length - 1]?.cursor : undefined,
    loaded: !!pages,
    error: q.error ?? undefined,
    busy: q.isFetching,
    at: q.dataUpdatedAt || undefined,
    unreachableNodes: pages?.[pages.length - 1]?.unreachableNodes,
    more: () => void q.fetchNextPage(),
    reload: () => void q.refetch(),
  }
}

/** Marks codes disabled in every loaded page: the answer is obvious, so it shows before the call returns. */
function markDisabled(codes: string[]): () => void {
  const before = queryClient.getQueryData<InfiniteData<CodePage>>(K.invites)
  if (before)
    queryClient.setQueryData<InfiniteData<CodePage>>(K.invites, {
      ...before,
      pages: before.pages.map((p) => ({ ...p, codes: p.codes.map((c) => (codes.includes(c.code) ? { ...c, disabled: true } : c)) })),
    })
  return () => queryClient.setQueryData(K.invites, before)
}

const publicBase = () => (clusterQ.get().data?.publicUrl ?? location.origin).replace(/\/+$/, '')
export const inviteLinks = (code: string) => {
  const q = `?invite=${encodeURIComponent(code)}`
  return { signup: `${publicBase()}/account/signup${q}`, migrate: `${publicBase()}/migrate${q}` }
}

export function disableCodes(codes: string[], after?: () => void) {
  return confirmAction({
    tone: 'err',
    title: codes.length === 1 ? `Disable ${codes[0]}?` : `Disable ${codes.length} invite codes?`,
    items: ['Nobody can sign up or migrate in with them any more.', 'Accounts that already used them are unaffected.', 'There is no undo: create new codes instead.'],
    action: codes.length === 1 ? 'Disable code' : `Disable ${codes.length} codes`,
    call: 'com.atproto.admin.disableInviteCodes {codes}',
    run: async () => {
      await mutate({
        run: () => admin('com.atproto.admin.disableInviteCodes', { body: { codes } }),
        optimistic: () => markDisabled(codes),
        changes: [{ kind: 'invite', id: '*' }],
      })
      after?.()
    },
    done: codes.length === 1 ? 'Code disabled' : `${codes.length} codes disabled`,
  })
}

export function createInvitesDialog() {
  openDialog((close) => <CreateInvites close={close} />)
}

function CreateInvites({ close }: { close: () => void }) {
  const [count, setCount] = useState('1')
  const [uses, setUses] = useState('1')
  const [forAcc, setFor] = useState('')
  const go = useAction(async () => {
    let did: string | undefined = forAcc.trim().replace(/^@/, '') || undefined
    if (did && !did.startsWith('did:')) did = (await call<{ did: string }>('com.atproto.identity.resolveHandle', { params: { handle: did } })).did
    const r = await mutate({
      run: () =>
        admin<{ codes: { account: string; codes: string[] }[] }>('com.atproto.server.createInviteCodes', {
          body: { codeCount: Number(count), useCount: Number(uses), forAccounts: did ? [did] : undefined },
        }),
      changes: [{ kind: 'invite', id: '*' }],
    })
    openDialog((c) => <Created codes={r.codes.flatMap((x) => x.codes)} close={c} />)
  })
  const ok = Number(count) >= 1 && Number(count) <= 100 && Number(uses) >= 1 && Number(uses) <= 1000
  return (
    <FormDialog title="Create invite codes" call="com.atproto.server.createInviteCodes" action="Create codes" busy={go.busy} disabled={!ok} error={go.error} onSubmit={() => go.run()} onCancel={close}>
      <div className="cx-form-row">
        <div style={{ flex: 1 }}>
          <label className="cx-lbl" htmlFor="inv-n">
            How many codes
          </label>
          <input id="inv-n" className="cx-inp mono" type="number" min={1} max={100} autoFocus value={count} onChange={(e) => setCount(e.target.value)} />
        </div>
        <div style={{ flex: 1 }}>
          <label className="cx-lbl" htmlFor="inv-u">
            Uses per code
          </label>
          <input id="inv-u" className="cx-inp mono" type="number" min={1} max={1000} value={uses} onChange={(e) => setUses(e.target.value)} />
        </div>
      </div>
      <div>
        <label className="cx-lbl" htmlFor="inv-f">
          For an account (handle or DID; blank: admin)
        </label>
        <input id="inv-f" className="cx-inp mono" value={forAcc} onChange={(e) => setFor(e.target.value)} placeholder="admin" spellCheck={false} autoCapitalize="none" />
      </div>
    </FormDialog>
  )
}

function Created({ codes, close }: { codes: string[]; close: () => void }) {
  return (
    <FormDialog title={codes.length === 1 ? 'Created one code' : `Created ${codes.length} codes`} icon="✓" action="Done" onSubmit={close} onCancel={close}>
      <p className="t2" style={{ margin: 0 }}>
        Click a code or link to copy it.
      </p>
      <div className="cxp-codes">
        {codes.map((c) => {
          const l = inviteLinks(c)
          return (
            <div key={c}>
              <Copy text={c} />
              <span className="cx-form-row" style={{ gap: 10 }}>
                <Copy text={l.signup} mono={false}>
                  sign-up link
                </Copy>
                <Copy text={l.migrate} mono={false}>
                  migrate link
                </Copy>
              </span>
            </div>
          )
        })}
      </div>
    </FormDialog>
  )
}

export function InviteStatus({ c }: { c: Code }) {
  const [k, t] = inviteTone(c)
  return <Chip k={k}>{t}</Chip>
}

/** "admin" or an account. */
function Owner({ x }: { x: string }) {
  return x.startsWith('did:') ? <AccountLink did={x} /> : <span className="t2">{x}</span>
}

registerDetail('invite', {
  kind: 'Invite code',
  section: 'domains',
  use: (id) => {
    const s = useInvites()
    const c = s.codes.find((x) => x.code === id)
    if (!c) return { title: <span className="mono">{id}</span>, body: null, loading: !s.loaded || s.busy, missing: s.error ? errText(s.error) : `Not among the ${fmtNum(s.codes.length)} newest codes.` }
    const l = inviteLinks(c.code)
    return {
      title: <span className="mono">{c.code}</span>,
      chip: <InviteStatus c={c} />,
      updated: s.at,
      foot: <Src>getInviteCodes · disableInviteCodes</Src>,
      body: (
        <>
          <Strip
            items={[
              ['used', `${c.uses.length}/${c.available}`],
              ['left', fmtNum(usesLeft(c))],
              ['created', ago(Date.parse(c.createdAt))],
              ['for', c.forAccount.startsWith('did:') ? 'an account' : c.forAccount],
            ]}
          />
          {usable(c) && (
            <Sec title="Links" digest="copy and send" open>
              <KV
                rows={[
                  ['Code', <Copy text={c.code} />],
                  ['Sign-up', <Copy text={l.signup} mono={false}>{l.signup.replace(/^https?:\/\//, '')}</Copy>],
                  ['Migrate', <Copy text={l.migrate} mono={false}>{l.migrate.replace(/^https?:\/\//, '')}</Copy>],
                ]}
              />
            </Sec>
          )}
          <Sec title="Used by" digest={plural(c.uses.length, 'account')} open flush>
            {c.uses.length ? (
              c.uses.map((u) => (
                <RRow key={u.usedBy} x={ago(Date.parse(u.usedAt))}>
                  <AccountLink did={u.usedBy} />
                </RRow>
              ))
            ) : (
              <div className="cx-empty">Nobody yet.</div>
            )}
          </Sec>
          <Sec title="Details" open>
            <KV
              rows={[
                ['Created', new Date(c.createdAt).toLocaleString()],
                ['Created by', <Owner x={c.createdBy} />],
                ['For', <Owner x={c.forAccount} />],
                ['Uses', `${c.available} in all`],
              ]}
            />
          </Sec>
          {!c.disabled && (
            <div>
              <button type="button" className="cx-btn sm danger" onClick={() => disableCodes([c.code])}>
                Disable code…
              </button>
            </div>
          )}
        </>
      ),
    }
  },
})

// ---------------------------------------------------------------- ⌘K

registerPalette({
  items: (q) => {
    const out = [
      {
        group: 'Actions',
        title: 'Add handle domain…',
        desc: 'addHandleDomain',
        run: () => {
          navigate('/admin/domains')
          addDomainDialog()
        },
      },
      {
        group: 'Actions',
        title: 'Create invite codes…',
        desc: 'createInviteCodes',
        run: () => {
          navigate('/admin/domains')
          createInvitesDialog()
        },
      },
    ]
    const doms = (domainsQ.get().data?.domains ?? []).map((d) => ({
      group: 'Domains',
      glyph: '.',
      title: `.${d.domain}`,
      desc: `${d.accounts === null ? '?' : fmtNum(d.accounts)} accounts${d.primary ? ' · primary' : ''}`,
      run: () => navigate(`/admin/domains?open=${encodeURIComponent(panelParam('domain', d.domain))}`),
    }))
    const codes = q.length >= 4 ? cachedCodes().filter((c) => c.code.toLowerCase().includes(q.toLowerCase())).slice(0, 6) : []
    return [
      ...out,
      ...doms,
      ...codes.map((c) => ({ group: 'Invites', glyph: '›', title: c.code, desc: `${c.uses.length}/${c.available} used${c.disabled ? ' · disabled' : ''}`, run: () => navigate(`/admin/domains?open=${encodeURIComponent(panelParam('invite', c.code))}`) })),
    ]
  },
})
