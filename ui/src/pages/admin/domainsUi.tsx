import { useEffect, useState, useSyncExternalStore } from 'react'
import { confirmAction, FormDialog, openDialog } from '../../components/console/dialogs'
import { registerDetail } from '../../components/console/Drawer'
import { Chip, Copy, KV, RRow, Sec, Src, Strip } from '../../components/console/kit'
import { panelParam } from '../../components/console/nav'
import { registerPalette } from '../../components/console/Palette'
import { toast } from '../../components/console/toast'
import { clusterPoll } from '../../lib/console/cluster'
import { ago, fmtNum, plural } from '../../lib/console/fmt'
import { createPoller } from '../../lib/console/live'
import { useAction } from '../../lib/hooks'
import { navigate } from '../../lib/router'
import { admin, call, errText } from '../../lib/xrpc'
import { AccountLink } from './peopleUi'

// Domains & invites: the handle-domain list (polled), invite codes (paged), their slide-overs,
// dialogs and ⌘K entries.

// ---------------------------------------------------------------- handle domains

export type Domain = { domain: string; primary: boolean; accounts: number | null; addedAt?: string | null; addedBy?: string | null }
export type DomainList = { primary: string; domains: Domain[]; updatedAt?: string | null; refreshSecs: number; countsPartial?: boolean; unreachableNodes?: string[] }

export const domainsPoll = createPoller(() => admin<DomainList>('vlpds.admin.listHandleDomains'), 5000)

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
    const r = await admin<Applied>('vlpds.admin.addHandleDomain', { body: { domain: typed } })
    domainsPoll.refresh()
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
    run: async (v) => {
      const r = await admin<{ accounts?: number }>('vlpds.admin.removeHandleDomain', { body: { domain: d.domain, force: v.force ? true : undefined } })
      domainsPoll.refresh()
      return r
    },
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
    const s = domainsPoll.use()
    const d = s.data?.domains.find((x) => x.domain === id)
    if (!s.data) return { title: id, body: null, loading: !s.error, missing: s.error ? errText(s.error) : undefined }
    if (!d) return { title: <span className="mono">.{id}</span>, body: null, missing: `${id} isn’t a handle domain here (any more).` }
    const total = s.data.domains.reduce((a, x) => a + (x.accounts ?? 0), 0)
    return {
      title: <span className="mono">.{d.domain}</span>,
      chip: d.primary ? <Chip k="acc">primary</Chip> : <Chip k="ok">served</Chip>,
      foot: <Src>listHandleDomains · 5 s</Src>,
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

type InvState = { codes: Code[]; cursor?: string; loaded: boolean; error?: unknown; busy: boolean; unreachableNodes?: string[] }
let inv: InvState = { codes: [], loaded: false, busy: false }
const invSubs = new Set<() => void>()
const setInv = (p: Partial<InvState>) => {
  inv = { ...inv, ...p }
  invSubs.forEach((l) => l())
}
export const useInvites = () =>
  useSyncExternalStore(
    (l) => {
      invSubs.add(l)
      return () => {
        invSubs.delete(l)
      }
    },
    () => inv,
  )

/** The newest page again, or (`more`) the next one. */
export async function loadInvites(more = false) {
  if (inv.busy) return
  setInv({ busy: true })
  try {
    const r = await admin<{ codes: Code[]; cursor?: string; unreachableNodes?: string[] }>('com.atproto.admin.getInviteCodes', { params: { sort: 'recent', limit: 100, cursor: more ? inv.cursor : undefined } })
    setInv({ codes: more ? [...inv.codes, ...r.codes] : r.codes, cursor: r.cursor, loaded: true, error: undefined, unreachableNodes: r.unreachableNodes })
  } catch (e) {
    setInv({ error: e })
  } finally {
    setInv({ busy: false })
  }
}

const publicBase = () => (clusterPoll.get().data?.publicUrl ?? location.origin).replace(/\/+$/, '')
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
      await admin('com.atproto.admin.disableInviteCodes', { body: { codes } })
      after?.()
      await loadInvites()
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
    const r = await admin<{ codes: { account: string; codes: string[] }[] }>('com.atproto.server.createInviteCodes', {
      body: { codeCount: Number(count), useCount: Number(uses), forAccounts: did ? [did] : undefined },
    })
    loadInvites()
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
  return c.disabled ? <Chip k="idle">disabled</Chip> : usesLeft(c) === 0 ? <Chip k="plain">used up</Chip> : <Chip k="ok">usable</Chip>
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
    useEffect(() => {
      if (!inv.loaded && !inv.busy) loadInvites()
    }, [])
    const c = s.codes.find((x) => x.code === id)
    if (!c) return { title: <span className="mono">{id}</span>, body: null, loading: !s.loaded || s.busy, missing: s.error ? errText(s.error) : `Not among the ${fmtNum(s.codes.length)} newest codes.` }
    const l = inviteLinks(c.code)
    return {
      title: <span className="mono">{c.code}</span>,
      chip: <InviteStatus c={c} />,
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
    const doms = (domainsPoll.get().data?.domains ?? []).map((d) => ({
      group: 'Domains',
      glyph: '.',
      title: `.${d.domain}`,
      desc: `${d.accounts === null ? '?' : fmtNum(d.accounts)} accounts${d.primary ? ' · primary' : ''}`,
      run: () => navigate(`/admin/domains?open=${encodeURIComponent(panelParam('domain', d.domain))}`),
    }))
    const codes = q.length >= 4 ? inv.codes.filter((c) => c.code.toLowerCase().includes(q.toLowerCase())).slice(0, 6) : []
    return [
      ...out,
      ...doms,
      ...codes.map((c) => ({ group: 'Invites', glyph: '›', title: c.code, desc: `${c.uses.length}/${c.available} used${c.disabled ? ' · disabled' : ''}`, run: () => navigate(`/admin/domains?open=${encodeURIComponent(panelParam('invite', c.code))}`) })),
    ]
  },
})
