import { useEffect, useState, type FormEvent } from 'react'
import { Confirm, CopyText, Empty, ErrorNotice, JsonView, Loading, Notice, PageHead, Panel, Spinner } from '../../components/ui'
import { fmtNum, fmtTime, short } from '../../lib/format'
import { useAction, useLoad, useSession } from '../../lib/hooks'
import { ACCOUNT_CALLBACK_PATH, clientInfo, type OAuthSession } from '../../lib/oauth'
import { Link, navigate, useSearch } from '../../lib/router'
import {
  connect,
  disconnect,
  governance,
  listSpaces,
  myRepo,
  OWNER_SCOPE,
  readText,
  pool,
  READ_SCOPE,
  resolveMember,
  spacePath,
  spaceUri,
  useIdentity,
  useSpacesSession,
  type Governance,
  type MyRepo,
  type SpaceRef,
  writeText,
} from '../../lib/spaces'
import { Nsid, preview } from './Repo'

const base = '/account/spaces'

/** A DID as its handle when the handle verifies back to it, else the DID itself. */
function Who({ did, you }: { did: string; you?: string }) {
  const id = useIdentity(did)
  if (did === you) return <b>you</b>
  return id.handle ? (
    <span title={did}>@{id.handle}</span>
  ) : (
    <span className="mono" title={did}>
      {short(did, 12)}
    </span>
  )
}

function SpaceName({ s }: { s: SpaceRef }) {
  return (
    <span className="space-name">
      <Nsid nsid={s.type} />
      <span className="muted mono small">{s.skey}</span>
    </span>
  )
}

function lastWrite(r: MyRepo) {
  return r.lastWrite ? fmtTime(r.lastWrite) : '—'
}

function count(r: MyRepo) {
  return `${fmtNum(r.records)}${r.more ? '+' : ''}`
}

/** Signs in for this section only: the rest of /account stays on the password session. */
function ConnectPanel({ error }: { error?: unknown }) {
  const s = useSession()!
  const client = clientInfo(ACCOUNT_CALLBACK_PATH)
  const go = useAction(() => connect(s.did, READ_SCOPE, base))
  return (
    <Panel title="Connect to see your spaces">
      <ErrorNotice error={error || go.error} />
      <p>
        Spaces hold data that isn't public: what you write in a group or a private app lives in a space, and only the people the space admits can read
        it. Your password can't open it. This page asks for a separate permission, just for this section, to read your own space data on{' '}
        {location.hostname} and nothing else.
      </p>
      <p className="small muted">
        It lasts while you stay in this section. Leaving it or signing out revokes it, and nothing is kept in this browser after that.
      </p>
      {!client && <Notice kind="warn">Connecting needs this page on https (or http://127.0.0.1 for development).</Notice>}
      <details className="small scope-details">
        <summary>What it asks for</summary>
        <span className="mono">{READ_SCOPE}</span>
        <p className="muted">
          Read your own records in any space, and the settings and member lists of the spaces you run. Changing members or deleting a space asks again,
          separately.
        </p>
      </details>
      <div className="row end">
        <button type="button" className="btn primary" name="spaces-connect" disabled={go.busy || !client} onClick={() => go.run()}>
          {go.busy && <Spinner />}
          Connect
        </button>
      </div>
    </Panel>
  )
}

function DisconnectButton() {
  const [busy, setBusy] = useState(false)
  return (
    <button
      type="button"
      className="btn sm"
      name="spaces-disconnect"
      disabled={busy}
      onClick={() => {
        setBusy(true)
        void disconnect().finally(() => setBusy(false))
      }}
    >
      {busy && <Spinner />}
      Disconnect
    </button>
  )
}

type Row = { s: SpaceRef; mine: MyRepo | null; gov?: Governance; error?: unknown }

async function overview(sess: OAuthSession): Promise<Row[]> {
  const all = await listSpaces(sess)
  return pool(all, 4, async (s) => {
    try {
      const [mine, gov] = await Promise.all([myRepo(sess, s.uri), s.authority === sess.did ? governance(sess, s.uri) : Promise.resolve(undefined)])
      return { s, mine, gov }
    } catch (e) {
      return { s, mine: null, error: e }
    }
  })
}

export function SpacesHome() {
  const me = useSession()!
  const { session, loading, error } = useSpacesSession(me.did)
  const head = (
    <PageHead
      title="Your spaces"
      desc="Data you've written in spaces, and the spaces you run. Only you and the people a space lets in can read it."
    />
  )
  if (loading)
    return (
      <>
        {head}
        <Loading />
      </>
    )
  if (!session)
    return (
      <>
        {head}
        <ConnectPanel error={error} />
      </>
    )
  return (
    <>
      {head}
      <Overview sess={session} />
    </>
  )
}

function Overview({ sess }: { sess: OAuthSession }) {
  const d = useLoad(() => overview(sess), [sess])
  const rows = d.data ?? []
  const written = rows.filter((r) => r.mine)
  const governed = rows.filter((r) => r.s.authority === sess.did)
  const failed = rows.filter((r) => r.error)
  return (
    <>
      <div className="row between spaces-bar">
        <span className="small muted">Connected for this section only.</span>
        <DisconnectButton />
      </div>
      <ErrorNotice error={d.error} />
      {failed.length > 0 && (
        <Notice kind="warn">
          {failed.length === 1 ? 'One space' : `${failed.length} spaces`} couldn't be read just now: {failed.map((f) => f.s.uri).join(', ')}.
        </Notice>
      )}
      <Panel title="Spaces you write in" desc={d.data ? `${written.length} ${written.length === 1 ? 'space' : 'spaces'}` : undefined} flush id="spaces-written">
        {!d.data ? (
          !d.error && <Loading />
        ) : written.length === 0 ? (
          <Empty title="Nothing written in a space yet">When an app saves something of yours in a space, it shows up here.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="data spaces-table">
              <thead>
                <tr>
                  <th>Space</th>
                  <th className="hide-sm">Run by</th>
                  <th className="num">Records</th>
                  <th className="hide-sm">Last write</th>
                </tr>
              </thead>
              <tbody>
                {written.map((r) => (
                  <tr key={r.s.uri} className="link" onClick={() => navigate(spacePath(r.s))}>
                    <td>
                      <Link to={spacePath(r.s)} onClick={(e) => e.stopPropagation()}>
                        <SpaceName s={r.s} />
                      </Link>
                      <span className="sm-meta small muted">
                        Run by <Who did={r.s.authority} you={sess.did} /> · {lastWrite(r.mine!)}
                      </span>
                    </td>
                    <td className="hide-sm">
                      <Who did={r.s.authority} you={sess.did} />
                    </td>
                    <td className="num">{count(r.mine!)}</td>
                    <td className="hide-sm nowrap">{lastWrite(r.mine!)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <Panel title="Spaces you run" desc={d.data ? `${governed.length} ${governed.length === 1 ? 'space' : 'spaces'}` : undefined} flush id="spaces-governed">
        {!d.data ? (
          !d.error && <Loading />
        ) : governed.length === 0 ? (
          <Empty title="You don't run any spaces">A space an app creates for you (a group you start, say) shows up here.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="data spaces-table">
              <thead>
                <tr>
                  <th>Space</th>
                  <th className="num">Members</th>
                  <th className="num">Writers</th>
                  <th className="hide-sm">Who can read · write</th>
                </tr>
              </thead>
              <tbody>
                {governed.map((r) => (
                  <tr key={r.s.uri} className="link" onClick={() => navigate(spacePath(r.s))}>
                    <td>
                      <Link to={spacePath(r.s)} onClick={(e) => e.stopPropagation()}>
                        <SpaceName s={r.s} />
                      </Link>
                      {r.gov && (
                        <span className="sm-meta small muted">
                          Read: {readText(r.gov.policy)} · write: {writeText(r.gov.policy)}
                        </span>
                      )}
                    </td>
                    <td className="num">{r.gov?.memberList ? `${fmtNum(r.gov.members.length)}${r.gov.more ? '+' : ''}` : '—'}</td>
                    <td className="num">{r.gov ? writers(r.gov) : '—'}</td>
                    <td className="hide-sm">{r.gov ? `${readText(r.gov.policy)} · ${writeText(r.gov.policy)}` : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  )
}

/** Who can write besides the owner: members with write, everyone (publicWrite), an app, or no one. */
function writers(g: Governance): string {
  if (!g.memberList) return g.policy.managingApp ? 'app' : '—'
  if (g.policy.publicWrite) return 'anyone'
  return `${fmtNum(g.members.filter((m) => m.write).length)}${g.more ? '+' : ''}`
}

// ---------------------------------------------------------------- one space

export function SpaceView({ authority, type, skey }: { authority: string; type: string; skey: string }) {
  const me = useSession()!
  const { session, loading, error } = useSpacesSession(me.did)
  const s: SpaceRef = { uri: spaceUri(authority, type, skey), authority, type, skey }
  const head = (
    <PageHead
      title={
        <>
          <Nsid nsid={type} /> <span className="muted mono">{skey}</span>
        </>
      }
      crumbs={[{ to: base, label: 'Your spaces' }]}
    />
  )
  if (loading)
    return (
      <>
        {head}
        <Loading />
      </>
    )
  if (!session)
    return (
      <>
        {head}
        <ConnectPanel error={error} />
      </>
    )
  return (
    <>
      {head}
      <SpaceBody sess={session} s={s} />
    </>
  )
}

function SpaceBody({ sess, s }: { sess: OAuthSession; s: SpaceRef }) {
  const owner = s.authority === sess.did
  const mine = useLoad(() => myRepo(sess, s.uri), [sess, s.uri])
  const gov = useLoad(() => (owner ? governance(sess, s.uri) : Promise.resolve(undefined)), [sess, s.uri, owner])
  return (
    <>
      <div className="row between spaces-bar">
        <span className="small muted">Connected for this section only.</span>
        <DisconnectButton />
      </div>
      <ErrorNotice error={mine.error || gov.error} />
      <Panel>
        <dl className="dl">
          <dt>Type</dt>
          <dd className="mono">{s.type}</dd>
          <dt>Run by</dt>
          <dd>
            <Who did={s.authority} /> {owner && <span className="pill accent">you</span>}
          </dd>
          <dt>Address</dt>
          <dd>
            <CopyText text={s.uri} />
          </dd>
          <dt>Your records</dt>
          <dd>{mine.data === undefined ? '…' : mine.data ? count(mine.data) : 'none'}</dd>
          <dt>Last write</dt>
          <dd>{mine.data ? lastWrite(mine.data) : '—'}</dd>
        </dl>
      </Panel>
      {mine.data && <MyRecords sess={sess} s={s} />}
      {owner && gov.data && <Governed sess={sess} s={s} gov={gov.data} reload={gov.reload} />}
    </>
  )
}

type Rec = { collection: string; rkey: string; cid: string; value: any }
const PAGE = 50

/** Your own records here: values shown only to you, the signed-in owner of the repo. */
function MyRecords({ sess, s }: { sess: OAuthSession; s: SpaceRef }) {
  const [recs, setRecs] = useState<Rec[]>([])
  const [cursor, setCursor] = useState<string>()
  const [open, setOpen] = useState<string>()
  const [first, setFirst] = useState(true)
  const page = useAction(async (cur?: string) => {
    const r = await sess.call('com.atproto.space.listRecords', { params: { space: s.uri, repo: sess.did, limit: PAGE, cursor: cur } })
    setRecs((x) => (cur ? [...x, ...(r.records ?? [])] : (r.records ?? [])))
    setCursor(r.cursor)
    setFirst(false)
  })
  useEffect(() => {
    setRecs([])
    setFirst(true)
    void page.run(undefined)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.uri, sess])
  const key = (r: Rec) => `${r.collection}/${r.rkey}`
  return (
    <Panel title="Your records here" desc="Only you can see these values on this page. Newest first." flush id="space-records">
      <ErrorNotice error={page.error} />
      {first && page.busy ? (
        <Loading />
      ) : recs.length === 0 ? (
        <Empty title="No records" />
      ) : (
        <>
          <div className="table-wrap">
            <table className="data spaces-records">
              <thead>
                <tr>
                  <th>Record</th>
                  <th>Content</th>
                </tr>
              </thead>
              <tbody>
                {recs.map((r) => {
                  const k = key(r)
                  const shown = open === k
                  return [
                    <tr key={k} className="link" aria-expanded={shown} onClick={() => setOpen(shown ? undefined : k)}>
                      <td className="nowrap">
                        <button type="button" className="linklike mono" onClick={(e) => (e.stopPropagation(), setOpen(shown ? undefined : k))}>
                          {r.rkey}
                        </button>
                        <span className="small muted" style={{ display: 'block' }}>
                          {r.collection}
                        </span>
                      </td>
                      <td>
                        <span className="preview">{preview(r.value) || <span className="muted">{r.value?.$type}</span>}</span>
                      </td>
                    </tr>,
                    shown && (
                      <tr key={`${k}#v`} className="record-open">
                        <td colSpan={2}>
                          <div className="row between small muted">
                            <span className="mono">{short(r.cid, 10)}</span>
                            <CopyText text={JSON.stringify(r.value, null, 2)} display="Copy JSON" mono={false} />
                          </div>
                          <JsonView value={r.value} />
                        </td>
                      </tr>
                    ),
                  ]
                })}
              </tbody>
            </table>
          </div>
          {cursor && (
            <div className="row end panel-foot">
              <button className="btn" onClick={() => page.run(cursor)} disabled={page.busy}>
                {page.busy && <Spinner />}
                Load {PAGE} more
              </button>
            </div>
          )}
        </>
      )}
    </Panel>
  )
}

/** Members and policy, and (after a second, wider grant) the owner controls. */
function Governed({ sess, s, gov, reload }: { sess: OAuthSession; s: SpaceRef; gov: Governance; reload: () => void }) {
  const q = useSearch()
  const [manage, setManage] = useState(q.get('manage') === '1')
  const granted = sess.grants(OWNER_SCOPE)
  const here = `${spacePath(s)}?manage=1`
  const ask = useAction(() => connect(sess.did, `${READ_SCOPE} ${OWNER_SCOPE}`, here))
  const [removing, setRemoving] = useState<string>()
  const remove = useAction(async (did: string) => {
    await sess.call('com.atproto.memberspace.removeMember', { body: JSON.stringify({ space: s.uri, did }), type: 'application/json' })
    setRemoving(undefined)
    reload()
  })
  const controls = manage && granted
  return (
    <>
      <Panel
        title="Members"
        desc={`${gov.memberList ? `${fmtNum(gov.members.length)}${gov.more ? '+' : ''} ${gov.members.length === 1 ? 'member' : 'members'}. ` : ''}Read: ${readText(gov.policy)}. Write: ${writeText(gov.policy)}.`}
        actions={
          !manage && (
            <button type="button" className="btn sm" name="spaces-manage" onClick={() => setManage(true)}>
              Manage
            </button>
          )
        }
        flush
        id="space-members"
      >
        {!gov.memberList ? (
          <Empty title={gov.policy.managingApp ? 'An app decides who is in this space' : 'No member list'}>
            {gov.policy.managingApp ? <span className="mono break">{gov.policy.managingApp}</span> : 'Only you can read and write here.'}
          </Empty>
        ) : gov.members.length === 0 ? (
          <Empty title="No members yet" />
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Member</th>
                  <th>Access</th>
                  {controls && (
                    <th>
                      <span className="sr-only">Remove</span>
                    </th>
                  )}
                </tr>
              </thead>
              <tbody>
                {gov.members.map((m) => (
                  <tr key={m.did}>
                    <td className="break">
                      <Who did={m.did} />
                    </td>
                    <td>
                      <span className={`pill${m.write ? ' accent' : ''}`}>{m.write ? 'read and write' : m.read ? 'read' : 'none'}</span>
                    </td>
                    {controls && (
                      <td className="num">
                        <button type="button" className="btn sm danger" name="spaces-remove" onClick={() => setRemoving(m.did)}>
                          Remove
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {gov.policy.allowedApps && <p className="small muted panel-foot">Apps allowed: {gov.policy.allowedApps.join(', ') || 'none'}</p>}
      </Panel>
      {manage && !granted && (
        <Panel title="Manage this space" id="space-grant">
          <ErrorNotice error={ask.error} />
          <p>
            Adding or removing members and deleting the space need one more permission: to change and delete the spaces you run (only yours, never
            anyone else's). You'll be asked to approve it, then come straight back here.
          </p>
          <details className="small scope-details">
            <summary>What it asks for</summary>
            <span className="mono">{OWNER_SCOPE}</span>
          </details>
          <div className="row between">
            <button type="button" className="btn quiet" onClick={() => setManage(false)}>
              Not now
            </button>
            <button type="button" className="btn primary" name="spaces-allow-manage" disabled={ask.busy} onClick={() => ask.run()}>
              {ask.busy && <Spinner />}
              Allow managing
            </button>
          </div>
        </Panel>
      )}
      {controls && gov.memberList && <AddMember sess={sess} s={s} reload={reload} />}
      {controls && <DeleteSpace sess={sess} s={s} />}
      <Confirm
        open={!!removing}
        title="Remove this member?"
        action="Remove"
        danger
        busy={remove.busy}
        onConfirm={() => removing && remove.run(removing)}
        onClose={() => setRemoving(undefined)}
      >
        <ErrorNotice error={remove.error} />
        {removing && <Who did={removing} />} won't be able to read or write in this space any more. What they already wrote stays in their own
        repo.
      </Confirm>
    </>
  )
}

function AddMember({ sess, s, reload }: { sess: OAuthSession; s: SpaceRef; reload: () => void }) {
  const [handle, setHandle] = useState('')
  const [access, setAccess] = useState<'read' | 'write'>('write')
  const [pending, setPending] = useState<{ did: string; handle?: string }>()
  const [done, setDone] = useState<string>()
  const look = useAction(async () => setPending(await resolveMember(handle)))
  const add = useAction(async () => {
    if (!pending) return
    await sess.call('com.atproto.memberspace.putMember', {
      body: JSON.stringify({ space: s.uri, did: pending.did, read: true, write: access === 'write' }),
      type: 'application/json',
    })
    setDone(pending.handle ? `@${pending.handle}` : pending.did)
    setPending(undefined)
    setHandle('')
    reload()
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setDone(undefined)
    void look.run()
  }
  return (
    <Panel title="Add a member" id="space-add">
      <ErrorNotice error={look.error} />
      {done && <Notice kind="ok">Added {done}.</Notice>}
      <form onSubmit={submit} className="add-member">
        <div className="field">
          <label>
            <span className="label">Handle</span>
            <input
              type="text"
              name="member-handle"
              value={handle}
              onChange={(e) => setHandle(e.target.value)}
              placeholder="alice.example.com"
              autoCapitalize="none"
              autoComplete="off"
              spellCheck={false}
              required
            />
          </label>
        </div>
        <div className="field">
          <label>
            <span className="label">Access</span>
            <select name="member-access" value={access} onChange={(e) => setAccess(e.target.value as 'read' | 'write')}>
              <option value="write">Read and write</option>
              <option value="read">Read only</option>
            </select>
          </label>
        </div>
        <button className="btn primary" name="spaces-add" disabled={look.busy}>
          {look.busy && <Spinner />}
          Add
        </button>
      </form>
      <Confirm
        open={!!pending}
        title="Add this member?"
        action="Add member"
        busy={add.busy}
        onConfirm={() => add.run()}
        onClose={() => setPending(undefined)}
      >
        <ErrorNotice error={add.error} />
        {pending && (
          <>
            <b>{pending.handle ? `@${pending.handle}` : pending.did}</b> <span className="mono small">({short(pending.did, 12)})</span> will be able to{' '}
            {access === 'write' ? 'read and write' : 'read'} in this space.
          </>
        )}
      </Confirm>
    </Panel>
  )
}

function DeleteSpace({ sess, s }: { sess: OAuthSession; s: SpaceRef }) {
  const [open, setOpen] = useState(false)
  const del = useAction(async () => {
    await sess.call('com.atproto.space.deleteSpace', { body: JSON.stringify({ space: s.uri }), type: 'application/json' })
    setOpen(false)
    navigate(base)
  })
  return (
    <Panel title="Delete this space" danger desc="Its member list and settings go, and so do your own records in it. Members' records stay in their own repos.">
      <ErrorNotice error={del.error} />
      <button type="button" className="btn danger" name="spaces-delete" onClick={() => setOpen(true)}>
        Delete space
      </button>
      <Confirm
        open={open}
        title="Delete this space?"
        action="Delete space"
        danger
        confirmText={s.skey}
        busy={del.busy}
        onConfirm={() => del.run()}
        onClose={() => setOpen(false)}
      >
        <span className="mono break">{s.uri}</span> will be deleted for everyone in it. This can't be undone.
      </Confirm>
    </Panel>
  )
}
