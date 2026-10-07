import { type ReactNode } from 'react'
import { confirmAction, FormDialog, openDialog } from '../../components/console/dialogs'
import { Copy, KV } from '../../components/console/kit'
import { openPanel } from '../../components/console/nav'
import * as api from '../../lib/adminApi'
import type { AccountRow } from '../../lib/adminApi'
import { withAdmin } from '../../lib/console/adminAdapter'
import type { Change } from '../../lib/console/changes'
import { fmtBytes, fmtNum, plural } from '../../lib/console/fmt'
import { K } from '../../lib/console/keys'
import { mutate, patchAccountRow, put } from '../../lib/console/mutate'
import { queryClient } from '../../lib/console/query'
import { admin } from '../../lib/xrpc'

// Every action the Accounts section can take on one account, each behind a typed confirm that
// shows the call it makes. Shared by the account detail and ⌘K ("take down @handle"). Each runs
// as a mutation (lib/console/mutate.ts): what its answer settles is written into the cache (the
// account's row in every list, its status, its info), then the account, its lists and the audit
// log are refetched, here at once and in other tabs through the change feed.

export type Who = { did: string; handle: string; node?: string }

type SubjectStatus = { takedown?: { applied: boolean; ref?: string }; deactivated?: { applied: boolean } }

/** Runs an action on one account: `row` patches its row wherever it's cached, `then` writes more of the answer. */
function onAccount<R>(a: Who, run: () => Promise<R>, o: { row?: (r: AccountRow) => AccountRow | null; then?: (r: R) => unknown; also?: Change[] } = {}) {
  return mutate({
    run,
    write: async (r) => {
      if (o.row) patchAccountRow(a.did, o.row)
      await o.then?.(r)
    },
    changes: [{ kind: 'account', id: a.did }, ...(o.also ?? [])],
  })
}

/** What getSubjectStatus would answer now, from updateSubjectStatus's answer. */
function setStatus(did: string, p: Partial<SubjectStatus>) {
  const prev = queryClient.getQueryData<SubjectStatus>(K.accountStatus(did)) ?? {}
  return put(K.accountStatus(did), { ...prev, ...p })
}
function setInfo(did: string, p: Record<string, unknown>) {
  const prev = queryClient.getQueryData<Record<string, unknown>>(K.accountInfo(did))
  return prev ? put(K.accountInfo(did), { ...prev, ...p }) : undefined
}

const repoRef = (did: string) => ({ $type: 'com.atproto.admin.defs#repoRef', did })
const to = (a: Who) => (a.node ? ` → ${a.node}` : '')
const text = (v: string | boolean | undefined) => String(v ?? '').trim()

export const takeDown = (a: Who) =>
  confirmAction({
    tone: 'err',
    title: `Take down @${a.handle}?`,
    items: ['Its repo stops being served to apps, relays and AppViews.', 'An #account event goes out with status takendown.', 'Every session is revoked.'],
    fields: [{ id: 'ref', label: 'Reference (kept with the takedown)', placeholder: 'a case or ticket id' }],
    word: a.handle,
    action: 'Take down',
    call: `com.atproto.admin.updateSubjectStatus takedown${to(a)}`,
    run: (v) =>
      onAccount(a, () => admin('com.atproto.admin.updateSubjectStatus', { body: { subject: repoRef(a.did), takedown: { applied: true, ref: text(v.ref) || undefined } } }), {
        row: (r) => ({ ...r, status: 'takendown' }),
        then: () => setStatus(a.did, { takedown: { applied: true, ref: text(v.ref) || undefined } }),
        also: [{ kind: 'takedown', id: a.did }],
      }),
    done: `Took down @${a.handle}`,
  })

export const reverseTakedown = (a: Who) =>
  confirmAction({
    tone: 'warn',
    title: `Reverse the takedown of @${a.handle}?`,
    items: ['The repo is served again and an #account event says it is active.', 'Sessions revoked by the takedown stay revoked.'],
    word: a.handle,
    action: 'Reverse takedown',
    primary: true,
    call: `com.atproto.admin.updateSubjectStatus takedown off${to(a)}`,
    run: () =>
      onAccount(a, () => admin('com.atproto.admin.updateSubjectStatus', { body: { subject: repoRef(a.did), takedown: { applied: false } } }), {
        row: (r) => (r.status === 'takendown' ? { ...r, status: 'active' } : r),
        then: () => setStatus(a.did, { takedown: { applied: false } }),
        also: [{ kind: 'takedown', id: a.did }],
      }),
    done: `Reversed the takedown of @${a.handle}`,
  })

export const deactivate = (a: Who) =>
  confirmAction({
    tone: 'warn',
    title: `Deactivate @${a.handle}?`,
    items: ['The repo stops being served and an #account event says deactivated.', 'Any deletion the owner scheduled is cancelled.', 'Reactivate it here to serve it again.'],
    word: a.handle,
    action: 'Deactivate',
    call: `com.atproto.admin.updateSubjectStatus deactivated${to(a)}`,
    run: () =>
      onAccount(a, () => admin('com.atproto.admin.updateSubjectStatus', { body: { subject: repoRef(a.did), deactivated: { applied: true } } }), {
        row: (r) => (r.status === 'active' ? { ...r, status: 'deactivated' } : r),
        then: () => setStatus(a.did, { deactivated: { applied: true } }),
      }),
    done: `Deactivated @${a.handle}`,
  })

export const reactivate = (a: Who) =>
  confirmAction({
    tone: 'warn',
    title: `Reactivate @${a.handle}?`,
    items: ['The repo is served again and an #account event says it is active.', 'A scheduled deletion is cancelled.'],
    action: 'Reactivate',
    primary: true,
    call: `com.atproto.admin.updateSubjectStatus deactivated off${to(a)}`,
    run: () =>
      onAccount(a, () => admin('com.atproto.admin.updateSubjectStatus', { body: { subject: repoRef(a.did), deactivated: { applied: false } } }), {
        row: (r) => (r.status === 'deactivated' ? { ...r, status: 'active', deleteAfter: undefined } : r),
        then: () => setStatus(a.did, { deactivated: { applied: false } }),
      }),
    done: `Reactivated @${a.handle}`,
  })

export const deleteAccount = (a: Who, what?: { records?: number; blobs?: number }) =>
  confirmAction({
    tone: 'err',
    title: `Delete @${a.handle}?`,
    items: [
      `Erases the repo${what?.records !== undefined ? ` (${plural(what.records, 'record')})` : ''}, ${what?.blobs !== undefined ? plural(what.blobs, 'blob') : 'its blobs'} and the account record.`,
      'An #account event marks it deleted on the firehose.',
      'There is no undo. The DID stays in PLC, pointing here.',
    ],
    word: a.handle,
    action: 'Delete account',
    call: `com.atproto.admin.deleteAccount${to(a)}`,
    run: () => onAccount(a, () => admin('com.atproto.admin.deleteAccount', { body: { did: a.did } }), { row: () => null }),
    done: `Deleted @${a.handle}`,
  })

export const rotateKey = (a: Who) =>
  confirmAction({
    tone: 'err',
    title: `Rotate the signing key for @${a.handle}?`,
    items: [
      'Generates a new repo signing key and signs a PLC operation with the PDS rotation key.',
      'Re-signs the repo and sends an #identity event, so relays verify the next commit against the new key.',
      'The PLC directory rate-limits: keep this to a few at a time.',
    ],
    word: a.handle,
    action: 'Rotate key',
    call: `com.atproto.admin.updateAccountSigningKey${to(a)}`,
    run: () => onAccount(a, () => admin<{ signingKey: string }>('com.atproto.admin.updateAccountSigningKey', { body: { did: a.did } })),
    done: (r) => `New signing key ${(r as { signingKey?: string }).signingKey?.slice(0, 24) ?? ''}…`,
  })

export const publishIdentity = (a: Who) =>
  confirmAction({
    tone: 'warn',
    title: `Publish an #identity event for @${a.handle}?`,
    items: ['Relays and AppViews re-resolve the DID and handle.', 'Nothing about the account changes.'],
    action: 'Publish',
    primary: true,
    call: `vlpds.admin.publishIdentity${to(a)}`,
    run: () => onAccount(a, () => admin('vlpds.admin.publishIdentity', { body: { did: a.did } })),
    done: 'Published #identity',
  })

type RebuildDry = { records: number; before: { ok: boolean; problems?: string[] } }

/** A dry run first: its record count and problems go in the confirm. */
export async function rebuildRepo(a: Who) {
  const dry = await admin<RebuildDry>('vlpds.admin.rebuildRepo', { body: { did: a.did, dryRun: true } })
  const probs = dry.before.problems ?? []
  return confirmAction({
    tone: 'err',
    title: `Rebuild the repo of @${a.handle}?`,
    items: [
      `Re-derives it from its ${fmtNum(dry.records)} records under a new signed commit and emits a #sync.`,
      probs.length ? `The check found: ${probs.join('; ')}.` : 'The check found nothing wrong: a rebuild changes only the commit.',
      'A write landing in between fails it with InvalidSwap: run it again.',
    ],
    word: a.handle,
    action: 'Rebuild repo',
    call: `vlpds.admin.rebuildRepo${to(a)}`,
    run: () => onAccount(a, () => admin<{ rev: string }>('vlpds.admin.rebuildRepo', { body: { did: a.did } })),
    done: (r) => `Rebuilt at rev ${(r as { rev?: string }).rev ?? ''}`,
  })
}

export const signOutEverywhere = (a: Who, sessions?: number) =>
  confirmAction({
    tone: 'warn',
    title: `Sign @${a.handle} out everywhere?`,
    items: [
      `Revokes ${sessions !== undefined ? plural(sessions, 'session') : 'every session'}, every OAuth grant, device sign-in and trusted browser, as a password change does.`,
      'App passwords keep working: revoke them one by one.',
    ],
    fields: [{ id: 'reason', label: 'Reason (audited)' }],
    word: a.handle,
    action: 'Sign out everywhere',
    call: `vlpds.admin.revokeSessions (all)${to(a)}`,
    run: (v) => onAccount(a, () => withAdmin((c) => api.revokeSessions(c, { did: a.did, reason: text(v.reason) || undefined }))),
    done: 'Signed out everywhere',
  })

export const revokeSession = (a: Who, id: string, label: string) =>
  confirmAction({
    tone: 'warn',
    title: `Revoke ${label}?`,
    items: ['That session or grant stops working at its next request.', 'Other sessions keep working.'],
    action: 'Revoke',
    call: `vlpds.admin.revokeSessions {ids: ["${id}"]}${to(a)}`,
    run: () =>
      onAccount(a, () => withAdmin((c) => api.revokeSessions(c, { did: a.did, ids: [id] })), {
        // the session is gone: no need to wait for the list to say so
        then: () => {
          const prev = queryClient.getQueryData<{ did: string; sessions: api.Session[] }>(K.accountSessions(a.did))
          return prev && put(K.accountSessions(a.did), { ...prev, sessions: prev.sessions.filter((s) => s.id !== id) })
        },
      }),
    done: `Revoked ${label}`,
  })

export const revokeAppPassword = (a: Who, name: string) =>
  confirmAction({
    tone: 'warn',
    title: `Revoke the app password “${name}”?`,
    items: ['The password stops working, and so do the sessions it signed in.', 'The owner can make a new one.'],
    fields: [{ id: 'reason', label: 'Reason (audited)' }],
    action: 'Revoke',
    call: `vlpds.admin.revokeAppPassword {name: "${name}"}${to(a)}`,
    run: (v) => onAccount(a, () => withAdmin((c) => api.revokeAppPassword(c, { did: a.did, name, reason: text(v.reason) || undefined }))),
    done: `Revoked “${name}”`,
  })

export const resetSecondFactors = (a: Who) =>
  confirmAction({
    tone: 'err',
    title: `Reset two-factor sign-in for @${a.handle}?`,
    items: [
      'Removes their passkeys, authenticator app, recovery codes and trusted browsers.',
      'Their password and email codes stay. They are emailed about it.',
      'For someone who lost every factor: check who is asking first.',
    ],
    fields: [
      { id: 'reason', label: 'Reason (audited)', placeholder: 'how you checked it was them', required: true },
      { id: 'revoke', label: 'Also sign out everywhere', type: 'checkbox' },
    ],
    word: a.handle,
    action: 'Reset',
    call: `vlpds.admin.resetSecondFactors${to(a)}`,
    run: (v) => onAccount(a, () => admin('vlpds.admin.resetSecondFactors', { body: { did: a.did, reason: text(v.reason), revokeSessions: !!v.revoke } })),
    done: 'Two-factor sign-in reset',
  })

export const clearLockout = (a: Who) =>
  confirmAction({
    tone: 'warn',
    title: `Unlock sign-in codes for @${a.handle}?`,
    items: ['Clears the 2FA, recovery-code and email-code locks and their wrong-code counts.', 'Check it is them first: the codes were guessed wrong for a reason.'],
    fields: [{ id: 'reason', label: 'Reason (audited)', required: true }],
    action: 'Unlock',
    primary: true,
    call: `vlpds.admin.clearLockout${to(a)}`,
    run: (v) => onAccount(a, () => withAdmin((c) => api.clearLockout(c, { did: a.did, reason: text(v.reason) })), { also: [{ kind: 'lockout', id: a.did }] }),
    done: 'Unlocked',
  })

export const setInvites = (a: Who, enable: boolean) =>
  confirmAction({
    tone: 'warn',
    title: `${enable ? 'Allow' : 'Block'} invite codes for @${a.handle}?`,
    items: [enable ? 'The account may create invite codes again.' : 'The account can no longer create invite codes. Codes it already made keep working.'],
    action: enable ? 'Allow invites' : 'Block invites',
    primary: true,
    call: `com.atproto.admin.${enable ? 'enable' : 'disable'}AccountInvites`,
    run: () =>
      onAccount(a, () => admin(`com.atproto.admin.${enable ? 'enable' : 'disable'}AccountInvites`, { body: { account: a.did } }), {
        then: () => setInfo(a.did, { invitesDisabled: !enable }),
      }),
    done: enable ? 'Invites allowed' : 'Invites blocked',
  })

export const setHandle = (a: Who) =>
  confirmAction({
    tone: 'warn',
    title: `Change the handle of @${a.handle}?`,
    items: ['Sends an #identity event. The old handle is free for anyone to take.'],
    fields: [{ id: 'handle', label: 'New handle', placeholder: a.handle, required: true }],
    action: 'Set handle',
    primary: true,
    call: `com.atproto.admin.updateAccountHandle${to(a)}`,
    run: (v) => {
      const handle = text(v.handle).replace(/^@/, '')
      return onAccount(a, () => admin('com.atproto.admin.updateAccountHandle', { body: { did: a.did, handle } }), {
        row: (r) => ({ ...r, handle }),
        then: () => setInfo(a.did, { handle }),
      })
    },
    done: 'Handle updated',
  })

export const setEmail = (a: Who, current?: string) =>
  confirmAction({
    tone: 'warn',
    title: `Change the email of @${a.handle}?`,
    items: ['Mail for this account goes to the new address from now on.'],
    fields: [{ id: 'email', label: 'New email', placeholder: current, required: true }],
    action: 'Set email',
    primary: true,
    call: `com.atproto.admin.updateAccountEmail${to(a)}`,
    run: (v) => {
      const email = text(v.email)
      return onAccount(a, () => admin('com.atproto.admin.updateAccountEmail', { body: { account: a.did, email } }), {
        row: (r) => ({ ...r, email, emailConfirmed: false }),
        then: () => setInfo(a.did, { email, emailConfirmedAt: undefined }),
      })
    },
    done: 'Email updated',
  })

export const setPassword = (a: Who) =>
  confirmAction({
    tone: 'err',
    title: `Set a new password for @${a.handle}?`,
    items: ['The old password stops working.', 'Every session is signed out, as a password change does.'],
    fields: [{ id: 'password', label: 'New password', required: true }],
    word: a.handle,
    action: 'Set password',
    call: `com.atproto.admin.updateAccountPassword${to(a)}`,
    run: (v) => onAccount(a, () => admin('com.atproto.admin.updateAccountPassword', { body: { did: a.did, password: String(v.password ?? '') } })),
    done: 'Password set',
  })

export type Quota = {
  bytes: number
  uploadsToday: number
  limitBytes: number
  limitUploadsPerDay: number
  override: { bytes?: number; uploadsPerDay?: number }
  defaults: { bytes: number; uploadsPerDay: number }
  over: boolean
}

export const setQuota = (a: Who, q: Quota) =>
  confirmAction({
    tone: 'warn',
    title: `Change the blob quota of @${a.handle}?`,
    items: [`Defaults: ${(q.defaults.bytes / 1e9).toFixed(1)} GB and ${fmtNum(q.defaults.uploadsPerDay)} uploads a day. Leave both empty to go back to them.`],
    fields: [
      { id: 'gb', label: 'Bytes (GB)', type: 'number', initial: q.override.bytes !== undefined ? String(q.override.bytes / 1e9) : '' },
      { id: 'perDay', label: 'Uploads per day', type: 'number', initial: q.override.uploadsPerDay !== undefined ? String(q.override.uploadsPerDay) : '' },
      { id: 'reason', label: 'Reason (audited)' },
    ],
    action: 'Save quota',
    primary: true,
    call: 'vlpds.admin.setBlobQuota',
    run: (v) => {
      const body: Record<string, unknown> = { did: a.did, reason: text(v.reason) || undefined }
      if (text(v.gb)) body.bytes = Math.round(Number(text(v.gb)) * 1e9)
      if (text(v.perDay)) body.uploadsPerDay = Math.round(Number(text(v.perDay)))
      return onAccount(a, () => admin('vlpds.admin.setBlobQuota', { body }))
    },
    done: 'Quota saved',
  })

export const recountRepo = (a: Who) =>
  confirmAction({
    tone: 'warn',
    title: `Recount @${a.handle}'s repo?`,
    items: ['Reads the whole repo, as Check repo does, and replaces its kept counts and size with exact ones.', 'A commit landing meanwhile refuses it: run it again.'],
    action: 'Recount',
    primary: true,
    call: `vlpds.admin.recountRepo${to(a)}`,
    run: () => onAccount(a, () => withAdmin((c) => api.recountRepo(c, a.did))),
    done: (r) => {
      const b = (r as { repoBytes?: number | null }).repoBytes
      return `Recounted @${a.handle}${b != null ? `: ${fmtBytes(b)}` : ''}`
    },
  })

/** The password made for a new account, shown once. */
function Created({ made, close }: { made: { did: string; handle: string; password?: string }; close: () => void }) {
  return (
    <FormDialog title={`Created @${made.handle}`} icon="✓" action="Done" onSubmit={close} onCancel={close}>
      <KV
        rows={[
          ['DID', <Copy text={made.did} />],
          ...(made.password ? ([['Password', <Copy text={made.password} />]] as [string, ReactNode][]) : []),
        ]}
      />
      {made.password && <p className="t2 sm">Shown once. Hand it over; they can change it after signing in, or reset it by email.</p>}
    </FormDialog>
  )
}

/** As a sign-up, with no invite code; leaving the password blank generates one. */
export const createAccount = () => {
  let made: { did: string; handle: string; password?: string } | undefined
  return confirmAction({
    tone: 'warn',
    title: 'Create an account',
    items: ['Checks and claims the handle and email as a sign-up does, and registers the DID.', 'No invite code is needed. Audited as account.create.'],
    fields: [
      { id: 'handle', label: 'Handle', required: true, placeholder: 'alice.example.com' },
      { id: 'email', label: 'Email', required: true },
      { id: 'password', label: 'Password (blank: generate one)' },
      { id: 'reason', label: 'Reason (audited)' },
    ],
    action: 'Create',
    primary: true,
    call: 'vlpds.admin.createAccount',
    run: async (v) => {
      made = await mutate({
        run: () =>
          withAdmin((c) =>
            api.createAccount(c, {
              handle: text(v.handle).replace(/^@/, ''),
              email: text(v.email),
              password: text(v.password) || undefined,
              reason: text(v.reason) || undefined,
            }),
          ),
        changes: (r) => [{ kind: 'account', id: r.did }],
      })
      return made
    },
    done: () => `Created @${made?.handle ?? ''}`,
  }).then((ok) => {
    if (ok && made) {
      const m = made
      openPanel('account', m.did)
      if (m.password) openDialog((close) => <Created made={m} close={close} />)
    }
    return ok
  })
}
