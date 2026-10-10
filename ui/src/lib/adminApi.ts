// Typed client for the operator console's admin API (docs/operations/admin-console.md, "Console API").
// Self-contained: give it the admin token and, for calls about one node's own
// state, the node to ask. Every time is unix ms; every seq is a string (seqs
// are past 2^53).

export class AdminApiError extends Error {
  status: number
  error: string
  constructor(status: number, error: string, message: string) {
    super(message || error)
    this.status = status
    this.error = error
  }
}

export type AdminClient = {
  /** The admin token (`--admin-token`); unset behind a proxy that names the operator. */
  token?: string
  /** Another server's origin; default this one. */
  base?: string
}

type Params = Record<string, string | number | boolean | undefined | null>

/** Relays a vlpds.admin.* call to another node over peer mTLS. */
const NODE_HEADER = 'x-vlpds-node'

async function call<T>(
  c: AdminClient,
  nsid: string,
  o: { params?: Params; body?: unknown; node?: string; signal?: AbortSignal } = {},
): Promise<T> {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(o.params ?? {})) {
    if (v !== undefined && v !== null && v !== '') u.set(k, String(v))
  }
  const q = u.toString()
  const headers: Record<string, string> = c.token ? { Authorization: `Basic ${btoa(`admin:${c.token}`)}` } : {}
  if (o.body !== undefined) headers['Content-Type'] = 'application/json'
  if (o.node) headers[NODE_HEADER] = o.node
  const r = await fetch(`${c.base ?? ''}/xrpc/${nsid}${q ? `?${q}` : ''}`, {
    method: o.body !== undefined ? 'POST' : 'GET',
    headers,
    body: o.body !== undefined ? JSON.stringify(o.body) : undefined,
    signal: o.signal,
  })
  const text = await r.text()
  let body: any = undefined
  try {
    body = text ? JSON.parse(text) : undefined
  } catch {
    body = text
  }
  if (!r.ok) {
    const e = typeof body === 'object' && body ? body : {}
    throw new AdminApiError(r.status, e.error ?? `HTTP ${r.status}`, e.message ?? (typeof body === 'string' ? body : ''))
  }
  return body as T
}

/** Set on every answer gathered from all nodes. */
export type Gathered = {
  /** Peers that didn't answer (or whose build lacks the call). */
  unreachableNodes?: string[]
}

/** One node's entry in a gathered answer; `reachable: false` rows carry nothing else. */
export type NodeTagged = { node: string; self: boolean; reachable: boolean }

// ------------------------------------------------------------------ accounts

export type AccountFilter = 'all' | 'attention' | 'deactivated' | 'takendown' | 'no2fa' | 'unconfirmed'

export type AccountRow = {
  did: string
  handle: string
  email?: string | null
  emailConfirmed: boolean
  /** RFC 3339. */
  createdAt: string
  /** active | deactivated | takendown | suspended | deleted */
  status: string
  shard: number
  /** The node that read it (its shard's owner). */
  node: string
  invitesDisabled: boolean
  secondFactors: { passkeys: number; totp: boolean; emailCode: boolean }
  blobBytes: number
  overQuota: boolean
  /** From the repo's kept counts; absent for an account without a repo. */
  records?: number
  mstNodes?: number
  /** Distinct blobs the records reference. */
  blobs?: number
  /** Record blocks + MST node blocks (what a getRepo CAR carries). The record part is close, not exact, between recounts (recountRepo); the node part is exact; absent until the repo's next load counts it. */
  repoBytes?: number
  recordBytes?: number
  mstBytes?: number
  /** TID of the head commit. */
  rev?: string
  lastCommitAt?: number
  deactivatedAt?: string
  deleteAfter?: string
  takedownRef?: string
}

export type ListAccountsParams = {
  /** Handle prefix (leading @ ignored), email prefix or DID. A whole DID is one lookup. */
  q?: string
  filter?: AccountFilter
  /** recent: newest commit first (default without q). slot: every account, in cursor order (default with q). */
  sort?: 'recent' | 'slot'
  cursor?: string
  /** 1-200, default 50. */
  limit?: number
}

/** Every account, from the shards' kept totals (no scan). */
export type AccountCounts = {
  total: number
  active: number
  deactivated: number
  takendown: number
  suspended: number
  unconfirmed: number
  /** Active, with no second factor on the account row. */
  no2fa: number
  /** A shard's totals are loading, a node didn't answer or a shard has no owner. */
  approximate: boolean
}

export type ListAccountsResult = Gathered & {
  accounts: AccountRow[]
  /** Absent on a whole-DID lookup. */
  counts?: AccountCounts
  /** Pass back for the next page; absent at the end. */
  cursor?: string
  sort?: 'recent' | 'slot'
  /** A whole-DID lookup answered directly. */
  exact?: boolean
  unsupportedNodes?: string[]
  /** Shards no answering node owned (mid-move): their accounts are missing. */
  missingShards?: number[]
}

export const listAccounts = (c: AdminClient, p: ListAccountsParams = {}, signal?: AbortSignal) =>
  call<ListAccountsResult>(c, 'vlpds.admin.listAccounts', { params: p, signal })

export type AccountKeys = {
  did: string
  /** Multibase multikey of the account's signing key. */
  signingKey: string
  pendingSigningKey?: string | null
  /** From the DID document (the resolver's cache). */
  verificationMethods?: { id: string; type: string; controller?: string; publicKeyMultibase?: string | null; matchesAccount: boolean }[]
  alsoKnownAs?: string[]
  pds?: string | null
  didDocError?: string
  /** did:plc only, from the directory (one request). */
  rotationKeys?: { didKey: string; role: 'server' | 'operator_recovery' | 'other' }[]
  rotationKeysError?: string
}

/** `refresh`: drop the cached DID document first. */
export const getAccountKeys = (c: AdminClient, did: string, refresh = false, signal?: AbortSignal) =>
  call<AccountKeys>(c, 'vlpds.admin.getAccountKeys', { params: { did, refresh: refresh || undefined }, signal })

/** As createAccount, no invite needed. Without `password`, one is generated and returned once. */
export const createAccount = (
  c: AdminClient,
  input: { handle: string; email: string; password?: string; reason?: string; actor?: string },
) => call<Audited & { did: string; handle: string; password?: string }>(c, 'vlpds.admin.createAccount', { body: input })

type RepoCounts = { records: number; nodes: number; blobs: number; recordBytes?: number | null; nodeBytes?: number | null }

/** Counts the repo from a snapshot and installs it (InvalidSwap if a commit landed meanwhile: run it again). */
export const recountRepo = (c: AdminClient, did: string) =>
  call<{ did: string; before?: RepoCounts | null; after: RepoCounts; repoBytes?: number | null }>(c, 'vlpds.admin.recountRepo', {
    body: { did },
  })

// --------------------------------------------------------- account security

export type FactorLockKind = 'second_factor' | 'email_code'

export type AccountSecurity = {
  did: string
  passwordSet: boolean
  oauthOnly: boolean
  blockAppPasswords: boolean
  /** A password sign-in asks for a second factor. */
  secondFactorRequired: boolean
  passkeys: { name: string; createdAt: number; lastUsedAt?: number | null; backedUp: boolean; suspect: boolean; transports: string[] }[]
  totp: { enabled: boolean; enabledAt?: string | null }
  emailCode: { enabled: boolean; since?: string | null }
  recoveryCodes: { remaining: number; total: number; issuedAt?: number | null }
  /** Wrong-code counts, and the lock while one is in force. */
  lockouts: { factor: FactorLockKind; failures: number; lockedUntil?: number | null }[]
  trustedBrowsers: { device: string; ip?: string | null; createdAt: number; lastUsedAt: number; expiresAt: number }[]
  appPasswords: { name: string; createdAt: string; privileged: boolean; scopes?: string | null }[]
  /** Newest first, last 30 days: at most 50 sign-ins and 20 refused ones (`failed` set). */
  recentSignIns: {
    /** A refused entry's latest attempt. */
    at: number
    method: 'password' | 'app_password' | 'oauth' | 'passkey' | string
    appPassword?: string | null
    clientId?: string | null
    /** Parsed from `userAgent`: "Chrome on macOS". */
    device: string
    userAgent?: string | null
    ip?: string | null
    factor?: string | null
    newDevice: boolean
    /** Refused. Like attempts (method, reason, address) within 10 minutes are one entry. */
    failed?: SignInFailure
    /** The attempts a refused entry stands for, and its first. */
    count?: number
    firstAt?: number
  }[]
}

export type SignInFailure = 'wrong_password' | 'wrong_code' | 'factor_locked' | 'rate_limited'

export const getAccountSecurity = (c: AdminClient, did: string, signal?: AbortSignal) =>
  call<AccountSecurity>(c, 'vlpds.admin.getAccountSecurity', { params: { did }, signal })

// ----------------------------------------------------------------- sessions

export type Session =
  | {
      /** `oauth:{id}`: pass to revokeSessions. */
      id: string
      kind: 'oauth'
      clientId: string
      scope: string
      signedInAt: number
      /** Last token refresh. */
      refreshedAt: number
      expiresAt?: number | null
      device?: string | null
      userAgent?: string | null
      deviceLastSeenAt?: number | null
      passkey: boolean
      /** Client address at the latest refresh, and at sign-in. */
      ip?: string | null
      signedInIp?: string | null
    }
  | {
      /** `legacy:{family}` */
      id: string
      kind: 'legacy' | 'appPassword'
      appPassword?: string | null
      privileged: boolean
      signedInAt?: number | null
      refreshedAt: number
      expiresAt: number
      passkey: boolean
      ip?: string | null
      signedInIp?: string | null
    }

export const listSessions = (c: AdminClient, did: string, signal?: AbortSignal) =>
  call<{ did: string; sessions: Session[] }>(c, 'vlpds.admin.listSessions', { params: { did }, signal })

export type Audited = { auditId: string }

/** No `ids`: every session, OAuth grant, device sign-in and trusted browser. App passwords keep working. */
export const revokeSessions = (c: AdminClient, input: { did: string; ids?: string[]; reason?: string; actor?: string }) =>
  call<Audited & { did: string; revoked: { all: boolean; oauth: number; legacy: number } }>(c, 'vlpds.admin.revokeSessions', {
    body: input,
  })

export const revokeAppPassword = (c: AdminClient, input: { did: string; name: string; reason?: string; actor?: string }) =>
  call<Audited & { did: string; name: string }>(c, 'vlpds.admin.revokeAppPassword', { body: input })

// ------------------------------------------------------------------ repo ops

export type RepoEvent = { seq: string; time?: string | null } & (
  | { kind: 'commit'; rev: string; commit?: string | null; ops: { action: 'create' | 'update' | 'delete'; path: string; cid?: string | null }[] }
  | { kind: 'sync'; rev: string }
  | { kind: 'identity'; handle?: string | null }
  | { kind: 'account'; active: boolean; status?: string | null }
)

export type RepoOpsResult = {
  did: string
  /** Newest first. */
  events: RepoEvent[]
  /** Ring events looked at. */
  scanned: number
  /** True: the whole in-memory ring was read, so nothing older is listed. */
  ringExhausted: boolean
  ringFloor: string
  /** The oldest seq looked at, and its time when seqs are time-based. */
  reachesBackTo?: string
  reachesBackToTime?: number
}

/** From the firehose ring in memory (no bucket reads): as far back as the ring reaches. */
export const listRepoOps = (c: AdminClient, did: string, limit = 25, signal?: AbortSignal) =>
  call<RepoOpsResult>(c, 'vlpds.admin.listRepoOps', { params: { did, limit }, signal })

// -------------------------------------------------------------- node metrics

export type MetricsPoint = {
  /** End of the interval. */
  t: number
  commitsPerSec: number
  opsPerSec: number
  httpPerSec: number
  http5xxPerSec: number
  rateLimitedPerSec: number
  firehoseEventsPerSec: number
  firehoseBytesPerSec: number
  repoLoadsPerSec: number
  /** Billable object-store requests: A = writes, lists, CAS; B = reads. */
  classAPerSec: number
  classBPerSec: number
  storeErrorsPerSec: number
  /** Cores busy (1 = one core). */
  cpuCores: number
  rssBytes: number
  subscribers: number
  cachedRepos: number
  mailQueue: number
  commitP50Ms?: number | null
  commitP99Ms?: number | null
  putP50Ms?: number | null
  putP99Ms?: number | null
  emitP99Ms?: number | null
}

export type NodeMetrics = NodeTagged & {
  /** Oldest first, one per interval ending after `since`. */
  series?: MetricsPoint[]
  /** The last 10 s. */
  latest?: MetricsPoint | null
  /** Object-store requests by key component over the whole kept window (`storeWindowMs`), busiest first. */
  storeComponents?: { component: string; classAPerSec: number; classBPerSec: number }[]
  storeWindowMs?: number
  intervalMs?: number
  cpuLimitCores?: number
  memoryLimitBytes?: number
  startedAt?: number
}

/** `since`: only points after it (poll with the last `t` you have); 0 or absent: the last 3 minutes. */
export const getNodeMetrics = (c: AdminClient, since?: number, signal?: AbortSignal) =>
  call<Gathered & { time: number; nodes: NodeMetrics[] }>(c, 'vlpds.admin.getNodeMetrics', { params: { since }, signal })

// ----------------------------------------------------------------- segments

export type Segment = {
  ordinal: number
  /** Sequenced entries: firehose events plus private-state writes (OAuth, Spaces, GC). */
  entries: number
  events: number
  firstSeq: string
  lastSeq: string
  bytes: number
  /** Compressed, as stored; 0 until durable. */
  storedBytes: number
  sealedAt: number
  /** Null while its PUT (or an earlier one) is in flight. */
  durableAt?: number | null
  putMs?: number | null
}

export type NodeSegments = NodeTagged & {
  log?: string
  durableOrdinal?: number | null
  nextOrdinal?: number
  watermark?: string
  watermarkLagMs?: number | null
  /** Oldest first. */
  segments?: Segment[]
}

/** `since` default: the last 20 s. Each node keeps its last 1,024 segments. */
export const listSegments = (c: AdminClient, since?: number, signal?: AbortSignal) =>
  call<Gathered & { time: number; since: number; lastEmitted: string; minWatermark?: string | null; nodes: NodeSegments[] }>(
    c,
    'vlpds.admin.listSegments',
    { params: { since }, signal },
  )

// --------------------------------------------------------------------- mail

export type MailStatus = 'queued' | 'retrying' | 'sent' | 'failed' | 'dropped' | 'suppressed' | 'logged'

export type MailEntry = {
  id: number
  node: string
  at: number
  purpose: string
  /** The account it was sent for. */
  did?: string
  /** All that is kept of the recipient's address. */
  toDomain: string
  status: MailStatus
  attempts: number
  /** Provider error, with any address in it removed. */
  error?: string
  /** suppressed: recipient_limit | node_limit | cluster_limit */
  reason?: string
  doneAt?: number
  sendMs?: number
}

/** `did`: only the mail sent for that account. */
export const listMail = (c: AdminClient, limit = 100, signal?: AbortSignal, did?: string) =>
  call<Gathered & { mail: MailEntry[]; nodes: (NodeTagged & { queued?: number })[] }>(c, 'vlpds.admin.listMail', {
    params: { limit, did },
    signal,
  })

// ----------------------------------------------------------------- lockouts

export type Lockout = { did: string; handle?: string | null; factor: FactorLockKind; failures: number; lockedUntil: number }

/** Factor locks in force. Sign-in rate-limit buckets are in getRateLimits' topKeys. */
export const listLockouts = (c: AdminClient, signal?: AbortSignal) =>
  call<Gathered & { lockouts: Lockout[] }>(c, 'vlpds.admin.listLockouts', { signal })

export const clearLockout = (c: AdminClient, input: { did: string; reason: string; actor?: string }) =>
  call<Audited & { did: string }>(c, 'vlpds.admin.clearLockout', { body: input })

// ------------------------------------------------------------------- config

export type Setting = {
  flag: string
  env?: string
  /** file: a secret set through its `-file` flag. */
  source: 'flag' | 'env' | 'default' | 'unset' | 'file'
  /** Never present for a secret. */
  value?: string
  secret?: boolean
  /** Secrets: `sha256:` + 8 hex digits of the value in use. */
  fingerprint?: string
  help?: string
}

export type NodeConfig = {
  node: string
  version: string
  rev: string
  settings: Setting[]
  /** False on a node without a command line (tests). */
  recorded: boolean
  stored: {
    handleDomains: { domain: string; added_at?: string; added_by?: string }[]
    rateLimitsVersion: number
    shardLayout?: { version: number; shards: number }
    featureLevel?: number | null
  }
  /** The node's peer mTLS certificate in use; null without peer TLS. */
  peerTls?: PeerTlsCert | null
  /** Secrets read from `-file` flags, and when each file last changed (a rotation). */
  secretFiles?: SecretFile[]
}

export type PeerTlsCert = {
  nodeId: string
  subject: string
  /** DNS and IP SANs. */
  hosts: string[]
  notBefore: number
  notAfter: number
  /** The earliest-expiring trusted CA. */
  caNotAfter: number
  /** Re-read from its files on change and SIGHUP. */
  reloadable: boolean
}

export type SecretFile = {
  flag: string
  path: string
  /** File mtime; null when it can't be read (`error`). */
  modifiedAt?: number | null
  error?: string | null
}

/** One node's; `node` relays the call to it. */
export const getConfig = (c: AdminClient, node?: string, signal?: AbortSignal) =>
  call<NodeConfig>(c, 'vlpds.admin.getConfig', { node, signal })

// ------------------------------------------------------------------ firehose

/** Closes the connection (reason `kicked`); it can reconnect with its cursor. `node`: where it's connected. */
export const kickSubscriber = (c: AdminClient, input: { node: string; conn: string }) =>
  call<{ node: string; conn: string }>(c, 'vlpds.admin.kickSubscriber', { body: { conn: input.conn }, node: input.node })

// ------------------------------------------------------------- storage stats

export type StorageComponent = {
  /** objstats component: log_segment, state_sst, blob, ctl_lease, ... */
  component: string
  objects: number
  bytes: number
  /** Changes since the seed whose effect was guessed (a delete of an object of unknown size, ...). */
  uncertain: number
  exact: boolean
}

export type StorageBackfill = {
  epoch: number
  /** capped: stopped at its budget; another call resumes it. */
  phase: 'running' | 'capped' | 'done' | 'failed'
  runner: string
  heartbeatAt: number
  startedAt: number
  finishedAt?: number | null
  /** The last key listed. */
  cursor?: string | null
  /** LIST requests so far (each lists up to 1,000 keys). */
  requests: number
  keys: number
  bytes: number
  /** The latest call's budget. */
  maxRequests: number
  pagesPerSecond: number
  error?: string | null
}

export type StorageStats = Gathered & {
  /** The last backfill's listing plus every node's changes since. */
  components: StorageComponent[]
  totalObjects: number
  totalBytes: number
  /** True only after a finished backfill, with every node heard from and no guessed change since. */
  exact: boolean
  uncertainChanges: number
  /** Why the whole answer isn't exact, whatever each component's own changes. */
  inexactBecause: string[]
  seeded: boolean
  lastBackfillAt?: number | null
  backfill?: StorageBackfill | null
  /** Changes nodes keep aside while a backfill lists. */
  windowChanges: number
  /** What the LISTs the nodes' background jobs ran last saw: the backfill's estimate before a seed. */
  observed: { objects: number; bytes: number; prefixes: number }
  nodes: {
    node: string
    self: boolean
    reachable: boolean
    /** Crashed without folding its last changes. */
    gone?: boolean
    pendingObjects?: number
    pendingBytes?: number
    windowChanges?: number
    foldedAt?: number | null
  }[]
  time: number
}

export const getStorageStats = (c: AdminClient, signal?: AbortSignal) => call<StorageStats>(c, 'vlpds.admin.getStorageStats', { signal })

export type StorageBackfillPlan = {
  estimatedObjects: number
  /** LIST requests left: ceil(objects / 1000), less what a resumed run already listed. */
  estimatedRequests: number
  estimateBasis: 'counters' | 'observed LISTs'
  observedPrefixes: number
  resume: boolean
  alreadyListed: number
  estimatedSeconds: number
  pagesPerSecond: number
  backfill?: StorageBackfill | null
}

/**
 * Lists the bucket once in the background to seed the counters. `dryRun` only estimates;
 * otherwise `maxRequests` (this call's LIST budget) is required, and a stopped run resumes where
 * it stopped unless `restart`. `pagesPerSecond`: 0.1 to 50, default 2. Audited.
 */
export const backfillStorageStats = (
  c: AdminClient,
  input: { dryRun?: boolean; maxRequests?: number; pagesPerSecond?: number; restart?: boolean; actor?: string },
) =>
  call<StorageBackfillPlan & { dryRun?: true; started?: true }>(c, 'vlpds.admin.backfillStorageStats', { body: input })
