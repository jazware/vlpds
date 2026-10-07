// Every query key the console uses, in one place, so a change (changes.ts) can name exactly the
// queries it touches. An entity's queries share a prefix (['account', did, …]): invalidating the
// prefix reaches all of them. Lists and aggregates have their own roots.

export const K = {
  // telemetry, polled as series
  cluster: ['cluster'] as const,
  nodeMetrics: ['nodeMetrics'] as const,
  segments: ['segments'] as const,

  // one account; every per-account read sits under it
  account: (did: string) => ['account', did] as const,
  accountRow: (did: string) => ['account', did, 'row'] as const,
  accountInfo: (did: string) => ['account', did, 'info'] as const,
  accountStatus: (did: string) => ['account', did, 'status'] as const,
  accountSecurity: (did: string) => ['account', did, 'security'] as const,
  accountSessions: (did: string) => ['account', did, 'sessions'] as const,
  accountOps: (did: string, n: number) => ['account', did, 'ops', n] as const,
  accountSpaces: (did: string) => ['account', did, 'spaces'] as const,
  accountDevMail: (did: string, email: string) => ['account', did, 'devMail', email] as const,
  /** getSubject: the account, a record or a blob of it, with its quota. */
  subject: (did: string, uri?: string, cid?: string) => ['account', did, 'subject', uri ?? '', cid ?? ''] as const,
  accounts: (p?: { q?: string; filter?: string }) => (p ? (['accounts', p] as const) : (['accounts'] as const)),

  // moderation
  resolve: (q: string) => ['resolve', q] as const,
  case: (id: string) => ['case', id] as const,
  cases: (p?: { status?: string; did?: string; subject?: string }) => (p ? (['cases', p] as const) : (['cases'] as const)),
  audit: (p?: { limit?: number; did?: string; space?: string }) => (p ? (['audit', p] as const) : (['audit'] as const)),
  auditEntry: (id: string) => ['auditEntry', id] as const,
  takedowns: ['takedowns'] as const,
  overQuota: ['overQuota'] as const,

  // limits, mail, relays, domains, invites
  lockouts: ['lockouts'] as const,
  ratelimits: ['ratelimits'] as const,
  mail: (p?: { limit?: number; did?: string }) => (p ? (['mail', p] as const) : (['mail'] as const)),
  subscribers: ['subscribers'] as const,
  crawlers: ['crawlers'] as const,
  domains: ['domains'] as const,
  invites: ['invites'] as const,

  // system
  config: ['config'] as const,
  storageStats: ['storageStats'] as const,
  spacesStatus: ['spacesStatus'] as const,
  spaces: ['spaces'] as const,
  spacesList: (p: { sort: string; cursor?: string }) => ['spaces', p] as const,
  space: (uri: string) => ['space', uri] as const,
  describe: ['describeServer'] as const,
}
