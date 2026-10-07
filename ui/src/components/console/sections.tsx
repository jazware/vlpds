import type { ReactNode } from 'react'

// The console's information architecture: one entry per sidebar item, in order. `key` is the
// letter after `g`; `aliases` are older paths that still land in the section.

export type SectionId = 'overview' | 'nodes' | 'storage' | 'firehose' | 'accounts' | 'moderation' | 'limits' | 'domains' | 'spaces' | 'mail' | 'config'

export type Section = { id: SectionId; label: string; short?: string; key: string; group: '' | 'Cluster' | 'People' | 'System'; path: string; aliases?: string[]; icon: ReactNode; alpha?: boolean }

const svg = (children: ReactNode) => (
  <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true">
    {children}
  </svg>
)
const s = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.5 } as const

export const SECTIONS: Section[] = [
  {
    id: 'overview',
    label: 'Overview',
    key: 'o',
    group: '',
    path: '/admin',
    icon: svg(
      <>
        <rect x="1.5" y="1.5" width="5.5" height="5.5" rx="1" {...s} />
        <rect x="9" y="1.5" width="5.5" height="5.5" rx="1" {...s} />
        <rect x="1.5" y="9" width="13" height="5.5" rx="1" {...s} />
      </>,
    ),
  },
  {
    id: 'nodes',
    label: 'Nodes & shards',
    short: 'Nodes',
    key: 'n',
    group: 'Cluster',
    path: '/admin/nodes',
    aliases: ['/admin/metrics', '/admin/cluster'],
    icon: svg(
      <>
        <circle cx="4" cy="4" r="2.3" {...s} />
        <circle cx="12" cy="4" r="2.3" {...s} />
        <circle cx="8" cy="12" r="2.3" {...s} />
        <path d="M5.5 5.8 7 10M10.5 5.8 9 10" stroke="currentColor" strokeWidth="1.3" />
      </>,
    ),
  },
  {
    id: 'storage',
    label: 'Object store',
    key: 'b',
    group: 'Cluster',
    path: '/admin/storage',
    icon: svg(
      <>
        <ellipse cx="8" cy="3.5" rx="5.5" ry="2" {...s} />
        <path d="M2.5 3.5v9c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2v-9M2.5 8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2" {...s} />
      </>,
    ),
  },
  {
    id: 'firehose',
    label: 'Firehose & relays',
    short: 'Firehose',
    key: 'f',
    group: 'Cluster',
    path: '/admin/firehose',
    aliases: ['/admin/relays'],
    icon: svg(<path d="M1.5 4h9M1.5 8h13M1.5 12h7" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />),
  },
  {
    id: 'accounts',
    label: 'Accounts',
    key: 'a',
    group: 'People',
    path: '/admin/accounts',
    icon: svg(
      <>
        <circle cx="8" cy="5.5" r="3" {...s} />
        <path d="M2.5 14.5c.6-3 2.8-4.5 5.5-4.5s4.9 1.5 5.5 4.5" {...s} />
      </>,
    ),
  },
  {
    id: 'moderation',
    label: 'Moderation',
    key: 'm',
    group: 'People',
    path: '/admin/moderation',
    icon: svg(<path d="M8 1.5 13.5 4v4c0 3.2-2.3 5.6-5.5 6.5C4.8 13.6 2.5 11.2 2.5 8V4Z" {...s} />),
  },
  {
    id: 'limits',
    label: 'Limits & lockouts',
    key: 'l',
    group: 'People',
    path: '/admin/limits',
    aliases: ['/admin/ratelimits'],
    icon: svg(
      <>
        <circle cx="8" cy="9" r="5.5" {...s} />
        <path d="M8 9 10.5 6.2M6.5 1.5h3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      </>,
    ),
  },
  {
    id: 'domains',
    label: 'Domains & invites',
    key: 'd',
    group: 'People',
    path: '/admin/domains',
    aliases: ['/admin/invites', '/admin/handle-domains'],
    icon: svg(<path d="M5.5 3.5h-2a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h2M10.5 3.5h2a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2M5 8h6" {...s} strokeLinecap="round" />),
  },
  {
    id: 'spaces',
    label: 'Spaces',
    key: 's',
    group: 'People',
    path: '/admin/spaces',
    alpha: true,
    icon: svg(
      <>
        <rect x="1.5" y="1.5" width="13" height="13" rx="3" {...s} strokeDasharray="3 2" />
        <circle cx="8" cy="8" r="2" fill="currentColor" />
      </>,
    ),
  },
  {
    id: 'mail',
    label: 'Mail',
    key: 'e',
    group: 'System',
    path: '/admin/mail',
    icon: svg(
      <>
        <rect x="1.5" y="3" width="13" height="10" rx="1.5" {...s} />
        <path d="m2 4 6 5 6-5" {...s} />
      </>,
    ),
  },
  {
    id: 'config',
    label: 'Config',
    key: 'c',
    group: 'System',
    path: '/admin/config',
    icon: svg(
      <>
        <path d="M2 4h7M12 4h2M2 12h2M7 12h7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
        <circle cx="10.5" cy="4" r="1.6" {...s} />
        <circle cx="5.5" cy="12" r="1.6" {...s} />
      </>,
    ),
  },
]

export const SECTION: Record<SectionId, Section> = Object.fromEntries(SECTIONS.map((x) => [x.id, x])) as Record<SectionId, Section>

/** The section a path belongs to (longest matching prefix, aliases included). */
export function sectionOf(path: string): Section {
  let best: Section = SECTION.overview
  let len = 0
  for (const sec of SECTIONS) {
    for (const p of [sec.path, ...(sec.aliases ?? [])]) {
      if (p === '/admin') continue
      if ((path === p || path.startsWith(`${p}/`)) && p.length > len) {
        best = sec
        len = p.length
      }
    }
  }
  return best
}

export const TABBAR: SectionId[] = ['overview', 'nodes', 'accounts', 'moderation', 'firehose']
