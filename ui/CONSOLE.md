# Operator console

The console at `/admin` is a status-first shell: a top bar with the strata rule, a rail of sections, a dense main column and one slide-over for any row. This file is the kit and the rules for building a section in it.

## Where things live

| Path | What |
| --- | --- |
| `src/console.css` | Tokens and every console class. All classes start with `cx-` (or sit under one) because `styles.css` is global and already owns `.btn`, `.tile`, `.seg`, `.empty`. |
| `src/components/console/` | The kit: `kit.tsx` (small parts), `DataTable.tsx`, `Drawer.tsx` (detail kinds), `dialogs.tsx` (confirm and form dialogs), `toast.tsx`, `LiveTail.tsx`, `Strata.tsx`, `Palette.tsx`, `Shell.tsx`, `sections.tsx` (the IA), `nav.ts` (slide-over URLs). |
| `src/lib/console/` | Data: `live.ts` (pause, stale, shared pollers), `cluster.ts` (getClusterStatus + derived view), `nodeMetrics.ts` (the one getNodeMetrics poll every per-node reader shares), `metrics.ts` (its series as cluster and node rates, or local /metrics scrapes to rates), `firehose.ts` (subscribeRepos tail, handle lookups), `polls.ts` (subscribers, cases, audit, lockouts), `segments.ts` (listSegments for the strata), `sys.ts` (the system sections: raw getNodeMetrics series with per-component store rates, getStorageStats, per-connection firehose rates, relays, mail, config and Spaces health from every node, `adminAt` for one node's answer), `adminAdapter.ts` (the way into `lib/adminApi.ts`), `fmt.ts`. |
| `src/pages/admin/` | Pages. `AdminApp.tsx` routes. `Overview.tsx` and `Nodes.tsx` are built on the kit, `clusterUi.tsx` holds what they share, `clusterDetails.tsx` registers the node, shard, event and sub details. The rest are the pre-console pages, shown inside `<Legacy>`. |

## Building a section

1. Replace the section's `case` in `route()` (`AdminApp.tsx`) with your page. Keep the old paths in `aliases` (`sections.tsx`) so links keep landing.
2. Start the page with `<PageHead title sub actions />`, then `<Banners>` if anything needs attention, then `<Tiles boxed>` for the figures, then panels in `cx-grid2` / `cx-grid3` / `cx-stack`.
3. Every row that has more to show opens in the slide-over. Register a detail kind (below) and give the table `open={(row) => ({ type, id })}`.
4. Anything that changes the cluster goes through `confirmAction`. No mock actions: call the real endpoint, or the adapter, and let the dialog show the error.
5. Add your entities and verbs to ⌘K with `registerPalette`.
6. Check it at 390 px and in both themes, and that the console log stays clean.

## Kit

All from `components/console/kit.tsx` unless noted.

- `Glyph k`, `Chip k`: status is a colour and a glyph, always both. `ok ●`, `warn ▲`, `err ■`, `info ◆`, `idle ○`. Chips also come in `acc`, `plain`, `violet`, `stale`.
- `Kbd k`, `Swatch color` (a node's square; striped red when nobody owns it), `Spinner`.
- `Spark data l2 color th min size` draws a sparkline in a 100-wide box. `color` is a token name (`accent`, `amber`, `c1`–`c6`, `warn`, `violet`). `l2` is dashed on the same scale and `th` is a dotted threshold. Under two points it draws a hatched placeholder.
- `Meter v max k wide`, `MiniBar parts`.
- `Tiles tiles boxed`: `{ label, right, value, unit, sec, spark, to }`. Values are wrapped in `LiveVal`, so they hatch when the console is stale.
- `HealthLine cells`: one cell per subsystem, each a link with `tone`, `value`, `unit`, `sub`.
- `Banners items`: `{ id, tone, title, desc, right, body, open }`. With `body` it's a collapsible `<details>`.
- `Panel title to src right foot`: `to` links the title to a section with a ›. Put tables and tiles straight inside. Wrap free content in `PanelBody`.
- `Sec title digest right open flush danger`: a collapsible section for drawers and detail pages. `flush` drops the padding for tables.
- `PageHead`, `KV rows`, `Strip items` (figures across a drawer), `Minis n` + `Mini label value` (labelled sparklines), `RRow onClick|to x` (a rail row), `Copy text full` (click to copy; `full` puts the whole value in the tooltip, for a value truncated to a fixed width), `Json value`, `Toggle`, `Seg`, `SearchInput` (has `data-search`, so `/` focuses it).
- A `KV` row can take a third element, `{ chip, act }`: the status chip and the row's button each get a right-aligned column, so values, chips and buttons line up down the list and every row is a small button high. Put a row's action there, not after its value.
- States: `Loading`, `Empty title`, `ErrorState error retry`, `NeedsVersion what nsid` (in place of a panel whose endpoint this server doesn't have), and `Loaded load` which does loading, error and keep-last-data in one.
- `Src` tags where a panel's data comes from. They only show with "Show data sources" (sidebar foot or ⌘K), so leave them in.
- `DataTable rows cols rowKey open onRow sort dim empty` (`DataTable.tsx`). Columns are `{ id, label, r, sort, render, title, style }`. Rows that open carry `data-open="type:id"`, which is all the shell's `j` / `k` / `Enter` handling needs. A row whose detail is open gets `.sel`.
- `LiveTail height max nodeFilter` (`LiveTail.tsx`) is the merged firehose. It's pausable (global space), filterable by text, kind and node, and keeps your place when you've scrolled down.
- `Strata view fetchedAt` (`Strata.tsx`) is the logs → watermark → firehose canvas. Blocks are real segments from `listSegments` (outlined while the PUT is in flight), or the durable ordinal's steps on a server without it.
- `toast(msg, { err })` (`toast.tsx`).

## Details: slide-over and full page

```tsx
registerDetail('account', {
  kind: 'Account',            // eyebrow over the title
  section: 'accounts',        // full page lives at /admin/accounts/account/<id>
  use: (id, mode) => {        // a hook: load what you need here
    const info = useLoad(...)
    return { title, chip, body, foot, loading, missing }
  },
})
```

`openPanel(type, id)` opens `?open=type:id` on the current page, so a reload keeps it and back closes it. `o` or "Full page ↗" goes to `/admin/<section>/<type>/<id>`, and `mode === 'page'` tells `use` to open more sections or lay out two columns (`<div className="cols">` inside the body). `wide: true` lets the full page grow past the usual 1,100 px for wide tables (the account page). Register kinds in a module that `AdminApp.tsx` imports.

## Actions

```ts
confirmAction({
  tone: 'err',                       // or 'warn'
  title: `Take down @${handle}?`,
  items: ['Its repo stops being served…', 'Every session is revoked.'],
  fields: [{ id: 'reason', label: 'Reason (audited)', required: true }],
  word: handle,                      // must be typed to enable the button
  action: 'Take down',
  primary: false,                    // true: verdigris button for routine or reversible actions
  call: 'com.atproto.admin.updateSubjectStatus → owner node',
  run: (v) => admin('…', { body: { … } }),
  done: 'Taken down',
})
```

The footer shows `call`, the request it makes. `run` errors stay in the dialog. `openDialog(close => <FormDialog …/>)` is for forms that aren't confirmations.

## Data

- `createPoller(fetch, ms, { heartbeat })` (`live.ts`) is one shared poll per thing. It runs only while something renders `poll.use()` and skips ticks while paused. `getClusterStatus` is the heartbeat: when it fails the shell shows "Not updating", hatches live values and greys the sparklines.
- `useClusterView()` gives the status plus node colours, shard counts, watermark lag per log, lease time left and `health` per node.
- `nodeMetrics.ts` is the only poller of `getNodeMetrics`: one request every 2 s with `since` while anything subscribes, paused with the rest. `useNodeMetrics()` (sys.ts) reads its raw series and `storeComponents`, `useMetrics()` and `rate429Poll` derive from it. Don't call `getNodeMetrics` anywhere else.
- `useMetrics()` gives per-node and merged `Point[]` (3 minutes at 2 s) and gauges. The source is `getNodeMetrics` (every node's series, gathered by the node you reach), else this node's `/metrics`, else `'none'` (show `NeedsVersion`). The fan-out has no hedge, lease-ratio or mail-budget figures, so hide what's `undefined` rather than drawing an empty spark.
- `useFirehose()` is the live tail. `useHandle(did)` batches handle lookups through `getAccountInfos`.
- `adminAdapter.ts` is the way into `lib/adminApi.ts`. `withAdmin(c => api.listAccounts(c, …))` hands a call the admin token and turns its errors into `XrpcError`s (a 401 goes back to the token form). The `optional` wrappers (`nodeMetrics`, `segmentFeed`, `lockouts`, `mailLog`, `getConfig`, `kickSubscriber`) answer `{ supported: true, data }` or `{ supported: false, nsid }` for servers older than the console API.
- `useLoad` and `admin()` from `lib/hooks.ts` and `lib/xrpc.ts` still work for one-off loads inside a section.

## Keyboard

`⌘K` palette. `g` then a letter jumps to a section (the letters are in `sections.tsx`). `j` / `k` move through rows, `Enter` opens, `o` goes full page, `Esc` closes the panel, dialog or full page. `/` focuses the page's `data-search` input, else the palette. `space` pauses live updates, `t` toggles the theme, `?` lists all of it.

## Look

- Tokens are on `.cx`: `--paper --sheet --raised --sunk --hover`, ink `--ink --ink2 --ink3`, rules `--rule --rule2`, `--accent` (verdigris, for action), `--amber` (the live signal: watermark, latency), status `--ok --warn --err --info --idle --violet`, node and series colours `--c1`–`--c6`. Dark mode follows the system unless `t` picked one.
- Schibsted Grotesk for text, JetBrains Mono for ids, numbers and code (`.mono`). 13 px base, tables 12.5 px.
- Numbers right-aligned in `td.r`, ids in mono, durations through `fmt.ts` (`dur`, `fmtMs`, `fmtSec`, `ago`). In a table, keep a column's contents one width (a key truncated to a fixed width, a count before a fixed-width meter) and give the slack to one text column (`style: { width: '100%' }`) rather than letting it spread between numbers. A sparkline with nothing to show is a muted `—`, not a flat line.
- No new colours for status. No colour without its glyph.
- Use example.com-style names in fixtures and placeholders. main syncs to the public repo.

## Sections

| Section | Path | State |
| --- | --- | --- |
| Overview | `/admin` | Built |
| Nodes & shards | `/admin/nodes` | Built. A cluster of one (or `--memory`) gets one panel for its node (`nodeSolo.tsx`); more get node cards, and the nodes table past three. Old page at `/admin/cluster`. Live metrics at `/admin/metrics` (`Metrics.tsx`, every getNodeMetrics series per node) |
| Object store | `/admin/storage` | Built (`Storage.tsx`). Detail kind `storecomp` (a key component). No bucket listing |
| Firehose & relays | `/admin/firehose` | Built, alias `/admin/relays`. Detail kinds `event`, `sub` (live or disconnected, id `node/conn`), `relay` |
| Accounts | `/admin/accounts` | Built. Detail kind `account` (`accountDetail.tsx`, actions in `accountActions.tsx`), full page at `/admin/accounts/account/<did>`; the old `/admin/accounts/<did>` still lands there |
| Moderation | `/admin/moderation` | Built. Detail kinds `case`, `subject` (id: what resolveSubject takes), `audit`. `?q=` and `/admin/moderation/cases/:id` still land |
| Limits & lockouts | `/admin/limits` | Built, alias `/admin/ratelimits`. Detail kinds `bucket`, `override`. Every edit goes through `editLimits` (diff, then updateRateLimits with ifVersion) |
| Domains & invites | `/admin/domains` | Built. Detail kinds `domain`, `invite` |
| Spaces | `/admin/spaces` | Built. Detail kind `space` (id: the space URI); `/admin/spaces/space?uri=` shows its full page |
| Mail | `/admin/mail` | Built. Detail kind `mail` (id `node:id`). Budgets from getRateLimits' `mail-*` buckets |
| Config | `/admin/config` | Built. Detail kind `cfg` (id: the flag). getConfig from every node, relayed by `x-vlpds-node` |

## Trying it

`just dev` (or any local vlpds) and `just dev-ui url=http://127.0.0.1:2620`, then `/admin` with the dev admin token. `loadgen setup` and `loadgen run --rate 5` give the tail and the strata something to show. A real three-node cluster needs an S3 bucket (a throwaway MinIO works) and three `--dev-mode` nodes sharing `--peer-tls-dir` and `--prefix`, as `bench/ha/hactl.py` starts them.
