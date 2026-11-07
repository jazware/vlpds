# boards

boards is a small Reddit-like message board built on atproto Spaces. Each board is a private space,
and members post, comment and vote in their own space repos. The app lives in `packages/boards`
(its README.md covers the production server at boards.example.com). This directory runs it on the
harness stack in `bench/spaces` (README.md there) to test vlpds's Spaces code through the flows a
real app runs. `harness.mjs` wires the app to the harness's PLC and accounts, and `lib/space.mjs`
and `lib/syncer.mjs` run on the app's Spaces client (`packages/boards/src/spaces/`).

```
just spaces-boards                  # every story in all-vlpds, vlpds-owner, ref-owner and all-ref
just spaces-boards ref-owner        # one config
VLPDS_BIN=none just spaces-boards all-ref   # the reference alone, no vlpds build
CLUSTER=1 just spaces-boards        # 3 vlpds nodes, and story 11 kills one mid-run
just spaces-boards-ui               # the web UI on http://127.0.0.1:2888 until Ctrl-C
UI_E2E=1 just spaces-boards-ui      # the UI in headless Chromium, then exit
just spaces-boards-prod             # the production server on http://boards.localhost:2889 until Ctrl-C
UI_E2E=1 just spaces-boards-prod    # the production server in headless Chromium, then exit
```

`BRANCH=<ref>` builds vlpds from that ref instead of this checkout, as for the other harness modes.
Runs can overlap: a second one moves to the next free block of ports and prints it, with its
reports and screenshots under `out/<base>/` (`../README.md`, "Running two at once"). `SCALE=small`
shrinks story 10 for quick runs and `SEED` fixes its workload. Reports land in
`bench/spaces/out/boards.{md,json}` (`boards-cluster.*` with `CLUSTER=1`).

## The app

A board is a space of type `dev.example.boards.board` under a `com.atproto.memberspace.policy`, and its
owner's DID is the authority. The lexicons are in `packages/boards/lexicons/dev/example/boards/`:

| collection | what |
|---|---|
| `board` | the space type declaration (name, description, its collections) |
| `settings` | name, description, flairs, pinned posts and removed members. Only the owner's copy (rkey `self`) counts |
| `post` | title, body, an optional image blob and a flair |
| `comment` | the post's URI and an optional parent comment's URI |
| `vote` | a subject URI and `up` or `down`. The rkey is a hash of the subject, so a member has one vote per subject and changing it is a `putRecord` |

`packages/boards/src/client.mjs` is what an app does for a signed-in member: create a board, invite writers and lurkers,
post (with `uploadBlob` for images), comment, vote, edit, delete, pin, remove a member, delete the
board. Reads of other members' repos go through a space credential. vlpds resolves a bare `space:`
grant's collections from the type's declaration over DNS (`_lexicon.boards.example.com`), which this
stack can't reach, so the client asks for explicit `collection=` scopes. When the vlpds binary has
`--lexicon-authority-override` (dev mode, spaces-2a on), the runner publishes the lexicons as
`com.atproto.lexicon.schema` records from a local vlpds account and restarts vlpds with
`boards.example.com` pointed at it. Story `0.bare-grant` then covers the bare grant. Without the flag it
reports not impl.

`packages/boards/src/appview.mjs` is the indexer and API. The owner adds the appview's account as a read-only member and
calls `indexBoard`. The appview registers for notifies and syncs every member repo with the
app's `SpaceSyncer` (listRepos from a spaceRev checkpoint, listRepoOps with a running LtHash checked
against the commit once its MAC verifies, a verified STAR getRepo on a mismatch). It holds nothing it didn't get that
way. A poll every 2 s catches what nothing pushes, which today is a record takedown. `src/model.mjs`
turns the synced repos into the board, and the scenario runner runs the same function over the
writes it saw acked, so the two can be compared post for post.

The API is XRPC-style: `dev.example.boards.getBoard`, `getPosts?sort=hot|new|top`, `getPostThread`,
`getKarma`, `getImage` (the appview fetches the blob with its own credential) and `getIndexState`.
Every call needs a space credential the board's owner issued, signed for the appview's DID. So a
non-member can't read a board through the appview either, and the appview honours the owner's
`notifyCredentialRevoked`.

The board rules, as `model.mjs` has them:

- A removed member's posts, comments and votes are hidden. Removal takes the member out of the
  writer set, so listRepos stops naming them, but it isn't announced: a syncer that already holds
  their repo keeps it, and one that starts later never pulls it. Hiding by `settings.removed` gives
  every appview the same board.
- A comment whose post is gone isn't shown. A reply whose parent is gone hangs under a `[removed]`
  placeholder.
- Score is ups minus downs over each member's latest vote. Karma is the score of a member's posts and
  comments. Hot is Reddit's formula with pinned posts first.

## The stories

| step | what it checks |
|---|---|
| 0.bare-grant | a bare `space:dev.example.boards.board` grant. The consent screen says "Board spaces" and lists the declared collections, the token carries them, a post works and an undeclared collection is refused |
| 1.create-board | alice makes "rustaceans", bob and carol write, dave lurks, eve isn't in it, and the appview indexes it |
| 2.post-comment-vote | a post with an image, a two-deep thread, votes changed and taken back. Scores, threads, karma and the three sorts match the model and hand-counted numbers. The image comes back from `space.getBlob` and the appview, and `sync.getBlob` answers `BlobNotFound` |
| 3.lurker-outsider | dave reads everything. His own-repo writes go untracked and never show (the reference rule), and he can't write into bob's repo. eve gets no credential (`SpaceNotFound`), and the appview refuses her own board's credential and a stolen one signed with her key |
| 4.edit-delete-converge | 40 edits, comments and deletes with the appview's poll off, so only notifies move it. Reports ack-to-visible p50 and p99 |
| 5.remove-member | carol loses her credential (`SpaceNotFound`) and drops out of listRepos. Her content disappears from the appview |
| 6.takedown | an operator takes bob's post down (vlpds only). It's gone from every read, its image answers `BlobNotFound`, and the appview converges without it. `vlpds.admin.getSpaceRecord` reads it flagged `takendown` and the read is audited. A reversal brings it all back |
| 8.revoke | alice revokes a stolen credential on every member host and the appview. Reads with it fail with `CredentialRevoked` |
| 10.scale | 20 members, 200 posts, 1,000 comments and 3,000 votes, 16 in flight. Nothing acked is lost, and the appview matches the model on every post, thread and karma. Reports throughput, appview catch-up and vlpds bucket ops per write |
| 11.fault | `CLUSTER=1` only. vlpds node 1 gets `kill -9` 30% into story 10 and stays down 20 s. The board keeps taking writes, no acked write is lost and listRepos ends at every writer's head |
| 9.delete-board | `SpaceDeleted` for credentials, `notifySpaceDeleted` to the appview, which drops the board. Members keep their own repos (the reference sweeps only the authority's rows) |
| 7.privacy | runs last. Every board write carries the run's sentinel. No firehose frame (live or a cursor-0 backfill), `getRepo`, `listBlobs` or `getBlob` shows it, and no member's public repo rev moved |

The configs place people on hosts. all-vlpds puts everyone on vlpds. vlpds-owner has alice and bob on
vlpds, carol on ref-b and dave on ref-a. ref-owner has alice on ref-a, bob and dave on vlpds and carol
on ref-b. all-ref has no vlpds at all, so it checks the stories and the app against the reference.
Story 10's crowd is spread over the config's hosts.

## The web UI

`just spaces-boards-ui` starts vlpds (`--spaces --dev-mode`), the appview, and the UI on
`http://127.0.0.1:2888`, then seeds a board with four accounts. It prints their handles, and the
generated passwords go to `.local/seed-accounts.json` (git ignored). vlpds accounts sign in with
atproto OAuth on vlpds's own pages (a loopback client). The reference PDSes here only serve OAuth over
https, so their accounts sign in with a password. `devauth.mjs` holds those sessions, and the app's BFF
(`packages/boards/src/bff.mjs`) does
everything through the boards client and the appview API. Each board has a Spaces debug drawer with the authority, the
member repos the appview syncs (rev, record count, LtHash), the last notify and the credential
expiries.

The UI lives in `packages/boards/web/` (Vite, React, TypeScript). `npm run dev` there proxies to a
running `spaces-boards-ui` on the first port block, though OAuth sign-ins come back to :2888. `packages/boards/e2e/ui.mjs`
signs alice (vlpds, OAuth)
and carol (ref-a, password) in, has them post, comment, reply and vote, checks each sees the other's
changes, and saves screenshots to `bench/spaces/out/boards-ui/`.

## The production server

`just spaces-boards-prod` runs `packages/boards/src/server.mjs` as it's deployed, with vlpds
standing in for real PDSes. `prod.mjs` publishes the boards lexicons from a local account and
restarts vlpds with `--lexicon-authority-override`, so the bare `space:dev.example.boards.board`
grant resolves. It seeds a board (alice owns it, bob writes, carol and dave aren't members) and
writes the server's env and the accounts to `.local/prod-seed.json`. The server is a confidential
OAuth client at `http://boards.localhost:2889` (Chromium and macOS resolve `*.localhost` to
loopback, and vlpds in dev mode takes an http client_id that isn't a loopback client), resolves DIDs
from the local PLC and handles through vlpds, and its notify target is `did:web:127.0.0.1%3A2889`.

`packages/boards/e2e/prod.mjs` checks it in headless Chromium: the public documents, sign-in,
posting with an image, bob opening the board by its link, comments and votes each way (notify
driven), the notify registration, an invite and a removal, a non-member refused, the CSRF and
origin checks, metrics, and a restart that keeps the sealed index and the sessions. Screenshots go
to `bench/spaces/out/boards-prod/`.
