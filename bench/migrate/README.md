# Migration e2e

`/migrate` moves an account from another PDS to this one, in the browser.
This harness runs the page end to end, entirely on this machine:

```
just migrate-e2e          # or bench/migrate/run.sh
```

It starts, in docker (`docker-compose.yml`, project `vlpds-migrate-e2e`):

- **PLC directory** (`did-method-plc`, built from source at a pinned commit, because the published images are amd64-only) with Postgres, on `127.0.0.1:2782`.
- **Reference PDS** (`ghcr.io/bluesky-social/pds:0.4`, dev mode, hostname `localhost`, handles `*.test`) on `localhost:2783`. It registers DIDs with the local PLC.
- **Mailpit** on `127.0.0.1:2785`. It catches the reference PDS's email, so the harness can read the 2FA and PLC codes.

It then builds the UI and `vlpds`, and runs vlpds on `127.0.0.1:2784` (rate limits on) with these flags: `--memory --dev-mode --plc-mode directory --plc-url <local PLC> --invite-required`. Then `e2e.mjs` runs three phases.

1. **Seed.** It creates four accounts on the reference PDS. They have posts (some with images), a profile with an avatar and a banner, follows and likes between the accounts, and preferences. Bob also has email 2FA turned on. The harness records every record CID, blob hash and preference.
2. **Drive.** Headless Chromium (Playwright) goes through the whole wizard for each account:
   - **alice** (advanced mode): found by handle plus a server address. An app password is refused first. She uses the one-click `?invite=` link and keeps her old password. On the identity step she generates her own recovery key in the browser: the harness checks that the shown private key derives the shown did:key, that moving waits for "I saved it", and that the private key is never in localStorage or sessionStorage.
   - **bob** (simple mode): starts from the landing page link and signs in with his email 2FA code. The harness drops the `createAccount` answer, so the account is created but the page sees an error; he retries. He sets a new password, types a wrong PLC code, then the right one. Afterwards, on the account page (Security), he adds a recovery key (pasted did:key, code from vlpds's dev mail) and removes it again; the local PLC is checked after each.
   - **carol** (simple mode): about 420 records and 42 blobs, some of them 1.5 MB. The page reloads in the middle of the blob copy and must resume without importing the repo again. Then a new tab resumes at the identity step, after signing in to both servers again.
   - **dave** (advanced mode): keeps his handle as if it were a custom domain. The old server's `describeServer` is faked so that it doesn't seem to own `.test`. He pastes an invalid did:key (refused before anything is signed), then a valid one as his recovery key.
   - In simple mode every screen is checked for protocol jargon (PLC, DID, repo, blobs, rotation keys, …), and the key table and recovery-key option must be absent.
   - Simple mode's counts must match the seeded data: the checks screen (bob gets a faked AppView `getProfile`, so "About 30 posts and 3 follows, plus 6 photos & videos"; carol has no AppView, so photos only), the copy step ("All 30 posts, 15 likes and 3 follows copied", "N of 42 photos & videos copied", still there after carol's reload; bob's blobs and settings are held so each line can be read), and the welcome tiles.
   - **Backups.** Between the copy and the identity step, bob saves the optional backup (the File System Access path, with a stand-in save picker that keeps the bytes); the others skip it, and a reload must not offer it again. alice also saves one from the welcome screen with her new recovery key ticked in, and dave one from the account page's Export (both the in-memory download path). Each ZIP is unzipped (`unzip -t` first) and checked: `repo.car` parses, every block hashes to its CID and its root is the server's `getLatestCommit`; every blob in `blobs/` has the seeded bytes; `preferences.json` equals the seeded preferences; `identity/did.json` and `identity/plc-audit-log.json` match the local PLC; `account.json` agrees; no password or token anywhere; `keys/` only with the opt-in; the account page's `vlpds/*.json` extras are there.
   - After the four accounts, the harness checks two refusals: an account that already moved here, and a `did:web`.
3. **Verify.** For each account, on vlpds:
   - Every record has the same CID, and every blob has identical bytes.
   - `listMissingBlobs` is empty, and the preferences are equal.
   - The local PLC names vlpds as the PDS, its signing key and handle are vlpds's, and its rotation keys are vlpds's recommended ones, preceded by the user's own recovery key for alice and dave.
   - The account is active here and deactivated on the reference PDS.
   - Login works, `getRepo` and `getLatestCommit` answer, and a new post is accepted.

Screenshots of every screen go to `out/shots/`, and the vlpds log goes to `out/vlpds.log`. Everything is torn down at the end: containers, volumes and the vlpds process. To keep it running, set `KEEP=1`. To iterate on a running stack:

```
cd bench/migrate
node e2e.mjs            # fresh accounts each run; `node e2e.mjs verify` re-checks the last run (out/state.json)
docker compose -p vlpds-migrate-e2e down -v       # when done
```

Other options: `HEADED=1` shows the browser, and `VLPDS_BIN=...` skips the build.

## Spaces

```
just migrate-spaces-e2e   # or bench/migrate/spaces.sh
```

This one checks the Spaces step of `/migrate`: after the account goes live here and before the old one goes offline, the page signs in with OAuth at both servers and copies each space the account runs (`exportSpaceMeta`, then `importSpaceMeta` here) and each space repo it writes (`getRepo`, then `importRepo` here). It starts, in docker (project `vlpds-migrate-spaces`), the same PLC directory and Mailpit, plus the reference PDS at the pin `bench/spaces/refpds.sh` builds, natively, the first time (set `REF_SPACES_IMAGE` to point at another image) on `localhost:2786`. It runs two vlpds with `--spaces`: the target on `127.0.0.1:2787` and a source on `localhost:2788` (another host name, so the two don't share cookies).

`spaces.mjs` then:

1. **Seeds** two accounts with the same shape. On the reference PDS, `owner` governs a space `club` where **alice** is a member, and alice has a space `notes` of her own. She writes 3 records in `club` and 4 in `notes`, one of them with a PNG blob. **erin** gets the same on the source vlpds; her writes there go through a headless OAuth client (`lib/oauth.mjs`), since vlpds takes space writes only over OAuth. Each repo is read back with `space.getRepo` (a STAR archive) and checked with `@atproto/space`'s `readRepoStar`: its records fold to the commit's data.
2. **Drives** `/migrate` in headless Chromium: alice in simple mode (checked for jargon), erin in advanced mode. At the switch-over, the page signs in at the old server (the reference's own authorization UI for alice, vlpds's for erin) and then here, through the real authorization and consent pages. For alice, the first `importRepo` lands but its answer is dropped, so the page's retry imports it again. The harness checks that the page lists both spaces, moves `notes` (the space each account runs) with one `importSpaceMeta`, shows each one copied (with its blob), and leaves no OAuth session, pending sign-in or DPoP key behind. It also checks that a key made the way the client makes them can't be exported.
3. **Verifies** on vlpds for both accounts:
   - the DID names vlpds's signing key and its `#atproto_kem` key now;
   - each space repo has the same records and data, at a new rev;
   - importing it again changes nothing;
   - `notes` keeps its member list;
   - the space blob has the same bytes;
   - a new write goes on from the imported repo;
   - the old account is deactivated.
   It also checks that `/oauth/client-metadata.json` lists the scope the UI client asks for.

The reference containers can't reach vlpds here on Linux (only `127.0.0.1`), so the authority's notify after an import isn't part of this run. `bench/spaces` covers notify between hosts.

Screenshots go to `out/spaces/shots/` and the vlpds logs to `out/spaces/`. `KEEP=1`, `HEADED=1` and `VLPDS_BIN` work as above.
