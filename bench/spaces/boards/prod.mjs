// `just spaces-boards-prod`: the production boards server
// (packages/boards/src/server.mjs, as deployed) against the harness stack.
// vlpds (--spaces --dev-mode, with the boards lexicons published locally so
// the bare `space:dev.example.boards.board` grant resolves) stands in for real
// PDSes, the local PLC for plc.directory, and the server runs as a
// confidential OAuth client at http://boards.localhost:2889 (PORT_BASE + 29)
// with its notify target did:web:127.0.0.1%3A2889. It seeds a board (alice
// owns it, bob writes, carol and dave aren't in it yet), writes the server's
// env and the accounts to boards/.local/prod-seed.json (LOCAL_DIR; git
// ignored, test-only values), and waits. With START_SERVER=1 it runs the server too (until Ctrl-C);
// otherwise packages/boards/e2e/prod.mjs (UI_E2E=1 in run.sh) starts the
// server from that file and drives it.
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { createWriteStream, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { SCOPES } from '../../../../boards/src/client.mjs'
import { generateClientKey } from '../../../../boards/src/oauth.mjs'
import { Actor } from '../lib/actor.mjs'
import { LOCAL, OUT, PORTS, URLS, log } from '../lib/env.mjs'
import { Vlpds } from '../lib/vlpds.mjs'
import { BoardsClient, boardLink } from './harness.mjs'
import { png, setupLexicons } from './scenarios.mjs'

const PORT = PORTS.boardsProd

let vlpds
async function main() {
  vlpds = await new Vlpds({ memory: !!process.env.MEMORY }).start()
  const lex = await setupLexicons({ vlpds })
  if (!lex) throw new Error('this vlpds binary has no --lexicon-authority-override; the bare grant needs it')
  const acct = {}
  for (const name of ['alice', 'bob', 'carol', 'dave']) acct[name] = await Actor.create('vlpds', name, { scope: SCOPES.owner })
  const alice = new BoardsClient(acct.alice)
  const bob = new BoardsClient(acct.bob)
  const board = await alice.createBoard(`lobby${Date.now().toString(36)}`, {
    name: 'lobby',
    description: 'A private board for the people who run things here. Members only.',
    flairs: ['meta', 'question', 'show-and-tell'],
  })
  await alice.addMember(board, acct.bob.did)
  const welcome = await alice.post(board, { title: 'Welcome to the lobby', body: 'Posts here live in your own space repo on your PDS, never on the firehose. Only members can read them.', flair: 'meta' })
  await alice.pin(board, welcome.uri)
  const q = await bob.post(board, { title: 'Ferris, one pixel at a time', body: 'Took me all weekend.', flair: 'show-and-tell', image: { bytes: png('ferris'), mimeType: 'image/png', alt: 'a very small crab' } })
  await alice.comment(board, q.uri, 'Majestic.')
  await alice.vote(board, q.uri, 'up')

  const dir = `${OUT}boards-prod/`
  rmSync(dir, { recursive: true, force: true })
  mkdirSync(dir, { recursive: true })
  const ui = `http://boards.localhost:${PORT}`
  // the secrets go in as files, the way yeet mounts them in production
  const secret = (name, value) => {
    writeFileSync(`${dir}${name}`, `${value}\n`, { mode: 0o600 })
    return `${dir}${name}`
  }
  const env = {
    BOARDS_PUBLIC_URL: ui,
    BOARDS_ALLOW_HTTP: '1',
    BOARDS_LISTEN: `127.0.0.1:${PORT},[::1]:${PORT}`,
    BOARDS_METRICS_LISTEN: `127.0.0.1:${PORT + 1}`,
    BOARDS_DB: `${dir}boards.sqlite`,
    BOARDS_OAUTH_CLIENT_KEY_FILE: secret('client-key', generateClientKey()),
    BOARDS_SESSION_SECRET_FILE: secret('session-secret', randomBytes(32).toString('base64url')),
    BOARDS_SERVICE_DID: `did:web:127.0.0.1%3A${PORT}`,
    BOARDS_PLC_URL: URLS.plc,
    BOARDS_HANDLE_RESOLVER: URLS.vlpds,
    BOARDS_POLL_MS: '5000',
  }
  mkdirSync(LOCAL, { recursive: true })
  const file = `${LOCAL}prod-seed.json`
  const accounts = Object.entries(acct).map(([name, a]) => ({ name, handle: a.handle, did: a.did, password: a.password }))
  writeFileSync(file, JSON.stringify({ ui, board, metrics: `http://127.0.0.1:${PORT + 1}/metrics`, logDir: dir, env, accounts }, null, 2))
  log(`seeded board ${boardLink(ui, board)}; lexicons by ${lex.handle}`)
  for (const a of accounts) log(`  @${a.handle}`)
  log(`server env and passwords: ${file}`)
  let server
  if (process.env.START_SERVER === '1') {
    const out = createWriteStream(`${dir}server.log`)
    server = spawn(process.execPath, [fileURLToPath(new URL('../../../../boards/src/server.mjs', import.meta.url))], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] })
    server.stdout.pipe(out)
    server.stderr.pipe(out)
    log(`boards (production mode): ${ui} (log: ${dir}server.log)`)
  }
  const stop = async () => {
    server?.kill('SIGTERM')
    await vlpds.stop()
    process.exit(0)
  }
  process.on('SIGINT', stop)
  process.on('SIGTERM', stop)
}

main().catch(async (e) => {
  console.error(e)
  await vlpds?.stop()
  process.exit(2)
})
