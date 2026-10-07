import { adminHeaders, setAdminToken } from '../xrpc'
import { apply, resync, type Change } from './changes'
import { getLive, setPush, type PushState } from './live'

// The change feed: vlpds.admin.subscribeChanges, read with fetch rather than EventSource so it
// carries the admin token (EventSource can't send headers). Each change invalidates the queries
// it names (changes.ts). A reconnect refetches everything on screen, since changes made while it
// was down were missed. The node answering follows its peers, so one connection covers the cluster.
//
// One stream per browser, not per tab: over plain HTTP/1.1 (localhost, an SSH tunnel) a browser
// opens at most six connections to a host, and a stream per console tab would starve the rest.
// The tab holding the `vlpds.console.feed` lock (Web Locks) reads the stream and passes each
// batch to the other tabs over a BroadcastChannel; when it closes, the next tab in line takes over.

const IDLE_MS = 45_000
const ALIVE_MS = 10_000
const LOCK = 'vlpds.console.feed'

type Msg = { t: 'changes'; changes: Change[] } | { t: 'resync' } | { t: 'state'; push: PushState; at?: number } | { t: 'who' }

let gen = 0
let ctl: AbortController | undefined
let connectedOnce = false
let bc: BroadcastChannel | undefined
let leading = false
let followerTimer: ReturnType<typeof setTimeout> | undefined

function post(m: Msg) {
  try {
    bc?.postMessage(m)
  } catch {
    /* closed */
  }
}

/** This tab's feed state, and (leading) every other tab's. */
function state(push: PushState, at?: number) {
  setPush(push, at)
  if (leading) post({ t: 'state', push, at })
}

/** Starts the feed for this tab; the returned function stops it. */
export function startPush(): () => void {
  const mine = ++gen
  const stop = new AbortController()
  if (typeof BroadcastChannel !== 'undefined') {
    bc = new BroadcastChannel(LOCK)
    bc.onmessage = (e: MessageEvent<Msg>) => {
      if (!leading) follow(e.data)
      else if (e.data.t === 'who') post({ t: 'state', push: getLive().push, at: getLive().pushAt })
    }
  }
  const lead = async () => {
    if (gen !== mine) return
    leading = true
    clearTimeout(followerTimer)
    try {
      await loop(mine)
    } finally {
      leading = false
    }
  }
  if (typeof navigator !== 'undefined' && navigator.locks && bc) {
    // another tab may lead already: until it says otherwise, assume it's connecting
    setPush('connecting')
    post({ t: 'who' })
    navigator.locks.request(LOCK, { signal: stop.signal }, lead).catch(() => {})
  } else void lead()
  // a page leaving (or frozen in the back-forward cache) gives its connection back at once
  const leave = () => end()
  addEventListener('pagehide', leave)
  function end() {
    if (gen !== mine) return
    gen++
    stop.abort()
    ctl?.abort()
    removeEventListener('pagehide', leave)
    clearTimeout(followerTimer)
    bc?.close()
    bc = undefined
  }
  return end
}

/** A tab that doesn't hold the stream: it hears the leader's. */
function follow(m: Msg) {
  if (m.t === 'who') return
  // a tab that followed has data: if it takes over, its first stream is a reconnect
  connectedOnce = true
  if (m.t === 'changes') apply(m.changes)
  else if (m.t === 'resync') resync()
  else if (m.t === 'state') setPush(m.push, m.at)
  // the leader says something at least every 10 s while its stream is up
  clearTimeout(followerTimer)
  followerTimer = setTimeout(() => setPush(getLive().push === 'live' ? 'down' : getLive().push), IDLE_MS)
}

async function loop(mine: number) {
  let backoff = 1000
  while (gen === mine) {
    state(connectedOnce ? 'down' : 'connecting')
    const outcome = await connect(mine)
    if (gen !== mine || outcome === 'stop') return
    if (outcome === 'unsupported') return state('off')
    state(connectedOnce ? 'down' : 'connecting')
    if (outcome === 'ok') backoff = 1000
    await new Promise((r) => setTimeout(r, backoff))
    backoff = Math.min(backoff * 2, 15_000)
  }
}

async function connect(mine: number): Promise<'ok' | 'failed' | 'stop' | 'unsupported'> {
  const auth = adminHeaders()
  if (!auth) return 'stop'
  const c = new AbortController()
  ctl = c
  let idle: ReturnType<typeof setTimeout> | undefined
  let aliveAt = 0
  const poke = () => {
    clearTimeout(idle)
    idle = setTimeout(() => c.abort(), IDLE_MS)
    if (Date.now() - aliveAt > ALIVE_MS && getLive().push === 'live') {
      aliveAt = Date.now()
      post({ t: 'state', push: 'live', at: getLive().pushAt })
    }
  }
  try {
    poke()
    const r = await fetch('/xrpc/vlpds.admin.subscribeChanges', { headers: { ...auth, accept: 'text/event-stream' }, signal: c.signal, cache: 'no-store' })
    if (r.status === 401) {
      setAdminToken(null)
      return 'stop'
    }
    if (r.status === 404 || r.status === 501) return 'unsupported'
    if (!r.ok || !r.body) return 'failed'
    const reader = r.body.pipeThrough(new TextDecoderStream()).getReader()
    let buf = ''
    for (;;) {
      const { value, done } = await reader.read()
      if (done || gen !== mine) break
      poke()
      buf += value
      let i: number
      while ((i = buf.indexOf('\n\n')) >= 0) {
        onMessage(buf.slice(0, i))
        buf = buf.slice(i + 2)
      }
    }
    return 'ok'
  } catch {
    return 'failed'
  } finally {
    clearTimeout(idle)
  }
}

let batch: Change[] = []
let flush: ReturnType<typeof setTimeout> | undefined

function onMessage(msg: string) {
  let event = 'message'
  let data = ''
  for (const line of msg.split('\n')) {
    if (line.startsWith('event:')) event = line.slice(6).trim()
    else if (line.startsWith('data:')) data += line.slice(5).trim()
  }
  if (!data) return
  let body: unknown
  try {
    body = JSON.parse(data)
  } catch {
    return
  }
  if (event === 'hello') {
    // changes made while the feed was down were missed (here, and by the tabs that follow it)
    if (connectedOnce) {
      resync()
      post({ t: 'resync' })
    }
    connectedOnce = true
    state('live', Date.now())
    return
  }
  const c = body as Change
  if (!c?.kind) return
  setPush('live', Date.now())
  // one invalidation pass per burst the server sent together
  batch.push(c)
  flush ??= setTimeout(() => {
    const b = batch
    batch = []
    flush = undefined
    apply(b)
    post({ t: 'changes', changes: b })
  }, 0)
}
