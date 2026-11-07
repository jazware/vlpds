// Linux only (run.sh starts it): the reference PDS containers reach the host
// at Docker's host-gateway address, where nothing listens, since every host
// side service binds 127.0.0.1. This forwards each harness port on that
// address to the same port on 127.0.0.1, so the containers reach vlpds, the
// notify services and the fault proxies. The gateway address is only
// routable from this host's own containers.
//
//   node lib/hostbridge.mjs <gateway ip> <first port> <last port> [skip port ...]
import net from 'node:net'

const [gw, first, last, ...skip] = process.argv.slice(2)
const skipped = new Set(skip.map(Number))
let up = 0
for (let p = Number(first); p <= Number(last); p++) {
  if (skipped.has(p)) continue
  const port = p
  const server = net.createServer((inbound) => {
    const out = net.connect(port, '127.0.0.1')
    inbound.pipe(out).pipe(inbound)
    const close = () => {
      inbound.destroy()
      out.destroy()
    }
    inbound.on('error', close)
    out.on('error', close)
  })
  server.on('error', (e) => console.error(`hostbridge ${gw}:${port}: ${e.message}`))
  server.listen(port, gw, () => {
    if (++up === Number(last) - Number(first) + 1 - skipped.size) console.error(`hostbridge: ${gw}:${first}-${last} -> 127.0.0.1`)
  })
}
