# auth-providers: the sign-in pages in a real browser

`run.sh` starts a local in-memory vlpds on `http://localhost:2795` with
Sign-In with Ethereum enabled, links a wallet to a fresh account over the HTTP
API, and then drives the *authorization page* in headless Chromium:

1. The sign-in page offers the configured method ("Continue with Ethereum"),
   as a link, so no form post and no page script is needed for it.
2. The wallet page (`/oauth/authorize/wallet`) renders its one button and runs
   its one script under its own CSP (`connect-src 'self'`, allowed by hash).
3. The injected `window.ethereum` signs the exact EIP-4361 message the page
   fetched, with secp256k1 and a recovery id over Keccak-256 — the same curve
   and hash the server recovers the address from.
4. The server verifies it, resolves the account, and renders the consent page,
   which now names the account.
5. Allowing it yields a code, which the script exchanges for DPoP-bound tokens
   and reads `getSession` back with.

Any page error or CSP violation fails the run, and screenshots land in
`out/shots/` (`SHOTS` overrides the directory, `HEADED=1` shows the browser).

```sh
bench/auth-providers/run.sh      # or: just auth-providers-e2e
VLPDS_BIN=target/dev-release/vlpds bench/auth-providers/run.sh
```

The wallet's private key is derived from a fixed string, so a failure is
reproducible. The signing happens in Node (secp256k1 is not a browser API);
the page asks this process for the signature through `page.exposeFunction`,
which is why the harness depends on `@noble/curves` and `@noble/hashes`. That
is the only part of the wallet that is not the browser's own: the message, the
origin, the CSP, the page script, the form post and the server's verification
are all real.

What this covers that the Rust suite cannot: the rendered HTML and its CSP, the
wallet page's script (its hash has to match, or the browser refuses to run it),
the same-origin XMLHttpRequest a real page makes, and the whole
authorization-page → consent → code path a client app sees.

Not covered here: a Google or Apple round trip (they need a provider that
redirects, and a stub issuer is what `tests/all/auth_oidc.rs` uses), the
account app's own pages, and the passkey ceremony (see `bench/passkeys`).