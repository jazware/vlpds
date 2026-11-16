---
title: Theming
section: Operations
order: 116
status: ready
summary: "Putting your name, logo, colors and links on the pages users see (sign-in, consent, the account app, /migrate) and in account email, at runtime, without touching the CSP."
---

```hero
diagram:
  caption: "A theme is one config object in the bucket. Every node re-reads it within seconds and renders it into the server-rendered OAuth pages (as a hashed inline stylesheet), the SPA shells (as /theme.css) and account email. The operator console and the docs keep vlpds's look."
  nodes:
    - { id: op, label: Operator, sub: console · CLI · admin XRPC, at: [0, 0], size: [9, 2.6] }
    - { id: cfg, label: theme.json, sub: "bucket object · images inline", at: [14, 0], size: [11, 2.6], shape: store, tone: amber }
    - { id: node, label: vlpds node, sub: "in memory, ≤ 10 s", at: [14, 6], size: [11, 2.6], tone: accent }
    - { id: oauth, label: OAuth pages, sub: "sign-in · consent · errors", at: [30, 3], size: [11, 2.4] }
    - { id: spa, label: Account app, sub: "/account · /migrate · /", at: [30, 6.5], size: [11, 2.4] }
    - { id: mail, label: Account email, sub: "name · logo · color", at: [30, 10], size: [11, 2.4], tone: muted }
  edges:
    - "op -> cfg: putTheme (ifVersion)"
    - "cfg -> node: read"
    - { from: node.r, to: oauth.l, label: inline + hash }
    - { from: node.r, to: spa.l, label: /theme.css }
    - { from: node.r, to: mail.l, dash: true }
facts:
  - { value: "0", unit: changes, label: when unconfigured, note: "no theme is the vlpds look, byte for byte on the OAuth pages" }
  - { value: "4", unit: colors, label: per mode, note: "primary, text on primary, secondary, accent; light and dark apart", tone: blue }
  - { value: "AA", label: contrast checked, note: "a warning in the console and the API, never a refusal", tone: amber }
  - { value: "no", label: custom CSS, note: "tokens only: the consent page must keep saying what it says", tone: rust }
```

A theme puts your name on the server. Without one, users see "vlpds" and its verdigris-and-amber
look. With one, the sign-in, sign-up, consent and federated sign-up pages, the error pages, the
account app, /migrate and the landing page show your name, logo, colors and font, link to your
terms, privacy policy and support, and account email carries your name, logo and color.

It's a runtime setting like [sign-in providers](sign-in-providers.md): one object in the bucket,
saved with `ifVersion`, audited, and picked up by every node within about ten seconds. Nothing
needs a restart or a rebuild.

## What a theme sets

| Setting | Where it shows | Notes |
|---|---|---|
| `name` | Page headers and titles, email's service name and footer, the landing page and its link previews | Up to 48 characters. Replaces "vlpds" (and `--email-brand-name`). |
| `logo` | Page headers, email's header and footer mark | PNG, JPEG or WebP, up to 256 KiB, shown 26–28 px tall. Replaces the strata mark. |
| `logoIsWordmark` | Page headers | The logo already spells the name, so it's shown alone (the name becomes its alt text). |
| `favicon` | Browser tabs on the user pages | PNG or ICO, up to 64 KiB. |
| `colors.light`, `colors.dark` | Every user page; email uses the light primary | See [Colors](#colors). |
| `font` | Every user page | `default` (Schibsted Grotesk), `system`, `serif`, `rounded` or `mono`. |
| `links.home` | Under the pages, email's footer link | Replaces `--email-home-url`. |
| `links.terms`, `links.privacy` | Under the pages, and describeServer's `links` | Replace `--terms-of-service-url` and `--privacy-policy-url`. |
| `links.support` | Under the pages | An `https:` or `mailto:` link. |

Everything is optional. Whatever a theme doesn't set keeps vlpds's value, or the boot-time flag's
where there is one. The rule is the theme first, then the flag (and the reference PDS's `PDS_*`
variable behind it), then the default. The console lists the flags a node has set, so you can see
what still applies.

The operator console and the docs keep vlpds's look. They're the software's own pages, and a
console that looks like the user pages makes it too easy to forget which one you're on.

## Setting it

```steps
- title: In the console
  body: "**Theme** (`g t`) has the form and a live preview of the sign-in page in light and dark, with contrast warnings as you type. **Save…** asks for an audit note and saves against the version you loaded."
- title: With the CLI
  body: "`vlpds admin theme set --name cavu --primary '#0f766e' --primary-dark '#2dd4bf' --logo ./logo.png --terms https://cavu.example/terms` changes just those settings. An empty value (`--terms \"\"`) clears one. `vlpds admin theme show` prints the result and any warnings."
- title: Over XRPC
  body: "`vlpds.admin.getTheme`, then `vlpds.admin.putTheme` with `theme` and the `ifVersion` you read. A stale version answers 409 `VersionMismatch`."
- title: Back to vlpds
  body: "`vlpds admin theme reset --yes`, or **Reset to vlpds…** in the console."
```

`putTheme` replaces the whole theme, except the images. A `logo` or `favicon` left out keeps the
stored one, `null` removes it, and a `data:` URI replaces it:

```json
{
  "theme": {
    "name": "cavu",
    "colors": {
      "light": { "primary": "#0f766e", "secondary": "#f59e0b" },
      "dark": { "primary": "#2dd4bf" }
    },
    "font": "system",
    "links": { "home": "https://cavu.example", "terms": "https://cavu.example/terms", "support": "mailto:help@cavu.example" },
    "logo": "data:image/png;base64,iVBORw0KGgo…"
  },
  "ifVersion": 3,
  "note": "launch branding"
}
```

Each save writes a `theme.put` entry to the audit log, naming the operator, your note, the new
version and which settings changed. Images are checked by their bytes, not by the type the
upload claims. SVG is refused, because an SVG opened from the server's own origin could run
script, and most mail clients won't show one anyway.

## Colors

Each mode has four colors, all `#rrggbb` (`#rgb` is accepted and expanded):

- **primary**: buttons, links, checkboxes and the selected item, plus the first band of the stripe
  under the header.
- **primaryText**: the text on a primary button. If you leave it blank, vlpds picks white or near
  black, whichever reads better on your primary.
- **secondary**: the stripe's second band. It doesn't change warnings, which stay amber.
- **accent**: focus rings.

Light and dark are separate. A color you set for light only doesn't carry over to dark mode,
where vlpds's own color stays, because a primary that reads well on a light page is often too dark
on a dark one. Set both if you want your color in both. The pages follow the user's light, dark
or system choice as before.

The console and `getTheme` / `putTheme` check contrast against WCAG AA: 4.5:1 for text on the
primary and for the primary as link text on the page, and 3:1 for the focus ring against the
background. A failing pair is a warning, not a refusal, but take it seriously. The sign-in and
consent pages are where people decide what to trust.

## How it reaches the pages

```diagram
nodes:
  - { id: doc, label: theme.json, sub: "{prefix}/config/theme.json", at: [0, 2], size: [10, 2.6], shape: store, tone: amber }
  - { id: css, label: "stylesheet", sub: "custom properties only", at: [15, 0], size: [10, 2.4], tone: accent }
  - { id: brand, label: "name · logo · links", at: [15, 4], size: [10, 2.4], tone: accent }
  - { id: oauth, label: "OAuth pages", sub: "<style> + CSP hash", at: [30, 0], size: [11, 2.4] }
  - { id: spa, label: "SPA shell", sub: "/theme.css + JSON block", at: [30, 4], size: [11, 2.4] }
edges:
  - "doc -> css"
  - "doc -> brand"
  - "css -> oauth"
  - "css -> spa"
  - "brand -> oauth"
  - "brand -> spa"
```

The theme becomes a small stylesheet that only sets CSS custom properties (`--accent`,
`--accent-ink`, `--accent-wash`, `--brand2`, `--focus`, `--sans`), and nothing at all when the
theme sets no color or font.

- **The OAuth pages** are server-rendered with no external assets. The theme's stylesheet is a
  second inline `<style>`, and its SHA-256 is added to the page's `style-src`, so the CSP stays
  hash-only. With no theme, the page and its CSP are what they were before themes existed.
- **The SPA** (the account app, /migrate, the landing page) loads `/theme.css?v=…`. Its CSP
  already allows same-origin stylesheets. The name, logo and links come in the page as a JSON
  data block, which isn't script, so `script-src 'self'` doesn't apply and the header is right
  on first paint.
- **Images** are served from `/theme/logo` and `/theme/favicon` with their sniffed type,
  `nosniff`, a `sandbox` CSP, an ETag, and a year's immutable caching under the `?v=` hash the
  pages link. A new logo is a new URL.
- **Email** gets the name, the logo's absolute URL, the light primary and the home link.

### Why there's no custom CSS

Free-form CSS was left out on purpose. A stylesheet an admin login could write would be allowed
on the consent page by its hash like any other, and it could make that page say something it
doesn't, for example by hiding a permission or relabelling **Deny**. It would also break on the
next release, because the pages have no stable selectors to aim at. Design tokens give you the
brand without either problem. If you need more than the tokens, put a proxy in front of the
pages, where you own both the change and its CSP.

## For apps: describeTheme

`GET /xrpc/vlpds.server.describeTheme` is public and cached for a minute. It's for apps that want
to match the server's look. It returns the name, absolute logo and favicon URLs, the font, both
modes' colors resolved (vlpds's where the theme sets none), the links, and the stylesheet's URL:

```json
{
  "name": "cavu",
  "custom": true,
  "logo": "https://pds.cavu.example/theme/logo?v=3f1c…",
  "logoIsWordmark": false,
  "favicon": null,
  "font": "system",
  "colors": {
    "light": { "primary": "#0f766e", "primaryText": "#ffffff", "secondary": "#f59e0b", "accent": "#3561c9", "background": "#edefea", "surface": "#f8f9f6" },
    "dark": { "primary": "#2dd4bf", "primaryText": "#101418", "secondary": "#e3a43a", "accent": "#8fb0ff", "background": "#121820", "surface": "#19212b" }
  },
  "links": { "home": "https://cavu.example", "terms": "https://cavu.example/terms" },
  "stylesheet": "https://pds.cavu.example/theme.css?v=9a0b…",
  "version": 4
}
```

## Clusters and failure

Saving writes `{prefix}/config/theme.json` with a conditional put, installs it on the node that
took the call, and nudges the others to re-read it. A node that misses the nudge picks the change
up on its next ten-second read. A node that can't read the object, or finds it unreadable, keeps
the last good theme. One that has never read it shows vlpds's look.

An older vlpds build doesn't know the object and keeps vlpds's look. Theming needs no feature
level: a mixed cluster just shows the theme on the nodes that know it until the roll finishes.
