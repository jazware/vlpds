---
title: Branding
section: Operations
order: 116
status: ready
summary: "Put your name, logo, favicon, accent color and links on the pages your users see, in email and in describeServer, with a few boot flags."
---

```hero
diagram:
  caption: "Branding is boot config. A node reads the flags and image files once at startup, refuses to start on a bad value, and serves the images itself. The operator console and the docs keep vlpds's own look."
  nodes:
    - { id: flags, label: Flags and files, sub: "--brand-name · --logo-file · --primary-color", at: [0, 3], size: [11, 3], shape: note, tone: muted }
    - { id: pds, label: vlpds node, sub: "checked once at startup", at: [15, 3], size: [9, 3], tone: accent }
    - { id: oauth, label: OAuth pages, sub: "sign-in · consent", at: [29, 0], size: [9, 2.6] }
    - { id: spa, label: Account pages, sub: "landing · account · /migrate", at: [29, 3.4], size: [9, 2.6] }
    - { id: mail, label: Email, sub: "name · logo · color · links", at: [29, 6.8], size: [9, 2.6], tone: violet }
    - { id: ds, label: describeServer, sub: "terms · privacy", at: [29, 10.2], size: [9, 2.6], tone: muted }
  edges:
    - { from: flags.r, to: pds.l, label: read once }
    - { from: pds.r, to: oauth.l }
    - { from: pds.r, to: spa.l }
    - { from: pds.r, to: mail.l }
    - { from: pds.r, to: ds.l }
facts:
  - { value: "256 KiB", label: largest logo or favicon, note: "PNG, JPEG or WebP, sniffed by their bytes; never SVG" }
  - { value: "#rrggbb", label: accent color, note: "text on it is black or white, whichever contrasts more", tone: amber }
  - { value: "0", unit: objects, label: stored in the bucket, note: "change a flag and restart the node", tone: blue }
  - { value: "4", unit: links, label: under the pages, note: "home, terms, privacy and support", tone: violet }
```

Branding lets you put your own name, logo and color on a vlpds server, so your users see your
service when they sign in to an app or manage their account. It's a handful of flags. Without any
of them, every page looks the way it always has.

## The flags

| Flag | Fallback variables | What it does |
|---|---|---|
| `--brand-name` | `VLPDS_EMAIL_BRAND_NAME`, `PDS_SERVICE_NAME` | the name in the page header, the page titles and email (up to 64 characters). Also `--email-brand-name` |
| `--logo-file` | | a PNG, JPEG or WebP of at most 256 KiB, served at `/brand/logo`. It goes beside the name in the header and is email's logo |
| `--favicon-file` | | the same kinds of file, served at `/brand/favicon`. Unset, the pages keep vlpds's icon |
| `--primary-color` | `VLPDS_EMAIL_PRIMARY_COLOR`, `PDS_PRIMARY_COLOR` | the accent, as `#rrggbb`: buttons, links, checkboxes and email's handle color. Also `--email-primary-color` |
| `--primary-color-dark` | | the accent in dark mode. Unset, dark mode uses `--primary-color` too. Needs a light color from `--primary-color` or its variables, else startup fails |
| `--home-url` | `VLPDS_EMAIL_HOME_URL`, `PDS_HOME_URL` | a "Home" link under the pages and email's footer link. Also `--email-home-url` |
| `--support-url` | `PDS_SUPPORT_URL` | a "Support" link, https or `mailto:` |
| `--terms-of-service-url` | `PDS_TERMS_OF_SERVICE_URL` | describeServer's `links.termsOfService` and a link under the pages |
| `--privacy-policy-url` | `PDS_PRIVACY_POLICY_URL` | describeServer's `links.privacyPolicy` and a link under the pages |
| `--email-logo-url` | `PDS_LOGO_URL` | email's logo, when it should come from somewhere other than `/brand/logo` |

Each flag also has a `VLPDS_` variable (`VLPDS_BRAND_NAME`, `VLPDS_LOGO_FILE` and so on). A flag
wins over its fallbacks, and the fallbacks are tried in the order listed, so a reference PDS's
`pds.env` works as it is. An empty value counts as unset.

The `--email-*` names are from when these settings only reached email. They still work, as
aliases of the server-wide flags.

## What fails startup

```steps
- title: A color that isn't `#rrggbb`
  body: "`#c2410c` is fine. `red`, `#fff` and `rgb(…)` stop the node with an error naming the flag."
- title: A link that isn't https
  body: "Every link must be `https://` with a host and no credentials. The support link may also be `mailto:`."
- title: An image vlpds won't serve
  body: "A file that can't be read, is empty, is over 256 KiB, or isn't a PNG, JPEG or WebP by its first bytes. SVG is refused even when it's named `.png`, since an SVG opened from your domain can run script."
```

A node that starts has branding it can serve. One check only warns: an accent with less than 4.5:1
contrast against the page background (`#f8f9f6` light, `#19212b` dark). Links in that color would
be hard to read, so the log says which mode and suggests `--primary-color-dark` when the light
color is too dark for dark mode.

## Where it shows

| Place | Name | Logo | Favicon | Accent | Links |
|---|---|---|---|---|---|
| OAuth sign-in, consent and connected apps | header | header | yes | yes | under the card |
| Landing, account, sign-up and /migrate | header and title | header | yes | yes | under the page |
| Email | footer and logo text | header and footer | | handles | footer |
| describeServer | | | | | terms and privacy |
| Operator console and /docs | vlpds | vlpds | vlpds | vlpds | |

On the OAuth pages, branding changes the header and the links under the card. The app's name and
client ID, the permission rows and the Deny and Allow buttons look the same on every server, so a
user can always tell what an app asks for. The accent recolors buttons and links, but the red and
amber that mark risky permissions don't change.

The pages' Content-Security-Policy stays strict. The OAuth pages allow their two stylesheets by
hash, and the account pages load the accent from `/brand/brand.css` on the same origin. The logo
and favicon are served from your server with `X-Content-Type-Options: nosniff` and a sandboxed CSP,
so they're only ever images.

Email uses `--email-logo-url` when it's set, then the served logo's full URL, then the Bluesky logo
the reference PDS uses. Plenty of mail clients don't show WebP, so use a PNG or JPEG logo if your
users read mail in Outlook.

## Changing it

Branding is boot config. vlpds keeps no copy of it in the bucket, so changing it means changing
the flags or files and restarting each node. In a cluster, give every node the same values. Pages
reference the images as `/brand/logo?v=<hash>`, so a new logo shows up as soon as a node serves it,
with no stale cache.

Details: [Configuration](configuration.md) lists the rest of the flags, and
[Email and moderation](email-and-moderation.md) covers sending mail.
