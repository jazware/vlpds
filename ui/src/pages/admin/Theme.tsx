import { useEffect, useMemo, useState, type CSSProperties, type ReactNode } from 'react'
import { confirmAction } from '../../components/console/dialogs'
import { Banners, Chip, ErrorState, Loading, NeedsVersion, PageHead, Panel, PanelBody, Src, type BannerSpec } from '../../components/console/kit'
import '../../console-theme.css'
import { fmtBytes } from '../../lib/format'
import { missing } from '../../lib/console/sys'
import { dataUri, draftOf, normalize, resolve, saveTheme, sniff, themeQ, VLPDS, warnings, mix, type ColorKey, type Draft, type Font, type ImageEdit, type LinkKey, type Mode, type Resolved, type ThemeView } from '../../lib/console/theme'
import { Link } from '../../lib/router'

// Theme (docs/operations/theming.md): the name, logo, colors, font and links users see on the
// sign-in pages, the account app, /migrate and in account email. One config object saved with
// ifVersion; the preview renders from the draft before anything is saved. The console itself and
// the docs keep vlpds's look.

export function Theme() {
  const q = themeQ.use()
  const d = q.data
  if (!d) {
    if (q.error && missing(q.error))
      return (
        <>
          <PageHead title="Theme" />
          <Panel>
            <NeedsVersion what="Theming" nsid="vlpds.admin.getTheme" />
          </Panel>
        </>
      )
    return q.error ? <ErrorState error={q.error} retry={themeQ.refresh} /> : <Loading />
  }
  return <Editor v={d} at={q.at} stale={!!q.error} />
}

const FONTS: [Font, string][] = [
  ['default', 'Schibsted Grotesk (vlpds)'],
  ['system', 'The device’s UI font'],
  ['serif', 'Serif'],
  ['rounded', 'Rounded'],
  ['mono', 'JetBrains Mono'],
]
const COLORS: [ColorKey, string, string][] = [
  ['primary', 'Primary', 'buttons, links, checkboxes'],
  ['primaryText', 'Text on primary', 'blank: white or near black, whichever reads better'],
  ['secondary', 'Secondary', 'the second band under the header'],
  ['accent', 'Accent', 'focus rings'],
]
const LINKS: [LinkKey, string, string][] = [
  ['home', 'Home', 'https://example.com — also email’s footer link'],
  ['terms', 'Terms', 'https://example.com/terms — also describeServer'],
  ['privacy', 'Privacy', 'https://example.com/privacy — also describeServer'],
  ['support', 'Support', 'https://… or mailto:help@example.com'],
]

function Editor({ v, at, stale }: { v: ThemeView; at?: number; stale: boolean }) {
  const [draft, setDraft] = useState<Draft>(() => draftOf(v))
  const [base, setBase] = useState(v.version)
  const [imgErr, setImgErr] = useState<string>()
  const saved = useMemo(() => JSON.stringify(draftOf(v)), [v])
  const dirty = JSON.stringify(draft) !== saved
  // someone else saved while this was clean: take theirs
  useEffect(() => {
    if (!dirty && v.version !== base) {
      setDraft(draftOf(v))
      setBase(v.version)
    }
  }, [v, dirty, base])
  const conflict = v.version !== base

  const set = (f: (d: Draft) => void) =>
    setDraft((d) => {
      const n: Draft = structuredClone(d)
      f(n)
      return n
    })
  const badColors = (['light', 'dark'] as Mode[]).flatMap((m) => COLORS.filter(([k]) => draft.colors[m][k]?.trim() && !normalize(draft.colors[m][k])).map(([k]) => `${m}.${k}`))
  const badLinks = LINKS.filter(([k]) => {
    const u = draft.links[k]?.trim()
    return u && !(/^https:\/\//.test(u) || /^http:\/\/(localhost|127\.0\.0\.1)/.test(u) || (k === 'support' && /^mailto:[^@\s]+@\S+$/.test(u)))
  }).map(([k]) => k)
  const warn = warnings(draft.colors, v.defaults)
  const logoSrc = draft.logo === undefined ? v.theme.logo?.url : draft.logo ?? undefined
  const faviconSrc = draft.favicon === undefined ? v.theme.favicon?.url : draft.favicon ?? undefined

  const pick = (kind: 'logo' | 'favicon') => async (f: File | undefined) => {
    setImgErr(undefined)
    if (!f) return
    const max = kind === 'logo' ? v.limits.logoBytes : v.limits.faviconBytes
    const types = kind === 'logo' ? v.limits.logoTypes : v.limits.faviconTypes
    const mime = await sniff(f)
    if (!mime || !types.includes(mime)) return setImgErr(`${kind}: ${types.map((t) => t.replace('image/', '').replace('x-icon', 'ico')).join(', ')} only (SVG can’t be served safely)`)
    if (f.size > max) return setImgErr(`${kind}: ${fmtBytes(f.size)}, over the ${fmtBytes(max)} limit`)
    const uri = await dataUri(f)
    set((d) => void (d[kind] = uri))
  }

  const save = () =>
    confirmAction({
      tone: 'warn',
      primary: true,
      title: 'Save the theme?',
      items: [
        <>Every node shows it within seconds: the sign-in and consent pages, the account app, /migrate and new account email.</>,
        warn.length ? <>{warn.length} contrast warning{warn.length > 1 ? 's' : ''}: text may be hard to read.</> : <>Contrast passes WCAG AA.</>,
      ],
      fields: [{ id: 'note', label: 'Note for the audit log', placeholder: 'optional' }],
      action: 'Save',
      call: `vlpds.admin.putTheme {ifVersion: ${base}}`,
      run: async (vals) => {
        const r = await saveTheme(draft, { ifVersion: base, note: String(vals.note ?? '') })
        setDraft(draftOf(r))
        setBase(r.version)
        return r
      },
      done: (r) => `Theme saved (v${(r as ThemeView).version})`,
    })
  const reset = () =>
    confirmAction({
      tone: 'warn',
      title: 'Back to vlpds’s look?',
      items: [<>Clears the name, both images, every color, the font and the links.</>],
      action: 'Reset',
      call: `vlpds.admin.putTheme {ifVersion: ${v.version}}`,
      run: async () => {
        const r = await saveTheme(VLPDS, { ifVersion: v.version, note: 'reset to vlpds' })
        setDraft(draftOf(r))
        setBase(r.version)
        return r
      },
      done: 'Theme reset',
    })

  const banners: BannerSpec[] = []
  if (stale) banners.push({ id: 'stale', tone: 'warn', title: 'Not updating', desc: 'getTheme is failing; showing the last answer.' })
  if (conflict && dirty) banners.push({ id: 'conflict', tone: 'warn', title: `Changed elsewhere (now v${v.version})`, desc: 'Saving would be refused. Discard your edits to load it.', right: <button type="button" className="cx-btn sm" onClick={() => (setDraft(draftOf(v)), setBase(v.version))}>Discard edits</button> })
  if (imgErr) banners.push({ id: 'img', tone: 'err', title: imgErr })
  for (const w of warn) banners.push({ id: `${w.mode}-${w.check}`, tone: 'warn', title: `Contrast: ${w.message}`, desc: 'Saving is allowed; readers with low vision may struggle.' })

  const flags = Object.entries(v.fallbacks).filter(([, x]) => x)
  const custom = v.version > 0 && JSON.stringify(draftOf(v)) !== JSON.stringify({ ...VLPDS, logo: undefined, favicon: undefined }) || !!v.theme.logo || !!v.theme.favicon

  return (
    <>
      <PageHead
        title="Theme"
        sub={
          <>
            <span>{custom ? (v.theme.name ?? 'custom') : 'vlpds (unthemed)'}</span>
            {v.version > 0 && <span>v{v.version}</span>}
            {v.updatedBy && <span className="muted">by {v.updatedBy}</span>}
          </>
        }
        updated={at}
        actions={
          <>
            <button type="button" className="cx-btn" disabled={!custom} onClick={() => void reset()}>
              Reset to vlpds…
            </button>
            <button type="button" className="cx-btn" disabled={!dirty} onClick={() => setDraft(draftOf(v))}>
              Discard
            </button>
            <button type="button" className="cx-btn primary" disabled={!dirty || badColors.length > 0 || badLinks.length > 0 || (conflict && dirty)} onClick={() => void save()}>
              Save…
            </button>
          </>
        }
      />
      <Banners items={banners} />
      <div className="cxt-grid">
        <div className="cxt-form">
          <Panel title="Identity" src={<Src>getTheme · putTheme</Src>}>
            <PanelBody>
              <Row label="Name" hint={`Replaces “vlpds” in the pages’ headers and titles, and the service name in email. Up to ${v.limits.nameChars} characters.`}>
                <input className="cx-inp" value={draft.name} maxLength={v.limits.nameChars} placeholder="vlpds" onChange={(e) => set((d) => void (d.name = e.target.value))} />
              </Row>
              <ImageRow label="Logo" hint={`PNG, JPEG or WebP, up to ${fmtBytes(v.limits.logoBytes)}. Shown 26–28 px tall.`} accept="image/png,image/jpeg,image/webp" src={logoSrc} stored={v.theme.logo} edit={draft.logo} onPick={pick('logo')} onClear={() => set((d) => void (d.logo = v.theme.logo ? null : undefined))} onUndo={() => set((d) => void (d.logo = undefined))} />
              <Row label="">
                <label className="cxt-check">
                  <input type="checkbox" checked={draft.logoIsWordmark} disabled={!logoSrc} onChange={(e) => set((d) => void (d.logoIsWordmark = e.target.checked))} />
                  The logo already spells the name: show it alone
                </label>
              </Row>
              <ImageRow label="Favicon" hint={`PNG or ICO, up to ${fmtBytes(v.limits.faviconBytes)}.`} accept="image/png,image/x-icon,.ico" src={faviconSrc} stored={v.theme.favicon} edit={draft.favicon} onPick={pick('favicon')} onClear={() => set((d) => void (d.favicon = v.theme.favicon ? null : undefined))} onUndo={() => set((d) => void (d.favicon = undefined))} />
              <Row label="Font" hint="Only fonts that load nothing from another host (the pages’ CSP).">
                <select className="cx-inp" value={draft.font} onChange={(e) => set((d) => void (d.font = e.target.value as Font))}>
                  {FONTS.map(([f, l]) => (
                    <option key={f} value={f}>
                      {l}
                    </option>
                  ))}
                </select>
              </Row>
            </PanelBody>
          </Panel>
          <Panel title="Colors" foot={<span>Each mode on its own: a color left blank keeps vlpds’s for that mode. Warnings use WCAG AA (4.5:1 for text, 3:1 for the focus ring).</span>}>
            <PanelBody>
              <div className="cxt-colors">
                <span />
                <b>Light</b>
                <b>Dark</b>
                {COLORS.map(([k, label, hint]) => (
                  <ColorRow key={k} k={k} label={label} hint={hint} draft={draft} v={v} set={set} />
                ))}
              </div>
            </PanelBody>
          </Panel>
          <Panel title="Links" foot={<span>Shown under the sign-in pages, the account app and /migrate. Terms and privacy also answer describeServer’s links.</span>}>
            <PanelBody>
              {LINKS.map(([k, label, ph]) => (
                <Row key={k} label={label}>
                  <input className="cx-inp mono" value={draft.links[k] ?? ''} placeholder={ph} aria-invalid={badLinks.includes(k) || undefined} onChange={(e) => set((d) => void (d.links[k] = e.target.value))} />
                </Row>
              ))}
            </PanelBody>
          </Panel>
          {flags.length > 0 && (
            <Panel title="Boot-time settings this replaces">
              <PanelBody>
                <p className="muted sm">These flags are set on this node. Where the theme sets the same thing, the theme wins; where it doesn’t, they still apply.</p>
                <dl className="cxt-flags">
                  {flags.map(([k, x]) => (
                    <div key={k}>
                      <dt>{k}</dt>
                      <dd className="mono sm">{x}</dd>
                    </div>
                  ))}
                </dl>
              </PanelBody>
            </Panel>
          )}
        </div>
        <div className="cxt-side">
          <Panel title="Preview" right={dirty ? <Chip k="warn">unsaved</Chip> : <Chip k="ok">saved</Chip>}>
            <PanelBody>
              {(['light', 'dark'] as Mode[]).map((m) => (
                <Preview key={m} mode={m} r={resolve(draft.colors[m], v.defaults[m])} d={v.defaults[m]} draft={draft} logo={logoSrc} />
              ))}
              <p className="muted sm">
                The sign-in page as users will see it. The console and the <Link to="/docs/operations/theming">docs</Link> keep vlpds’s look.
              </p>
            </PanelBody>
          </Panel>
        </div>
      </div>
    </>
  )
}

function Row({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="cxt-row">
      <span className="cx-lbl">{label}</span>
      <div>
        {children}
        {hint && <div className="muted sm cxt-hint">{hint}</div>}
      </div>
    </div>
  )
}

function ImageRow(p: { label: string; hint: string; accept: string; src?: string; stored: ThemeView['theme']['logo']; edit: ImageEdit; onPick: (f: File | undefined) => void; onClear: () => void; onUndo: () => void }) {
  return (
    <Row label={p.label} hint={p.hint}>
      <div className="cx-form-row">
        {p.src ? <img className="cxt-thumb" src={p.src} alt="" /> : <span className="muted sm">none</span>}
        {p.edit === undefined && p.stored && <span className="mono sm muted">{fmtBytes(p.stored.bytes)} · {p.stored.sha256.slice(0, 12)}</span>}
        {p.edit !== undefined && <Chip k="warn">{p.edit === null ? 'removed' : 'new'}</Chip>}
        <label className="cx-btn sm">
          Choose…
          <input type="file" hidden accept={p.accept} onChange={(e) => (p.onPick(e.target.files?.[0]), (e.target.value = ''))} />
        </label>
        {p.src && (
          <button type="button" className="cx-btn sm" onClick={p.onClear}>
            Remove
          </button>
        )}
        {p.edit !== undefined && (
          <button type="button" className="cx-btn sm" onClick={p.onUndo}>
            Undo
          </button>
        )}
      </div>
    </Row>
  )
}

function ColorRow({ k, label, hint, draft, v, set }: { k: ColorKey; label: string; hint: string; draft: Draft; v: ThemeView; set: (f: (d: Draft) => void) => void }) {
  return (
    <>
      <span className="cxt-cl" title={hint}>
        {label}
        <span className="muted sm">{hint}</span>
      </span>
      {(['light', 'dark'] as Mode[]).map((m) => {
        const val = draft.colors[m][k] ?? ''
        const ok = normalize(val)
        const shown = ok ?? resolve(draft.colors[m], v.defaults[m])[k]
        return (
          <div key={m} className="cxt-color">
            <input type="color" value={shown} aria-label={`${label} (${m})`} onChange={(e) => set((d) => void (d.colors[m][k] = e.target.value))} />
            <input className="cx-inp mono" value={val} placeholder={resolve({ ...draft.colors[m], [k]: undefined }, v.defaults[m])[k]} aria-label={`${label} (${m}) hex`} aria-invalid={(!!val.trim() && !ok) || undefined} onChange={(e) => set((d) => void (d.colors[m][k] = e.target.value))} />
            {val && (
              <button type="button" className="cx-iconbtn" title="Back to vlpds’s" aria-label={`Clear ${label} (${m})`} onClick={() => set((d) => void delete d.colors[m][k])}>
                ×
              </button>
            )}
          </div>
        )
      })}
    </>
  )
}

const FONT_STACK: Record<Font, string> = {
  default: "'Schibsted Grotesk', ui-sans-serif, system-ui, sans-serif",
  system: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
  serif: "ui-serif, Georgia, Cambria, 'Times New Roman', serif",
  rounded: "ui-rounded, 'SF Pro Rounded', system-ui, sans-serif",
  mono: "'JetBrains Mono', ui-monospace, Menlo, monospace",
}

/** A small sign-in card painted from the draft (inline custom properties: style-src doesn't govern them). */
function Preview({ mode, r, d, draft, logo }: { mode: Mode; r: Resolved; d: Resolved; draft: Draft; logo?: string }) {
  const dark = mode === 'dark'
  const vars = {
    '--p-paper': r.background,
    '--p-sheet': r.surface,
    '--p-ink': dark ? '#dce4e3' : '#18222d',
    '--p-ink2': dark ? '#93a0a8' : '#4d5966',
    '--p-rule': dark ? '#2a3542' : '#c9cfc8',
    '--p-accent': r.primary,
    '--p-accent-ink': r.primaryText,
    '--p-wash': mix(r.primary, d.background, 0.16),
    '--p-brand2': r.secondary,
    '--p-focus': r.accent,
    fontFamily: FONT_STACK[draft.font],
  } as CSSProperties
  const name = draft.name.trim() || 'vlpds'
  const links = LINKS.filter(([k]) => draft.links[k]?.trim()).map(([, l]) => l)
  return (
    <div className="cxt-pv" style={vars} aria-label={`${mode} preview`}>
      <div className="cxt-pv-brand">
        {logo ? <img src={logo} alt={draft.logoIsWordmark ? name : ''} /> : <Mark />}
        {!(logo && draft.logoIsWordmark) && <b>{name}</b>}
        <span>account security</span>
        <span className="cxt-pv-mode">{mode}</span>
      </div>
      <div className="cxt-pv-card">
        <div className="cxt-pv-strata" />
        <div className="cxt-pv-h">Sign in to pds.example.com</div>
        <div className="cxt-pv-muted">to continue to</div>
        <div className="cxt-pv-client">https://app.example</div>
        <div className="cxt-pv-lbl">Handle or email</div>
        <div className="cxt-pv-in cxt-pv-focus">alice.example.com</div>
        <div className="cxt-pv-row">
          <a href="#preview" onClick={(e) => e.preventDefault()}>
            Forgot password?
          </a>
          <span className="cxt-pv-btn">Sign in</span>
        </div>
        <label className="cxt-pv-check">
          <input type="checkbox" checked readOnly tabIndex={-1} /> Trust this device
        </label>
      </div>
      {links.length > 0 && <div className="cxt-pv-links">{links.join('  ·  ')}</div>}
    </div>
  )
}

const Mark = () => (
  <svg width="22" height="18" viewBox="0 0 22 18" aria-hidden="true">
    <rect x="0" y="0" width="22" height="4" rx="1" fill="currentColor" />
    <rect x="3" y="7" width="16" height="4" rx="1" fill="currentColor" opacity=".6" />
    <rect x="6" y="14" width="10" height="4" rx="1" fill="currentColor" opacity=".35" />
  </svg>
)
