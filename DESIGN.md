# DESIGN.md — NTOD Design System

**NTOD** — LAN discovery & packet tools.
Sibling of NTOK SCAN: same product family, same design language.

The full system is defined in `ntok-scan/DESIGN.md` ("Blue Ceramic +
Obsidian Bento", v11). This file is the ntod-specific delta — the shared
part is vendored into `apps/web/app.css`; ntod-only additions
live in `apps/web/ntod.css`. ntod is dark-only, so the vendored copy has
the `paper`/`terminal` theme blocks and theme-menu swatches stripped —
a re-sync from `crates/ntok-web/assets/app.css` restores them (harmless,
they're inert under `data-view="night"`); feature rules still come from
ntok, ntod deltas stay in `ntod.css`.

## What ntod uses

- **Views**: `night` only — "Obsidian Ember". `data-view` is pinned in
  `shell()` + `boot.js`; there is no appearance menu and `ntok-view`
  localStorage is ignored. All ntod theming is token-overrides on
  `[data-view="night"]` in `ntod.css` — the vendored `app.css` is
  untouched so ntok re-syncs stay clean.
- **Accent**: ember/amber ramp (`#F59E4C` family) matching the gold
  ribbon-N mark — primary actions carry a soft ember halo; obsidian
  islands use a warm `--obs-line`. Semantic ok/warn/err unchanged.
- **Chrome**: floating glass `.top` nav — gold ribbon-N mark
  (`apps/web/brand.png` on an obsidian chip, favicon `icon.png`),
  `NTOD` wordmark, `.nav` segmented view switch centered in the bar
  (Scan / Sniff / Wi-Fi / Analyze / Tools / Devices), `.sys-pill`
  engine status (`.live` while an operation runs). A faint ember
  horizon bloom sits behind the content (background layer, no fills).
- **Layout**: `.page-head` (grotesk title + `.lede`) → action `.btn` →
  `.panel.flush` results table → `.status-row` `.pill`.
- **Data**: IBM Plex Mono, tabular numerals, hairline separators; state
  semantics map to `.pill` (`running` / `done` / `err` / `warn`).
- **Icons**: the same authored 24px / 1.5px-stroke / `currentColor` set
  as ntok (`icons.rs`), inlined — no icon font, no CDN icons.
- **Fonts**: Space Grotesk (variable 300–700) + IBM Plex Mono (400/500/
  600) self-hosted as woff2 in `apps/web/fonts/` behind `fonts.css`
  (@font-face, latin subset, `display=swap`). Identical faces to ntok's
  Google-Fonts stack, rendered fully offline — no CDN fetch.
- **Telemetry islands** (obsidian, ember accent — the signature motif):
  - *Scan*: per-host `.grid` port map — the 24 `TOP_PORTS` probes as
    cells, `.cell.open` lit sky when the enrichment lands.
  - *Sniff*: live `.wave` packets/sec spline from a client-side
    48-bucket ring (1s tick), area fill, proto counts, peak + total
    meta row. Bounded: table capped at 300 rows.
  - *Wi-Fi*: `.sec-pips` 5-segment signal meter in the Signal column
    (`.low` warn under 40%).

## ntod deltas (in `ntod.css`)

- Brand: `.mark` img sizing + warm ring, ember accent ramp on
  `[data-view="night"]`, ambient horizon bloom, centered floating
  `.nav`, ember halo on primary `.btn`, edge-light on panels.
- `.nav .navbtn[aria-current="page"]` — segmented-nav active state for
  `<button>` (ntok uses `<a>`; ntod switches views client-side).
- `.status-row` — status pill lane under the results panel.
- `tr.flash` / `@keyframes row-in` — fresh-row settle as WS results
  stream in (transform+opacity only, honors reduced-motion).
- `td.idx` — quiet index column.

## Rules that carry over unchanged

- One accent family, neutralized in ntok — ntod diverges on purpose:
  ember `#F59E4C` matches the gold mark, semantic ok/warn/err stay
  functional. Hairlines remain the resting elevation;
  `--shadow-float` only on floating layers; no gradients on fills.
  ntod relaxes "no colored glows" exactly twice: the ambient page
  bloom and the primary-button halo.
- Four radii: `--r-sm 8` / `--r-md 12` / `--r-lg 16` / `--r-pill 999`.
- Motion: `--ease` expo-out on everything; `transform`/`opacity` only;
  `prefers-reduced-motion` kills all.
- Bounded display: packet feed capped at 300 rows; overflow stays inside
  the panel, never the page.
- Escaped text everywhere remote data lands (`esc()` in `app.js`) —
  SSIDs and hostnames are untrusted input.
