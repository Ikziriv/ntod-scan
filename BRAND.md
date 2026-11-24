# NTOD Brand Guidelines

### Network Threat Observation & Discovery

**Document type:** Brand identity & product design language
**Brand:** NTOD · **Primary product:** ntod-scan
**Design system:** Obsidian Ember — dark-only
**Version:** 2.0 — November 2026
**Status:** Canonized — aligned with the shipped product

Companion to [DESIGN.md](DESIGN.md), which carries the token-level
implementation delta. This document is the identity layer: what the
brand is, what it looks like, and the rules that keep it coherent.

------------------------------------------------------------------------

## 1. Brand Foundations

| | |
|---|---|
| **Brand name** | NTOD |
| **Expansion** | Network Threat Observation & Discovery |
| **Category** | Network intelligence · LAN discovery · Packet analysis |
| **Product** | ntod-scan — LAN discovery & packet tools |
| **Positioning** | Local-first network visibility for technical users |
| **Tagline** | **Discover. Observe. Understand.** |

### Positioning statement

For network administrators, IT professionals, and security-curious users
who need a clearer view of their own networks, NTOD provides local-first
tools for discovery, observation, and analysis — the capture-analysis
layer hosted pcap services sell, running entirely on the user's machine.

### Acronym rationale

| Initial | Meaning | Strategic role |
|---|---|---|
| **N** | Network | The technical domain — connected environments. |
| **T** | Threat | Security-aware perspective on network activity. |
| **O** | Observation | Visibility into behavior, not just inventory. |
| **D** | Discovery | Finding devices, connections, and assets. |

*Discovery* is the canonical **D** — it spans identification, scanning,
and mapping, and leaves room for future capabilities. *Diagnostic* is a
module-level name, not the expansion.

> "Threat" sets a security expectation. Messaging may only claim
> detection of what the deterministic detectors actually verify —
> describe evidence, not omniscience.

### Brand pillars

1. **Discover** — identify devices, addresses, and connections.
2. **Observe** — make live network activity visible.
3. **Analyze** — triage captures into flows, protocols, and findings.
4. **Diagnose** — investigate anomalies and connectivity problems.

### Personality

**Intelligent · Precise · Reliable · Professional · Accessible.**

Evidence-led above all: confirmed findings, warnings, and possibilities
are always visually and verbally distinct.

### Tone of voice

- Clear and direct; technical but approachable.
- Confident without exaggerated security claims.
- Action verbs: *Discover, Scan, Sniff, Analyze, Export.*
- Never anthropomorphic, never alarmist. States are named plainly:
  `running`, `done`, `warn`, `err`.

------------------------------------------------------------------------

## 2. Brand Architecture

- **NTOD** — the umbrella brand for network intelligence tools.
- **ntod-scan** — the product: CLI (`ntod`), daemon (`ntod serve`), and
  web console. Written lowercase with a hyphen in prose and repo
  contexts; **NTOD** in the UI wordmark.
- **Sibling:** ntok-scan — same product family, same design language,
  different accent world. NTOD is the *ember* sibling; never borrow
  ntok's palette.
- **Modules** use descriptive names (Discovery, Observe, Analyze,
  Diagnostic). No separate logos per feature.

------------------------------------------------------------------------

## 3. The Mark

The NTOD mark is a **folded gold ribbon "N"** — an isometric band that
turns through space like a routed path — terminating beside a detached
**node dot**. The ribbon reads as connection; the dot as a discovered
endpoint. Together: a network made visible.

### Lockups

| Lockup | Use |
|---|---|
| Mark + `NTOD` wordmark (Space Grotesk 800) | Top bar, splash, about |
| Mark on obsidian chip | Primary UI presentation |
| Mark only | Favicon, app icon, compact brand moments |

### Chip construction

The mark sits on an **obsidian chip**: `--obs` fill, `--r-md` (12px)
radius, warm ring `rgba(245,185,115,.22)`. Top-bar size 40×34px with
4px inset. The chip is part of the identity — the gold is always
framed by obsidian, never placed directly on arbitrary backgrounds.

### Rules

- **Clear space** ≥ the width of the node dot's diameter ×3 on all sides.
- **Minimum sizes:** chip 24px, mark 16px. Below that, use the wordmark.
- Do not recolor, restroke, flatten, stretch, rotate, or add effects.
- Do not place the gold mark on warm, gold, or photographic backgrounds —
  it needs obsidian contrast.
- Assets today are raster (`apps/web/brand.png` 245×186,
  `icon.png` 512²). A vector source should be produced before the next
  phase; until then, scale down only, never up.

------------------------------------------------------------------------

## 4. Color — Obsidian Ember

NTOD is **dark-only**. The interface is a night surface with a single
warm accent family — obsidian for calm, ember for attention. Dark is
not a theme here; it is the brand.

### 4.1 Foundation — obsidian ramp

| Token | Value | Role |
|---|---|---|
| `--bg` | `#05080F` | Page ground |
| `--obs` | `#080E1A` | Obsidian islands, mark chip |
| `--field` | `#0A101C` | Inputs |
| `--obs-elev` | `#101A2E` | Raised obsidian |
| `--surface` | `#0D1524` | Panels, sticky headers |
| `--well` | `#111C2F` | Insets |
| `--ceramic` | `#131F35` | Badges, icon wells |
| `--hover` | `#142138` | Hover fills |

### 4.2 Lines

| Token | Value | Role |
|---|---|---|
| `--line-soft` | `#152136` | Hairline separators |
| `--line` | `#1C2B45` | Default borders |
| `--line-strong` | `#283D60` | Emphasized borders, scrollbars |
| `--obs-line` | `rgba(245,185,115,.16)` | Warm hairline on obsidian |

### 4.3 Type ramp

| Token | Value | Role | On `--bg` |
|---|---|---|---|
| `--ink` | `#F0F6FF` | Titles, primary text | 18.4:1 AAA |
| `--fg` | `#C8D7EC` | Body text | 13.7:1 AAA |
| `--muted` | `#7E95B5` | Secondary, lede | 6.5:1 AA+ |
| `--faint` | `#4E6484` | Meta, placeholders — *decoration only* | 3.3:1 ✗ text |

`--faint` fails AA — reserve it for index columns, hints, and
non-essential metadata. Never body copy.

### 4.4 Ember accent ramp

| Token | Value | Role |
|---|---|---|
| `--accent-deep` | `#C97A22` | Pressed, deepest ember |
| `--accent-mid` | `#E8892F` | Hover midpoint |
| `--accent` | `#F59E4C` | **Core ember** — primary actions, active states |
| `--accent-bright` | `#FFB86B` | Highlights, eyebrow text |
| `--accent-sky` | `#FFC98A` | Lightest ember — fills, hovers on dark |
| `--accent-soft` | `rgba(245,158,76,.13)` | Tinted fills |
| `--accent-line` | `rgba(245,158,76,.32)` | Accent hairlines |
| `--on-accent` | `#180C02` | Text/icons on ember fills — 9.0:1 AA |

Ember is earned: it marks *the* primary action, the active nav item,
fresh data, and interactive affordances. A screen with many ember
elements is a bug, not a celebration.

### 4.5 Semantic status

| State | Ink | Background | Line | On `--bg` |
|---|---|---|---|---|
| ok | `#4ADE9B` | `#0D261C` | `#1F523D` | 11.7:1 |
| warn | `#E5BE5E` | `#261E0A` | `#493914` | 11.3:1 |
| err | `#F28482` | `#2B1315` | `#522427` | 8.0:1 |

Semantic colors report status only — never branding. Ember = *you can
act*; ok/warn/err = *what happened*.

### 4.6 Usage rules

- **Two glows, ever:** the ambient ember/steel horizon bloom behind the
  page, and the soft halo on the primary button. No other colored
  glows, no glow on text.
- **No gradients on fills.** Flat surfaces, hairline borders, one float
  shadow (`--shadow-float`) reserved for floating layers.
- **Hairlines are the resting elevation.** Depth comes from borders and
  one inset edge-light (`inset 0 1px 0 rgba(255,255,255,.035)`).
- Color is never the sole carrier of meaning — statuses always pair
  with a label or icon.
- The steel-blue in the ambient bloom (`rgba(80,130,220,.07)`) is
  atmosphere only. It never appears as a UI accent — that would tip the
  palette back into generic cybersecurity blue.

------------------------------------------------------------------------

## 5. Typography

Two self-hosted faces (woff2, latin subset, `display=swap`) — fully
offline, no CDN.

| Face | Weights | Role |
|---|---|---|
| **Space Grotesk** | 300–700 var | Display, headings, UI chrome, wordmark |
| **IBM Plex Mono** | 400/500/600 | All data: IPs, MACs, ports, timestamps, counts, code |

The split is the voice: Grotesk speaks, Mono reports.

### Scale

| Style | Spec | Use |
|---|---|---|
| Display | 700 40px/1.02, −0.04em | Page titles (30px under 480px) |
| Section head | 600–800 13.5px | Panel titles, findings headings |
| Body | 400 14px/1.55 | Everything default |
| Lede | 400 14px `--muted` | One-line page description |
| Nav / button | 500–600 12.5px | Chrome actions |
| Eyebrow | 600 10.5px mono, +0.09em, caps | Live section marker above titles |
| Meta | 11.5px | Supporting detail |
| Data | mono, tabular numerals | Tables, values, evidence strings |

Rules: monospace is for data and micro-labels, never paragraphs.
Tracking tightens as size grows; small caps-labels get the wide
letter-spacing, not headlines.

------------------------------------------------------------------------

## 6. Iconography

One authored set, inlined from `icons.rs`:

- 24px grid, **1.5px stroke**, `currentColor`.
- Geometric, single-weight strokes — no filled blobs, no multicolor.
- No icon fonts, no CDN icon services, no emoji as UI icons.
- Status uses the authored glyphs (pulse, check, warn triangle, cross) —
  never recolor a glyph to invent a new state.

------------------------------------------------------------------------

## 7. Motion

- **One ease:** `--ease` = `cubic-bezier(0.22, 1, 0.36, 1)` (expo-out)
  on everything.
- **Two properties:** `transform` and `opacity` only. Nothing animates
  layout, color, or shadow.
- Durations 140–250ms for UI feedback; the streaming `row-in` settle is
  the signature (fresh table rows drop 3px and fade in).
- `prefers-reduced-motion` disables all of it — motion is garnish,
  never information.

------------------------------------------------------------------------

## 8. Graphic Language

### Signature motifs

- **Ambient horizon** — the faint ember bloom rising behind the page
  (with its whisper of steel blue). The brand's one atmosphere.
- **Floating glass chrome** — translucent `.top` bar, `--top-blur`,
  segmented nav centered like a docked instrument.
- **Eyebrow chip** — ember dot + mono caps label above every page
  title: the "live instrument" marker.
- **Telemetry islands** — obsidian panels that visualize, not
  decorate: the per-host 24-port `.grid` (cells ignite when open
  ports land), the sniff `.wave` packets/sec spline, the Wi-Fi
  `.sec-pips` 5-segment signal meter.

### Imagery direction

Real software surfaces, abstract topology, clean diagrams. Visuals
explain the product.

### Never

- Hooded hackers, code rain, matrix streams.
- Circuit-board wallpaper, padlocks, generic shields.
- Neon glow everywhere (see: two glows, ever).
- Blue/cyan "cyber" palettes — the industry's visual cliché and
  ntok's neighboring territory.
- Imagery implying capabilities the product doesn't have.

------------------------------------------------------------------------

## 9. Product UI Principles

1. **Visibility first** — devices, flows, and findings legible at a
   glance; the data is the hero.
2. **Hierarchy** — primary findings, supporting detail, and metadata
   are three distinct layers (ink / muted / faint).
3. **Action clarity** — one ember primary action per surface; verbs on
   buttons (`Scan`, `Sniff`, `Export pcap`).
4. **Trustworthy status** — `running` / `done` / `warn` / `err` pills;
   live work shows the `.sys-pill.live` engine dot; in-flight buttons
   show the spinner, never a dead click.
5. **Responsible operation** — authorization scope is stated in the UI
   footer: *"scan only systems you own or are authorized to test."*

### Component grammar

| Pattern | Behavior |
|---|---|
| `.page-head` + `.lede` | Grotesk title, one-line description, eyebrow above |
| `.panel.flush` | Bounded results table — `max-height: min(62vh,620px)`, sticky header, slim dark scrollbar |
| `.pill` | State language — running/done/warn/err |
| `.sev-*` | Severity chips on findings (alert/warn/info) |
| `.status-row` | Status lane under panels, zero layout jump |
| `.finding` | Card — hover borders ember, click drills to detail |
| `.empty` + `.dropzone` | Centered icon-well empty states; drag-over goes ember |
| `.ntod-toast` | Obsidian pill bottom-right, mono text |
| `td[data-copy]` | Hover underlines dotted + ember — click-to-copy |

### Interaction conventions

- **Bounded everything, visually too:** feeds cap (300 rows), overflow
  scrolls inside panels, never the page.
- **Streaming, not popping:** rows arrive with `row-in`, counts update
  in place.
- **Remote data is untrusted:** SSIDs/hostnames escape before render —
  a security posture that's also a brand behavior.
- Mobile collapses nav to a bottom dock; touch targets ≥44px.

------------------------------------------------------------------------

## 10. Voice & Messaging

### Tagline

**Discover. Observe. Understand.**

### Supporting messages

- See your network more clearly.
- Local-first — the capture never leaves your disk.
- One engine: CLI, daemon, and web console.
- Practical visibility for networks you're responsible for.

### Product description

**ntod-scan** is a local-first LAN discovery and packet-analysis tool:
live host discovery, bounded packet capture, Wi-Fi survey, and full
pcap triage reports with deterministic detectors — running entirely on
the user's machine, with no accounts and no telemetry.

### Guardrails

- Describe evidence, not omniscience: "flags likely port-scanning,"
  never "stops threats."
- No claims of prevention, guarantee, or complete coverage.
- "AI" seams are optional and labeled; the deterministic engine is the
  product.

------------------------------------------------------------------------

## 11. Applications

| Surface | Asset / rule |
|---|---|
| Web UI top bar | Mark on obsidian chip + `NTOD` wordmark, `.mark` spec |
| Favicon / app icon | `icon.png` 512²; mark only |
| README / docs | Centered mark ≤96px wide, tagline beneath |
| Reports & exports | Wordmark top-left, mono for all data |
| Screenshots | `docs/screenshots/` — regenerated via `scripts/capture-shots.mjs` against a live daemon; always real UI, never mockups |
| Presentations | Obsidian background, ember accent, Grotesk headlines |

------------------------------------------------------------------------

## 12. Governance

### Do

- Use the shipped tokens — the CSS *is* the spec.
- Keep ember scarce; one primary action per view.
- Pair every status color with a label.
- Keep all network data in IBM Plex Mono.
- Keep the footer authorization line visible.

### Don't

- Edit `apps/web/app.css` — it's vendored from ntok-scan; ntod deltas
  live in `apps/web/ntod.css`.
- Introduce light mode, a second accent family, or new gradients.
- Use `--faint` for anything a user must read.
- Ship "threat detection" language for discovery-only features.
- Recolor or re-render the mark.

### Files of truth

| File | Owns |
|---|---|
| `BRAND.md` (this) | Identity, palette meaning, voice |
| `DESIGN.md` | Implementation delta + system rules |
| `apps/web/ntod.css` | Token values (the executable spec) |
| `apps/web/app.css` | Vendored shared system — read-only |

------------------------------------------------------------------------

## 13. Current Decisions

| Item | Decision |
|---|---|
| Brand | NTOD — Network Threat Observation & Discovery |
| Product | ntod-scan (`ntod` binary) |
| Visual world | **Obsidian Ember** — dark-only |
| Mark | Gold folded-ribbon N + node dot on obsidian chip |
| Accent | Ember `#F59E4C` ramp |
| Foundation | Obsidian `#05080F` / `#080E1A` |
| Type | Space Grotesk + IBM Plex Mono, self-hosted |
| Tagline | Discover. Observe. Understand. |
| Glow budget | Two — ambient bloom + primary-button halo |
| Open item | Vector (SVG) source for the mark; raster only today |
