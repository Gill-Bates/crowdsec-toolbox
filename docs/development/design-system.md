# Documentation Design System

This page records the visual contract for the documentation site. Token values
and component styles are implemented in [`extra.css`](../stylesheets/extra.css);
`zensical.toml` selects the Light and Dark theme schemes.

## Color tokens

| Token | Light: Arctic Paper | Dark: Midnight Navy | Use |
|---|---|---|---|
| `--cst-bg` | `#F5F8FB` | `#0C1928` | Page background |
| `--cst-header` | `#FFFFFF` | `#102236` | Header, tabs, and footer surfaces |
| `--cst-surface` | `#FFFFFF` | `#14293C` | Cards, code, and callouts |
| `--cst-surface-alt` | `#EAF2F6` | `#1B3449` | Secondary surfaces and control hover |
| `--cst-text` | `#152A3B` | `#F1F7FA` | Main text |
| `--cst-text-muted` | `#496376` | `#B3C8D7` | Secondary text |
| `--cst-primary` | `#087C80` | `#45D8C8` | Primary actions, links, and focus |
| `--cst-on-primary` | `#FFFFFF` | `#0C1928` | Text on primary actions |
| `--cst-accent` | `#4554AD` | `#8FA7FF` | Secondary highlights |
| `--cst-border` | `#C7D9E3` | `#36536A` | Card and table borders |
| `--cst-code-bg` | `#EDF3F6` | `#102235` | Code blocks and inline code |
| `--cst-success` | `#187451` | `#57D59F` | Success states |
| `--cst-warning` | `#925500` | `#FFD166` | Warning states |
| `--cst-danger` | `#B4233A` | `#FF8C9B` | Error and danger states |

## Typography

| Role | Typeface | Weights |
|---|---|---|
| Headlines, body, navigation, and buttons | IBM Plex Sans | 400, 500, 600, 700 |
| Code and technical labels | IBM Plex Mono | 400, 500, 700 |

The fonts load from the Google Fonts CSS2 API with `display=swap`. The exact
request, including weights and fallbacks, is in `extra.css`; the CSS import is
the only font source, so Zensical's font integration stays disabled.

## Layout density

The landing page keeps its hero and destination cards compact beside the
reference content.

| Element | Size |
|---|---|
| Body text | `0.8rem` |
| Heading scale | `h1` `2.1em`, `h2` `1.55em`, `h3` `1.2em` relative to body text |
| Hero heading | Fluid, up to `3.25em` relative to body text; measure of `26ch` |
| Hero panel padding | Fluid, up to `2.5rem` |
| Card padding | `1rem` |
| Card grid gap | `0.75rem` |

## Action variants

| Variant | Class or control | Resting state | Hover / active state | Keyboard focus |
|---|---|---|---|---|
| Primary | `.md-button--primary` | `--cst-primary` background and `--cst-on-primary` text | `--cst-primary-hover` surface; slight press offset | 3px `--cst-primary` outline |
| Secondary | `.md-button` | `--cst-surface` background, `--cst-border-strong` border | `--cst-surface-alt` background | 3px `--cst-primary` outline |
| Text link | `.md-typeset a:not(.md-button)` | `--cst-primary` text | `--cst-primary-hover` with underline | 3px `--cst-primary` outline |
| Icon action | Theme, search, copy, and back-to-top controls | Inherits text color | `--cst-surface-alt` background and primary icon color | 3px `--cst-primary` outline |

Icon actions keep their Zensical-provided accessible names. New icon-only links
must add an accessible name and a visible focus state.
