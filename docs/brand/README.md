# Heimdall

Ledger card (decision U16, 2026-10-25; it replaced Burning Bridge, U15). Heimdall is a custom OAuth 2.1 and OpenID Connect identity provider. Each account page (sign in, consent, error, signed out) is one centered card that names the host, the account and the state in plain text. The mockups are in `docs/mockups/`. This page is the short version, with the logo. `tokens.json` and `logos/` still hold the U15 values. Update them when the Ledger tokens settle.

## Logo

**The watcher's eye.** In the myths Heimdall guards the bridge to Asgard and can see a hundred leagues by day or night. The mark is an open eye whose pupil is a keyhole: it watches, and it grants access. It is drawn on the same square, flat geometry as the rest of the system.

| File | Use |
|---|---|
| `heimdall-mark.svg` | Default. Favicon and app icon. A white eye on a `lapis` square, the keyhole white in a lapis iris. |
| `heimdall-mark-dark.svg` | Dark theme. The same on `lapis`'s dark value (#2b3f99). |
| `heimdall-eye-on-lapis.svg` | The bare white eye with a see-through iris, for the issuer band beside the wordmark. |
| `heimdall-eye-ink.svg` | One ink (`ink`, #0b0c14), see-through iris. Print and single-colour contexts. |

- **Tile:** square, no radius (**The Square Corner Rule** covers the logo too).
- **On a page:** the eye at 32px, 12px before the wordmark "Heimdall", at the top left of the card. A client never carries the eye: it is not Heimdall.
- **In code:** `HdCard` (ui-kit) draws the eye inline in `currentColor`, so it follows the display color in both themes. A tenant colour change needs no new SVG.
- **Colours:** lapis and white only, or one ink. Never red: red means a refusal.
- **Minimum size:** 16px. The keyhole drops out below that; use the mark at 16px or larger.
- **Never** round the tile, add a gradient, glow or shadow, or put the eye on a client's band or plate.

## Content fundamentals

Plain, factual and short. The large statement may be figurative ("Gate shut."), but a plain heading always follows it and says the same thing ("Heimdall does not know this app"). Say who asks and what leaves. Name the host exactly, in monospace. Errors say what happened and what to do next. Every page states that Heimdall is a development build.

## Colour

**The One Meaning Rule:** each colour means one thing on every page.

- Blue (`act`, `link`) is Heimdall and its actions: primary buttons, links, scope names.
- Red (`fire`) is a refusal and nothing else: wrong credentials, the throttle, an error page.
- The keyboard focus ring is blue too: 3px, with a 2px gap. It has about 7:1 contrast on the card in both themes. Yellow was rejected because it has about 1.7:1 on white.
- Night and day themes follow `prefers-color-scheme`. Text passes 4.5:1 in both.
- **The Tokens Not Components Rule.** Tenant branding changes token values, never a component.

## Typography

IBM Plex Sans (text) and IBM Plex Mono (hosts, codes, scope names), self-hosted `woff2` files under the SIL Open Font License 1.1 (U8, U16). No font service and no third-party origin.

- Mono only for values a person or machine compares character by character (**The Machine Value Rule**).

## Layout

One card, 448 px wide at most, on a faint ledger grid. On a phone the card loses its border and fills the screen.

## Do and don't

- Do show the host in the card, with the address bar check line.
- Do keep the title plain: it says what is happening and what the user can do.
- Don't use red for anything but a refusal.
- Don't load a font or anything else from a third-party origin.
- Don't use this look in a client app. The demo SPA keeps its own look.
