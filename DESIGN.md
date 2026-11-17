# Product design spec

Copy this file into another project and follow it as the visual system. Keep the product’s own content. Reproduce the chrome, type, color rules, density, and layout below.

This is a dense operational tool, not a marketing site. Color is an accent the user can change. Large surfaces stay quiet so the accent, status, and the inset frame stay readable.

## How to apply this

- Use IBM Plex Sans Variable for UI text and IBM Plex Mono for code, keys, and short mono labels.
- Scale the whole app to 80% with a transform on the root child, not CSS `zoom`. The code popup or any full-screen editor sets `html[data-screen="editor"]` and turns the scale off.
- One primary color drives buttons, the account mark, focus rings, and small tints. It does not paint the sidebar or the page in light mode.
- Light mode and dark mode use different recipes. Do not mirror one into the other.
- The signed-in app is an inset shell: a gray or deep frame, with the page in a rounded panel.
- Prefer short rows, 12–13px text, and 24px controls. Avoid tall headers and large empty padding.

## Personality

- Quiet chrome, loud accents. The frame is neutral. The primary color appears on the mark, primary buttons, the active ink, and small chips.
- Status colors stay distinct from the theme: info blue, warning amber, danger rose, success green. Do not recolor them when the user changes the primary.
- Corners are modest: 10px base radius (`0.625rem`). Cards use `rounded-xl`. Pills use `rounded-full`. Do not use sharp corners or oversized 24px radii on app chrome.
- Shadows are small. The inset panel gets `shadow-sm` plus a 1px ring. Login card gets a soft primary-tinted shadow. Nothing else floats.
- Icons are Tabler outline, 14px in rows and 16px in the collapsed rail.

## Type

| Use | Size | Weight |
| --- | --- | --- |
| Page title | 13px | medium |
| Sidebar item | 12px | regular, medium when active |
| Group label | 10px | semibold, uppercase, wider tracking, 70% muted |
| Body / table | 12–13px | regular |
| Eyebrow on login | 11–12px | medium, tracking 0.14–0.16em |
| Login headline | 28px | medium, tight leading |
| Mono bits | 10–11px | IBM Plex Mono |

Do not use a display font. Do not set page titles at 20px or larger inside the app shell.

## Color rules

Default primary is `#3be8b0`. Text on that color is `#10241c` when the color is light (relative luminance above 0.4) and `#ffffff` when it is dark. Persist the choice in `localStorage` under `primary-color` and set `--primary` and `--primary-foreground` on `documentElement` before first paint. Offer presets `#3be8b0`, `#2563eb`, `#7c3aed`, `#d97706`, plus a native color input.

`--primary` is set on the light root only. Dark mode must not reset it, or the user’s color disappears when the theme toggles.

`--primary-ink` is for text and eyebrows that should read as the theme color: in light mode mix the primary 46% toward `#0c1f18`; in dark mode mix it 58% toward white.

### Light mode

Large surfaces are neutral. A mint wash on the sidebar and canvas looks wrong.

| Token | Value |
| --- | --- |
| background, card, popover | `#ffffff` |
| foreground, card text | `#14211c` |
| sidebar frame | `#e6e9ec` |
| sidebar text | `#1c2428` |
| sidebar border | `#d0d5d9` |
| border | `#e2e6e9` |
| input | `#d8dee2` |
| muted surface | `#f3f5f6` |
| secondary | `#eef1f3` |
| muted text | `#5c676e` |
| canvas stage | `#f3f5f6` |
| canvas dots | `#d2d8dc` |
| destructive | `#e11d48` |
| success | `#0f9f6e` |
| info | `#2563eb` |
| warning | `#d97706` |

The login rail is the one light-mode surface that is dark and colored: mix the primary 26% into `#10242c`, with foreground `#f4fbf8`.

### Dark mode

The frame is darker than the page. The page may carry a small primary mix. The canvas is a step darker than the page.

| Token | Value |
| --- | --- |
| sidebar frame | `color-mix(in oklch, var(--primary) 12%, #070c0f)` |
| background | `color-mix(in oklch, var(--primary) 6%, #1c262b)` |
| card, popover | `color-mix(in oklch, var(--primary) 11%, #182228)` |
| foreground | `#f3f7f6` |
| muted text | `#b7c6c1` |
| border | `color-mix(in oklch, var(--primary) 16%, #2c3c42)` |
| canvas | `color-mix(in oklch, var(--primary) 5%, #141c20)` |
| canvas dots | `color-mix(in oklch, var(--primary) 24%, #3a4c47)` |
| destructive | `#fb7185` |
| success | `#34d399` |
| info | `#60a5fa` |
| warning | `#fbbf24` |

## App shell

Signed-in screens use an inset layout, the same idea as a sidebar `variant="inset"`.

- The outer frame is `bg-sidebar` and fills the viewport.
- The sidebar sits on that frame. It has no right border.
- The page is a `<main>` with margin `8px` on the top, right, and bottom, and `0` on the left. It is `rounded-xl`, `bg-background`, `shadow-sm`, and a 1px `ring` in the sidebar border color. `overflow: hidden` clips the corners.
- Library and inspector panels inside the page use the page background, not the sidebar color. If they match the frame, the inset gap disappears.
- Minimum layout size is about 1180×640 CSS pixels before the 0.8 scale.

There is no site header above the page. Navigation lives in the sidebar. Each page has its own short header inside the panel.

## Sidebar

Expanded width is 220px. Collapsed width is 56px. Width animates over 200ms. Persist collapsed state in `localStorage` under `sidebar-collapsed`.

Structure, top to bottom:

1. Account row: 32px rounded mark filled with the primary color and the user’s initial, then name at 13px and the word “Account” at 11px muted. Collapse control sits at the end.
2. Group label, then items. Groups stack with an 8px gap. Items have no gap between them.
3. Footer, separated by a hairline: theme color, theme toggle, log out.

Expanded item: height 28px, padding `0 8px`, gap 8px, 12px text, 14px icon. Collapsed item: height 28px, icon centered at 16px, label hidden, `title` set to the label. The expand icon is 16px. Do not jump collapsed icons to 20px.

Active item: page-colored chip (`bg-background`), primary ink, medium weight, `shadow-sm`. Hover: `bg-background/55`. Group labels are hidden when collapsed. A second group gets a top border only while collapsed.

Theme color in the expanded footer is one row labeled “Color” with 14px round swatches. When collapsed, one swatch opens a small palette to the right of the rail. The rail is `z-20` so the palette paints over the page.

## Page header

One shared header, 36px tall, bottom border, horizontal padding 12px.

- Title is a single 13px medium line. No eyebrow above it.
- Actions sit on the right: inputs and buttons are 24px tall, 11px text, `rounded-md`.
- The header does not scroll. The page body scrolls under it.

## Content

- Page padding is 20px.
- Tables sit in a white or card surface with a hairline border and `rounded-xl`. Header row can take a light primary tint. Row hover uses the accent color. Status is a pill: success tint for ok/active, warning tint for error/draft.
- Metric cards are a 4-column grid. Each card has its own hue (primary, info, danger, warning), a 4px left border, tinted fill, and a 20px value. Do not make every card the theme color.
- Empty states are one 12px muted sentence. No illustrations.

## Login

Split layout. Below `lg`, show only the form.

- Left rail, about 42% width, hidden under `lg`: dark rail color, primary mark, tracked eyebrow, 28px headline, three bullets with primary, info, and warning dots. Soft blurred orbs of primary, info, and warning sit behind the type.
- Right side: the form is a 360px card, `rounded-2xl`, border, 20px padding, and a shadow mixed from the primary at 12% alpha. Inputs are 36px. The submit button is full width, primary fill, 36px.

## Tool canvas

When the product has a canvas or designer:

- Default zoom is 70% (`zoom: 0.7`). A labeled control still snaps back to 100%. Fit frames the content and may choose another zoom.
- Canvas background is the neutral stage color with a 16px dot grid. In dark mode the stage may pick up a little primary. In light mode the dots stay gray.
- Floating controls sit 8px from the bottom corners. They are one compact bar, `rounded-lg`, `p-0.5`, card background, hairline ring, `shadow-sm`.
- Buttons in those bars are 24px, `rounded-md`, icons 14px, zoom label 11px. Do not use 32px circular buttons there.
- Left bar holds panel toggles. Right bar holds fit, zoom out, the percent, zoom in, and export.

## Category color

When a screen lists kinds of objects, give each kind a fixed hue and keep it in both themes:

| Kind | Light | Dark |
| --- | --- | --- |
| Input / start | emerald | emerald-300 on emerald-950 |
| Logic | blue | blue-300 on blue-950 |
| AI | violet | violet-300 on violet-950 |
| Transform | orange | orange-300 on orange-950 |
| Output | rose | rose-300 on rose-950 |
| Integration | teal | teal-300 on teal-950 |

## Do not

- Do not tint the light sidebar, page, borders, or canvas with the primary. That hides the inset and makes light mode look stained.
- Do not use the same mix percentages for light and dark.
- Do not put a second site header above the inset panel.
- Do not copy a community theme that sets radius to 0, makes inputs near-black, or sets muted text equal to the foreground.
- Do not scale the UI with the CSS `zoom` property. Use `transform: scale(0.8)` on `#root > *`, with width and height divided by 0.8, origin top left.
