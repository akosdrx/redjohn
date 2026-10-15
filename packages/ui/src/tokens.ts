/**
 * RedJohn design tokens — single source of truth.
 * Dark graphite palette + restrained red accent (#E5484D family),
 * sampled from the approved reference design.
 *
 * These values are mirrored into Tailwind theme variables in `styles.css`
 * (`--color-rj-*`). Keep both in sync.
 */

export const colors = {
  /** Deepest background (side panels, terminal well) */
  bg: "#0e1216",
  /** App background */
  bgApp: "#13181d",
  /** Sidebar background */
  sidebar: "#10151a",
  /** Card / panel background */
  panel: "#1a2128",
  /** Secondary (sunken) panel background */
  panelSunken: "#151b21",
  /** Interactive hover on panels/rows */
  panelHover: "#202832",
  /** Terminal background */
  terminal: "#0d1116",
  /** Default border */
  border: "#242d36",
  /** Stronger border (focus, active panels) */
  borderStrong: "#2e3944",

  text: "#e8ebee",
  textSecondary: "#9aa7b0",
  textMuted: "#66727d",

  /** Brand red accent */
  accent: "#e5484d",
  /** Vivid red for the primary CTA button */
  accentStrong: "#f0353f",
  /** Subtle red wash (selected nav / rows) */
  accentSubtle: "#2a1518",
  /** Red border for accent surfaces */
  accentBorder: "#5a2327",

  /** Status colors */
  live: "#46c78c",
  starting: "#e0c04b",
  degraded: "#e0863c",
  down: "#f05353",
  notConfigured: "#6b7680",

  /** Severity colors */
  critical: "#ff5c77",
  high: "#e5484d",
  medium: "#e0a83c",
  low: "#4f9fd8",
  info: "#8a949e",

  /** Agent tag palette used in the terminal (cycled by agent index) */
  agentTags: ["#4f9fd8", "#46c78c", "#e0a83c", "#b98ae0", "#e0863c", "#5cc8c0", "#e5a0b0"],
} as const;

export const spacing = {
  sidebarWidth: 232,
  envPanelWidth: 288,
  topBarHeight: 56,
} as const;

export const typography = {
  fontSans:
    'ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
  fontMono: 'ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
  sizeXs: "11px",
  sizeSm: "12px",
  sizeMd: "13px",
  sizeLg: "15px",
  sizeXl: "18px",
} as const;

export const radius = {
  sm: "4px",
  md: "6px",
  lg: "8px",
  pill: "999px",
} as const;

export const tokens = { colors, spacing, typography, radius } as const;
export type Tokens = typeof tokens;
