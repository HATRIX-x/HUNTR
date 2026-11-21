import type { Config } from "tailwindcss";

// Every color resolves to a CSS variable defined in app/globals.css — that file is
// the single source of truth. Channel vars (`--x-rgb`) keep alpha modifiers
// (`bg-brand/10`, `border-green/40`) working.
const c = (name: string) => `rgb(var(--${name}-rgb) / <alpha-value>)`;

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: c("bg"),
        surface: c("surface"),
        surface2: c("surface-2"),
        fg: c("fg"),
        muted: c("muted"),
        faint: c("faint"),
        line: "var(--line)",
        "line-2": "var(--line-2)",
        brand: {
          DEFAULT: c("brand"),
          200: "var(--brand-200)",
          300: "var(--brand-300)",
          500: "var(--brand-500)",
          600: "var(--brand-600)",
        },
        "brand-deep": "var(--brand-500)",
        "brand-ink": c("bg"),
        green: {
          DEFAULT: c("green"),
          200: "var(--green-200)",
          300: "var(--green-300)",
          500: "var(--green-500)",
          600: "var(--green-600)",
        },
        cyan: {
          DEFAULT: c("cyan"),
          200: "var(--cyan-200)",
          300: "var(--cyan-300)",
          500: "var(--cyan-500)",
          600: "var(--cyan-600)",
        },
        signal: c("cyan"),
        live: c("green"),
        critical: c("critical"),
        high: c("high"),
        testing: c("testing"),
      },
      fontFamily: {
        display: ["var(--font-display)", "ui-sans-serif", "system-ui", "sans-serif"],
        sans: ["var(--font-body)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      letterSpacing: { tightest: "-0.045em" },
      maxWidth: { site: "1280px" },
      boxShadow: {
        1: "var(--shadow-1)",
        2: "var(--shadow-2)",
        "glow-brand": "var(--glow-brand)",
        "glow-live": "var(--glow-live)",
        "glow-signal": "var(--glow-signal)",
      },
      backgroundImage: {
        "grad-brand": "var(--grad-brand)",
        "grad-soft": "var(--grad-brand-soft)",
      },
      transitionTimingFunction: { out: "cubic-bezier(.2,.7,.2,1)" },
    },
  },
  plugins: [],
};
export default config;
