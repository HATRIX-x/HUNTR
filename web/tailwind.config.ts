import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0A0B0D",
        surface: "#121419",
        surface2: "#191C23",
        fg: "#ECEEF2",
        muted: "#8A909C",
        faint: "#5A606C",
        line: "rgba(255,255,255,0.12)",
        "line-2": "rgba(255,255,255,0.22)",
        brand: "#A78BFA",
        "brand-deep": "#8B6DF0",
        green: "#4ADE80",
        "brand-ink": "#0A0B0D",
      },
      fontFamily: {
        display: ["var(--font-display)", "ui-sans-serif", "system-ui", "sans-serif"],
        sans: ["var(--font-body)", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      letterSpacing: { tightest: "-0.045em" },
      maxWidth: { site: "1280px" },
    },
  },
  plugins: [],
};
export default config;
