// Server component: always renders the real value. No count-from-0 animation —
// that repeatedly left "0" in static HTML, full-page screenshots, and before-scroll
// views. A confident, always-correct number beats a fragile count-up.
export function Stat({
  value,
  suffix = "",
  label,
  sub,
  tone = "brand",
}: {
  value: number;
  suffix?: string;
  label: string;
  sub?: string;
  tone?: "brand" | "green" | "fg";
}) {
  const color = tone === "green" ? "text-green" : tone === "fg" ? "text-fg" : "text-brand";

  return (
    <div>
      <div className={`numeral text-6xl sm:text-7xl lg:text-8xl ${tone === "fg" ? "text-fg" : color}`}>
        {value}
        {suffix && <span className={color}>{suffix}</span>}
      </div>
      <div className="mt-4 label text-fg">{label}</div>
      {sub && <p className="mt-2 max-w-[28ch] text-sm leading-relaxed text-muted">{sub}</p>}
    </div>
  );
}
