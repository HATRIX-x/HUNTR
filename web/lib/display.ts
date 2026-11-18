// Display helpers for operator-facing text.
//
// HUNTR never surfaces the underlying model vendor/names in the console — the
// engine's logs mention concrete model ids (e.g. "model=claude-haiku-5-5"), so
// we rewrite them to HUNTR's own agent-tier codenames before rendering.

const TIER: Array<[RegExp, string]> = [
  [/claude[-\s]?haiku[-\w.]*/gi, "SCOUT"],
  [/claude[-\s]?sonnet[-\w.]*/gi, "HUNTER"],
  [/claude[-\s]?opus[-\w.]*/gi, "OVERSEER"],
  [/claude[-\s]?fable[-\w.]*/gi, "SCRIBE"],
  [/\bhaiku[-\s]?[\d.]*\b/gi, "Scout"],
  [/\bsonnet[-\s]?[\d.]*\b/gi, "Hunter"],
  [/\bopus[-\s]?[\d.]*\b/gi, "Overseer"],
  [/\bfable[-\s]?[\d.]*\b/gi, "Scribe"],
  // generic engine references → neutral wording
  [/claude\s*-p\b/gi, "the agent"],
  [/\banthropic\b/gi, "HUNTR"],
  [/\bclaude\b/gi, "the agent"],
];

/** Rewrite any model-name mentions in a line of engine/log text to HUNTR's own
 *  agent codenames. Safe on arbitrary strings; returns the cleaned text. */
export function sanitizeModels(text: string): string {
  let out = text ?? "";
  for (const [re, name] of TIER) out = out.replace(re, name);
  return out;
}

// Severity normalization. The engine emits severity as a single-letter code
// (c/h/m/l/i); older paths use full words. Normalize both so the semantic
// severity colors (critical=red, high=amber, medium=yellow, low=slate) apply
// instead of everything falling back to the info/cyan default.
const SEV_FULL: Record<string, string> = {
  c: "critical", h: "high", m: "medium", l: "low", i: "info",
  critical: "critical", high: "high", medium: "medium", low: "low", info: "info",
};
export function sevKey(s?: string | null): string {
  return SEV_FULL[(s ?? "").trim().toLowerCase()] ?? "info";
}
/** Info-severity findings carry no triage value — hidden from the console. */
export function isInfo(s?: string | null): boolean {
  return sevKey(s) === "info";
}
/** A finding counts as a real/verified finding (not noise) when it's proven and
 *  not info-severity. Used for the headline findings count. */
export function isRealFinding(f: { severity?: string | null; poc_verified?: boolean; verdict?: string }): boolean {
  if (isInfo(f.severity)) return false;
  if (f.poc_verified) return true;
  return (f.verdict ?? "").toLowerCase() === "confirmed";
}
