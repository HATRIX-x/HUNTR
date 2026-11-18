// Per-finding submission tracker ("CRM"): where each finding is in the bug-bounty
// submission lifecycle — submitted, triaged, accepted, resolved, etc. This is the
// operator's own workflow state, kept per-viewer in localStorage (survives reloads
// on this browser). It never touches the finding data the engine produced.

export type Stage =
  | "new" | "submitted" | "triaged" | "accepted" | "resolved"
  | "duplicate" | "informative" | "rejected";

export const STAGES: { key: Stage; label: string; chip: string; dot: string; hint: string }[] = [
  { key: "new",         label: "Not submitted", chip: "mute", dot: "var(--faint)",    hint: "Not sent to the program yet" },
  { key: "submitted",   label: "Submitted",     chip: "info", dot: "var(--cyan)",     hint: "Report filed — awaiting triage" },
  { key: "triaged",     label: "Triaged",       chip: "high", dot: "var(--high)",     hint: "Program accepted triage (first approval)" },
  { key: "accepted",    label: "Accepted",      chip: "val",  dot: "var(--green)",    hint: "Validated as a real bug" },
  { key: "resolved",    label: "Resolved/Paid", chip: "val",  dot: "var(--green-600)",hint: "Fixed and/or bounty awarded" },
  { key: "duplicate",   label: "Duplicate",     chip: "low",  dot: "var(--low)",      hint: "Already reported by someone else" },
  { key: "informative", label: "Informative",   chip: "low",  dot: "var(--low)",      hint: "Acknowledged, not awarded" },
  { key: "rejected",    label: "Rejected/N/A",  chip: "crit", dot: "var(--critical)", hint: "Closed as not applicable" },
];

export const STAGE_MAP = Object.fromEntries(STAGES.map((s) => [s.key, s])) as Record<Stage, (typeof STAGES)[number]>;

// Stages that count as "in the pipeline" (submitted somewhere), for the summary.
export const PIPELINE: Stage[] = ["submitted", "triaged", "accepted", "resolved"];

const KEY = "huntr:finding-crm:v1";
type Store = Record<string, { stage: Stage; at: string }>;

export function readCrm(): Store {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as Store) : {};
  } catch {
    return {};
  }
}

export function writeCrm(store: Store): void {
  if (typeof window === "undefined") return;
  try { window.localStorage.setItem(KEY, JSON.stringify(store)); } catch { /* quota/blocked — no-op */ }
}

export function stageOf(store: Store, id: string): Stage {
  return store[id]?.stage ?? "new";
}

export function setStage(store: Store, id: string, stage: Stage): Store {
  const next = { ...store };
  if (stage === "new") delete next[id];
  else next[id] = { stage, at: new Date().toISOString() };
  writeCrm(next);
  return next;
}
