// HUNTR Cloud API client — used by the static huntr.run site to talk to the
// FastAPI backend (cloud/app) where accounts, sessions and agents live.
//
// The site is a static export (output: 'export'), so every call here runs in the
// browser. Point it at the backend with NEXT_PUBLIC_API_URL at build time; it
// falls back to the production Fly.io deployment.

// Point this at the backend (cloud/app). Set NEXT_PUBLIC_API_URL at build time.
// Default is a stable hostname you can repoint via DNS to whatever host runs the
// API (Render, Railway, a VPS, Fly — the frontend doesn't care).
export const API_URL = (
  process.env.NEXT_PUBLIC_API_URL || "https://api.huntr.run"
).replace(/\/$/, "");

const TOKEN_KEY = "huntr_session";

// ── session token (per-browser) ──────────────────────────────────────────
export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string) {
  try {
    window.localStorage.setItem(TOKEN_KEY, token);
  } catch {
    /* storage blocked (private window) — session lives only for this page */
  }
}

export function clearToken() {
  try {
    window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* no-op */
  }
}

// ── types ─────────────────────────────────────────────────────────────────
export interface AuthResult {
  session_token: string;
  user_id: string;
  email: string;
  plan: string;
}

export interface Profile {
  role?: string | null;
  experience?: string | null;
  platforms?: string[];
  goal?: string | null;
  referral?: string | null;
}

export interface Me {
  user_id: string;
  email: string;
  plan: string;
  credits?: number;
  created_at?: string | null;
  twofa_enabled?: boolean;
  onboarded?: boolean;
  profile?: Profile | null;
}

export interface CreditsInfo {
  balance: number;
  free_hunt_used: boolean;
  ledger: { delta: number; balance_after: number; reason: string; at: string }[];
}

export interface TwoFAChallenge {
  twofa_required: true;
  twofa_token: string;
}

export function isTwoFAChallenge(r: AuthResult | TwoFAChallenge): r is TwoFAChallenge {
  return (r as TwoFAChallenge).twofa_required === true;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

async function req<T>(path: string, init: RequestInit = {}, auth = false): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init.headers as Record<string, string> | undefined),
  };
  if (auth) {
    const t = getToken();
    if (t) headers["Authorization"] = `Bearer ${t}`;
  }

  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "Can't reach the server. Check your connection and try again.");
  }

  let data: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!res.ok) {
    const detail =
      (data && typeof data === "object" && "detail" in data
        ? String((data as { detail: unknown }).detail)
        : typeof data === "string"
          ? data
          : "") || `Request failed (${res.status})`;
    throw new ApiError(res.status, detail);
  }
  return data as T;
}

// ── auth ────────────────────────────────────────────────────────────────
export function signup(email: string, password: string) {
  return req<AuthResult>("/v1/auth/signup", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export function login(email: string, password: string) {
  return req<AuthResult | TwoFAChallenge>("/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

// ── 2FA (TOTP) ─────────────────────────────────────────────────────────────
export function twofaVerify(twofa_token: string, code: string) {
  return req<AuthResult>("/v1/auth/2fa/verify", {
    method: "POST",
    body: JSON.stringify({ twofa_token, code }),
  });
}

export function twofaSetup() {
  return req<{ secret: string; otpauth_uri: string }>(
    "/v1/auth/2fa/setup",
    { method: "POST" },
    true,
  );
}

export async function twofaEnable(code: string) {
  // the server rotates the session on 2FA changes (old tokens are revoked)
  return keepRotated(await req<{ enabled: boolean; backup_codes: string[] ; session_token?: string }>(
    "/v1/auth/2fa/enable",
    { method: "POST", body: JSON.stringify({ code }) },
    true,
  ));
}

export async function twofaDisable(code: string) {
  // the server rotates the session on 2FA changes (old tokens are revoked)
  return keepRotated(await req<{ enabled: boolean ; session_token?: string }>(
    "/v1/auth/2fa/disable",
    { method: "POST", body: JSON.stringify({ code }) },
    true,
  ));
}

export function me() {
  return req<Me>("/v1/auth/me", { method: "GET" }, true);
}

export async function changePassword(current_password: string, new_password: string) {
  // a password change revokes every other session; keep this one signed in
  return keepRotated(await req<{ ok: boolean; session_token?: string }>(
    "/v1/auth/password",
    { method: "POST", body: JSON.stringify({ current_password, new_password }) },
    true,
  ));
}

export function logoutAll() {
  return req<{ ok: boolean }>("/v1/auth/logout-all", { method: "POST" }, true)
    .finally(() => clearToken());
}

function keepRotated<T extends { session_token?: string }>(r: T): T {
  if (r && r.session_token) setToken(r.session_token);
  return r;
}

export function saveProfile(p: Profile) {
  return req<{ ok: boolean; onboarded: boolean; profile: Profile }>(
    "/v1/auth/profile",
    { method: "POST", body: JSON.stringify(p) },
    true,
  );
}

// ── billing (Creem) ────────────────────────────────────────────────────────
export function checkout(plan: string) {
  return req<{ checkout_url: string }>(
    "/v1/billing/checkout",
    { method: "POST", body: JSON.stringify({ plan }) },
    true,
  );
}

export function creditsBalance() {
  return req<CreditsInfo>("/v1/billing/credits", { method: "GET" }, true);
}

// ── hunts (cloud execution) ─────────────────────────────────────────────────
export interface Hunt {
  hunt_id: string;
  target: string;
  program: string;
  mode: string;
  status: string; // queued | running | done | error | blocked | cancelled
  stage?: string;
  pct?: number;
  vnc?: boolean;
  findings: number;
  logs?: string[];
  error?: string | null;
  created_at: string;
  updated_at: string;
}

export interface HuntCreds {
  /** one-paste blob: cookie / bearer / header line / Netscape file / copied cURL */
  session?: string;
  auth_header?: string;
  ua?: string;
}

export function startHunt(body: {
  target: string;
  program?: string;
  mode?: string;
  scope_types?: string;
  /** full program/scope page paste → Haiku 5.5 classifies in/out-of-scope server-side */
  scope_text?: string;
  creds?: HuntCreds;
}) {
  return req<{ hunt_id: string; status: string }>(
    "/v1/hunts",
    { method: "POST", body: JSON.stringify(body) },
    true,
  );
}

export function listHunts() {
  return req<{ hunts: Hunt[] }>("/v1/hunts", { method: "GET" }, true);
}

export function getHunt(id: string) {
  return req<Hunt>(`/v1/hunts/${encodeURIComponent(id)}`, { method: "GET" }, true);
}

export function cancelHunt(id: string) {
  return req<{ ok: boolean; status: string }>(
    `/v1/hunts/${encodeURIComponent(id)}/cancel`,
    { method: "POST" },
    true,
  );
}

export interface Finding {
  id: string;
  program: string;
  cls: string;
  endpoint: string;
  severity: string;
  title: string;
  verdict: string;
  status: string;
  created_at: string;
}

export function listFindings(program: string) {
  return req<{ total: number; findings: Finding[] }>(
    `/v1/findings?program=${encodeURIComponent(program)}&limit=200`,
    { method: "GET" },
    true,
  );
}

export interface HuntFinding {
  title: string;
  severity: string;
  cls: string;
  endpoint: string;
  verdict?: string;
  poc_verified?: boolean;
  cvss?: number | null;
  bounty_est?: number | null;
  detail?: string;
  repro?: string;
  steps?: string;
  report?: string;
  poc?: string;
}

export function listHuntFindings(huntId: string) {
  return req<{ findings: HuntFinding[] }>(
    `/v1/hunts/${encodeURIComponent(huntId)}/findings`,
    { method: "GET" },
    true,
  );
}

export interface AllFinding extends HuntFinding {
  hunt_id: string;
  target: string;
  program?: string;
  hunt_created_at?: string;
}

// Aggregate every finding across the user's hunts for the console Findings view.
// We build this client-side from the per-hunt endpoint (which reads the hunt's
// findings_json — where findings actually live) instead of the server's
// /v1/findings, because that route is shadowed by a stale handler reading an
// always-empty Finding table, so it returns nothing. Mirrors what the backend's
// `all_findings` would return, using only endpoints that work.
export async function listAllFindings(): Promise<{ findings: AllFinding[]; count: number }> {
  const { hunts } = await listHunts();
  const ordered = [...hunts].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  const per = await Promise.all(
    ordered.map((h) =>
      listHuntFindings(h.hunt_id)
        .then((r) =>
          (r.findings ?? []).map((f): AllFinding => ({
            ...f,
            hunt_id: h.hunt_id,
            target: h.target,
            program: h.program,
            hunt_created_at: h.created_at,
          })),
        )
        .catch(() => [] as AllFinding[]),
    ),
  );
  const findings = per.flat();
  return { findings, count: findings.length };
}

export interface SurfaceHost { host?: string; scheme?: string; status?: string }
export interface SurfaceEndpoint { url?: string; method?: string; host?: string; src?: string }
export interface CoverageRow { item: string; cells: Record<string, string> }
export interface GraphNode { id: string; label?: string; type?: string; community?: number }
export interface GraphEdge { source: string; target: string }
export interface HuntArtifacts {
  surface?: {
    hosts: SurfaceHost[];
    endpoints: SurfaceEndpoint[];
    stats?: Record<string, number>;
    scope?: { allow: string[]; deny: string[] };
  } | null;
  coverage?: { classes: string[]; rows: CoverageRow[]; tested: number; total: number; pct: number } | null;
  graph?: { nodes: GraphNode[]; edges: GraphEdge[] } | null;
}

export function getHuntArtifacts(huntId: string) {
  return req<HuntArtifacts>(`/v1/hunts/${encodeURIComponent(huntId)}/artifacts`, { method: "GET" }, true);
}

export function controlHunt(huntId: string, action: "pause" | "resume" | "cancel") {
  return req<{ ok: boolean; status: string }>(
    `/v1/hunts/${encodeURIComponent(huntId)}/control`,
    { method: "POST", body: JSON.stringify({ action }) },
    true,
  );
}

