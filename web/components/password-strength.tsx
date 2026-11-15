"use client";

// Lightweight, dependency-free password strength heuristic. Mirrors the
// server-side policy in cloud/app/routers/auth.py (min 8, ≥2 character classes)
// and layers on length/variety scoring for user feedback.

const COMMON = new Set([
  "password", "password1", "password123", "12345678", "123456789", "1234567890",
  "qwerty123", "qwertyuiop", "11111111", "00000000", "letmein1", "iloveyou",
  "admin123", "welcome1", "changeme", "passw0rd", "huntr123",
]);

export interface Strength {
  score: 0 | 1 | 2 | 3 | 4; // 0 too-weak … 4 strong
  label: string;
  classes: number;
  ok: boolean; // meets the minimum policy (len≥8, ≥2 classes, not common)
}

export function scorePassword(pw: string): Strength {
  if (!pw) return { score: 0, label: "", classes: 0, ok: false };

  const classes =
    (/[a-z]/.test(pw) ? 1 : 0) +
    (/[A-Z]/.test(pw) ? 1 : 0) +
    (/[0-9]/.test(pw) ? 1 : 0) +
    (/[^A-Za-z0-9]/.test(pw) ? 1 : 0);

  const common = COMMON.has(pw.toLowerCase());
  const ok = pw.length >= 8 && classes >= 2 && !common;

  if (common || pw.length < 8) {
    return { score: pw.length < 4 ? 0 : 1, label: pw.length < 8 ? "Too short" : "Too common", classes, ok: false };
  }

  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (classes >= 3) s++;
  if (classes >= 4 || (pw.length >= 16 && classes >= 2)) s++;
  const score = Math.max(1, Math.min(4, s)) as 1 | 2 | 3 | 4;

  const label = ["", "Weak", "Fair", "Good", "Strong"][score];
  return { score, label, classes, ok };
}

const BAR_COLORS = ["var(--faint)", "var(--critical)", "var(--high)", "var(--brand)", "var(--green)"];

export function PasswordStrength({ password }: { password: string }) {
  const st = scorePassword(password);
  if (!password) return null;
  return (
    <div className="mt-2" aria-live="polite">
      <div className="flex gap-1.5">
        {[1, 2, 3, 4].map((i) => (
          <span
            key={i}
            className="h-1 flex-1 rounded-full transition-colors"
            style={{ background: i <= st.score ? BAR_COLORS[st.score] : "rgba(255,255,255,0.10)" }}
          />
        ))}
      </div>
      <div className="mt-1.5 flex items-center justify-between">
        <span className="text-[11px]" style={{ color: BAR_COLORS[st.score] }}>
          {st.label}
        </span>
        {!st.ok && (
          <span className="text-[11px] text-faint">
            8+ chars · mix letters, numbers or symbols
          </span>
        )}
      </div>
    </div>
  );
}
