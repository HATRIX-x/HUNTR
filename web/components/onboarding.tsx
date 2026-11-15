"use client";

import { useState } from "react";
import { saveProfile, type Profile } from "@/lib/api";
import { QUESTIONS } from "@/lib/profile-schema";

function Check() {
  return (
    <svg viewBox="0 0 24 24" fill="none" className="h-4 w-4" aria-hidden>
      <path d="M5 12.5l4.2 4.2L19 7" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Onboarding({ email, onDone }: { email?: string; onDone: (p: Profile) => void }) {
  const [step, setStep] = useState(0);
  const [answers, setAnswers] = useState<Profile>({ platforms: [] });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const q = QUESTIONS[step];
  const isLast = step === QUESTIONS.length - 1;
  const pct = Math.round(((step + 1) / QUESTIONS.length) * 100);

  const selected = (val: string): boolean => {
    if (q.multi) return (answers.platforms ?? []).includes(val);
    return (answers[q.key] as string | undefined) === val;
  };

  const pick = (val: string) => {
    setErr(null);
    if (q.multi) {
      const cur = new Set(answers.platforms ?? []);
      cur.has(val) ? cur.delete(val) : cur.add(val);
      setAnswers((a) => ({ ...a, platforms: [...cur] }));
    } else {
      setAnswers((a) => ({ ...a, [q.key]: val }));
      // single-select auto-advances for a snappy feel (except the final step)
      if (!isLast) setTimeout(() => setStep((s) => s + 1), 160);
    }
  };

  const answeredHere =
    q.multi ? (answers.platforms ?? []).length > 0 : Boolean(answers[q.key]);

  const finish = async (payload: Profile) => {
    setBusy(true);
    setErr(null);
    try {
      await saveProfile(payload);
    } catch {
      /* non-blocking — we still let them in even if the save hiccups */
    } finally {
      onDone(payload);
    }
  };

  const next = () => {
    if (isLast) return finish(answers);
    setStep((s) => s + 1);
  };

  const skip = () => finish(answers);

  return (
    <div className="panel overflow-hidden rounded-xl p-7 sm:p-9">
      {/* header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <span className="label text-brand">Welcome{email ? `, ${email.split("@")[0]}` : ""}</span>
          <p className="mt-1 text-xs text-faint">Step {step + 1} of {QUESTIONS.length}</p>
        </div>
        <button type="button" onClick={skip} disabled={busy} className="rounded px-2 py-1.5 text-xs text-muted transition-colors hover:text-fg">
          Skip for now
        </button>
      </div>

      {/* progress */}
      <div className="mt-4 h-1 w-full overflow-hidden rounded-full bg-line" role="progressbar" aria-valuemin={1} aria-valuemax={QUESTIONS.length} aria-valuenow={step + 1} aria-label="Setup progress">
        <div
          className="h-full rounded-full bg-grad-brand transition-[width] duration-500 ease-out"
          style={{ width: `${pct}%` }}
        />
      </div>

      {/* question */}
      <h2 key={step} className="enter display mt-7 text-2xl text-fg">{q.title}</h2>
      <p className="mt-2 text-sm text-muted">{q.subtitle}</p>

      {err && <p className="mt-4 text-sm text-critical">{err}</p>}

      {/* options */}
      <div className="mt-6 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
        {q.options.map((o) => {
          const on = selected(o.value);
          return (
            <button
              key={o.value}
              type="button"
              onClick={() => pick(o.value)}
              aria-pressed={on}
              className={`group flex items-start gap-3 rounded-xl border p-4 text-left transition-all ${
                on
                  ? "border-brand bg-brand/10 shadow-[0_0_0_4px_var(--brand-a10)]"
                  : "border-line-2 bg-bg/40 hover:border-brand/60 hover:bg-brand/5"
              }`}
            >
              <span
                className={`mt-0.5 grid h-5 w-5 shrink-0 place-items-center border transition-colors ${
                  on ? "border-brand bg-brand text-brand-ink" : "border-line-2 text-transparent group-hover:border-brand/60"
                } ${q.multi ? "rounded-md" : "rounded-full"}`}
              >
                {on && <Check />}
              </span>
              <span className="min-w-0">
                <span className="block text-sm font-semibold text-fg">{o.label}</span>
                {o.hint && <span className="mt-0.5 block text-xs leading-snug text-muted">{o.hint}</span>}
              </span>
            </button>
          );
        })}
      </div>

      {/* footer controls */}
      <div className="mt-7 flex items-center justify-between gap-3">
        <button
          type="button"
          onClick={() => setStep((s) => Math.max(0, s - 1))}
          disabled={step === 0}
          className="text-sm text-muted transition-colors hover:text-fg disabled:opacity-0"
        >
          ← Back
        </button>
        <button
          type="button"
          onClick={next}
          disabled={busy || (!answeredHere && q.multi) || (isLast && !answeredHere)}
          className={answeredHere || isLast ? "btn-brand" : "btn-outline"}
        >
          {busy && <span className="spinner" aria-hidden />}
          {busy ? "Saving…" : isLast ? "Finish setup" : answeredHere || q.multi ? "Continue" : "Skip question"}
        </button>
      </div>
    </div>
  );
}
