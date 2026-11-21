"use client";

import { useState } from "react";
import { changePassword, ApiError } from "@/lib/api";
import { PasswordStrength, scorePassword } from "@/components/password-strength";

function LockIcon({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden>
      <rect x="4.5" y="10.5" width="15" height="10" rx="2.4" stroke="currentColor" strokeWidth="1.6" />
      <path d="M8 10.5V7.8A4 4 0 0 1 16 7.8v2.7" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      <circle cx="12" cy="15.3" r="1.5" fill="currentColor" />
      <path d="M12 16.4v1.8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

function Field({
  id, label, value, onChange, autoComplete,
}: {
  id: string; label: string; value: string; onChange: (v: string) => void; autoComplete: string;
}) {
  const [show, setShow] = useState(false);
  return (
    <div>
      <label htmlFor={id} className="label mb-2 block text-muted">{label}</label>
      <div className="relative">
        <input
          id={id}
          type={show ? "text" : "password"}
          autoComplete={autoComplete}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="field pr-16"
        />
        <button
          type="button"
          onClick={() => setShow((v) => !v)}
          className="absolute right-3 top-1/2 -translate-y-1/2 text-[11px] font-semibold uppercase tracking-wider text-faint transition-colors hover:text-brand"
          aria-label={show ? "Hide password" : "Show password"}
          tabIndex={-1}
        >
          {show ? "Hide" : "Show"}
        </button>
      </div>
    </div>
  );
}

export function ChangePassword() {
  const [open, setOpen] = useState(false);
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const strongEnough = scorePassword(next).ok;
  const matches = next.length > 0 && next === confirm;
  const canSubmit = cur.length > 0 && strongEnough && matches && next !== cur;

  const reset = () => { setCur(""); setNext(""); setConfirm(""); setErr(null); };
  const close = () => { reset(); setOpen(false); };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    if (next !== confirm) { setErr("New passwords don't match."); return; }
    if (next === cur) { setErr("New password must be different from the current one."); return; }
    if (!strongEnough) { setErr("Choose a stronger password — at least 8 characters, mixing letters, numbers or symbols."); return; }
    setBusy(true);
    try {
      await changePassword(cur, next);
      reset();
      setOpen(false);
      setDone(true);
      setTimeout(() => setDone(false), 3000);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) setErr("Current password is incorrect.");
      else setErr(e instanceof Error ? e.message : "Couldn't change your password.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="panel p-7 sm:p-8">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="icon-badge h-10 w-10 text-brand"><LockIcon className="h-5 w-5" /></span>
          <h2 className="display text-xl text-fg">Password</h2>
        </div>
        {!open ? (
          <button
            type="button"
            onClick={() => { setDone(false); setOpen(true); }}
            className="label rounded-md border border-line px-3 py-1.5 text-muted transition-colors hover:border-brand hover:text-brand"
          >
            {done ? "Changed ✓" : "Change"}
          </button>
        ) : (
          <span className="label text-faint">Editing</span>
        )}
      </div>

      {!open ? (
        <p className="mt-3 text-sm text-muted">
          {done ? "Your password was updated." : "Set a new password. You'll need your current one to confirm it's you."}
        </p>
      ) : (
        <form onSubmit={submit} className="mt-6 space-y-4" noValidate>
          {err && (
            <div role="alert" className="enter rounded-lg border border-critical/30 bg-critical/10 px-4 py-3 text-sm text-critical">
              {err}
            </div>
          )}

          <Field id="cur-pw" label="Current password" value={cur} onChange={setCur} autoComplete="current-password" />

          <div>
            <Field id="new-pw" label="New password" value={next} onChange={setNext} autoComplete="new-password" />
            {next.length > 0 && <PasswordStrength password={next} />}
          </div>

          <div>
            <Field id="confirm-pw" label="Confirm new password" value={confirm} onChange={setConfirm} autoComplete="new-password" />
            {confirm.length > 0 && !matches && (
              <p className="mt-1.5 text-xs text-critical">Passwords don&apos;t match.</p>
            )}
          </div>

          <div className="flex gap-3 pt-1">
            <button type="submit" disabled={busy || !canSubmit} className="btn-brand">
              {busy ? "Saving…" : "Update password"}
            </button>
            <button type="button" onClick={close} disabled={busy} className="btn-outline">Cancel</button>
          </div>
        </form>
      )}
    </div>
  );
}
