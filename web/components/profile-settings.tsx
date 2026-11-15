"use client";

import { useState } from "react";
import { saveProfile, type Profile } from "@/lib/api";
import { QUESTIONS, labelFor, type Q } from "@/lib/profile-schema";

function Check() {
  return (
    <svg viewBox="0 0 24 24" fill="none" className="h-4 w-4" aria-hidden>
      <path d="M5 12.5l4.2 4.2L19 7" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
function UserIcon({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden>
      <circle cx="12" cy="8" r="3.6" stroke="currentColor" strokeWidth="1.6" />
      <path d="M5 20c0-3.3 3.1-5.6 7-5.6s7 2.3 7 5.6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

function valueOf(p: Profile, q: Q): string[] {
  if (q.multi) return p.platforms ?? [];
  const v = p[q.key] as string | null | undefined;
  return v ? [v] : [];
}

export function ProfileSettings({ initial, onSaved }: { initial: Profile; onSaved?: (p: Profile) => void }) {
  const [saved, setSaved] = useState<Profile>(initial);
  const [draft, setDraft] = useState<Profile>(initial);
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [justSaved, setJustSaved] = useState(false);

  const selected = (q: Q, v: string) => valueOf(draft, q).includes(v);

  const pick = (q: Q, v: string) => {
    if (q.multi) {
      const cur = new Set(draft.platforms ?? []);
      cur.has(v) ? cur.delete(v) : cur.add(v);
      setDraft((d) => ({ ...d, platforms: [...cur] }));
    } else {
      setDraft((d) => ({ ...d, [q.key]: d[q.key] === v ? null : v }));
    }
  };

  const startEdit = () => { setDraft(saved); setErr(null); setEditing(true); };
  const cancel = () => { setDraft(saved); setEditing(false); setErr(null); };

  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      const res = await saveProfile(draft);
      const next = res.profile ?? draft;
      setSaved(next);
      setDraft(next);
      setEditing(false);
      setJustSaved(true);
      setTimeout(() => setJustSaved(false), 2200);
      onSaved?.(next);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Couldn't save your profile.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="panel p-7 sm:p-8">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="icon-badge h-10 w-10 text-brand"><UserIcon className="h-5 w-5" /></span>
          <h2 className="display text-xl text-fg">Your profile</h2>
        </div>
        {!editing ? (
          <button type="button" onClick={startEdit} className="label rounded-md border border-line px-3 py-1.5 text-muted transition-colors hover:border-brand hover:text-brand">
            {justSaved ? "Saved ✓" : "Edit"}
          </button>
        ) : (
          <span className="label text-faint">Editing</span>
        )}
      </div>

      <p className="mt-3 max-w-2xl text-sm leading-relaxed text-muted">
        Tells HUNTR who you are and how you work. You can change these any time.
      </p>

      {err && (
        <div role="alert" className="mt-4 enter rounded-lg border border-critical/30 bg-critical/10 px-4 py-3 text-sm text-critical">
          {err}
        </div>
      )}

      {/* ── view mode ── */}
      {!editing && (
        <dl className="mt-6 divide-y divide-line border-y border-line">
          {QUESTIONS.map((q) => {
            const vals = valueOf(saved, q);
            return (
              <div key={String(q.key)} className="flex items-start justify-between gap-6 py-3.5">
                <dt className="label shrink-0 pt-0.5 text-faint">{q.short}</dt>
                <dd className="flex flex-wrap justify-end gap-1.5 text-right">
                  {vals.length === 0 ? (
                    <button type="button" onClick={startEdit} className="text-sm text-brand hover:underline">
                      Add
                    </button>
                  ) : (
                    vals.map((v) => (
                      <span key={v} className="rounded-full border border-line-2 bg-bg/50 px-3 py-1 text-xs font-medium text-fg">
                        {labelFor(q.key, v)}
                      </span>
                    ))
                  )}
                </dd>
              </div>
            );
          })}
        </dl>
      )}

      {/* ── edit mode ── */}
      {editing && (
        <div className="mt-6 space-y-7">
          {QUESTIONS.map((q) => (
            <div key={String(q.key)}>
              <p className="text-sm font-semibold text-fg">{q.title}</p>
              {q.multi && <p className="mt-0.5 text-xs text-faint">Pick all that apply.</p>}
              <div className="mt-3 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                {q.options.map((o) => {
                  const on = selected(q, o.value);
                  return (
                    <button
                      key={o.value}
                      type="button"
                      onClick={() => pick(q, o.value)}
                      aria-pressed={on}
                      className={`group flex items-start gap-3 rounded-xl border p-3.5 text-left transition-all ${
                        on ? "border-brand bg-brand/10" : "border-line-2 bg-bg/40 hover:border-brand/60 hover:bg-brand/5"
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
                        <span className="block text-sm font-medium text-fg">{o.label}</span>
                        {o.hint && <span className="mt-0.5 block text-xs leading-snug text-muted">{o.hint}</span>}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}

          <div className="flex gap-3">
            <button type="button" onClick={save} disabled={busy} className="btn-brand">
              {busy ? "Saving…" : "Save changes"}
            </button>
            <button type="button" onClick={cancel} disabled={busy} className="btn-outline">
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
