"use client";

import { useState } from "react";
import { twofaSetup, twofaEnable, twofaDisable } from "@/lib/api";
import { QRCode } from "@/components/qr-code";

type Step = "idle" | "setup" | "backup" | "disable";

function ShieldIcon({ className = "", on = false }: { className?: string; on?: boolean }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden>
      <path d="M12 3l7 2.6v5.2c0 4.3-2.9 8-7 9.2-4.1-1.2-7-4.9-7-9.2V5.6L12 3z"
        stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
      {on && <path d="M8.8 12.2l2.2 2.2 4.2-4.4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />}
    </svg>
  );
}

function CopyLine({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          /* ignore */
        }
      }}
      className="label shrink-0 border border-line px-3 py-1 text-muted transition-colors hover:border-brand hover:text-brand"
    >
      {done ? "Copied" : "Copy"}
    </button>
  );
}

export function TwoFactor({ enabled: initialEnabled }: { enabled: boolean }) {
  const [enabled, setEnabled] = useState(initialEnabled);
  const [step, setStep] = useState<Step>("idle");
  const [uri, setUri] = useState("");
  const [secret, setSecret] = useState("");
  const [code, setCode] = useState("");
  const [backup, setBackup] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const begin = async () => {
    setErr(null);
    setBusy(true);
    try {
      const s = await twofaSetup();
      setUri(s.otpauth_uri);
      setSecret(s.secret);
      setStep("setup");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Couldn't start setup.");
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    setErr(null);
    setBusy(true);
    try {
      const r = await twofaEnable(code.trim());
      setBackup(r.backup_codes);
      setEnabled(true);
      setCode("");
      setStep("backup");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "That code didn't match.");
    } finally {
      setBusy(false);
    }
  };

  const disable = async () => {
    setErr(null);
    setBusy(true);
    try {
      await twofaDisable(code.trim());
      setEnabled(false);
      setCode("");
      setStep("idle");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Couldn't turn off 2FA.");
    } finally {
      setBusy(false);
    }
  };

  const reset = () => { setStep("idle"); setCode(""); setErr(null); };

  const codeInput = (onEnter: () => void) => (
    <input
      inputMode="numeric"
      autoComplete="one-time-code"
      value={code}
      onChange={(e) => setCode(e.target.value)}
      onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); onEnter(); } }}
      placeholder="123456"
      className="field py-3.5 text-center font-mono text-lg tracking-[0.4em] placeholder:tracking-normal"
    />
  );

  return (
    <div className="panel p-7 sm:p-8">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="icon-badge h-10 w-10 text-brand">
            <ShieldIcon className="h-5 w-5" on={enabled} />
          </span>
          <h2 className="display text-xl text-fg">Two-factor authentication</h2>
        </div>
        <span className={`statuspill ${enabled ? "text-green" : "text-faint"}`}>
          <span className="dot" />
          {enabled ? "On" : "Off"}
        </span>
      </div>

      {err && (
        <div role="alert" className="mt-4 enter rounded-lg border border-critical/30 bg-critical/10 px-4 py-3 text-sm text-critical">
          {err}
        </div>
      )}

      {/* IDLE */}
      {step === "idle" && (
        <>
          <p className="mt-3 max-w-2xl text-sm leading-relaxed text-muted">
            {enabled
              ? "Your account is protected with an authenticator app. You'll enter a code each time you sign in."
              : "Add a second step at sign-in with an authenticator app (Google Authenticator, 1Password, Authy…). Strongly recommended."}
          </p>
          {enabled ? (
            <button type="button" onClick={() => setStep("disable")} className="btn-outline mt-6">
              Turn off 2FA
            </button>
          ) : (
            <button type="button" onClick={begin} disabled={busy} className="btn-brand mt-6">
              {busy ? "Starting…" : "Enable two-factor"}
            </button>
          )}
        </>
      )}

      {/* SETUP */}
      {step === "setup" && (
        <div className="mt-6 space-y-5">
          <p className="text-sm text-muted">
            1. Scan this QR with your authenticator app, or enter the key manually.
          </p>
          <div className="flex flex-wrap items-center gap-6">
            <QRCode text={uri} />
            <div className="min-w-[220px] flex-1">
              <span className="label text-muted">Manual key</span>
              <div className="mt-2 flex items-center gap-3 rounded-lg border border-line bg-bg px-4 py-3">
                <code className="min-w-0 flex-1 break-all font-mono text-xs text-brand">{secret}</code>
                <CopyLine text={secret} />
              </div>
            </div>
          </div>
          <div>
            <p className="mb-2 text-sm text-muted">2. Enter the 6-digit code it shows:</p>
            {codeInput(confirm)}
          </div>
          <div className="flex gap-3">
            <button type="button" onClick={confirm} disabled={busy} className="btn-brand">
              {busy ? "Verifying…" : "Verify & enable"}
            </button>
            <button type="button" onClick={reset} className="btn-outline">Cancel</button>
          </div>
        </div>
      )}

      {/* BACKUP CODES */}
      {step === "backup" && (
        <div className="mt-6 space-y-4">
          <p className="text-sm text-fg">
            ✅ Two-factor is on. <span className="text-muted">Save these backup codes somewhere safe —
            each works once if you lose your authenticator. They won&apos;t be shown again.</span>
          </p>
          <div className="grid grid-cols-2 gap-2 rounded-lg border border-green/25 bg-green/[0.04] p-4 font-mono text-sm text-green sm:grid-cols-4">
            {backup.map((c) => <span key={c} className="text-center">{c}</span>)}
          </div>
          <div className="flex gap-3">
            <CopyLine text={backup.join("\n")} />
            <button type="button" onClick={() => setStep("idle")} className="btn-brand">
              I&apos;ve saved them
            </button>
          </div>
        </div>
      )}

      {/* DISABLE */}
      {step === "disable" && (
        <div className="mt-6 space-y-4">
          <p className="text-sm text-muted">
            Enter a current authenticator code (or a backup code) to turn off two-factor.
          </p>
          {codeInput(disable)}
          <div className="flex gap-3">
            <button type="button" onClick={disable} disabled={busy} className="btn-outline">
              {busy ? "Turning off…" : "Turn off 2FA"}
            </button>
            <button type="button" onClick={reset} className="btn-outline">Cancel</button>
          </div>
        </div>
      )}
    </div>
  );
}
