"use client";

import Link from "next/link";
import { BrandMark } from "@/components/brand-mark";
import { useState } from "react";
import {
  signup, login, twofaVerify, setToken, checkout, isTwoFAChallenge, ApiError,
  type AuthResult,
} from "@/lib/api";
import { PasswordStrength, scorePassword } from "@/components/password-strength";

const validEmail = (v: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

export function AuthForm({ mode }: { mode: "signup" | "login" }) {
  const isSignup = mode === "signup";
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // 2FA challenge state (login only)
  const [challenge, setChallenge] = useState<string | null>(null);
  const [code, setCode] = useState("");

  // validate on blur, not on the first keystroke — nobody's email is valid at "s"
  const [emailBlurred, setEmailBlurred] = useState(false);
  const emailTouched = emailBlurred && email.length > 0;
  const emailValid = validEmail(email.trim());
  const pwOk = scorePassword(password).ok;
  const canSubmit = emailValid && (isSignup ? pwOk : password.length > 0);

  // setToken + continue to checkout (if ?plan) or the account page
  const finishAuth = async (res: AuthResult) => {
    setToken(res.session_token);
    const plan = new URLSearchParams(window.location.search).get("plan");
    if (plan) {
      try {
        const { checkout_url } = await checkout(plan);
        window.location.assign(checkout_url);
        return;
      } catch {
        /* fall through to account */
      }
    }
    window.location.assign("/account/");
  };

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    const mail = email.trim().toLowerCase();
    if (!validEmail(mail)) {
      setErr("Enter a valid email address.");
      return;
    }
    if (isSignup && !pwOk) {
      setErr("Choose a stronger password — at least 8 characters, mixing letters, numbers or symbols.");
      return;
    }
    if (!isSignup && password.length === 0) {
      setErr("Enter your password.");
      return;
    }
    setBusy(true);
    try {
      const res = isSignup ? await signup(mail, password) : await login(mail, password);
      if (!isSignup && isTwoFAChallenge(res)) {
        setChallenge(res.twofa_token); // show the code step
        setBusy(false);
        return;
      }
      await finishAuth(res as AuthResult);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setErr("That email already has an account. Sign in instead, using the link below.");
      } else if (e instanceof ApiError && e.status === 401) {
        setErr("Invalid email or password.");
      } else {
        setErr(e instanceof Error ? e.message : "Something went wrong. Try again.");
      }
      setBusy(false);
    }
  };

  const onVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    if (!challenge) return;
    if (code.trim().length < 6) {
      setErr("Enter the 6-digit code from your authenticator app, or a backup code.");
      return;
    }
    setBusy(true);
    try {
      const res = await twofaVerify(challenge, code.trim());
      await finishAuth(res);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "That code didn't work. Try again.");
      setBusy(false);
    }
  };

  // ── 2FA challenge view ────────────────────────────────────────────────
  if (challenge) {
    return (
      <div className="mx-auto w-full max-w-[420px]">
        <div className="panel brackets p-8 shadow-glow-brand sm:p-10">
          <BrandMark className="mb-7 h-10 w-10" glow />
          <h1 className="display text-3xl text-fg">Two-factor</h1>
          <p className="mt-3 text-sm text-muted">
            Enter the 6-digit code from your authenticator app. Lost your device? Use one of your
            backup codes.
          </p>

          {err && (
            <div role="alert" className="enter alert alert-error mt-6">
              {err}
            </div>
          )}

          <form onSubmit={onVerify} className="mt-6 space-y-4" noValidate>
            <input
              autoFocus
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="123456"
              aria-label="Authentication code"
              maxLength={32}
              className="field py-3.5 text-center font-mono text-lg tracking-[0.4em] placeholder:tracking-normal"
            />
            <button type="submit" disabled={busy} className="btn-grad w-full">
              {busy && <span className="spinner" aria-hidden />}{busy ? "Verifying…" : "Verify"}
            </button>
          </form>

          <button
            type="button"
            onClick={() => { setChallenge(null); setCode(""); setErr(null); }}
            className="mt-6 w-full text-center text-sm text-muted hover:text-fg"
          >
            ← Back to sign in
          </button>
        </div>
      </div>
    );
  }

  // ── signup / login view ───────────────────────────────────────────────
  return (
    <div className="mx-auto w-full max-w-[420px]">
      <div className="panel brackets p-8 shadow-glow-brand sm:p-10">
        <BrandMark lock className="mb-7 h-10 w-10" glow />
        <h1 className="display text-[2rem] text-fg sm:text-4xl">
          {isSignup ? "Create your account" : "Sign in"}
        </h1>
        <p className="mt-3 text-sm text-muted">
          {isSignup
            ? "Set up HUNTR in about a minute. Load credits and we run the hunts for you — no API key, no setup."
            : "Welcome back. Sign in to manage your account and agents."}
        </p>

        {err && (
          <div role="alert" className="enter alert alert-error mt-6">
            {err}
          </div>
        )}

        <form onSubmit={onSubmit} className="mt-6 space-y-4" noValidate>
          <div>
            <label htmlFor="email" className="field-label">Email</label>
            <input
              id="email"
              type="email"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onBlur={() => setEmailBlurred(true)}
              placeholder="you@company.com"
              aria-describedby={emailTouched && !emailValid ? "email-error" : undefined}
              aria-invalid={emailTouched && !emailValid}
              className={`field ${emailTouched && !emailValid ? "!border-critical/60" : ""}`}
            />
            {emailTouched && !emailValid && (
              <p id="email-error" className="mt-1.5 text-xs text-critical">That doesn&apos;t look like an email address. Check for a missing @ or domain.</p>
            )}
          </div>

          <div>
            <label htmlFor="password" className="field-label">Password</label>
            <div className="relative">
              <input
                id="password"
                type={show ? "text" : "password"}
                autoComplete={isSignup ? "new-password" : "current-password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={isSignup ? "At least 8 characters" : "Your password"}
                className="field pr-16"
              />
              <button
                type="button"
                onClick={() => setShow((v) => !v)}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded px-2 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted transition-colors hover:text-cyan"
                aria-label={show ? "Hide password" : "Show password"}
                aria-pressed={show}
              >
                {show ? "Hide" : "Show"}
              </button>
            </div>
            {isSignup && <PasswordStrength password={password} />}
          </div>

          <button
            type="submit"
            disabled={busy || !canSubmit}
            className="btn-grad w-full"
          >
            {busy && <span className="spinner" aria-hidden />}{busy ? (isSignup ? "Creating account…" : "Signing in…") : isSignup ? "Create account" : "Sign in"}
          </button>
        </form>

        <p className="mt-6 text-center text-sm text-muted">
          {isSignup ? (
            <>Already have an account?{" "}
              <Link href="/login/" className="ulink text-brand">Sign in</Link>
            </>
          ) : (
            <>New to HUNTR?{" "}
              <Link href="/signup/" className="ulink text-brand">Create an account</Link>
            </>
          )}
        </p>
      </div>

      <p className="mt-5 text-center text-xs leading-relaxed text-faint">
        By continuing you agree to the{" "}
        <Link href="/terms/" className="text-muted hover:text-fg">Terms</Link>{" "}
        and{" "}
        <Link href="/acceptable-use/" className="text-muted hover:text-fg">Acceptable Use Policy</Link>.
      </p>
    </div>
  );
}
