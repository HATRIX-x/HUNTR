"""Email sender for founder alerts — pluggable, stdlib only, never raises.

Priority: RESEND_API_KEY (HTTPS POST to Resend) → SMTP_* (smtplib) → log-only.
Recipients: NOTIFY_EMAIL (comma-separated) else ADMIN_EMAILS.
From: NOTIFY_FROM (default a Resend onboarding sender, which can email the
account owner without domain verification — set it to alerts@huntr.run once the
domain is verified in Resend for best deliverability).
"""
import os, json, ssl, smtplib, urllib.request, urllib.error
from email.message import EmailMessage

LAST_ERROR = None  # last send failure reason, for the dashboard self-test


def _recipients():
    raw = os.environ.get("NOTIFY_EMAIL") or os.environ.get("ADMIN_EMAILS", "")
    return [e.strip() for e in raw.split(",") if e.strip()]


def send_email(subject: str, html: str, text: str | None = None) -> bool:
    to = _recipients()
    if not to:
        print("[notify] no recipients (set NOTIFY_EMAIL or ADMIN_EMAILS)")
        return False
    global LAST_ERROR
    LAST_ERROR = None
    frm = os.environ.get("NOTIFY_FROM", "HUNTR <onboarding@resend.dev>")
    key = os.environ.get("RESEND_API_KEY")
    try:
        if key:
            data = json.dumps({"from": frm, "to": to, "subject": subject, "html": html}).encode()
            req = urllib.request.Request(
                "https://api.resend.com/emails", data=data, method="POST",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    r.read()
                return True
            except urllib.error.HTTPError as he:
                body = he.read().decode("utf-8", "replace")[:400]
                LAST_ERROR = f"Resend HTTP {he.code}: {body}"
                print(f"[notify] {LAST_ERROR}")
                return False
        host = os.environ.get("SMTP_HOST")
        if host:
            msg = EmailMessage()
            msg["Subject"] = subject; msg["From"] = frm; msg["To"] = ", ".join(to)
            msg.set_content(text or "Open admin.huntr.run")
            msg.add_alternative(html, subtype="html")
            with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587")), timeout=15) as sv:
                sv.starttls(context=ssl.create_default_context())
                user = os.environ.get("SMTP_USER")
                if user:
                    sv.login(user, os.environ.get("SMTP_PASS", ""))
                sv.send_message(msg)
            return True
        print(f"[notify] (dry-run) '{subject}' -> {to}; set RESEND_API_KEY or SMTP_HOST to send")
        return False
    except Exception as e:  # noqa: BLE001
        LAST_ERROR = str(e)[:400]
        print(f"[notify] send failed: {LAST_ERROR}")
        return False
