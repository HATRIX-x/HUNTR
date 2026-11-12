# HUNTR Acceptable Use Policy

**Version 2026-11-11**

HUNTR is a powerful, autonomous security-testing tool. This Acceptable Use
Policy ("AUP") sets the rules for using it responsibly and lawfully. It is
part of, and incorporated into, the HUNTR End User License Agreement
([LICENSE](./LICENSE)) and the online [Terms of Service](https://huntr.run/terms/).
Breaking this AUP is a breach of those terms. If anything here is unclear,
ask before you run a hunt: **support@huntr.run**.

## 1. The one rule: authorized targets only

You may use HUNTR **only against systems, applications, networks, and assets
that you own or that you are explicitly authorized to test.** "Authorized"
means you have clear, documented permission, such as:

- a system you own or operate yourself;
- a signed penetration-testing engagement or statement of work; or
- an asset that is explicitly in scope on a bug bounty or vulnerability-
  disclosure program whose rules permit automated testing.

If you are not certain a target is authorized and in scope, do not point
HUNTR at it. Testing systems without permission may be a crime in your
jurisdiction.

## 2. Respect scope and program rules

When testing under a bug bounty or disclosure program, you must stay within
that program's scope and follow its rules — including any limits on automated
tooling, request rates, out-of-scope assets, and prohibited test types.
Staying in scope is your responsibility. HUNTR provides scope controls to
help, but it cannot know a program's rules unless you configure them.

## 3. Prohibited uses

You must not use HUNTR to:

- access, test, or attack any system without authorization;
- violate any law or regulation, or infringe anyone's rights;
- intentionally cause damage, disruption, data loss, or denial of service;
- exfiltrate, retain, or expose other people's personal data or confidential
  information beyond what is strictly necessary to demonstrate a finding to
  an authorized party;
- test out-of-scope third-party or supporting infrastructure (for example
  shared cloud providers, email, or payment systems);
- circumvent, disable, or interfere with security or scope controls; or
- use HUNTR in any way that breaches the terms of your AI provider, your
  hosting provider, or a bug bounty platform.

## 4. AI-generated reports and findings

HUNTR uses AI to test targets and draft findings and reports. That output
can be wrong — it may include false positives, miss real issues, or describe
impact inaccurately. Therefore:

- **Verify before you rely.** Independently confirm every finding before
  acting on it.
- **Verify before you submit.** Do not submit AI-generated reports to a bug
  bounty program, a vendor, or any third party without reviewing and
  validating them yourself.
- **No spam.** Do not flood programs with unverified, duplicate, low-quality,
  or automated submissions. You are responsible for the accuracy and quality
  of anything you submit.

HUNTR drafts; you decide what is real and what gets sent. Every submission is
your own.

## 5. Comply with third-party terms

Your use of HUNTR must also comply with the terms of the services it relies
on — including Anthropic's usage policies for the AI model that powers HUNTR
(which may require verification for security-related use), and the rules of
any bug bounty platform you submit through.

## 6. Your responsibility and consequences

You are solely responsible for how you use HUNTR and for every target you
choose. Violating this AUP may result in immediate suspension or termination
of your access without refund, and you agree to indemnify HUNTR for any claim
arising from your misuse, as set out in the LICENSE. Serious misuse may be
reported to the relevant authorities.

## 7. Report misuse

If you believe HUNTR is being misused, or you have a question about whether a
use is acceptable, contact **support@huntr.run**.

---

© 2026 HUNTR. Authorized targets only.
