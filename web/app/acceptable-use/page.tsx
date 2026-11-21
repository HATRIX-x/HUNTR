import type { Metadata } from "next";
import Link from "next/link";
import { LegalPage, Clause, MailLink } from "@/components/legal";

export const metadata: Metadata = {
  title: "Acceptable Use Policy",
  description:
    "How HUNTR may and may not be used. The core rule: authorized targets only. Rules for AI-generated reports, prohibited activities, and your responsibilities.",
  alternates: { canonical: "/acceptable-use/" },
  robots: { index: true, follow: true },
};

export default function AcceptableUse() {
  return (
    <LegalPage
      kicker="Legal"
      title={
        <>
          Acceptable Use <span className="text-brand">Policy.</span>
        </>
      }
      intro={
        <>
          HUNTR is a powerful, autonomous security-testing tool. This Acceptable Use Policy (&ldquo;AUP&rdquo;)
          sets the rules for using it responsibly and lawfully. It is part of our{" "}
          <Link href="/terms/">Terms of Service</Link>, and breaking it is a breach of those Terms. If anything
          here is unclear, ask us before you run a hunt: <MailLink />.
        </>
      }
    >
      <Clause n={1} title="The one rule: authorized targets only">
        <p>
          You may use HUNTR <strong>only against systems, applications, networks, and assets that you own or
          that you are explicitly authorized to test.</strong> &ldquo;Authorized&rdquo; means you have clear,
          documented permission, such as:
        </p>
        <ul>
          <li>a system you own or operate yourself;</li>
          <li>a signed penetration-testing engagement or statement of work; or</li>
          <li>an asset that is explicitly in scope on a bug bounty or vulnerability-disclosure program whose rules permit automated testing.</li>
        </ul>
        <p>
          If you are not certain a target is authorized and in scope, do not point HUNTR at it. Testing systems
          without permission may be a crime in your jurisdiction.
        </p>
      </Clause>

      <Clause n={2} title="Respect scope and program rules">
        <p>
          When you test under a bug bounty or disclosure program, you must stay within that program&apos;s scope
          and follow its rules — including any limits on automated tooling, request rates, out-of-scope assets,
          and prohibited test types. Staying in scope is your responsibility; HUNTR provides scope controls to
          help, but it cannot know a program&apos;s rules unless you configure them correctly.
        </p>
      </Clause>

      <Clause n={3} title="Prohibited uses">
        <p>You must not use HUNTR to:</p>
        <ul>
          <li>access, test, or attack any system without authorization;</li>
          <li>violate any law or regulation, or infringe anyone&apos;s rights;</li>
          <li>intentionally cause damage, disruption, data loss, or denial of service to any system or its users;</li>
          <li>exfiltrate, retain, or expose other people&apos;s personal data or confidential information beyond what is strictly necessary to demonstrate a finding to an authorized party;</li>
          <li>test third-party or supporting infrastructure (for example shared cloud providers, email, or payment systems) that is out of scope;</li>
          <li>circumvent, disable, or interfere with security or scope controls; or</li>
          <li>use HUNTR in any way that would breach the terms of your AI provider, your hosting provider, or a bug bounty platform.</li>
        </ul>
      </Clause>

      <Clause n={4} title="AI-generated reports and findings">
        <p>
          HUNTR uses AI to test targets and to draft findings and reports. That output can be wrong — it may
          include false positives, miss real issues, or describe impact inaccurately. Therefore:
        </p>
        <ul>
          <li><strong>Verify before you rely.</strong> You must independently confirm every finding before acting on it.</li>
          <li><strong>Verify before you submit.</strong> Do not submit AI-generated reports to a bug bounty program, a vendor, or any third party without reviewing and validating them yourself.</li>
          <li><strong>No spam.</strong> Do not flood programs with unverified, duplicate, low-quality, or automated submissions. You are responsible for the quality and accuracy of anything you submit.</li>
        </ul>
        <p>HUNTR drafts; you decide what is real and what gets sent. Every submission is your own.</p>
      </Clause>

      <Clause n={5} title="Comply with third-party terms">
        <p>
          Your use of HUNTR must also comply with the terms and policies of the services it relies on or
          interacts with — including Anthropic&apos;s usage policies for the AI model that powers HUNTR (which may
          require verification for security-related use), and the rules of any bug bounty platform you submit
          through.
        </p>
      </Clause>

      <Clause n={6} title="Your responsibility and consequences">
        <p>
          You are solely responsible for how you use HUNTR and for every target you choose. Violating this AUP
          may result in immediate suspension or termination of your access without refund, and you agree to
          indemnify HUNTR for any claim arising from your misuse, as set out in the{" "}
          <Link href="/terms/">Terms of Service</Link>. Serious misuse may be reported to the relevant
          authorities.
        </p>
      </Clause>

      <Clause n={7} title="Report misuse">
        <p>
          If you believe HUNTR is being misused, or you have a question about whether a use is acceptable, contact
          us at <MailLink />.
        </p>
      </Clause>
    </LegalPage>
  );
}
