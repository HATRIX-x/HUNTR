import type { Metadata } from "next";
import Link from "next/link";
import { LegalPage, Clause, MailLink } from "@/components/legal";

export const metadata: Metadata = {
  title: "Terms of Service",
  description:
    "The terms that govern your use of HUNTR, the autonomous AI operator for bug bounty — license, billing, authorized-use requirement, warranties and liability.",
  alternates: { canonical: "/terms/" },
  robots: { index: true, follow: true },
};

export default function Terms() {
  return (
    <LegalPage
      kicker="Legal"
      title={
        <>
          Terms of <span className="text-brand">Service.</span>
        </>
      }
      intro={
        <>
          These Terms of Service (the &ldquo;Terms&rdquo;) are a binding agreement between you and HUNTR
          (&ldquo;HUNTR&rdquo;, &ldquo;we&rdquo;, &ldquo;us&rdquo;) covering your access to and use of the HUNTR
          software and the <Link href="/">huntr.run</Link> website. By creating an account, subscribing, or
          using HUNTR, you agree to these Terms and to our{" "}
          <Link href="/acceptable-use/">Acceptable Use Policy</Link> and{" "}
          <Link href="/privacy/">Privacy Policy</Link>. If you do not agree, do not use HUNTR.
        </>
      }
    >
      <Clause n={1} title="What HUNTR is">
        <p>
          HUNTR is an autonomous AI operator for security testing. It maps a target&apos;s attack surface, tests
          it, validates findings, and drafts reports. <strong>HUNTR drafts; you decide.</strong> It does not
          submit reports or take actions on your behalf — every finding is reviewed and acted on by you.
        </p>
      </Clause>

      <Clause n={2} title="Your licence to use HUNTR">
        <p>
          Subject to these Terms and your active subscription, we grant you a limited, non-exclusive,
          non-transferable, revocable licence to install and use HUNTR for your own authorized security
          testing. You may not:
        </p>
        <ul>
          <li>resell, sublicense, rent, lease, or otherwise make HUNTR available to any third party;</li>
          <li>share your subscription, licence, or account credentials with anyone else;</li>
          <li>copy, modify, translate, or create derivative works of HUNTR except as permitted by law;</li>
          <li>reverse-engineer, decompile, or disassemble HUNTR except to the extent that right cannot be excluded by law;</li>
          <li>remove or alter any proprietary notices; or</li>
          <li>use HUNTR to build or train a competing product or service.</li>
        </ul>
      </Clause>

      <Clause n={3} title="Your own AI provider key (BYO-key)">
        <p>
          HUNTR runs on <strong>your own Anthropic API key</strong>. You are Anthropic&apos;s customer for that
          usage, you are billed directly by Anthropic for the tokens HUNTR consumes, and your key is stored only
          on your own machine — we never receive, store, or process it. You are responsible for your own API
          spend and for complying with Anthropic&apos;s applicable terms and usage policies, including any
          verification required for security-related use. Our subscription fee is for the HUNTR software and does
          not include AI usage costs.
        </p>
      </Clause>

      <Clause n={4} title="Authorized use only">
        <p>
          HUNTR is a tool for <strong>authorized</strong> security testing. You may only direct HUNTR at systems,
          applications, and assets that you own or that you have explicit, documented permission to test — for
          example a signed engagement or an in-scope asset on a bug bounty program that permits automated testing.
          Your use of HUNTR is governed at all times by our{" "}
          <Link href="/acceptable-use/">Acceptable Use Policy</Link>, which is incorporated into these Terms.
          Unauthorized use of HUNTR against systems you do not have permission to test may be illegal and is a
          material breach of these Terms.
        </p>
      </Clause>

      <Clause n={5} title="Subscriptions, billing and taxes">
        <p>
          Paid plans are sold on a subscription basis and billed through our payments provider,{" "}
          <a href="https://www.creem.io" target="_blank" rel="noopener noreferrer">Creem</a>, who acts as the
          merchant of record for your purchase. Subscriptions renew automatically at the end of each billing
          period at the then-current price until cancelled. Prices are shown on our{" "}
          <Link href="/pricing/">pricing page</Link> and may be exclusive of taxes; applicable taxes are added at
          checkout where required. You authorize us and our payments provider to charge your payment method for
          each renewal.
        </p>
      </Clause>

      <Clause n={6} title="Cancellation and refunds">
        <p>
          You may cancel your subscription at any time; cancellation stops future renewals and your access
          continues until the end of the current paid period. Except where required by law, payments are
          non-refundable. If you believe you were charged in error, contact us at <MailLink /> and we will review
          it in good faith.
        </p>
      </Clause>

      <Clause n={7} title="Your responsibilities and warranties">
        <p>You represent, warrant, and agree that:</p>
        <ul>
          <li>you are at least 18 years old and able to enter into this agreement;</li>
          <li>you have all authorizations and permissions required for every target you test with HUNTR;</li>
          <li>you will comply with all applicable laws and with the rules of any bug bounty or disclosure program you participate in; and</li>
          <li>you are solely responsible for how you use HUNTR, for the targets you select, and for anything you submit to a third party based on HUNTR&apos;s output.</li>
        </ul>
      </Clause>

      <Clause n={8} title="AI output and no warranty">
        <p>
          HUNTR is provided <strong>&ldquo;as is&rdquo; and &ldquo;as available&rdquo;</strong>, without
          warranties of any kind, whether express or implied, including fitness for a particular purpose,
          merchantability, and non-infringement. HUNTR uses AI models and automated testing; its output may be
          incomplete, inaccurate, or wrong, and may include false positives or missed issues.{" "}
          <strong>You are responsible for independently verifying every finding before relying on it or
          submitting it anywhere.</strong> We do not warrant that HUNTR will be uninterrupted, error-free, or that
          it will find any particular vulnerability.
        </p>
      </Clause>

      <Clause n={9} title="Limitation of liability">
        <p>
          To the maximum extent permitted by law, HUNTR and its operators will not be liable for any indirect,
          incidental, special, consequential, or punitive damages, or for any loss of profits, data, goodwill, or
          business, arising out of or related to your use of (or inability to use) HUNTR. Our total aggregate
          liability for all claims relating to HUNTR will not exceed the amount you paid us for the subscription
          in the twelve (12) months before the event giving rise to the claim.
        </p>
      </Clause>

      <Clause n={10} title="Indemnification">
        <p>
          You agree to indemnify and hold harmless HUNTR and its operators from any claim, demand, loss,
          liability, or expense (including reasonable legal fees) arising out of or related to your use of HUNTR,
          your selection of targets, your breach of these Terms or the Acceptable Use Policy, or your violation of
          any law or third-party right. This includes any claim arising from testing a system you were not
          authorized to test.
        </p>
      </Clause>

      <Clause n={11} title="Intellectual property">
        <p>
          HUNTR, the huntr.run website, and all related software, content, and trademarks are owned by HUNTR and
          its licensors and are protected by law. These Terms grant you a licence to use HUNTR, not any ownership
          of it. Findings and reports that HUNTR generates for you from your own authorized testing are yours to
          use.
        </p>
      </Clause>

      <Clause n={12} title="Suspension and termination">
        <p>
          We may suspend or terminate your access if you breach these Terms or the Acceptable Use Policy, if
          required by law, or to protect HUNTR, our providers, or third parties. You may stop using HUNTR and
          cancel at any time. Provisions that by their nature should survive termination (including licence
          restrictions, warranties, liability limits, and indemnities) survive.
        </p>
      </Clause>

      <Clause n={13} title="Changes to the service and these Terms">
        <p>
          We may update HUNTR and these Terms from time to time. When we make material changes to the Terms, we
          will update the effective date above and, where appropriate, notify you. Continuing to use HUNTR after
          changes take effect means you accept the updated Terms.
        </p>
      </Clause>

      <Clause n={14} title="Governing law">
        <p>
          These Terms are governed by the laws of the jurisdiction in which the HUNTR operator is established,
          without regard to its conflict-of-laws rules, and the courts of that jurisdiction will have exclusive
          jurisdiction over any dispute, except where mandatory consumer-protection law gives you other rights.
        </p>
      </Clause>

      <Clause n={15} title="Contact">
        <p>
          Questions about these Terms? Reach us at <MailLink />.
        </p>
      </Clause>
    </LegalPage>
  );
}
