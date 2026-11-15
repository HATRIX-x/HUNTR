import type { Metadata } from "next";
import Link from "next/link";
import { LegalPage, Clause, MailLink } from "@/components/legal";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description:
    "What HUNTR collects and how we handle it. HUNTR runs hunts for you as a managed service — we process the targets you authorize, and we never sell your data or train AI models on it.",
  alternates: { canonical: "/privacy/" },
  robots: { index: true, follow: true },
};

export default function Privacy() {
  return (
    <LegalPage
      kicker="Legal"
      title={
        <>
          Privacy <span className="text-brand">Policy.</span>
        </>
      }
      intro={
        <>
          This policy explains what information HUNTR (&ldquo;HUNTR&rdquo;, &ldquo;we&rdquo;, &ldquo;us&rdquo;)
          collects through the <Link href="/">huntr.run</Link> website and account, how we use it, and the choices
          you have. HUNTR is a managed service — we run hunts for you on our own infrastructure — so we do process
          the targets you authorize us to test. The short version:{" "}
          <strong>we keep it to what&apos;s needed to run your hunts, we never sell your data, and we never train
          AI models on it.</strong>
        </>
      }
    >
      <Clause n={1} title="What we collect">
        <p>We keep what we collect deliberately small:</p>
        <ul>
          <li><strong>Account &amp; contact:</strong> the email address you give us to create an account or contact support.</li>
          <li><strong>Billing &amp; credits:</strong> when you buy credits or subscribe, payment is handled by our provider Creem. Creem processes your payment details; we receive limited information such as your purchase and subscription status and billing country. We do not store your full card details. We keep a record of your credit balance and usage.</li>
          <li><strong>Hunt data:</strong> because we run hunts for you, we process the targets and scope you authorize, the traffic HUNTR sends on your behalf, and the findings and reports it produces. We use this only to run the service for you.</li>
          <li><strong>Website analytics:</strong> privacy-friendly, cookieless usage statistics (via Cloudflare Web Analytics) and interaction analytics (via Microsoft Clarity) to understand how the site is used.</li>
          <li><strong>Support messages:</strong> anything you send us when you email support.</li>
        </ul>
      </Clause>

      <Clause n={2} title="How we handle your hunt data">
        <p>
          Running hunts for you means we process the data involved, but we hold ourselves to clear limits:
        </p>
        <ul>
          <li>We use your hunt data <strong>only</strong> to operate the service for you — mapping scope, running tests, and producing findings and reports.</li>
          <li>To run a hunt, we send the prompts and target traffic needed to Anthropic, our AI provider, under our own commercial agreement. We do not expose your data to other customers.</li>
          <li>We <strong>never sell</strong> your personal or hunt data, and we <strong>never use it to train AI models.</strong></li>
          <li>You may request deletion of your hunt data at any time (see &ldquo;Your rights&rdquo; below).</li>
        </ul>
      </Clause>

      <Clause n={3} title="How we use information">
        <p>We use the limited information we collect to:</p>
        <ul>
          <li>create and manage your account, credit balance, and subscription;</li>
          <li>run the hunts you request and deliver the findings and reports back to you;</li>
          <li>process payments and prevent fraud (through our payments provider);</li>
          <li>provide support and respond to your messages;</li>
          <li>send you essential service and account notices;</li>
          <li>understand and improve the website and product; and</li>
          <li>comply with legal obligations.</li>
        </ul>
      </Clause>

      <Clause n={4} title="Service providers we use">
        <p>We share the minimum necessary with trusted providers that process data on our behalf:</p>
        <ul>
          <li><a href="https://www.creem.io" target="_blank" rel="noopener noreferrer">Creem</a> — payments and subscription billing (merchant of record).</li>
          <li><a href="https://www.cloudflare.com" target="_blank" rel="noopener noreferrer">Cloudflare</a> — website hosting support and cookieless analytics.</li>
          <li><a href="https://clarity.microsoft.com" target="_blank" rel="noopener noreferrer">Microsoft Clarity</a> — website interaction analytics.</li>
          <li><a href="https://www.anthropic.com" target="_blank" rel="noopener noreferrer">Anthropic</a> — our AI provider. We send the prompts and target traffic needed to run your hunts to Anthropic for processing under our commercial agreement with them; their handling of that data is governed by their terms for business customers.</li>
        </ul>
      </Clause>

      <Clause n={5} title="Cookies and analytics">
        <p>
          The website uses privacy-friendly analytics to measure usage. Cloudflare Web Analytics is cookieless.
          Microsoft Clarity may use cookies or similar technology to measure how pages are used; it does not
          identify you personally to us. We do not use advertising trackers.
        </p>
      </Clause>

      <Clause n={6} title="Data retention">
        <p>
          We keep account and billing records for as long as your account is active and for as long afterwards as
          needed to meet legal, tax, and accounting obligations. Analytics data is retained in aggregated or
          short-lived form by the providers above. When data is no longer needed, we delete or anonymize it.
        </p>
      </Clause>

      <Clause n={7} title="Your rights">
        <p>
          Depending on where you live, you may have the right to access, correct, delete, or export your personal
          data, or to object to or restrict certain processing. To exercise any of these, email <MailLink /> and
          we will respond within the time required by applicable law.
        </p>
      </Clause>

      <Clause n={8} title="Security">
        <p>
          We use reasonable technical and organizational measures to protect the data we hold, including the hunt
          data we process on your behalf. We retain it only as long as needed to run the service and meet legal
          obligations, and we delete or anonymize it when it is no longer needed. No system is perfectly secure,
          but we keep access tightly scoped and minimize what we store.
        </p>
      </Clause>

      <Clause n={9} title="International transfers and children">
        <p>
          Our providers may process data in countries other than yours; where they do, they rely on appropriate
          safeguards. HUNTR is not directed to children, and you must be at least 18 to use it.
        </p>
      </Clause>

      <Clause n={10} title="Changes and contact">
        <p>
          We may update this policy from time to time; the effective date above will change when we do. For any
          privacy question or request, contact us at <MailLink />.
        </p>
      </Clause>
    </LegalPage>
  );
}
