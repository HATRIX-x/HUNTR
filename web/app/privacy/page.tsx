import type { Metadata } from "next";
import Link from "next/link";
import { LegalPage, Clause, MailLink } from "@/components/legal";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description:
    "What HUNTR collects and what it doesn't. Your API key and your hunt data stay on your machine. How we handle account, billing, and website analytics data.",
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
          you have. HUNTR runs locally on your own machine, so the short version is simple:{" "}
          <strong>your API key and your hunt data stay with you.</strong>
        </>
      }
    >
      <Clause n={1} title="What we collect">
        <p>We keep what we collect deliberately small:</p>
        <ul>
          <li><strong>Account &amp; contact:</strong> the email address you give us to request access, create an account, or contact support.</li>
          <li><strong>Billing:</strong> when you subscribe, payment is handled by our provider Creem. Creem processes your payment details; we receive limited information such as your subscription status and billing country. We do not store your full card details.</li>
          <li><strong>Website analytics:</strong> privacy-friendly, cookieless usage statistics (via Cloudflare Web Analytics) and interaction analytics (via Microsoft Clarity) to understand how the site is used.</li>
          <li><strong>Support messages:</strong> anything you send us when you email support.</li>
        </ul>
      </Clause>

      <Clause n={2} title="What we do NOT collect">
        <p>
          Because HUNTR runs on your own machine, several of the most sensitive things never reach us:
        </p>
        <ul>
          <li><strong>Your Anthropic API key</strong> is stored only on your device and sent only to Anthropic. We never receive or store it.</li>
          <li><strong>Your hunt data</strong> — the targets you test, the traffic HUNTR sends, and the findings and reports it produces — stays on your machine. We do not collect or receive it.</li>
          <li>We do not sell your personal data, and we do not use your data to train AI models.</li>
        </ul>
      </Clause>

      <Clause n={3} title="How we use information">
        <p>We use the limited information we collect to:</p>
        <ul>
          <li>create and manage your account and subscription;</li>
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
          <li><a href="https://www.anthropic.com" target="_blank" rel="noopener noreferrer">Anthropic</a> — the AI provider you connect with your own key; your usage with them is governed by their terms and privacy policy, as their direct customer.</li>
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
          We use reasonable technical and organizational measures to protect the limited data we hold. No system
          is perfectly secure, but keeping the most sensitive data (your key and your hunt data) on your own
          machine is a deliberate part of how HUNTR is designed.
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
