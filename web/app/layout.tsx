import "./globals.css";
import type { Metadata } from "next";
import { Bricolage_Grotesque, Inter } from "next/font/google";
import { Nav } from "@/components/nav";
import { Footer } from "@/components/footer";
import { Motion } from "@/components/motion";

const display = Bricolage_Grotesque({ subsets: ["latin"], variable: "--font-display", display: "swap" });
const body = Inter({ subsets: ["latin"], variable: "--font-body", display: "swap" });

export const metadata: Metadata = {
  metadataBase: new URL("https://huntr.run"),
  title: {
    default: "HUNTR — Autonomous AI Bug Bounty Operator",
    template: "%s — HUNTR",
  },
  description:
    "An autonomous AI operator for bug bounty: maps the attack surface, tests it, validates findings, drafts the report. You review and submit — not scanner noise.",
  keywords: [
    "bug bounty automation",
    "AI bug bounty",
    "autonomous security agent",
    "automated penetration testing",
    "vulnerability hunting",
    "report-ready findings",
    "agentic security testing",
  ],
  authors: [{ name: "HUNTR" }],
  alternates: { canonical: "/" },
  openGraph: {
    type: "website",
    siteName: "HUNTR",
    url: "https://huntr.run/",
    title: "HUNTR — Autonomous AI Bug Bounty Operator",
    description:
      "Anyone can run a scanner. HUNTR runs the hunt — maps the surface, tests it, validates what's real, and drafts the report. You review and submit; it never submits for you.",
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "HUNTR" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "HUNTR — Autonomous AI Bug Bounty Operator",
    description: "Anyone can run a scanner. HUNTR runs the hunt. Validated, report-ready vulnerabilities — not scanner noise.",
    images: ["/og.png"],
  },
  robots: { index: true, follow: true },
};

export const viewport = { themeColor: "#0A0B0D" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${display.variable} ${body.variable}`} style={{ background: "#0A0B0D", colorScheme: "dark" }}>
      <head>
        {/* paint dark on the very first frame, before external CSS — kills the white FOUC flash */}
        <style dangerouslySetInnerHTML={{ __html: "html{background:#0A0B0D}body{background:#0A0B0D;color:#ECEEF2;margin:0}" }} />
        <noscript>
          <style>{`[data-reveal]{opacity:1!important;transform:none!important;clip-path:none!important}`}</style>
        </noscript>
        {/* Cloudflare Web Analytics (cookieless) */}
        <script
          type="module"
          src="https://static.cloudflareinsights.com/beacon.min.js"
          data-cf-beacon='{"token": "4184f15001294b0bb008fb1a29108d24"}'
        />
        {/* Microsoft Clarity — heatmaps + session replays */}
        <script
          dangerouslySetInnerHTML={{
            __html:
              '(function(c,l,a,r,i,t,y){c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);})(window,document,"clarity","script","yy6i7wft44");',
          }}
        />
      </head>
      <body className="grain" style={{ background: "#0A0B0D" }}>
        <div className="aurora" aria-hidden="true">
          <b className="a1" />
          <b className="a2" />
          <b className="a3" />
        </div>
        <Motion />
        <Nav />
        {children}
        <Footer />
      </body>
    </html>
  );
}
