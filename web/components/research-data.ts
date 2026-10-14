export type Article = {
  slug: string;
  kicker: string;
  title: string;
  dek: string;
  readMins: number;
  updated: string; // human-readable, e.g. "October 2026"
  published: string; // ISO date for schema
  modified: string; // ISO date for schema
};

/** Source of truth for the /research hub — consumed by the index page,
 *  each article's JSON-LD, and the sitemap. */
export const ARTICLES: Article[] = [
  {
    slug: "automated-penetration-testing",
    kicker: "Primer",
    title: "Automated Penetration Testing: What It Actually Is (and What It Isn't)",
    dek: "Scanners, DAST, and autonomous operators all get called \"automated pentesting.\" They are not the same thing. Here's the honest taxonomy — and where the line between a scan and a hunt really falls.",
    readMins: 8,
    updated: "October 2026",
    published: "2026-10-14",
    modified: "2026-10-14",
  },
  {
    slug: "vulnerability-scanner-vs-validated-findings",
    kicker: "Signal vs noise",
    title: "Vulnerability Scanner vs. Validated Findings: Why Noise Costs More Than Missed Bugs",
    dek: "A scanner that flags 400 \"issues\" hasn't done your job — it's handed you a second one. The real metric isn't how much a tool finds, it's how much of what it hands you is true.",
    readMins: 7,
    updated: "October 2026",
    published: "2026-10-14",
    modified: "2026-10-14",
  },
  {
    slug: "ai-pentesting-tools",
    kicker: "Field guide",
    title: "AI Pentesting Tools in 2026: How Autonomous Operators Actually Work",
    dek: "LLM-driven security tools went from demos to a category in about eighteen months. This is what separates an autonomous operator from a scanner with a chat box bolted on.",
    readMins: 9,
    updated: "October 2026",
    published: "2026-10-14",
    modified: "2026-10-14",
  },
];

export const bySlug = (slug: string) => ARTICLES.find((a) => a.slug === slug);
