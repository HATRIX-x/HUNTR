import type { MetadataRoute } from "next";
import { ARTICLES } from "@/components/research-data";

export default function sitemap(): MetadataRoute.Sitemap {
  const base = "https://huntr.run";
  const now = new Date();
  return [
    { url: `${base}/`, lastModified: now, changeFrequency: "weekly", priority: 1 },
    { url: `${base}/platform/`, lastModified: now, changeFrequency: "monthly", priority: 0.8 },
    { url: `${base}/benchmark/`, lastModified: now, changeFrequency: "monthly", priority: 0.8 },
    { url: `${base}/access/`, lastModified: now, changeFrequency: "monthly", priority: 0.9 },
    { url: `${base}/pricing/`, lastModified: now, changeFrequency: "monthly", priority: 0.9 },
    { url: `${base}/research/`, lastModified: now, changeFrequency: "weekly", priority: 0.7 },
    { url: `${base}/terms/`, lastModified: now, changeFrequency: "yearly", priority: 0.4 },
    { url: `${base}/privacy/`, lastModified: now, changeFrequency: "yearly", priority: 0.4 },
    { url: `${base}/acceptable-use/`, lastModified: now, changeFrequency: "yearly", priority: 0.4 },
    ...ARTICLES.map((a) => ({
      url: `${base}/research/${a.slug}/`,
      lastModified: new Date(a.modified),
      changeFrequency: "monthly" as const,
      priority: 0.6,
    })),
  ];
}
