import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  const base = "https://huntr.run";
  const now = new Date();
  return [
    { url: `${base}/`, lastModified: now, changeFrequency: "weekly", priority: 1 },
    { url: `${base}/platform/`, lastModified: now, changeFrequency: "monthly", priority: 0.8 },
    { url: `${base}/benchmark/`, lastModified: now, changeFrequency: "monthly", priority: 0.8 },
    { url: `${base}/access/`, lastModified: now, changeFrequency: "monthly", priority: 0.9 },
  ];
}
