import type { Profile } from "@/lib/api";

export type Opt = { value: string; label: string; hint?: string };
export type Q = {
  key: keyof Profile;
  title: string;
  subtitle: string;
  short: string; // compact label for the settings view
  multi?: boolean;
  options: Opt[];
};

export const QUESTIONS: Q[] = [
  {
    key: "role",
    title: "What best describes you?",
    subtitle: "So HUNTR can speak your language.",
    short: "Role",
    options: [
      { value: "hunter", label: "Bug bounty hunter", hint: "Full- or part-time on programs" },
      { value: "pentester", label: "Penetration tester", hint: "Client engagements, VAPT" },
      { value: "researcher", label: "Security researcher", hint: "CVEs, novel classes" },
      { value: "appsec", label: "AppSec / blue team", hint: "Securing your own org" },
      { value: "learning", label: "Learning the ropes", hint: "New to offensive security" },
    ],
  },
  {
    key: "experience",
    title: "How long have you been at it?",
    subtitle: "This tunes how much HUNTR explains as it works.",
    short: "Experience",
    options: [
      { value: "new", label: "Just starting" },
      { value: "mid", label: "1–3 years" },
      { value: "senior", label: "3–7 years" },
      { value: "pro", label: "7+ years / full-time" },
    ],
  },
  {
    key: "platforms",
    title: "Where do you hunt?",
    subtitle: "Pick all that apply.",
    short: "Platforms",
    multi: true,
    options: [
      { value: "hackerone", label: "HackerOne" },
      { value: "bugcrowd", label: "Bugcrowd" },
      { value: "intigriti", label: "Intigriti" },
      { value: "private", label: "Private programs" },
      { value: "own-assets", label: "My own assets" },
    ],
  },
  {
    key: "goal",
    title: "What should HUNTR do for you?",
    subtitle: "We'll lead with what matters most to you.",
    short: "Primary goal",
    options: [
      { value: "more-bounties", label: "Find more bounties", hint: "Maximize valid, paid findings" },
      { value: "save-time", label: "Save time", hint: "Automate recon & triage" },
      { value: "coverage", label: "Broader coverage", hint: "More classes, fewer blind spots" },
      { value: "learning", label: "Learn by watching", hint: "See how a pro operator thinks" },
    ],
  },
  {
    key: "referral",
    title: "How did you hear about HUNTR?",
    subtitle: "Last one — promise.",
    short: "Found us via",
    options: [
      { value: "x", label: "X / Twitter" },
      { value: "friend", label: "A friend or colleague" },
      { value: "search", label: "Search engine" },
      { value: "youtube", label: "YouTube" },
      { value: "discord", label: "Discord / community" },
      { value: "other", label: "Somewhere else" },
    ],
  },
];

// value → human label, for rendering a saved profile
export function labelFor(key: keyof Profile, value: string): string {
  const q = QUESTIONS.find((x) => x.key === key);
  return q?.options.find((o) => o.value === value)?.label ?? value;
}
