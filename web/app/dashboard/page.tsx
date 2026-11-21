import type { Metadata } from "next";
import { HuntDashboard } from "@/components/hunt-dashboard";

export const metadata: Metadata = {
  title: "Dashboard",
  description: "Launch and watch your HUNTR hunts.",
  alternates: { canonical: "/dashboard/" },
  robots: { index: false, follow: false },
};

export default function DashboardPage() {
  return (
    <main className="site-wrap py-10 sm:py-16">
      <HuntDashboard />
    </main>
  );
}
