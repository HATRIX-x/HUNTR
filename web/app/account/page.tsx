import type { Metadata } from "next";
import { AccountPanel } from "@/components/account-panel";

export const metadata: Metadata = {
  title: "Account",
  description: "Manage your HUNTR account and connect your local operator.",
  alternates: { canonical: "/account/" },
  robots: { index: false, follow: false },
};

export default function AccountPage() {
  return (
    <main className="site-wrap min-h-[calc(100vh-4rem)] py-16 sm:py-20">
      <div className="mx-auto w-full max-w-2xl">
        <AccountPanel />
      </div>
    </main>
  );
}
