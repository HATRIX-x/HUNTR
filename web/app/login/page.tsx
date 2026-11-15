import type { Metadata } from "next";
import { AuthForm } from "@/components/auth-form";

export const metadata: Metadata = {
  title: "Sign in",
  description: "Sign in to your HUNTR account to manage your account and agents.",
  alternates: { canonical: "/login/" },
  robots: { index: false, follow: true },
};

export default function LoginPage() {
  return (
    <main className="site-wrap relative flex min-h-[calc(100vh-4rem)] items-center py-16 sm:py-24">
      <div
        className="pointer-events-none absolute left-1/2 top-1/2 h-[min(560px,100vw)] w-[min(560px,100vw)] -translate-x-1/2 -translate-y-1/2 rounded-full blur-3xl"
        style={{ background: "radial-gradient(circle at 40% 40%, rgba(139,92,246,0.22), transparent 60%), radial-gradient(circle at 65% 70%, rgba(74,222,128,0.10), transparent 60%)" }}
        aria-hidden
      />
      <div className="relative w-full"><AuthForm mode="login" /></div>
    </main>
  );
}
