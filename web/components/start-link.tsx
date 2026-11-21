"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { getToken } from "@/lib/api";

// Pricing-page call to action. Signed out → sign up. Signed in → jump to the
// packs, since there is nothing to sign up for.
export function StartLink({ className = "" }: { className?: string }) {
  const [signedIn, setSignedIn] = useState(false);
  useEffect(() => setSignedIn(!!getToken()), []);
  return signedIn ? (
    <a href="#buy" className={className}>Buy credits</a>
  ) : (
    <Link href="/signup/" className={className}>Get started</Link>
  );
}
