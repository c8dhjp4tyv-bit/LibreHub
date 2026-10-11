import type { Metadata } from "next";
import Link from "next/link";
import { logout } from "./actions";
import { token } from "../../lib/developer";

export const metadata: Metadata = {
  title: "Developer dashboard",
  robots: { index: false, follow: false },
};
export const dynamic = "force-dynamic";

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const signedIn = (await token()) !== null;
  return (
    <div className="dashboard">
      {signedIn ? (
        <nav aria-label="Developer navigation" className="subnav">
          <Link href="/dashboard/projects">Projects</Link>
          <Link href="/dashboard/approvals">Approvals</Link>
          <form action={logout}>
            <button className="link-button">Sign out</button>
          </form>
        </nav>
      ) : null}
      {children}
    </div>
  );
}
