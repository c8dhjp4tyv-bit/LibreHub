import type { Metadata } from "next";
import Link from "next/link";
import { ThemeToggle } from "../components/theme";
import { webBase } from "../lib/catalog";
import "./globals.css";
export const metadata: Metadata = {
  metadataBase: new URL(webBase),
  icons: { icon: "/mark.svg" },
  title: {
    default: "LibreHub — Open apps, clear origins",
    template: "%s · LibreHub",
  },
  description:
    "Discover Linux applications with transparent source provenance and standard signed Flatpak installation.",
};
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <a className="skip" href="#main">
          Skip to content
        </a>
        <header>
          <div className="nav-wrap">
            <Link href="/" className="brand" aria-label="LibreHub home">
              <span className="brand-mark" aria-hidden="true">
                L↗
              </span>
              LibreHub<span className="brand-tag">OPEN SOFTWARE</span>
            </Link>
            <nav aria-label="Main navigation">
              <Link href="/search">Explore</Link>
              <Link href="/categories">Categories</Link>
              <ThemeToggle />
            </nav>
          </div>
        </header>
        <main id="main">{children}</main>
        <footer>
          <Link href="/" className="brand">
            LibreHub
          </Link>
          <p>Open apps. Clear origins. Your Linux desktop.</p>
          <span>Built on Flatpak · Source comes first</span>
        </footer>
      </body>
    </html>
  );
}
