import { NextRequest, NextResponse } from "next/server";
import { apiBase, publicApiBase, type App } from "./lib/catalog";
export async function proxy(request: NextRequest) {
  const images = new Set(["'self'", new URL(publicApiBase).origin]);
  const match = request.nextUrl.pathname.match(
    /^\/apps\/([A-Za-z0-9_.-]{1,255})$/,
  );
  if (match) {
    try {
      const channel =
        request.nextUrl.searchParams.get("channel") === "beta"
          ? "beta"
          : "stable";
      const response = await fetch(
        `${apiBase}/api/v1/catalog/apps/${encodeURIComponent(match[1])}?channel=${channel}`,
        { signal: AbortSignal.timeout(5000) },
      );
      if (response.ok) {
        const app = (await response.json()) as App;
        for (const shot of app.screenshots.slice(0, 8)) {
          const url = new URL(shot.url);
          if (url.protocol === "https:" && !url.username && !url.password)
            images.add(url.origin);
        }
      }
    } catch {
      /* Fail closed for external image origins while the normal page shows its error state. */
    }
  }
  const response = NextResponse.next();
  response.headers.set(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src ${[...images].join(" ")}; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`,
  );
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "no-referrer");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );
  return response;
}
export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
