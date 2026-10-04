export const dynamic = "force-dynamic";
import type { MetadataRoute } from "next";
import { webBase } from "../lib/catalog";
export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: "*", allow: "/", disallow: ["/api/", "/search"] },
    sitemap: `${webBase}/sitemap.xml`,
  };
}
