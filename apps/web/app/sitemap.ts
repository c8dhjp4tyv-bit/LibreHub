export const dynamic = "force-dynamic";
import type { MetadataRoute } from "next";
import {
  getCatalog,
  type Page,
  type Card,
  type Category,
  webBase,
} from "../lib/catalog";
export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const [apps, categories] = await Promise.all([
    getCatalog<Page<Card>>(
      "/api/v1/catalog/apps?limit=100&sort=recently_updated",
    ),
    getCatalog<Category[]>("/api/v1/catalog/categories"),
  ]);
  return [
    { url: webBase },
    { url: `${webBase}/categories` },
    ...(apps?.items || []).map((a) => ({
      url: `${webBase}/apps/${encodeURIComponent(a.app_id)}`,
      lastModified: a.updated_at,
    })),
    ...(categories || []).map((c) => ({
      url: `${webBase}/categories/${c.id}`,
    })),
  ];
}
