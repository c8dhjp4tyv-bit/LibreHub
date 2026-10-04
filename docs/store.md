# LibreHub web store

`apps/web` uses Next.js App Router, TypeScript and React, server-rendered with a
small client theme control. There is no production application fixture array.
Home/search/category/publisher/app pages fetch the versioned public catalog API.
No developer bearer token or secrets are needed in the web service.

| Page | Experience |
| --- | --- |
| `/` | Recently updated, new stable apps, categories and search |
| `/search?q=...` | Server search, category/architecture/channel/sort filters, pagination |
| `/categories` / `/categories/{category}` | Real stable category counts and app results |
| `/apps/{app_id}` | Stable detail, screenshots, source/commit/publisher/license, release history, actual per-architecture permissions and installation |
| `/apps/{app_id}?channel=beta` | Explicit independent beta preview |
| `/publishers/{developer_id}` | Simple stable app/project/source list |
| `/health` | Web process liveness (catalog readiness is API `/ready`) |
| `/robots.txt` / `/sitemap.xml` | Indexable app/category pages; bounded first 100 updated stable apps in sitemap |

Search uses a standard GET form with URL-preserved parameters; submitting a query
is the server search trigger (no debouncing background requests). Empty/loading/
error/404 states are explicit. Cards omit description/screenshots/permissions.
Pages use short server fetch revalidation; no analytics or tracking is embedded.

The design has cream/forest colors, source-first detail panels, light/dark/system
modes, mobile navigation, semantic headings, visible focus, labels, skip link,
alt text, standard links/forms and reduced-motion support. Installation is never
a hover-only action. Browser acceptance exercises the mobile navigation/search/
detail/download flow. Unit tests cover rendering, forms, release/permission fields,
empty/loading/error states, theme controls, escaping and commit URL construction.

## Local operation

Compose adds a web container with Linux host networking so it can reach the host
API on localhost without giving **any** container a Docker socket. Its HTTP bind
is localhost:3000, it drops capabilities, runs as node and has no credentials or
host data mounts. The API/indexer remain one host supervisor; this intentionally
preserves M1's Docker boundary. `docker compose up --build` provisions worker,
manager/repository and web; one host API process is still required after bootstrap.

Standalone development also works:

```bash
cd apps/web
npm ci
npm run dev
```

Production checks: npm ci, npm run lint, npm run typecheck, npm test, npm run build.
Production server: npm run start. No generated node_modules/.next files are committed.

Configuration (operator values, never Host-derived):

| Variable | Default | Purpose |
| --- | --- | --- |
| LIBREHUB_API_URL | http://127.0.0.1:8080 | Server-side API origin |
| LIBREHUB_API_PUBLIC_URL | http://localhost:8080 | Public install/icon origin; also typed API config |
| LIBREHUB_WEB_PUBLIC_URL | http://localhost:3000 | Canonical/OG/robots/sitemap origin |
| LIBREHUB_CATALOG_PAGE_SIZE | 24 | API default page size, 1–100 |

For production, place web/API/repository behind TLS, configure their real URLs and
provision durable signing separately. The development Compose host network is not
a portable cloud deployment recipe. Frontend security headers include CSP,
nosniff, no-referrer, frame-ancestors none/X-Frame-Options DENY and restrictive
permissions policy. CSP allows Next.js's escaped inline hydration and inline
styles; no developer HTML/script is executed. Remote image optimization/proxy is
disabled (`unoptimized`) and screenshot origins are selected from indexed DTOs.

## Install flow

Install downloads `/api/v1/catalog/apps/{app_id}/flatpakref?channel=stable` (or beta).
The reference includes the real repository URL, branch, embedded public GPG key,
runtime repository and suggested remote name. It never disables verification.
Open it with a compatible Linux desktop software manager or run:

```bash
flatpak install --user ./org.example.App.flatpakref
```

The page also renders remote-add and ordinary flatpak install commands from trusted
operator repository/API configuration and canonical app identity. Stable and beta
use separate remotes. No custom native client/installer/URI protocol is required.
