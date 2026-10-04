# LibreHub store

Next.js App Router + TypeScript + React, backed by `/api/v1/catalog`.

```bash
npm ci
npm run dev
# Checks: npm run lint; npm run typecheck; npm test; npm run build
```

Configure LIBREHUB_API_URL, LIBREHUB_API_PUBLIC_URL and LIBREHUB_WEB_PUBLIC_URL
before startup. No application fixture data is used in production. See
[store](../../docs/store.md) and [M4 verification](../../docs/m4-verification.md).
