# nbb on Cloudflare Workers

A port of the NestJS API in the repo root to a single Cloudflare Worker (Hono + Neon serverless driver).
Same routes, same JSON shapes, same Neon Postgres database and Prisma-managed schema (no migration needed).

- Entry: `src/index.ts`
- Runtime secrets (Cloudflare dashboard, Settings > Variables and Secrets):
  `DATABASE_URL`, `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
  `GOOGLE_CALLBACK_URL`, optional `FRONT_GOOGLE_CALLBACK_URL`, optional `OSS_ID`, `OSS_NAME`, `OSS_KEY`, `OSS_REGION`.
- Deploy: root directory `worker`, build command `npm install`, deploy command `npx wrangler deploy`.
- Local: put the same variables in `worker/.dev.vars`, then `npm run dev`.

Differences from the Nest app: write endpoints (POST/PATCH/DELETE) all require a login token; Swagger UI is replaced by a plain `/api` ping.
