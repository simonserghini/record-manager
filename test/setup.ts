import { applyD1Migrations, env } from 'cloudflare:test'

// Runs before every test file inside the worker runtime.
//
// Bring the local D1 up to the latest schema, then pin every credential the
// app needs to known values: isConfigured() gates all non-auth routes, and
// SYSTEM_SECRET signs session cookies — test/helpers.ts forges cookies with
// the same value, so it must match exactly. Upsert (not insert-if-missing)
// keeps reruns deterministic even if state ever persists across runs.
await applyD1Migrations(env.record_manager_db, (env as any).TEST_MIGRATIONS)

export const TEST_SYSTEM_SECRET = 'test-system-secret'

await env.record_manager_db.batch([
  env.record_manager_db.prepare(
    "INSERT INTO settings (key, value) VALUES ('SYSTEM_SECRET', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
  ).bind(TEST_SYSTEM_SECRET),
  env.record_manager_db.prepare(
    "INSERT INTO settings (key, value) VALUES ('CF_API_TOKEN','cf-test-token'),('GOOGLE_CLIENT_ID','test-client-id'),('GOOGLE_CLIENT_SECRET','test-client-secret') ON CONFLICT(key) DO NOTHING"
  )
])
