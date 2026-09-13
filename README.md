# 🛠 Record Manager

A modern, high-security DNS administration portal for Cloudflare. Built for teams who need more control than the default dashboard offers, without the complexity of enterprise tools.

It’s fast, secure, and runs entirely on the Cloudflare edge using **Hono**, **D1**, and **JSX**.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/simonserghini/record-manager)

---

## Why use this?

Cloudflare's dashboard is great, but it’s often "all or nothing" when it comes to permissions. Record Manager lets you delegate DNS access with surgical precision. 

You can give an engineer access to **one single record** (like `dev.api.com`) without letting them touch the rest of your zone.

---

## ✨ What's inside?

*   **Modern Component UI**: Rewritten from scratch using **Hono JSX**. It’s clean, type-safe, and consistent.
*   **Zero-Config Security**: On first run, the app automatically generates a cryptographically strong system secret for session signing. No manual setup needed.
*   **Hardened by Default**: Comes pre-configured with **Secure Headers** (HSTS, CSP, XSS protection) and global **CSRF protection**.
*   **Granular RBAC & RLAC**: 
    *   **Zone-wide roles**: From `Read-Only` to `Full Admin`.
    *   **Record-level isolation**: Grant access to a specific record ID so a user sees *nothing* else in that domain.
*   **Real-time Feedback**: A built-in **Flash Message** system gives you instant confirmation for every DNS deployment or permission change.
*   **Safety Net**: A **Blacklist** feature lets you "lock" sensitive namespaces (like `*.internal.com`) — enforced on create, rename, *and* import.
*   **Audit Trails**: Every single click and deployment is logged. You’ll always know who changed what, and when.
*   **Record Change History**: Per-zone timeline of every create/update/delete with the full pre-image of each record — kept even after deletion.
*   **Import & Export**: Round-trip zones as **BIND zone files** or **CSV**. Paste a file to bulk-create up to 500 records, or download the current state for backup/migration.
*   **JSON API + Tokens**: Self-service API tokens (SHA-256-hashed, shown once, instantly revocable) that inherit your exact permissions — see the API section below.
*   **Session Control**: *Sign out everywhere* revokes all sessions on your account instantly via session epochs; zone ownership is transferable without database surgery.
*   **Dark Mode**: System-aware with a manual toggle, applied before first paint (no flash), zero inline styles.
*   **Ops-Friendly**: `/healthz` health endpoint plus a nightly cron that un-syncs domains whose Cloudflare zone has vanished.

---

## 🚀 Quick Start (Get it running in 2 mins)

1.  **Deploy**: Click that big blue **Deploy to Cloudflare** button at the top.
2.  **Database**: Once deployed, run the migrations to set up your D1 database:
    ```bash
    npx wrangler d1 migrations apply record-manager-db --remote
    ```
3.  **Setup**: Open your new Worker URL. The app will guide you through connecting your Cloudflare API Token and Google OAuth keys.
4.  **Ownership**: The very first person to log in via Google after setup becomes the **System Owner**. For production deployments, set the optional `OWNER_EMAIL` variable in `wrangler.jsonc` first — it restricts the owner claim to that exact address, so a stranger can't grab your instance by logging in first.

---

## 🛠 Local Development

If you want to tinker with the code:

1.  **Install**: `npm install`
2.  **Migrate local DB**: `npx wrangler d1 migrations apply record-manager-db --local`
3.  **Run**: `npm run dev`

---

## 🔒 A Note on Security

We take security seriously because this tool manages your infrastructure.
*   **Enforced Authorization**: Every mutating endpoint (records, users, clearances, blacklist, settings) verifies role *and* record-level permissions server-side — the UI hiding a button is never the only gate.
*   **Sessions**: All user sessions are cryptographically signed using a unique per-instance secret, re-validated against the database on every request (deleted accounts lose access immediately). Each account carries a session epoch — bumping it (sign out everywhere, ownership transfer) invalidates all previously issued cookies at once.
*   **Bootstrap Lockout**: The `/setup` wizard is only reachable anonymously while the system is unconfigured; afterwards it's owner-only, and stored secrets are never echoed back into the form.
*   **Blacklist Enforcement**: Protected namespace rules are checked on every record create and rename — not just displayed.
*   **Headers & CSRF**: Strict Content-Security-Policy (`script-src 'self'` — no inline scripts, no CDN), HSTS-class secure headers, and origin-checked CSRF protection on all cookie-session mutations (the token-authenticated JSON API is exempt by design).
*   **Rate Limiting**: Best-effort sliding windows brake OAuth sign-in starts (10/min/IP) and API traffic (120 reads / 30 writes per minute, per token owner); imports are capped at 10 per 5 minutes. Put WAF rules in front if you need hard global quotas.
*   **Secrets**: Cloudflare tokens and OAuth secrets live only in your D1 database and are write-only through the UI.
*   **Audit Trail**: Every permission change, record deployment, and blocked blacklist attempt is logged with actor and details.

## 🔌 JSON API

Every signed-in user can mint tokens at **/tokens**: label them, copy the secret once (only a SHA-256 hash is stored), revoke anytime. A token can do exactly what its owner can do — same permission ladder, same blacklist, same audit trail.

```bash
export T="Authorization: Bearer rm_..."

# Zones visible to this account (returns internal zone ids)
curl -H "$T" https://<your-worker>/api/v1/zones

# List / create records
curl -H "$T" https://<your-worker>/api/v1/zones/<zone-id>/records
curl -X POST -H "$T" -H "Content-Type: application/json" \
     -d '{"type":"A","name":"www","content":"203.0.113.7","ttl":300}' \
     https://<your-worker>/api/v1/zones/<zone-id>/records

# Update / delete
curl -X PUT -H "$T" -H "Content-Type: application/json" \
     -d '{"type":"A","name":"www","content":"203.0.113.8","ttl":60}' \
     https://<your-worker>/api/v1/zones/<zone-id>/records/<record-id>
curl -X DELETE -H "$T" \
     https://<your-worker>/api/v1/zones/<zone-id>/records/<record-id>
```

Record types: every type Cloudflare supports — `A`, `AAAA`, `CAA`, `CERT`, `CNAME`, `DNSKEY`, `DS`, `HTTPS`, `LOC`, `MX`, `NAPTR`, `NS`, `PTR`, `SMIMEA`, `SRV`, `SSHFP`, `SVCB`, `TLSA`, `TXT`, `URI`. Structured rdata rides in `content` (`SRV`: `priority weight port target`, `CAA`: `flags tag "value"`); `MX` takes an optional `priority` field. Proxying applies to `A`/`AAAA`/`CNAME` only and is forced off for everything else. `PUT` replaces the record but optional fields you omit (`ttl`, `proxied`, `priority`) keep their current values — an update can't accidentally unproxy a record or reset its TTL. Errors are structured JSON (`{"error": ...}`) with meaningful status codes: 400 validation · 401/403 auth · 404 · 429 rate-limited · 502 upstream.

---

### Development

```bash
npm run typecheck   # strict TypeScript check across the whole worker
npm run build:css   # compile Tailwind (src/styles.css → public/app.css)
npm test            # 41-test vitest suite running inside workerd against a
                    # real local D1 with a mocked Cloudflare API: forged-cookie
                    # session matrix, CSRF, epoch revocation, RBAC +
                    # record-level clearances, full API CRUD end-to-end,
                    # blacklist bypass attempts, zone-file parsing
```

---

*Made with ❤️ by developers, for developers.*

[serghini.me](https://serghini.me) 
