# 🛠 Record Manager

A modern, high-security DNS administration portal for Cloudflare. Built for teams who need more control than the default dashboard offers, without the complexity of enterprise tools.

It’s fast, secure, and runs entirely on the Cloudflare edge using **Hono**, **D1**, and **JSX**.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/simon-msdos/record-manager)

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
*   **Safety Net**: A **Blacklist** feature lets you "lock" sensitive namespaces (like `*.internal.com`) so only the system owner can modify them.
*   **Audit Trails**: Every single click and deployment is logged. You’ll always know who changed what, and when.

---

## 🚀 Quick Start (Get it running in 2 mins)

1.  **Deploy**: Click that big blue **Deploy to Cloudflare** button at the top.
2.  **Database**: Once deployed, run the migrations to set up your D1 database:
    ```bash
    npx wrangler d1 migrations apply record-manager-db --remote
    ```
3.  **Setup**: Open your new Worker URL. The app will guide you through connecting your Cloudflare API Token and Google OAuth keys.
4.  **Ownership**: The very first person to log in via Google after setup automatically becomes the **System Owner**.

---

## 🛠 Local Development

If you want to tinker with the code:

1.  **Install**: `npm install`
2.  **Migrate local DB**: `npx wrangler d1 migrations apply record-manager-db --local`
3.  **Run**: `npm run dev`

---

## 🔒 A Note on Security

We take security seriously because this tool manages your infrastructure.
*   **Sessions**: All user sessions are cryptographically signed using a unique system secret.
*   **Secrets**: We never store your Cloudflare tokens in the source code; they live safely in your private D1 instance.
*   **Headers**: Every request is protected by industry-standard security headers.

---

*Made with ❤️ by developers, for developers.*

[serghini.me](https://serghini.me) 
