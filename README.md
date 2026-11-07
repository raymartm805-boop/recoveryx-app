# RecoveryX Records Manager

A self-hosted, full-stack record-management application with a responsive dashboard, authentication, admin/staff roles, SQLite database, account records, recovery-request workflow, payment ledger, audit logs and CSV exports.

> **Scope and safety:** This app manages records stored in its own database only. Its “active/frozen” values are internal labels. It cannot access, freeze, unfreeze, recover or release funds or accounts on banks, e-wallets, social networks or other third-party services. The payment ledger is not a payment gateway; entries are unverified until independently checked.

## Requirements

- Node.js 20 or newer
- npm

## Run locally

```bash
cp .env.example .env
```

Edit `.env` and set a long, random `SESSION_SECRET` (at least 32 characters). Then:

```bash
npm install
npm start
```

Open `http://localhost:3000`. On first launch, create the administrator account in the first-run setup screen. Choose a unique password with at least 12 characters.

### Optional: create the first admin from environment

Set `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env` before the first launch. The password must be at least 12 characters. The app creates the first admin only when the users table is empty.

## Features

- Secure session login/logout with HTTP-only, SameSite cookies
- Password hashing with bcrypt
- First-run admin setup
- Admin and staff roles; user administration is admin-only
- Account records and internal status updates
- Recovery-request workflow
- Payment ledger with unverified-by-default entries
- Audit trail for changes and authentication events
- CSV export for accounts, requests, payments and activity
- SQLite persistence in `data/recoveryx.sqlite`
- Rate-limited login/setup, Helmet security headers, origin checks and session CSRF token

## Roles

- **Admin:** all workspace features, manage team access, delete account/payment entries and update payment ledger status.
- **Staff:** create and update account records, create/review requests, add payment ledger entries, and view activity. Staff cannot manage team access or verify/change payment status.

## Database

SQLite tables are created automatically on startup:

- `users`
- `accounts`
- `requests`
- `payments`
- `activity`

The database and session store are created under `data/`. Back up the SQLite database while the app is stopped, or use SQLite's online backup mechanism. Do not commit `.env`, database files, session files, or real customer data to GitHub.

## Deploy

1. Push this folder to a private GitHub repository.
2. Deploy to a Node.js host that supports persistent disk storage.
3. Set `NODE_ENV=production`, `SESSION_SECRET`, `PORT` (if required), and optionally the initial admin credentials.
4. Mount a persistent disk and set `DB_FILE` to a path on that disk. The `data/` directory must be writable.
5. Use HTTPS. The session cookie is marked `Secure` in production.
6. Create the first admin, then remove `ADMIN_PASSWORD` from the host environment if it was used.
7. Test login, roles, CRUD, CSV exports and backups before adding real customer records.

**Important:** Do not use ephemeral serverless filesystem hosting for this SQLite configuration. Use a Node host with persistent storage, or migrate the database and session store to managed PostgreSQL/Redis before using a horizontally scaled deployment.

## API overview

All write requests require the `x-csrf-token` header obtained from `GET /api/csrf`. Authentication uses the session cookie.

- `GET /api/setup-status`, `POST /api/setup`
- `POST /api/login`, `POST /api/logout`, `GET /api/me`
- `GET /api/dashboard`
- `GET/POST /api/accounts`, `PATCH/DELETE /api/accounts/:id`
- `GET/POST /api/requests`, `PATCH /api/requests/:id`
- `GET/POST /api/payments`, `PATCH/DELETE /api/payments/:id`
- `GET/POST /api/users`, `PATCH /api/users/:id` (admin)
- `GET /api/activity`
- `GET /api/export/:kind`
- `GET /api/health`

## Notes before production use

This is a functional starter project, not a security audit or compliance certification. Put it behind HTTPS, keep dependencies updated, use strong unique passwords, restrict host access, establish backups and retention policies, and have the deployment reviewed before storing sensitive personal data. Avoid storing third-party passwords, full payment-card data, identity documents or unnecessary personal information.
