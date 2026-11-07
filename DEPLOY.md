# Docker deployment quick start

1. Install Docker Engine and Docker Compose on a server.
2. Copy `.env.example` to `.env` and set a unique `SESSION_SECRET` with at least 32 characters.
3. Optionally set `ADMIN_EMAIL` and `ADMIN_PASSWORD` (12+ characters) for first launch. Otherwise create the admin through the first-run setup screen.
4. Run `docker compose up -d --build`.
5. Put the service behind an HTTPS reverse proxy before exposing it publicly.
6. Visit `http://SERVER-IP:3000` for initial setup (preferably through HTTPS once proxy is configured).

The named Docker volume `recoveryx_data` persists SQLite and session data across container restarts. Back it up regularly. Do not use this sample compose file as a substitute for TLS, firewalling, monitoring, or production security review.
