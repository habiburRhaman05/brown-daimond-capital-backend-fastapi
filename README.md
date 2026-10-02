# BDCap Client Portal API (FastAPI)

Drop-in replacement for the Node backend: same `/api/*` routes, same JSON shapes, so the React app
and the static portal page work unchanged (except change requests, which are now Pending/Resolved).

- **Auth**: our own JWT. Access token (HS256, 1 h) + rotating opaque refresh token (30 d, stored hashed).
  Passwords are bcrypt. Email verification, password reset and invites are one-time links.
- **Data**: any Postgres, via SQLAlchemy 2 async + asyncpg. Schema is `db/001_schema.sql`.
- **Email**: each message is POSTed to a GoHighLevel workflow webhook (`GHL_WEBHOOK_URL`); GHL sends it.

## Run locally

```bash
pip install -e ".[dev]"
cp .env.example .env          # fill DATABASE_URL, JWT_SECRET, ADMIN_EMAIL / ADMIN_PASSWORD
python scripts/apply_schema.py --yes     # creates the tables (DROPS existing ones)
python -m uvicorn app.main:app --port 8000 --proxy-headers
```

The first admin is created at startup from `ADMIN_EMAIL` / `ADMIN_PASSWORD` when no admin exists.
`python scripts/create_admin.py you@example.com "password" "Your Name"` adds or resets one.

`GET /api/health` reports `db: up|down|unconfigured`. `/docs` is available outside production.

## Tests

`python -m pytest` runs end-to-end tests against the database in `.env` (emails are captured, not sent;
all test accounts use `@e2e.test.invalid` and are deleted afterwards).

## Production notes

- `ENV=production`, a `JWT_SECRET` of 32+ random characters, `FRONTEND_URL` (the app) and
  `PUBLIC_API_URL` (this API, used in emailed links) are required.
- Run with `--proxy-headers` so rate limits key on the real client IP.
- Host it in the same region as the database; every query is a network round trip.
- Supabase's direct `db.<ref>.supabase.co` host is IPv6-only. Use the pooler host (session mode, port 5432).
- Every table has row-level security on with no policies, so Supabase's public REST API exposes nothing.
