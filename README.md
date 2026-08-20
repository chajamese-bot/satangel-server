# SAT Angel — backend server

A real Express + Postgres backend: hashed passwords, secure sessions, a
server-side paywall, persisted practice history that follows you across
devices, server-side AI explanations, and Stripe payments.

## Why Postgres, not SQLite

An earlier version of this server used local SQLite. That broke on Render's
free tier: free instances don't keep their local disk between restarts, so
every time the server spun down from inactivity and woke back up, the
database file — and every account in it — was wiped. That's why accounts
seemed to vanish and logging back in failed. Postgres lives on its own
separate, persistent host, so it survives restarts and lets the same
account log in from any device.

## What's real vs. what still needs setup

**Real and working once configured:**
- Signup/login with bcrypt-hashed passwords, one account per email
- httpOnly session cookies — same account works from any device, since the
  data actually persists now
- Practice attempts and target score saved per-account, durable across
  restarts and redeploys
- `/api/explain` calls Anthropic's API from the server using your own key
- `/api/checkout` creates real Stripe Checkout Sessions; the webhook
  verifies Stripe's signature before trusting any payment event
- The `/dashboard.html` page and its data endpoints are gated server-side —
  only `monthly` or `lifetime` plans get in; free/logged-out visitors are
  redirected, not just visually blocked

**Still needs you to configure:**
- Every feature above needs its matching environment variable (see
  `.env.example`) — most importantly `DATABASE_URL` now, since nothing
  works without a real database connection.
- Full Mock Test still isn't built.

**Not done for you, and matters before real users touch this:**
- Rate limiting exists on login/signup and AI requests, but consider
  tightening further before a public launch.
- Password reset flow — not built yet.
- If you ever outgrow a single free Postgres tier's connection limits,
  that's a scaling problem to solve later, not now.

## Getting a free Postgres database

**Option A — Neon (neon.tech):**
1. Sign up free, create a project
2. Copy the connection string it gives you (starts with `postgresql://`)
3. Paste it as `DATABASE_URL`

**Option B — Supabase (supabase.com):**
1. Sign up free, create a project
2. Go to Project Settings → Database → Connection string (use the "URI" /
   pooled connection format)
3. Paste it as `DATABASE_URL`

Either works fine for a project at this stage. The server creates its own
tables automatically on first run — you don't need to set up any schema
by hand.

## Local setup

```bash
cd satangel-server
npm install
cp .env.example .env
# edit .env — DATABASE_URL is required; AI/Stripe keys can stay blank
# to test accounts + progress tracking first
npm start
```

Visit `http://localhost:3000` — this serves the whole site and the API
from one server.

## Deploying it somewhere real (Render)

1. Push this folder to a GitHub repo (`.gitignore` already keeps `.env`
   out of it)
2. Create a new **Web Service** on [render.com](https://render.com),
   connect the repo
3. Build command: `npm install` — Start command: `npm start`
4. Add every variable from `.env.example` under **Environment**, including
   your real `DATABASE_URL`
5. Once deployed, update `CLIENT_URL` to your real Render URL
   (e.g. `https://sat-angel.onrender.com`)
6. In Stripe, point your webhook endpoint at
   `https://your-domain/api/webhooks/stripe` and copy the signing secret
   into `STRIPE_WEBHOOK_SECRET`
7. Turn on the **Customer Portal** so paying customers can cancel or
   manage their own subscription without needing to contact you: in
   Stripe, go to **Settings → Billing → Customer portal**, and activate
   it (the defaults are fine to start with). Without this step, the
   "Manage subscription" link on the dashboard will show an error.

Render's free tier still spins down after inactivity — but since your data
now lives in Postgres instead of on Render's disk, that's fine: the server
just restarts and reconnects, nothing is lost.

## Connecting your custom domain

Once deployed, follow your host's custom domain instructions (Render has a
straightforward one under Settings → Custom Domain) and point your domain's
DNS at it.
