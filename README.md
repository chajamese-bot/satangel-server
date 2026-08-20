# SAT Angel — backend server

A real Express + SQLite backend: hashed passwords, secure sessions, persisted
practice history, server-side AI explanations, and Stripe payments.

## What's real vs. what's still a placeholder

**Real and working once deployed:**
- Signup/login with bcrypt-hashed passwords (never stored in plain text)
- httpOnly session cookies (not readable or forgeable from browser JS)
- Practice attempts and target score saved per-account in SQLite, so progress
  follows you across devices once you log in on each one
- `/api/explain` calls Anthropic's API from the server using your own key —
  the key never reaches the browser
- `/api/checkout` creates real Stripe Checkout Sessions; the webhook verifies
  Stripe's signature before trusting any payment event

**Still needs you to configure before it does anything:**
- Every feature above needs its matching environment variable set in `.env`
  (see `.env.example`) — without `ANTHROPIC_API_KEY`, `/api/explain` returns
  a clear "not configured" error instead of failing silently. Same for Stripe.
- Full Mock Test still isn't built — that's a frontend/content gap, not a
  backend one.

**Not done for you, and matters before real users touch this:**
- HTTPS. Session cookies are only marked `secure` when `NODE_ENV=production`,
  which requires HTTPS to actually work in a real browser. Most hosts below
  give you HTTPS automatically.
- Rate limiting on `/api/signup` and `/api/login` (add `express-rate-limit`
  before launch, or a bad actor can hammer the login endpoint).
- Password reset flow — not built. Anyone who forgets their password is
  currently stuck; this needs an email-sending step (e.g. via Resend or
  SendGrid) to be worth building properly.
- SQLite is a single file on one server's disk. Fine for getting started;
  once you have real concurrent traffic, migrate to a managed Postgres
  (Supabase, Neon, Render Postgres) — the query patterns here would port over
  with modest changes.

## Local setup

```bash
cd satangel-server
npm install
cp .env.example .env
# edit .env with your real values (or leave AI/Stripe keys blank to test
# accounts + progress tracking without them)
npm start
```

Visit `http://localhost:3000` — this serves the whole site (landing page,
login, dashboard) AND the API from one server.

## Deploying it somewhere real

This is a standard Node.js app, so any of these work. **Render** is the
simplest match for what's built here (persistent disk for the SQLite file,
free tier available):

1. Push this folder to a GitHub repo (the `.gitignore` already keeps `.env`
   and the database file out of it)
2. Create a new **Web Service** on [render.com](https://render.com), connect
   the repo
3. Build command: `npm install` — Start command: `npm start`
4. Add every variable from `.env.example` under **Environment** in Render's
   dashboard (never commit real secrets to the repo)
5. Once deployed, update `CLIENT_URL` in your environment variables to your
   real Render URL (e.g. `https://sat-angel.onrender.com`)
6. In Stripe, point your webhook endpoint at
   `https://your-domain/api/webhooks/stripe` and copy the signing secret into
   `STRIPE_WEBHOOK_SECRET`

Other good fits: **Railway**, **Fly.io**, or a small **DigitalOcean/Linode**
droplet if you want more control. Avoid pure serverless platforms (Vercel
serverless functions, plain AWS Lambda) unless you first swap SQLite for a
hosted database — serverless functions don't have a persistent disk to keep
a SQLite file on.

## Connecting your custom domain

Once deployed, follow your host's custom domain instructions (Render has a
straightforward one under Settings → Custom Domain) and point your domain's
DNS at it. This replaces the earlier plan of hosting the static files
directly on Netlify — now that there's a real server, the server itself
should be what you deploy and point your domain at.
