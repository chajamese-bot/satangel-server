// SAT Angel backend — Express + Postgres
//
// IMPORTANT: this uses Postgres, not local SQLite. Render's free tier does
// NOT keep your server's local disk between restarts — every time the free
// instance spins down from inactivity and wakes back up, anything written
// to a local file (like a SQLite database) is wiped. That was the cause of
// accounts "disappearing" and being unable to log back in. Postgres lives
// on its own separate, persistent host, so it survives restarts and lets
// the same account log in from any device.
//
// You need a real Postgres database URL for this to work — see README.md
// for how to get a free one (Neon or Supabase both work) and set it as
// DATABASE_URL in your environment.
//
// What's real here:
//   - Passwords are hashed with bcrypt, never stored in plain text
//   - Sessions use httpOnly signed JWT cookies (not readable/forgeable from browser JS)
//   - Progress and target score persist in a real, durable Postgres database
//   - AI explanations call Anthropic's API from the SERVER, using a key that
//     never reaches the browser
//   - Stripe payments use real Checkout Sessions + a signature-verified webhook
//   - Login/signup and AI requests are rate-limited per IP
//   - The dashboard page and its data endpoints are gated server-side to
//     paid (monthly or lifetime) accounts only
//
// What this still is NOT, on its own:
//   - Production-hardened beyond the above. Put it behind HTTPS (Render does
//     this automatically) and keep NODE_ENV=production set.

require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const Stripe = require('stripe');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-insecure-secret-change-me';
const IS_PROD = process.env.NODE_ENV === 'production';

if (JWT_SECRET === 'dev-only-insecure-secret-change-me') {
  console.warn('⚠️  Using the default JWT_SECRET. Set a real one in .env before deploying.');
}
if (!process.env.DATABASE_URL) {
  console.warn('⚠️  DATABASE_URL is not set. Accounts will not work until this is configured — see README.md.');
}

const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

// -----------------------------------------------------------
// Database (Postgres — persistent, unlike local disk on Render's free tier)
// -----------------------------------------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
    ? false
    : { rejectUnauthorized: false } // required by most hosted Postgres free tiers (Neon, Supabase)
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      target_score INTEGER,
      plan TEXT DEFAULT 'free',
      stripe_customer_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS attempts (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      question_id TEXT NOT NULL,
      section TEXT NOT NULL,
      topic TEXT NOT NULL,
      correct BOOLEAN NOT NULL,
      ts BIGINT NOT NULL
    );
  `);
  console.log('Database ready.');
}

// -----------------------------------------------------------
// Stripe webhook — must read the RAW body, so this is registered
// BEFORE the global express.json() middleware below.
// -----------------------------------------------------------
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(501).send('Stripe not configured on this server.');
  }
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.client_reference_id;
    if (userId) {
      const plan = session.mode === 'subscription' ? 'monthly' : 'lifetime';
      try {
        await pool.query('UPDATE users SET plan = $1, stripe_customer_id = $2 WHERE id = $3', [plan, session.customer, userId]);
      } catch (err) {
        console.error('Failed to update plan after checkout:', err);
      }
    }
  }

  res.json({ received: true });
});

// -----------------------------------------------------------
// Global middleware (after the raw webhook route above)
// -----------------------------------------------------------
app.use(express.json());
app.use(cookieParser());

// -----------------------------------------------------------
// Auth helpers
// -----------------------------------------------------------
function signSession(userId) {
  return jwt.sign({ uid: userId }, JWT_SECRET, { expiresIn: '30d' });
}

async function requireAuth(req, res, next) {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT id, name, email, target_score, plan, stripe_customer_id FROM users WHERE id = $1', [payload.uid]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Account no longer exists' });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Session expired or invalid' });
  }
}

function isPaidPlan(plan) {
  return plan === 'monthly' || plan === 'lifetime';
}

// API-level gate: used on practice endpoints. Runs AFTER requireAuth (needs
// req.user already set). Returns JSON, since these are called by fetch().
function requirePaid(req, res, next) {
  if (!isPaidPlan(req.user.plan)) {
    return res.status(402).json({ error: 'This requires an active Monthly or Lifetime plan.', upgrade: true });
  }
  next();
}

// Page-level gate: protects the dashboard HTML file itself, so free/logged-out
// visitors never receive the file at all — not just a hidden UI.
async function requirePaidPage(req, res, next) {
  const token = req.cookies.session;
  if (!token) return res.redirect('/login.html?next=/dashboard.html');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT plan FROM users WHERE id = $1', [payload.uid]);
    const user = result.rows[0];
    if (!user) return res.redirect('/login.html?next=/dashboard.html');
    if (!isPaidPlan(user.plan)) return res.redirect('/index.html#pricing');
    next();
  } catch (e) {
    return res.redirect('/login.html?next=/dashboard.html');
  }
}

function setSessionCookie(res, userId) {
  res.cookie('session', signSession(userId), {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD, // requires HTTPS in production
    maxAge: 30 * 24 * 60 * 60 * 1000
  });
}

// Protect the dashboard page — registered BEFORE express.static, or static
// serving would hand out the file directly without checking payment status.
app.get('/dashboard.html', requirePaidPage, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

// -----------------------------------------------------------
// Rate limiting
// -----------------------------------------------------------
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please wait a few minutes and try again.' }
});

const aiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'AI explanation limit reached for now — try again later.' }
});

// -----------------------------------------------------------
// Auth routes
// -----------------------------------------------------------
app.post('/api/signup', authLimiter, async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password are required.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const normalizedEmail = String(email).trim().toLowerCase();

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existing.rows[0]) return res.status(409).json({ error: 'An account with that email already exists — try logging in instead.' });

    const id = crypto.randomUUID();
    const passwordHash = await bcrypt.hash(password, 12);
    await pool.query(
      'INSERT INTO users (id, name, email, password_hash) VALUES ($1, $2, $3, $4)',
      [id, name.trim(), normalizedEmail, passwordHash]
    );

    setSessionCookie(res, id);
    res.status(201).json({ id, name: name.trim(), email: normalizedEmail, plan: 'free', target_score: null });
  } catch (err) {
    if (err.code === '23505') { // Postgres unique constraint violation (race condition on email)
      return res.status(409).json({ error: 'An account with that email already exists — try logging in instead.' });
    }
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Could not create account — try again.' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  const normalizedEmail = String(email).trim().toLowerCase();
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Email or password is incorrect.' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Email or password is incorrect.' });

    setSessionCookie(res, user.id);
    res.json({ id: user.id, name: user.name, email: user.email, plan: user.plan, target_score: user.target_score });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Could not log in — try again.' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json(req.user);
});

// -----------------------------------------------------------
// Progress: target score
// -----------------------------------------------------------
app.post('/api/target', requireAuth, requirePaid, async (req, res) => {
  const { value } = req.body || {};
  const target = value ? parseInt(value, 10) : null;
  await pool.query('UPDATE users SET target_score = $1 WHERE id = $2', [target, req.user.id]);
  res.json({ target_score: target });
});

// -----------------------------------------------------------
// Progress: practice attempts
// -----------------------------------------------------------
app.get('/api/attempts', requireAuth, requirePaid, async (req, res) => {
  const result = await pool.query(
    'SELECT question_id as id, section, topic, correct, ts FROM attempts WHERE user_id = $1 ORDER BY ts ASC',
    [req.user.id]
  );
  res.json(result.rows);
});

app.post('/api/attempts', requireAuth, requirePaid, async (req, res) => {
  const { id, section, topic, correct, ts } = req.body || {};
  if (!id || !section || !topic || typeof correct !== 'boolean') {
    return res.status(400).json({ error: 'id, section, topic, and correct (boolean) are required.' });
  }
  await pool.query(
    'INSERT INTO attempts (user_id, question_id, section, topic, correct, ts) VALUES ($1, $2, $3, $4, $5, $6)',
    [req.user.id, id, section, topic, correct, ts || Date.now()]
  );
  res.status(201).json({ ok: true });
});

// -----------------------------------------------------------
// AI explanations — real server-side call, key never touches the browser
// -----------------------------------------------------------
app.post('/api/explain', requireAuth, requirePaid, aiLimiter, async (req, res) => {
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(501).json({ error: 'AI explanations are not configured on this server yet (missing ANTHROPIC_API_KEY).' });
  }
  const { question, answerRecord } = req.body || {};
  if (!question || !answerRecord) return res.status(400).json({ error: 'question and answerRecord are required.' });

  const letters = ['A', 'B', 'C', 'D'];
  const prompt = `You are a patient, encouraging SAT tutor. A student answered this practice question:

Question (${question.section} — ${question.topic}): ${question.text}
Choices: ${question.choices.map((c, i) => `${letters[i]}) ${c}`).join(' | ')}
Correct answer: ${letters[question.correct]}
Student selected: ${letters[answerRecord.selectedIndex]} (${answerRecord.correct ? 'correct' : 'incorrect'})

Give a short (3-4 sentence), plain-language explanation of why the correct answer is right, phrased differently than a textbook would. If the student got it wrong, briefly note what might lead someone to their answer choice and why it's a trap. Keep it encouraging and concise.`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 300,
        messages: [{ role: 'user', content: prompt }]
      })
    });
    const data = await response.json();
    if (!response.ok) {
      console.error('Anthropic API error:', data);
      return res.status(502).json({ error: 'The explanation service returned an error.' });
    }
    const text = (data.content || []).map(b => b.text || '').join('\n').trim();
    res.json({ explanation: text || "Couldn't generate an explanation just now — try again." });
  } catch (err) {
    console.error(err);
    res.status(502).json({ error: 'Could not reach the explanation service.' });
  }
});

// -----------------------------------------------------------
// Stripe checkout session creation
// -----------------------------------------------------------
app.post('/api/checkout', requireAuth, async (req, res) => {
  if (!stripe) return res.status(501).json({ error: 'Stripe is not configured on this server.' });
  const { plan } = req.body || {};
  const priceMap = {
    monthly: process.env.STRIPE_PRICE_MONTHLY,
    lifetime: process.env.STRIPE_PRICE_LIFETIME
  };
  const priceId = priceMap[plan];
  if (!priceId) return res.status(400).json({ error: 'Unknown plan.' });

  try {
    const session = await stripe.checkout.sessions.create({
      mode: plan === 'monthly' ? 'subscription' : 'payment',
      line_items: [{ price: priceId, quantity: 1 }],
      client_reference_id: req.user.id,
      customer_email: req.user.email,
      success_url: `${process.env.CLIENT_URL}/thank-you.html`,
      cancel_url: `${process.env.CLIENT_URL}/index.html`
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    res.status(502).json({ error: 'Could not start checkout.' });
  }
});

// -----------------------------------------------------------
// Stripe Customer Portal — lets a customer manage or cancel their own
// subscription without needing to email anyone. Requires "Customer portal"
// to be turned on in the Stripe Dashboard (Settings → Billing → Customer
// portal) — see README.md.
// -----------------------------------------------------------
app.post('/api/portal', requireAuth, async (req, res) => {
  if (!stripe) return res.status(501).json({ error: 'Stripe is not configured on this server.' });
  if (!req.user.stripe_customer_id) {
    return res.status(400).json({ error: 'No billing account found yet — this is available once you have an active plan.' });
  }
  try {
    const session = await stripe.billingPortal.sessions.create({
      customer: req.user.stripe_customer_id,
      return_url: `${process.env.CLIENT_URL}/dashboard.html`
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Portal session error:', err);
    res.status(502).json({ error: 'Could not open the billing portal. Make sure Customer Portal is enabled in your Stripe settings.' });
  }
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`SAT Angel server running on http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
