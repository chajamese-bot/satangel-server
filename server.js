// SAT Angel backend — Express + SQLite
//
// What's real here:
//   - Passwords are hashed with bcrypt, never stored in plain text
//   - Sessions use httpOnly signed JWT cookies (not readable/forgeable from browser JS)
//   - Progress and target score persist in a real SQLite database on disk
//   - AI explanations call Anthropic's API from the SERVER, using a key that
//     never reaches the browser
//   - Stripe payments use real Checkout Sessions + a signature-verified webhook
//
// What this still is NOT, on its own:
//   - Production-hardened. Before real users touch this: put it behind HTTPS,
//     set NODE_ENV=production, use a managed Postgres instead of a single
//     SQLite file once you have real concurrent traffic, and add rate limiting
//     to /api/signup and /api/login.
//   - Multi-server ready. SQLite is a single file — fine for one server
//     instance, not for horizontal scaling.

require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const Stripe = require('stripe');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-insecure-secret-change-me';
const IS_PROD = process.env.NODE_ENV === 'production';

if (JWT_SECRET === 'dev-only-insecure-secret-change-me') {
  console.warn('⚠️  Using the default JWT_SECRET. Set a real one in .env before deploying.');
}

const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

// -----------------------------------------------------------
// Database
// -----------------------------------------------------------
const db = new Database(path.join(__dirname, 'data.sqlite'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    target_score INTEGER,
    plan TEXT DEFAULT 'free',
    has_democourse INTEGER DEFAULT 0,
    stripe_customer_id TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    question_id TEXT NOT NULL,
    section TEXT NOT NULL,
    topic TEXT NOT NULL,
    correct INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// -----------------------------------------------------------
// Stripe webhook — must read the RAW body, so this is registered
// BEFORE the global express.json() middleware below.
// -----------------------------------------------------------
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
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
    const priceId = session.line_items?.data?.[0]?.price?.id; // requires expand, see /api/checkout
    if (userId) {
      if (session.mode === 'subscription') {
        db.prepare('UPDATE users SET plan = ?, stripe_customer_id = ? WHERE id = ?').run('monthly', session.customer, userId);
      } else if (session.mode === 'payment') {
        // Distinguish lifetime vs demo course by the amount charged, since a
        // one-time Checkout Session doesn't always carry the price id here
        // unless you expand line_items — this is a simple heuristic; swap in
        // your real price IDs / metadata for production.
        if (session.amount_total >= 9000) {
          db.prepare('UPDATE users SET plan = ?, stripe_customer_id = ? WHERE id = ?').run('lifetime', session.customer, userId);
        } else {
          db.prepare('UPDATE users SET has_democourse = 1, stripe_customer_id = ? WHERE id = ?').run(session.customer, userId);
        }
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
app.use(express.static(path.join(__dirname, 'public')));

// -----------------------------------------------------------
// Auth helpers
// -----------------------------------------------------------
function signSession(userId) {
  return jwt.sign({ uid: userId }, JWT_SECRET, { expiresIn: '30d' });
}

function requireAuth(req, res, next) {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id, name, email, target_score, plan, has_democourse FROM users WHERE id = ?').get(payload.uid);
    if (!user) return res.status(401).json({ error: 'Account no longer exists' });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Session expired or invalid' });
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

// -----------------------------------------------------------
// Auth routes
// -----------------------------------------------------------
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password are required.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const normalizedEmail = String(email).trim().toLowerCase();
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(normalizedEmail);
  if (existing) return res.status(409).json({ error: 'An account with that email already exists.' });

  const id = crypto.randomUUID();
  const passwordHash = await bcrypt.hash(password, 12);
  db.prepare(`INSERT INTO users (id, name, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)`)
    .run(id, name.trim(), normalizedEmail, passwordHash, new Date().toISOString());

  setSessionCookie(res, id);
  res.status(201).json({ id, name: name.trim(), email: normalizedEmail, plan: 'free', has_democourse: 0, target_score: null });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  const normalizedEmail = String(email).trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail);
  if (!user) return res.status(401).json({ error: 'Email or password is incorrect.' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Email or password is incorrect.' });

  setSessionCookie(res, user.id);
  res.json({ id: user.id, name: user.name, email: user.email, plan: user.plan, has_democourse: !!user.has_democourse, target_score: user.target_score });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ ...req.user, has_democourse: !!req.user.has_democourse });
});

// -----------------------------------------------------------
// Progress: target score
// -----------------------------------------------------------
app.post('/api/target', requireAuth, (req, res) => {
  const { value } = req.body || {};
  const target = value ? parseInt(value, 10) : null;
  db.prepare('UPDATE users SET target_score = ? WHERE id = ?').run(target, req.user.id);
  res.json({ target_score: target });
});

// -----------------------------------------------------------
// Progress: practice attempts
// -----------------------------------------------------------
app.get('/api/attempts', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT question_id as id, section, topic, correct, ts FROM attempts WHERE user_id = ? ORDER BY ts ASC').all(req.user.id);
  res.json(rows.map(r => ({ ...r, correct: !!r.correct })));
});

app.post('/api/attempts', requireAuth, (req, res) => {
  const { id, section, topic, correct, ts } = req.body || {};
  if (!id || !section || !topic || typeof correct !== 'boolean') {
    return res.status(400).json({ error: 'id, section, topic, and correct (boolean) are required.' });
  }
  db.prepare('INSERT INTO attempts (user_id, question_id, section, topic, correct, ts) VALUES (?, ?, ?, ?, ?, ?)')
    .run(req.user.id, id, section, topic, correct ? 1 : 0, ts || Date.now());
  res.status(201).json({ ok: true });
});

// -----------------------------------------------------------
// AI explanations — real server-side call, key never touches the browser
// -----------------------------------------------------------
app.post('/api/explain', requireAuth, async (req, res) => {
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
    lifetime: process.env.STRIPE_PRICE_LIFETIME,
    democourse: process.env.STRIPE_PRICE_DEMOCOURSE
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

app.listen(PORT, () => {
  console.log(`SAT Angel server running on http://localhost:${PORT}`);
});
