const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const { JSONFilePreset } = require('lowdb/node');

const app = express();
const PORT = process.env.PORT || 3000;

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '1571513134085312532';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || '';
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || `http://localhost:${PORT}/auth/discord/callback`;

let db;

async function initDb() {
  db = await JSONFilePreset('db.json', { users: {}, pastes: {} });
  console.log('[DB] Database connected');
}

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 }
}));

function requireAuth(req, res, next) {
  if (req.session.user) return next();
  return res.status(401).json({ error: 'unauthorized' });
}

app.post('/api/signup', async (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password) return res.status(400).json({ error: 'All fields required' });
  if (db.data.users[username]) return res.status(400).json({ error: 'Username taken' });
  db.data.users[username] = { email, password };
  await db.write();
  req.session.user = username;
  res.json({ ok: true });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.data.users[username];
  if (!user || user.password !== password) return res.status(401).json({ error: 'Invalid credentials' });
  req.session.user = username;
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ username: req.session.user }));
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/auth/discord', (req, res) => {
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify email'
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
});

app.get('/auth/discord/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect('/?error=no_code');
  try {
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: DISCORD_REDIRECT_URI
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return res.redirect('/?error=oauth_failed');

    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const dUser = await userRes.json();
    
    const username = `discord:${dUser.id}`;
    db.data.users[username] = {
      email: dUser.email || 'N/A',
      password: 'N/A',
      discordTag: dUser.username
    };
    await db.write();
    
    req.session.user = username;
    res.redirect('/');
  } catch (err) {
    res.redirect('/?error=oauth_failed');
  }
});

app.post('/api/paste', requireAuth, async (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'Title and content required' });
  const id = Math.random().toString(36).substring(2, 8);
  db.data.pastes[id] = { id, title, content, author: req.session.user, date: new Date().toISOString() };
  await db.write();
  res.json({ ok: true, id });
});

app.get('/api/paste/:id', (req, res) => {
  const paste = db.data.pastes[req.params.id];
  if (!paste) return res.status(404).json({ error: 'Not found' });
  res.json(paste);
});

app.get('/api/pastes/recent', (req, res) => {
  const pastes = Object.values(db.data.pastes).sort((a, b) => new Date(b.date) - new Date(a.date)).slice(0, 50);
  res.json(pastes);
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/create', (req, res) => res.sendFile(path.join(__dirname, 'public', 'create.html')));
app.get('/view/:id', (req, res) => res.sendFile(path.join(__dirname, 'public', 'view.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));

initDb().then(() => {
  app.listen(PORT, '0.0.0.0', () => console.log(`[READY] http://localhost:${PORT}`));
});