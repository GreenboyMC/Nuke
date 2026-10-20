
import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const app = express();
app.use(express.json({ limit: '12mb' }));

const PORT = process.env.PORT || 3000;
const DATA_DIR = '/data';
const DATA_FILE = path.join(DATA_DIR, 'greenboy-users.json');
const DAILY_LIMIT = 2000;
const MAX_OUTPUT = 200;

app.use((req, res, next) => {
  const origins = (process.env.FRONTEND_ORIGIN || '')
    .split(',').map(x => x.trim()).filter(Boolean);
  const origin = req.headers.origin;

  if (origin && origins.length && !origins.includes(origin)) {
    return res.status(403).json({ error: 'Origin không hợp lệ.' });
  }
  if (origin && (!origins.length || origins.includes(origin))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

function init() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ users: {} }), { mode: 0o600 });
  }
}
function load() {
  init();
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}
function save(db) {
  init();
  const temp = DATA_FILE + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(db), { mode: 0o600 });
  fs.renameSync(temp, DATA_FILE);
}
function hash(password, salt = crypto.randomBytes(16).toString('hex')) {
  return {
    salt,
    hash: crypto.scryptSync(password, salt, 64).toString('hex')
  };
}
function matches(password, saved) {
  const candidate = crypto.scryptSync(password, saved.salt, 64);
  const expected = Buffer.from(saved.hash, 'hex');
  return candidate.length === expected.length &&
    crypto.timingSafeEqual(candidate, expected);
}
function makeToken(username) {
  const secret = process.env.AUTH_SECRET;
  if (!secret || secret.length < 32) throw Error('Cần AUTH_SECRET dài ít nhất 32 ký tự.');
  const body = Buffer.from(JSON.stringify({
    username,
    exp: Date.now() + 7 * 86400000
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return body + '.' + sig;
}
function auth(req, res, next) {
  try {
    const [body, sig] = (req.headers.authorization || '')
      .replace(/^Bearer\s+/i, '').split('.');
    if (!body || !sig) return res.status(401).json({ error: 'Vui lòng đăng nhập.' });

    const secret = process.env.AUTH_SECRET || '';
    const expected = crypto.createHmac('sha256', secret).update(body).digest();
    const actual = Buffer.from(sig, 'base64url');
    if (secret.length < 32 || actual.length !== expected.length ||
        !crypto.timingSafeEqual(actual, expected)) {
      return res.status(401).json({ error: 'Phiên đăng nhập không hợp lệ.' });
    }

    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp < Date.now()) return res.status(401).json({ error: 'Phiên đã hết hạn.' });

    const db = load();
    const key = payload.username.toLowerCase();
    if (!db.users[key]) return res.status(401).json({ error: 'Không tìm thấy tài khoản.' });

    req.db = db;
    req.key = key;
    req.user = db.users[key];
    next();
  } catch (e) {
    res.status(500).json({ error: 'Lỗi xác thực hoặc dữ liệu Volume.' });
  }
}
function resetUsage(user) {
  if (!user.usage || Date.now() >= user.usage.resetAt) {
    user.usage = { used: 0, resetAt: Date.now() + 86400000 };
  }
  return user.usage;
}

app.get('/', (_req, res) => res.json({
  app: 'GREENBOY AI',
  status: 'online',
  dailyLimit: DAILY_LIMIT,
  maxOutputTokens: MAX_OUTPUT
}));
app.get('/api/health', (_req, res) => res.json({ status: 'online' }));

app.post('/api/register', (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    if (!/^[a-zA-Z0-9_.-]{3,24}$/.test(username)) {
      return res.status(400).json({ error: 'Tên tài khoản cần 3–24 ký tự.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Mật khẩu cần ít nhất 8 ký tự.' });
    }
    const db = load();
    const key = username.toLowerCase();
    if (db.users[key]) return res.status(409).json({ error: 'Tài khoản đã tồn tại.' });
    db.users[key] = {
      username, ...hash(password),
      usage: { used: 0, resetAt: Date.now() + 86400000 }
    };
    save(db);
    res.json({ token: makeToken(key), username });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    const db = load();
    const key = username.toLowerCase();
    const user = db.users[key];
    if (!user || !matches(password, user)) {
      return res.status(401).json({ error: 'Sai tài khoản hoặc mật khẩu.' });
    }
    resetUsage(user);
    save(db);
    res.json({ token: makeToken(key), username: user.username });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/me', auth, (req, res) => {
  const usage = resetUsage(req.user);
  save(req.db);
  res.json({
    username: req.user.username,
    usedTokens: usage.used,
    remainingTokens: Math.max(0, DAILY_LIMIT - usage.used),
    resetAt: usage.resetAt,
    dailyLimit: DAILY_LIMIT,
    maxOutputTokens: MAX_OUTPUT
  });
});

app.post('/api/chat', auth, async (req, res) => {
  try {
    if (!process.env.GROQ_API_KEY) {
      return res.status(503).json({ error: 'Thiếu GROQ_API_KEY trong Railway Variables.' });
    }
    const message = String(req.body?.message || '').trim();
    if (!message) return res.status(400).json({ error: 'Hãy nhập câu hỏi.' });

    const usage = resetUsage(req.user);
    const estimatedInput = Math.ceil(message.length / 4);
    if (usage.used + estimatedInput >= DAILY_LIMIT) {
      save(req.db);
      return res.status(429).json({
        error: 'Đã hết hạn mức 2.000 token/24 giờ.',
        remainingTokens: Math.max(0, DAILY_LIMIT - usage.used),
        resetAt: usage.resetAt
      });
    }

    const upstream = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: process.env.GROQ_MODEL || 'openai/gpt-oss-20b',
        messages: [
          { role: 'system', content: 'Bạn là GREENBOY AI, trợ lý hữu ích, thân thiện.' },
          { role: 'user', content: message }
        ],
        max_tokens: MAX_OUTPUT
      })
    });

    const data = await upstream.json();
    if (!upstream.ok) {
      return res.status(upstream.status).json({
        error: data?.error?.message || 'Groq API lỗi.'
      });
    }

    const reply = data.choices?.[0]?.message?.content || '';
    usage.used += Number(data.usage?.prompt_tokens || estimatedInput);
    usage.used += Number(data.usage?.completion_tokens || Math.ceil(reply.length / 4));
    save(req.db);

    res.json({
      reply,
      usedTokens: usage.used,
      remainingTokens: Math.max(0, DAILY_LIMIT - usage.used),
      resetAt: usage.resetAt,
      dailyLimit: DAILY_LIMIT,
      maxOutputTokens: MAX_OUTPUT
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Lỗi xử lý chat. Kiểm tra Railway logs.' });
  }
});

app.use((req, res) => res.status(404).json({
  error: `Không tìm thấy API: ${req.method} ${req.path}`
}));

try {
  init();
  app.listen(PORT, '0.0.0.0', () => console.log('GREENBOY AI API listening on', PORT));
} catch (e) {
  console.error(e);
  process.exit(1);
           }
