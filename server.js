import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const app = express();
app.use(express.json({ limit: '12mb' }));

const secret = process.env.AUTH_SECRET;
const DATA_DIR = process.env.DATA_DIR || '/data';
const USERS_FILE = path.join(DATA_DIR, 'greenboy-users.json');
const DAILY_LIMIT = 2000;
const RESPONSE_LIMIT = 200;
const WINDOW_MS = 24 * 60 * 60 * 1000;

let users = {};

async function loadUsers() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    users = JSON.parse(await fs.readFile(USERS_FILE, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    users = {};
  }
}

async function saveUsers() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  const tmp = USERS_FILE + '.tmp';
  await fs.writeFile(tmp, JSON.stringify(users, null, 2));
  await fs.rename(tmp, USERS_FILE);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, key) => {
      if (error) return reject(error);
      resolve({ salt, hash: key.toString('hex') });
    });
  });
}

async function passwordMatches(password, stored) {
  const result = await hashPassword(password, stored.salt);
  const a = Buffer.from(result.hash, 'hex');
  const b = Buffer.from(stored.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function createToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', secret)
    .update(body).digest('base64url');
  return `${body}.${signature}`;
}

function readToken(token) {
  try {
    const [body, signature] = token.split('.');
    const expected = crypto.createHmac('sha256', secret)
      .update(body).digest();
    const received = Buffer.from(signature, 'base64url');

    if (received.length !== expected.length ||
        !crypto.timingSafeEqual(received, expected)) return null;

    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    return payload.exp > Date.now() / 1000 ? payload : null;
  } catch {
    return null;
  }
}

function auth(req, res, next) {
  if (!secret) {
    return res.status(503).json({ error: 'Thiếu AUTH_SECRET.' });
  }

  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const payload = readToken(token);

  if (!payload) {
    return res.status(401).json({ error: 'Vui lòng đăng nhập lại.' });
  }

  req.username = payload.sub;
  next();
}

function getQuota(user) {
  const now = Date.now();
  if (!user.windowStart || now - user.windowStart >= WINDOW_MS) {
    user.windowStart = now;
    user.used = 0;
  }

  user.used = Math.max(0, Number(user.used) || 0);
  return {
    limit: DAILY_LIMIT,
    used: user.used,
    remaining: Math.max(0, DAILY_LIMIT - user.used),
    resetsAt: user.windowStart + WINDOW_MS
  };
}

app.get('/', (_req, res) => {
  res.json({ app: 'GREENBOY AI', status: 'online' });
});

app.post('/api/register', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    const key = username.toLowerCase();

    if (!/^[a-zA-Z0-9_.-]{3,24}$/.test(username)) {
      return res.status(400).json({ error: 'Tên tài khoản 3–24 ký tự.' });
    }
    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({ error: 'Mật khẩu cần 8–128 ký tự.' });
    }
    if (users[key]) {
      return res.status(409).json({ error: 'Tài khoản đã tồn tại.' });
    }

    const stored = await hashPassword(password);
    users[key] = {
      username,
      password: stored,
      createdAt: Date.now(),
      windowStart: Date.now(),
      used: 0
    };

    await saveUsers();
    const token = createToken({
      sub: key,
      exp: Math.floor(Date.now() / 1000) + 30 * 86400
    });

    res.status(201).json({
      token,
      username,
      quota: getQuota(users[key])
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Không thể tạo tài khoản.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    const key = username.toLowerCase();
    const user = users[key];

    if (!user || !await passwordMatches(password, user.password)) {
      return res.status(401).json({
        error: 'Sai tên tài khoản hoặc mật khẩu.'
      });
    }

    const token = createToken({
      sub: key,
      exp: Math.floor(Date.now() / 1000) + 30 * 86400
    });

    res.json({
      token,
      username: user.username,
      quota: getQuota(user)
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Không thể đăng nhập.' });
  }
});

app.get('/api/me', auth, async (req, res) => {
  const user = users[req.username];
  if (!user) {
    return res.status(401).json({ error: 'Không tìm thấy tài khoản.' });
  }

  const quota = getQuota(user);
  await saveUsers();
  res.json({ username: user.username, quota });
});

app.post('/api/chat', auth, async (req, res) => {
  try {
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'Thiếu GROQ_API_KEY.' });
    }

    const user = users[req.username];
    if (!user) {
      return res.status(401).json({ error: 'Tài khoản không tồn tại.' });
    }

    let quota = getQuota(user);
    if (quota.remaining <= 0) {
      await saveUsers();
      return res.status(429).json({
        error: 'Bạn đã hết 2.000 token trong 24 giờ.',
        quota
      });
    }

    const message = String(req.body?.message || '').trim();
    const image = req.body?.image;

    if (!message && !image) {
      return res.status(400).json({ error: 'Hãy nhập câu hỏi hoặc gửi ảnh.' });
    }

    const content = [];
    if (message) content.push({ type: 'text', text: message });

    if (image) {
      if (typeof image !== 'string' ||
          !/^data:image\/(png|jpeg|jpg|webp);base64,/i.test(image)) {
        return res.status(400).json({ error: 'Ảnh không hợp lệ.' });
      }
      if (image.length > 9000000) {
        return res.status(413).json({ error: 'Ảnh quá lớn.' });
      }
      content.push({
        type: 'image_url',
        image_url: { url: image }
      });
    }

    const model = image
      ? (process.env.GROQ_VISION_MODEL ||
         'meta-llama/llama-4-scout-17b-16e-instruct')
      : (process.env.GROQ_MODEL || 'openai/gpt-oss-20b');

    const response = await fetch(
      'https://api.groq.com/openai/v1/chat/completions',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model,
          messages: [
            {
              role: 'system',
              content: 'Bạn là GREENBOY AI 💚, thân thiện, hữu ích và trả lời tự nhiên.'
            },
            {
              role: 'user',
              content: image ? content : message
            }
          ],
          max_tokens: RESPONSE_LIMIT,
          temperature: 0.7
        })
      }
    );

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json({
        error: data?.error?.message || 'Lỗi Groq API.'
      });
    }

    const reply = data.choices?.[0]?.message?.content || '';
    const usedTokens = Number(data.usage?.total_tokens) ||
      Math.max(1, Math.ceil((message.length + reply.length) / 4));

    user.used = Math.min(DAILY_LIMIT, quota.used + usedTokens);
    quota = getQuota(user);
    await saveUsers();

    res.json({
      reply,
      model,
      quota,
      usage: { totalTokens: usedTokens }
    });
  } catch (error) {
    console.error('Chat error:', error);
    res.status(500).json({ error: 'Lỗi server khi chat AI.' });
  }
});

const port = process.env.PORT || 3000;
await loadUsers();

app.listen(port, '0.0.0.0', () => {
  console.log(`GREENBOY AI listening on ${port}`);
});
