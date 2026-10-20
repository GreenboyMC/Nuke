
import express from "express";
import crypto from "node:crypto";

const app = express();
app.use(express.json({ limit: "12mb" }));

const secret = process.env.AUTH_SECRET;
const frontendOrigins = (process.env.FRONTEND_ORIGIN || "")
  .split(",")
  .map(s => s.trim().replace(/\/$/, ""))
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const normalized = (origin || "").replace(/\/$/, "");

  if (origin && frontendOrigins.length &&
      !frontendOrigins.includes(normalized)) {
    return res.status(403).json({ error: "CORS origin not allowed" });
  }

  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const users = new Map();

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) return reject(err);
      resolve({ salt, hash: key.toString("hex") });
    });
  });
}

async function checkPassword(password, record) {
  const result = await hashPassword(password, record.salt);
  const a = Buffer.from(result.hash, "hex");
  const b = Buffer.from(record.hash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function createToken(username) {
  const payload = Buffer.from(JSON.stringify({
    sub: username,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

function verifyToken(token) {
  try {
    if (!secret) return null;
    const [payload, signature] = token.split(".");
    if (!payload || !signature) return null;

    const expected = crypto.createHmac("sha256", secret)
      .update(payload).digest();
    const actual = Buffer.from(signature, "base64url");

    if (actual.length !== expected.length ||
        !crypto.timingSafeEqual(actual, expected)) return null;

    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    return data.exp > Date.now() ? data : null;
  } catch {
    return null;
  }
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.replace(/^Bearer\s+/i, "");
  const payload = verifyToken(token);

  if (!payload) {
    return res.status(401).json({ error: "Phiên đăng nhập không hợp lệ." });
  }

  req.username = payload.sub;
  next();
}

app.get("/", (_req, res) => {
  res.json({ status: "online", app: "GREENBOY AI" });
});

app.post("/api/register", async (req, res) => {
  try {
    if (!secret) {
      return res.status(503).json({ error: "Thiếu AUTH_SECRET trên Railway." });
    }

    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    const key = username.toLowerCase();

    if (!/^[a-zA-Z0-9_.-]{3,24}$/.test(username)) {
      return res.status(400).json({ error: "Tên tài khoản cần 3–24 ký tự." });
    }
    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({ error: "Mật khẩu cần 8–128 ký tự." });
    }
    if (users.has(key)) {
      return res.status(409).json({ error: "Tên tài khoản đã tồn tại." });
    }

    const passwordRecord = await hashPassword(password);
    users.set(key, { username, password: passwordRecord });

    return res.status(201).json({
      token: createToken(key),
      username
    });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ error: "Lỗi đăng ký tài khoản." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    if (!secret) {
      return res.status(503).json({ error: "Thiếu AUTH_SECRET trên Railway." });
    }

    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    const key = username.toLowerCase();
    const user = users.get(key);

    if (!user || !(await checkPassword(password, user.password))) {
      return res.status(401).json({ error: "Sai tên đăng nhập hoặc mật khẩu." });
    }

    return res.json({
      token: createToken(key),
      username: user.username
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Lỗi đăng nhập tài khoản." });
  }
});

app.get("/api/me", auth, (req, res) => {
  const user = users.get(req.username);
  if (!user) return res.status(401).json({ error: "Không tìm thấy tài khoản." });
  res.json({ username: user.username });
});

app.post("/api/chat", auth, async (req, res) => {
  try {
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey) {
      return res.status(503).json({ error: "Thiếu GROQ_API_KEY." });
    }

    const message = String(req.body?.message || "").trim();
    if (!message) {
      return res.status(400).json({ error: "Hãy nhập nội dung chat." });
    }

    const response = await fetch(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: process.env.GROQ_MODEL || "openai/gpt-oss-20b",
          messages: [{ role: "user", content: message }],
          max_tokens: 200
        })
      }
    );

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json({
        error: data?.error?.message || "Groq API request failed."
      });
    }

    res.json({
      reply: data.choices?.[0]?.message?.content || "",
      model: data.model
    });
  } catch (err) {
    console.error("Chat error:", err);
    res.status(500).json({ error: "Lỗi backend chat." });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, "0.0.0.0", () => {
  console.log(`GREENBOY AI backend listening on ${port}`);
});
                         
