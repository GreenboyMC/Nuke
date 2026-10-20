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
    return res.status(403).json({
      error: "Nguồn website chưa được cho phép. Kiểm tra FRONTEND_ORIGIN."
    });
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
  const token = (req.headers.authorization || "")
    .replace(/^Bearer\s+/i, "");

  const payload = verifyToken(token);

  if (!payload) {
    return res.status(401).json({
      error: "Phiên đăng nhập không hợp lệ. Bro đăng nhập lại nhé."
    });
  }

  req.username = payload.sub;
  next();
}

app.get("/", (_req, res) => {
  res.json({ status: "đang hoạt động", app: "GREENBOY AI" });
});

app.post("/api/register", async (req, res) => {
  try {
    if (!secret) {
      return res.status(503).json({
        error: "Thiếu AUTH_SECRET trên Railway."
      });
    }

    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    const key = username.toLowerCase();

    if (!/^[a-zA-Z0-9_.-]{3,24}$/.test(username)) {
      return res.status(400).json({
        error: "Tên tài khoản cần 3–24 ký tự."
      });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: "Mật khẩu cần 8–128 ký tự."
      });
    }

    if (users.has(key)) {
      return res.status(409).json({
        error: "Tên tài khoản đã tồn tại."
      });
    }

    const passwordRecord = await hashPassword(password);
    users.set(key, { username, password: passwordRecord });

    return res.status(201).json({
      token: createToken(key),
      username
    });
  } catch (err) {
    console.error("Lỗi đăng ký:", err);
    return res.status(500).json({
      error: "Lỗi đăng ký tài khoản."
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    if (!secret) {
      return res.status(503).json({
        error: "Thiếu AUTH_SECRET trên Railway."
      });
    }

    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    const key = username.toLowerCase();
    const user = users.get(key);

    if (!user || !(await checkPassword(password, user.password))) {
      return res.status(401).json({
        error: "Sai tên đăng nhập hoặc mật khẩu."
      });
    }

    return res.json({
      token: createToken(key),
      username: user.username
    });
  } catch (err) {
    console.error("Lỗi đăng nhập:", err);
    return res.status(500).json({
      error: "Lỗi đăng nhập tài khoản."
    });
  }
});

app.get("/api/me", auth, (req, res) => {
  const user = users.get(req.username);

  if (!user) {
    return res.status(401).json({
      error: "Không tìm thấy tài khoản."
    });
  }

  res.json({ username: user.username });
});

const GREENBOY_SYSTEM_PROMPT = `
Bạn là GREENBOY AI 💚😎, trợ lý AI riêng của bro.

DANH TÍNH:
- Nếu được hỏi bạn là ai hoặc tên gì, trả lời:
  "Tui là GREENBOY AI đây bro 💚😎 Trợ lý riêng của bro nè!"
- Không tự nhận là ChatGPT, OpenAI, GPT hay trợ lý khác.
- Bạn là trợ lý AI mang tên GREENBOY AI, không giả vờ là người thật.

NGÔN NGỮ:
- Mặc định luôn trả lời bằng tiếng Việt, kể cả khi người dùng nhắn tiếng Anh.
- Chỉ đổi ngôn ngữ khi người dùng yêu cầu rõ ràng.

TÍNH CÁCH:
- Vui vẻ, thân thiện, hơi lầy vừa đủ.
- Gọi người dùng là bro khi tự nhiên.
- Dùng emoji vừa phải, không spam.
- Không lặp câu chào ở mọi câu trả lời.
- Không bịa thông tin; nếu không chắc thì nói rõ.
- Khi bro buồn, hãy lắng nghe và phản hồi chân thành.
`.trim();

app.post("/api/chat", auth, async (req, res) => {
  try {
    const apiKey = process.env.GROQ_API_KEY;

    if (!apiKey) {
      return res.status(503).json({
        error: "Thiếu GROQ_API_KEY trên Railway."
      });
    }

    const message = String(req.body?.message || "").trim();

    if (!message) {
      return res.status(400).json({
        error: "Bro nhập nội dung chat trước nhé 💚"
      });
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
          messages: [
            { role: "system", content: GREENBOY_SYSTEM_PROMPT },
            { role: "user", content: message }
          ],
          max_tokens: 200,
          temperature: 0.85
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("Lỗi dịch vụ AI:", data?.error?.message || response.status);
      return res.status(response.status).json({
        error: "GREENBOY AI đang gặp trục trặc. Bro thử lại sau nhé."
      });
    }

    res.json({
      reply: data.choices?.[0]?.message?.content ||
        "Bro ơi, tui chưa tạo được câu trả lời lần này 😅",
      model: data.model
    });
  } catch (err) {
    console.error("Lỗi chat:", err);
    res.status(500).json({
      error: "GREENBOY AI bị mất kết nối với máy chủ. Bro thử lại nhé 💚"
    });
  }
});

const port = process.env.PORT || 3000;

app.listen(port, "0.0.0.0", () => {
  console.log(`GREENBOY AI đang chạy tại cổng ${port}`);
});
