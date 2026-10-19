import express from "express";

const app = express();
app.use(express.json({ limit: "1mb" }));

// Health check: open the Railway domain to verify the backend is online.
app.get("/", (_req, res) => {
  res.json({ app: "GREENBOY AI", status: "online" });
});

// Optional CORS allowlist. Set FRONTEND_ORIGIN in Railway Variables to the
// exact origin of your deployed frontend (for example, https://example.com).
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowed = process.env.FRONTEND_ORIGIN;

  if (!allowed || origin === allowed) {
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
    }
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    if (req.method === "OPTIONS") return res.sendStatus(204);
    return next();
  }

  return res.status(403).json({ error: "Origin not allowed" });
});

app.post("/api/chat", async (req, res) => {
  try {
    const apiKey = process.env.GROQ_API_KEY;
    const message = req.body?.message;

    if (!apiKey) {
      return res.status(500).json({ error: "GROQ_API_KEY is not configured" });
    }
    if (typeof message !== "string" || !message.trim()) {
      return res.status(400).json({ error: "Message is required" });
    }

    const upstream = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: process.env.GROQ_MODEL || "openai/gpt-oss-20b",
        messages: [
          {
            role: "system",
            content: "Bạn là GREENBOY AI. Hãy trả lời hữu ích, rõ ràng bằng ngôn ngữ người dùng."
          },
          { role: "user", content: message.trim() }
        ],
        temperature: 0.7,
        max_completion_tokens: 1024
      })
    });

    const data = await upstream.json();
    if (!upstream.ok) {
      console.error("Groq API error:", upstream.status, data?.error?.message || "Unknown error");
      return res.status(upstream.status).json({
        error: data?.error?.message || "Groq API request failed"
      });
    }

    return res.json({ reply: data.choices?.[0]?.message?.content || "" });
  } catch (error) {
    console.error("Backend error:", error?.message || error);
    return res.status(500).json({ error: "Backend request failed" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, "0.0.0.0", () => {
  console.log(`GREENBOY AI API listening on ${port}`);
});
