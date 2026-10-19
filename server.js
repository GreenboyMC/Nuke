
const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json({ limit: "8mb" }));

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.GROQ_API_KEY;
const MODEL = process.env.GROQ_MODEL || "openai/gpt-oss-20b";

const SYSTEM_PROMPT = `
Bạn là GREENBOY AI, một người bạn AI vui vẻ, thân thiện và nhiệt tình.
- Nói tiếng Việt tự nhiên, gần gũi, có thể dùng "bro", "men" khi phù hợp.
- Dùng emoji vừa phải, biết đùa đúng lúc.
- Khi người dùng buồn, hãy lắng nghe và đồng cảm.
- Hướng dẫn từng bước, giải thích dễ hiểu.
- Không phán xét, không bịa thông tin.
- Không khẳng định đã thực hiện hành động nếu chưa thực hiện.
`;

app.get("/", (_req, res) => {
  res.json({ ok: true, service: "GREENBOY AI API" });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.post("/api/chat", async (req, res) => {
  try {
    if (!API_KEY) {
      return res.status(503).json({
        error: "Backend chưa cấu hình GROQ_API_KEY."
      });
    }

    const message = typeof req.body?.message === "string"
      ? req.body.message.trim()
      : "";

    if (!message) {
      return res.status(400).json({
        error: "Bro nhập tin nhắn trước nhé 😄"
      });
    }

    if (message.length > 12000) {
      return res.status(413).json({
        error: "Tin nhắn quá dài."
      });
    }

    const response = await fetch(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: MODEL,
          messages: [
            { role: "system", content: SYSTEM_PROMPT },
            { role: "user", content: message }
          ],
          temperature: 0.8,
          max_tokens: 1200
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("Groq error:", response.status);
      return res.status(502).json({
        error: "AI đang gặp sự cố, bro thử lại sau nhé."
      });
    }

    const reply = data?.choices?.[0]?.message?.content;

    if (typeof reply !== "string" || !reply.trim()) {
      return res.status(502).json({
        error: "AI chưa trả lời được lần này."
      });
    }

    return res.json({
      reply: reply.trim(),
      model: data.model || MODEL
    });
  } catch (error) {
    console.error("Chat error:", error.message);
    return res.status(500).json({
      error: "Máy chủ gặp lỗi. Bro thử lại sau nhé."
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`GREENBOY AI API running on port ${PORT}`);
});
