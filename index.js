const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());

// ===================== إعدادات =====================
const PORT = 3000; // ثابت
const JWT_SECRET = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET";
const CODE_TTL_MS = 10 * 60 * 1000; // 10 دقائق
const ALLOWED_DOMAIN = "@qicard.iq";

// sessionId -> { email, code, expiresAt, attempts }
const sessions = new Map();

// تنظيف الجلسات المنتهية
setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions.entries()) {
    if (!s || s.expiresAt <= now) sessions.delete(sid);
  }
}, 60 * 1000);

// ===================== أدوات مساعدة =====================
function random6() {
  return String(Math.floor(100000 + Math.random() * 900000));
}
function makeSessionId() {
  return "sid_" + Math.random().toString(36).slice(2) + Date.now().toString(36);
}
function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

// ===================== Routes =====================
app.get("/health", (req, res) => {
  res.json({ ok: true, name: "QiCard Auth API", time: new Date().toISOString() });
});

app.post("/api/auth/send-code", (req, res) => {
  const email = normalizeEmail(req.body?.email);

  if (!email) return res.status(400).json({ success: false, message: "البريد مطلوب" });

  if (!email.endsWith(ALLOWED_DOMAIN)) {
    return res.status(403).json({
      success: false,
      message: `يسمح فقط ببريد الشركة (${ALLOWED_DOMAIN})`,
    });
  }

  const sessionId = makeSessionId();
  const code = random6();

  sessions.set(sessionId, {
    email,
    code,
    expiresAt: Date.now() + CODE_TTL_MS,
    attempts: 0,
  });

  console.log(`[QiCard] Code for ${email}: ${code} (sessionId: ${sessionId})`);

  res.json({ success: true, message: "تم إنشاء رمز التحقق", sessionId });
});

app.post("/api/auth/verify-code", (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const code = String(req.body?.code || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();

  if (!email || !code || !sessionId) {
    return res.status(400).json({ success: false, message: "بيانات ناقصة" });
  }

  const s = sessions.get(sessionId);
  if (!s) return res.status(401).json({ success: false, message: "جلسة غير صالحة أو منتهية" });

  if (Date.now() > s.expiresAt) {
    sessions.delete(sessionId);
    return res.status(401).json({ success: false, message: "انتهت صلاحية الرمز" });
  }

  if (s.email !== email) {
    return res.status(401).json({ success: false, message: "البريد لا يطابق الجلسة" });
  }

  s.attempts += 1;
  if (s.attempts > 6) {
    sessions.delete(sessionId);
    return res.status(429).json({ success: false, message: "محاولات كثيرة، أعد المحاولة لاحقًا" });
  }

  if (s.code !== code) {
    return res.status(401).json({ success: false, message: "رمز غير صحيح" });
  }

  sessions.delete(sessionId);

  const token = jwt.sign({ email, app: "qicard-kb" }, JWT_SECRET, { expiresIn: "12h" });
  res.json({ success: true, token });
});

// ✅ تشغيل على 0.0.0.0
app.listen(3000, "0.0.0.0", () => {
  console.log("QiCard Auth API running on 0.0.0.0:3000");
});

