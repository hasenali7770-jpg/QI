const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());

// ===================== إعدادات =====================
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_TO_A_LONG_RANDOM_SECRET";
const CODE_TTL_MS = 10 * 60 * 1000; // 10 دقائق

// ✅ يسمح فقط ببريد الشركة
const ALLOWED_DOMAIN = "@qi.iq";

// تخزين مؤقت: sessionId -> { email, code, expiresAt, attempts }
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

// فحص السيرفر
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    name: "QiCard Auth API",
    time: new Date().toISOString(),
  });
});

// إرسال رمز التحقق
app.post("/api/auth/send-code", (req, res) => {
  const email = normalizeEmail(req.body?.email);

  if (!email) {
    return res.status(400).json({ success: false, message: "البريد مطلوب" });
  }

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

  // يظهر في Render Logs
  console.log(`[QiCard] Verification code for ${email}: ${code}`);

  return res.json({
    success: true,
    sessionId,
  });
});

// التحقق من الرمز
app.post("/api/auth/verify-code", (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const code = String(req.body?.code || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();

  if (!email || !code || !sessionId) {
    return res.status(400).json({ success: false, message: "بيانات ناقصة" });
  }

  const s = sessions.get(sessionId);
  if (!s) {
    return res.status(401).json({ success: false, message: "الجلسة غير صالحة" });
  }

  if (Date.now() > s.expiresAt) {
    sessions.delete(sessionId);
    return res.status(401).json({ success: false, message: "انتهت صلاحية الرمز" });
  }

  s.attempts++;
  if (s.attempts > 6) {
    sessions.delete(sessionId);
    return res.status(429).json({ success: false, message: "محاولات كثيرة" });
  }

  if (s.email !== email || s.code !== code) {
    return res.status(401).json({ success: false, message: "رمز غير صحيح" });
  }

  sessions.delete(sessionId);

  const token = jwt.sign({ email, app: "qicard-kb" }, JWT_SECRET, {
    expiresIn: "12h",
  });

  return res.json({ success: true, token });
});

// ===================== تشغيل السيرفر =====================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`QiCard Auth API running on 0.0.0.0:${PORT}`);
});
