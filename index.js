// ===== إعدادات السيرفر =====
const API_BASE = "https://qi-0odh.onrender.com";

// عناصر الصفحة
const emailInput = document.getElementById("emailInput");
const codeInput = document.getElementById("codeInput");
const sendCodeBtn = document.getElementById("sendCodeBtn");
const verifyBtn = document.getElementById("verifyBtn");
const codeBox = document.getElementById("codeBox");
const msg = document.getElementById("msg");

function setMsg(text, type) {
  msg.textContent = text || "";
  msg.className = "msg";
  if (type) msg.classList.add(type);
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

sendCodeBtn.addEventListener("click", async () => {
  const email = normalizeEmail(emailInput.value);

  if (!email) return setMsg("أدخل البريد الإلكتروني.", "error");

  sendCodeBtn.disabled = true;
  setMsg("جاري إرسال رمز التحقق...", "");

  try {
    const res = await fetch(`${API_BASE}/api/auth/send-code`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok || !data.success) {
      setMsg(data.message || "فشل إرسال الرمز.", "error");
      return;
    }

    codeBox.classList.remove("hidden");
    setMsg("تم إرسال رمز التحقق ✅", "success");
    codeInput.focus();

    if (data.sessionId) localStorage.setItem("qicard_session_id", data.sessionId);
  } catch {
    setMsg("تعذر الاتصال بالسيرفر.", "error");
  } finally {
    sendCodeBtn.disabled = false;
  }
});

verifyBtn.addEventListener("click", async () => {
  const email = normalizeEmail(emailInput.value);
  const code = String(codeInput.value || "").trim();
  const sessionId = localStorage.getItem("qicard_session_id");

  if (!email) return setMsg("أدخل البريد الإلكتروني.", "error");
  if (code.length !== 6) return setMsg("رمز التحقق يجب أن يكون 6 أرقام.", "error");

  verifyBtn.disabled = true;
  setMsg("جاري التحقق...", "");

  try {
    const res = await fetch(`${API_BASE}/api/auth/verify-code`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, code, sessionId }),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok || !data.success) {
      setMsg(data.message || "رمز غير صحيح.", "error");
      return;
    }

    localStorage.setItem("qicard_kb_logged_in", "1");
    if (data.token) localStorage.setItem("qicard_token", data.token);

    setMsg("تم تسجيل الدخول بنجاح ✅", "success");
    setTimeout(() => (window.location.href = "dashboard.html"), 600);
  } catch {
    setMsg("تعذر الاتصال بالسيرفر.", "error");
  } finally {
    verifyBtn.disabled = false;
  }
});
