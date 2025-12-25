/* ===============================
   exam_result.js ✅ FULL (Updated)
   - Search by: Name + ID + Section
   - Popup if not found (uses your existing noResultPopup)
=============================== */

import { db } from "./firebase.js";
import {
  collection, getDocs, doc, getDoc
} from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

/* ===============================
   Elements
================================ */
const empNameEl = document.getElementById("empName");
const empIdEl = document.getElementById("empId");

/* NEW ✅: Section selector */
const empSectionEl = document.getElementById("empSection");

const btnSearch = document.getElementById("btnSearch");
const hint = document.getElementById("hint");

const resultBox = document.getElementById("resultBox");
const infoBox = document.getElementById("infoBox");
const questionsBox = document.getElementById("questionsBox");
const totalScoreEl = document.getElementById("totalScore");

/* Popup */
const noResultPopup = document.getElementById("noResultPopup");
window.closeNoResult = () => {
  noResultPopup.style.display = "none";
};

/* ===============================
   Helpers
================================ */
function sameText(a, b) {
  return String(a || "").trim().toLowerCase() ===
         String(b || "").trim().toLowerCase();
}

function parseTF(v) {
  const s = String(v || "").toLowerCase();
  if (["true", "صح", "1"].includes(s)) return true;
  if (["false", "خطأ", "0"].includes(s)) return false;
  return null;
}

/* ===============================
   Search Result
================================ */
btnSearch.onclick = async () => {
  const name = empNameEl.value.trim();
  const id = empIdEl.value.trim();
  const section = (empSectionEl?.value || "").trim();

  if (!name || !id || !section) {
    hint.textContent = "⚠️ أدخل الاسم والرقم الوظيفي + اختر القسم";
    resultBox.style.display = "none";
    return;
  }

  hint.textContent = "…جاري البحث";
  resultBox.style.display = "none";

  const snap = await getDocs(collection(db, "exam_attempts"));

  const attempt = snap.docs
    .map(d => ({ id: d.id, ...d.data() }))
    .find(r =>
      sameText(r.employeeName, name) &&
      sameText(r.employeeId, id) &&
      sameText(r.section, section) // ✅ NEW
    );

  /* ❌ No Result */
  if (!attempt) {
    hint.textContent = "";
    noResultPopup.style.display = "flex";
    return;
  }

  /* Load Exam */
  const examSnap = await getDoc(doc(db, "exams", attempt.examId));
  if (!examSnap.exists()) {
    hint.textContent = "";
    noResultPopup.style.display = "flex";
    return;
  }
  const exam = examSnap.data();

  /* ===============================
     Info
  ================================ */
  infoBox.innerHTML = `
    <p><b>الاسم:</b> ${attempt.employeeName || "—"}</p>
    <p><b>الرقم الوظيفي:</b> ${attempt.employeeId || "—"}</p>
    <p><b>القسم:</b> ${attempt.section || "—"}</p>
    <p><b>اسم الامتحان:</b> ${(attempt.examTitle || exam.title) || "—"}</p>
    <p><b>حالة المحاولة:</b> ${attempt.status || "—"}</p>
  `;

  totalScoreEl.textContent = attempt.totalScore ?? 0;

  /* ===============================
     Questions (filtered by section like your admin_attempt)
  ================================ */
  questionsBox.innerHTML = "";

  const allQs = Array.isArray(exam.questions) ? exam.questions : [];
  const qs = section ? allQs.filter(q => sameText(q.section, section)) : allQs;

  qs.forEach((q, i) => {
    const ans = attempt.answers?.[q.id] ?? "—";
    let status = "—";

    if (q.correctionMode === "auto") {
      if (q.type === "tf") {
        const a = parseTF(ans);
        const c = parseTF(q.correctAnswer);
        status = (a !== null && c !== null && a === c) ? "✔️ صح" : "❌ خطأ";
      } else {
        status = sameText(ans, q.correctAnswer) ? "✔️ صح" : "❌ خطأ";
      }
    } else {
      status = "🟡 يدوي";
    }

    const cls =
      status.includes("✔") ? "ok" :
      status.includes("❌") ? "wrong" :
      "manual";

    const box = document.createElement("div");
    box.className = "qcard";
    box.innerHTML = `
      <p><b>${i + 1}. ${q.title || "—"}</b></p>
      <p>جوابك: ${ans}</p>
      <p>النتيجة: <span class="${cls}">${status}</span></p>
    `;
    questionsBox.appendChild(box);
  });

  /* Show Result */
  resultBox.style.display = "block";
  hint.textContent = "✅ تم العثور على النتيجة";
};
