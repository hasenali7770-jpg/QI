import { db } from "./firebase.js";
import { doc, getDoc, updateDoc, serverTimestamp } from
  "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

document.addEventListener("DOMContentLoaded", async () => {

  /* ===============================
     Admin Guard
  =============================== */
  const currentEmail = localStorage.getItem("kb_user_email") || "";
  if (!currentEmail) {
    location.href = "login.html";
    return;
  }

  const uSnap = await getDoc(doc(db, "users", currentEmail));
  const isAdmin =
    uSnap.exists() &&
    String(uSnap.data().role || "").toLowerCase() === "admin";

  if (!isAdmin) {
    alert("غير مخول");
    location.href = "dashboard.html";
    return;
  }

  /* ===============================
     State
  =============================== */
  const attemptId = localStorage.getItem("admin_selected_attempt");
  if (!attemptId) {
    alert("لا توجد محاولة محددة");
    return;
  }

  const infoBox = document.getElementById("infoBox");
  const questionsBox = document.getElementById("questionsBox");
  const adminNoteEl = document.getElementById("adminNote");
  const finishOverlay = document.getElementById("finishOverlay");

  const autoScoreEl = document.getElementById("autoScore");
  const manualScoreEl = document.getElementById("manualScore");
  const totalScoreEl = document.getElementById("totalScore");

  const btnFinalize = document.getElementById("btnFinalize");

  let attempt = null;
  let exam = null;

  let autoRaw = 0;
  let manualRaw = 0;
  let maxRaw = 0;

  /* ===============================
     Helpers
  =============================== */
  function uid() {
    return "q_" + Math.random().toString(16).slice(2) + Date.now();
  }

  function sameText(a, b) {
    return String(a ?? "").trim().toLowerCase() ===
           String(b ?? "").trim().toLowerCase();
  }

  function normalizeQuestion(q) {
    const type = q.type || "tf";
    const defaultMode =
      (type === "essay" || type === "short") ? "manual" : "auto";

    return {
      id: q.id || uid(),
      section: q.section || "Inbound",
      type,
      title: q.title || "",
      points: Number(q.points ?? 1),
      correctionMode: q.correctionMode || defaultMode,
      correctAnswer: q.correctAnswer ?? ""
    };
  }

  function num(v, d = 0) {
    const n = Number(v);
    return Number.isFinite(n) ? n : d;
  }

  /* ===============================
     🔥 Universal Answer Resolver
  =============================== */
  function getAnswer(attempt, qid) {
    if (!attempt) return "";

    // answers as object
    if (attempt.answers && typeof attempt.answers === "object") {
      if (attempt.answers[qid] !== undefined) return attempt.answers[qid];
      if (attempt.answers.questions?.[qid] !== undefined)
        return attempt.answers.questions[qid];
    }

    // responses
    if (attempt.responses?.[qid] !== undefined) {
      return attempt.responses[qid];
    }

    // userAnswers
    if (attempt.userAnswers?.[qid] !== undefined) {
      return attempt.userAnswers[qid];
    }

    // answers as array
    if (Array.isArray(attempt.answers)) {
      const found = attempt.answers.find(a =>
        a.qid === qid || a.id === qid || a.questionId === qid
      );
      if (found) return found.answer ?? found.value ?? "";
    }

    return "";
  }

  /* ===============================
     Load Data
  =============================== */
  async function loadData() {
    const aSnap = await getDoc(doc(db, "exam_attempts", attemptId));
    if (!aSnap.exists()) {
      alert("المحاولة غير موجودة");
      return;
    }

    attempt = aSnap.data();

    const eSnap = await getDoc(doc(db, "exams", attempt.examId));
    if (!eSnap.exists()) {
      alert("الامتحان غير موجود");
      return;
    }

    exam = eSnap.data();

    adminNoteEl.value = attempt.adminNote || "";

    renderInfo();
    renderQuestions();
    renderScores();
  }

  function renderInfo() {
    infoBox.innerHTML = `
      <p><b>الاسم:</b> ${attempt.employeeName || "—"}</p>
      <p><b>الرقم الوظيفي:</b> ${attempt.employeeId || "—"}</p>
      <p><b>القسم:</b> ${attempt.section || "—"}</p>
      <p><b>اسم الامتحان:</b> ${attempt.examTitle || exam.title || "—"}</p>
      <p><b>الحالة:</b> ${attempt.status || "—"}</p>
    `;
  }

  /* ===============================
     Render Questions
  =============================== */
  function renderQuestions() {
    questionsBox.innerHTML = "";
    autoRaw = 0;
    manualRaw = 0;
    maxRaw = 0;

    const section = String(attempt.section || "").trim();
    const all = (exam.questions || []).map(normalizeQuestion);
    const qs = section ? all.filter(q => q.section === section) : all;

    const savedManual = attempt.manualGrades || {};

    qs.forEach((q, i) => {
      const ans = getAnswer(attempt, q.id);
      const max = Math.max(1, num(q.points, 1));
      maxRaw += max;

      const isManual = q.correctionMode === "manual";
      let earnedAuto = 0;
      let correct = false;

      if (!isManual) {
        if (sameText(ans, q.correctAnswer)) {
          earnedAuto = max;
          correct = true;
        }
        autoRaw += earnedAuto;
      }

      const card = document.createElement("div");
      card.className = `question ${isManual ? "manual" : (correct ? "correct" : "wrong")}`;
      card.dataset.qid = q.id;

      card.innerHTML = `
        <div class="q-head">
          <div class="q-title">${i + 1}. ${q.title}</div>
          <div class="q-badges">
            <span class="badge">${q.type}</span>
            <span class="badge">الدرجة: ${max}</span>
          </div>
        </div>
        <div class="q-body">
          <p><b>جواب الموظف:</b> ${ans || "—"}</p>
          <p><b>الإجابة الصحيحة:</b> ${q.correctAnswer || "—"}</p>
          <p><b>درجة السؤال:</b> ${earnedAuto} / ${max}</p>
        </div>
      `;

      if (isManual) {
        const row = document.createElement("div");
        row.className = "manual-row";
        row.innerHTML = `
          <span>درجة يدوية:</span>
          <input class="manual-input" type="number" min="0" max="${max}"
            value="${num(savedManual[q.id], 0)}" data-max="${max}">
        `;
        card.appendChild(row);
      }

      questionsBox.appendChild(card);
    });
  }

  /* ===============================
     Scores
  =============================== */
  function renderScores() {
    manualRaw = 0;
    document.querySelectorAll(".manual-input").forEach(inp => {
      const mx = num(inp.dataset.max, 1);
      let v = num(inp.value, 0);
      v = Math.min(Math.max(v, 0), mx);
      manualRaw += v;
    });

    const earnedRaw = autoRaw + manualRaw;
    const totalPercent = maxRaw
      ? Math.round((earnedRaw / maxRaw) * 100)
      : 0;

    autoScoreEl.textContent = autoRaw;
    manualScoreEl.textContent = manualRaw;
    totalScoreEl.textContent = totalPercent;
  }

  document.addEventListener("input", e => {
    if (e.target.classList.contains("manual-input")) {
      renderScores();
    }
  });

  /* ===============================
     Finalize (SAVE FINAL SCORE)
  =============================== */
  btnFinalize.onclick = async () => {

    const manualGrades = {};
    document.querySelectorAll(".manual-input").forEach(inp => {
      const qid = inp.closest(".question")?.dataset.qid;
      if (qid) manualGrades[qid] = Number(inp.value || 0);
    });

    const earnedRaw = autoRaw + manualRaw;
    const finalPercent = maxRaw
      ? Math.round((earnedRaw / maxRaw) * 100)
      : 0;

    await updateDoc(doc(db, "exam_attempts", attemptId), {
      adminNote: adminNoteEl.value || "",
      manualGrades,

      autoScore: autoRaw,
      manualScore: manualRaw,
      totalScore: finalPercent,
      maxScore: maxRaw,

      status: "finalized",
      reviewedBy: currentEmail,
      finalizedAt: serverTimestamp()
    });

    finishOverlay.style.display = "flex";
    setTimeout(() => location.href = "admin_exam.html", 1600);
  };

  /* ===============================
     Start
  =============================== */
  loadData();

});
