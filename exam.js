/* ===============================
   exam.js ✅ FULL (Updated)
   - Load active exam by employee section
   - Attempt docId remains: examId__employeeId
=============================== */

import { db } from "./firebase.js";
import {
  collection, query, where, getDocs, doc, getDoc, setDoc, updateDoc, serverTimestamp
} from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

const examTitleEl = document.getElementById("examTitle");
const examDescEl  = document.getElementById("examDesc");
const timerEl     = document.getElementById("timer");
const pointsBox   = document.getElementById("pointsBox");

const empName = document.getElementById("empName");
const empId   = document.getElementById("empId");
const empSection = document.getElementById("empSection");
const empEmail   = document.getElementById("empEmail");

const btnStart = document.getElementById("btnStart");
const startHint = document.getElementById("startHint");

const examCard = document.getElementById("examCard");
const questionsBox = document.getElementById("questionsBox");
const btnSubmit = document.getElementById("btnSubmit");
const saveHint = document.getElementById("saveHint");

const finishOverlay = document.getElementById("finishOverlay");

let activeExamId = "";
let exam = null;
let questions = [];
let attemptRef = null;
let attemptId = "";
let answers = {}; // {qid: value}
let startedAtMs = 0;
let timerInt = null;

// Helpers
const num = (v,d=0)=> Number.isFinite(+v) ? +v : d;
const sameText = (a,b)=> String(a??"").trim().toLowerCase() === String(b??"").trim().toLowerCase();

function cleanTF(v){
  return String(v ?? "").replace(/[✔️✅❌✖️]/g,"").trim().toLowerCase();
}
function parseTF(v){
  const s = cleanTF(v);
  if (["true","1","yes","y","صح","صحيح"].includes(s)) return true;
  if (["false","0","no","n","خطأ","خاطئ","خطاء"].includes(s)) return false;
  return null;
}

function formatTime(sec){
  const m = Math.floor(sec/60);
  const s = sec%60;
  return `${String(m).padStart(2,"0")}:${String(s).padStart(2,"0")}`;
}

/* ✅ Load active exam by section */
async function loadActiveExamForSection(section){
  const qy = query(
    collection(db,"exams"),
    where("status","==","active"),
    where("section","==", String(section || "").trim())
  );

  const snap = await getDocs(qy);

  if (snap.empty){
    examTitleEl.textContent = "لا يوجد امتحان فعال لهذا القسم";
    examDescEl.textContent = "اطلب من الأدمن تفعيل امتحان لقسمك.";
    btnStart.disabled = true;
    return null;
  }

  const best = snap.docs
    .map(d=>({id:d.id,...d.data()}))
    .sort((a,b)=>(b.updatedAt?.seconds||b.createdAt?.seconds||0)-(a.updatedAt?.seconds||a.createdAt?.seconds||0))[0];

  activeExamId = best.id;
  exam = best;

  examTitleEl.textContent = exam.title || "Exam";
  examDescEl.textContent = exam.description || "";

  return best;
}

function normalizeQuestion(q){
  const type = q.type || "tf";
  const correctionMode = q.correctionMode || ((type==="short"||type==="essay")?"manual":"auto");
  return {
    id: q.id,
    section: q.section || "Inbound",
    type,
    title: q.title || "",
    points: num(q.points,1),
    correctionMode,
    options: Array.isArray(q.options)? q.options : [],
    correctAnswer: q.correctAnswer ?? ""
  };
}

function renderQuestionsForSection(section){
  questionsBox.innerHTML = "";
  answers = {};

  // ✅ Here we still filter exam.questions by question.section
  // But exam itself already targets a section
  const all = Array.isArray(exam.questions) ? exam.questions.map(normalizeQuestion) : [];
  questions = all.filter(q=> String(q.section).trim() === String(section).trim());

  if (!questions.length){
    questionsBox.innerHTML = `<div class="qcard">⚠️ لا توجد أسئلة لهذا القسم داخل الامتحان.</div>`;
    pointsBox.textContent = "0";
    btnSubmit.disabled = true;
    return;
  }

  const maxRaw = questions.reduce((s,q)=> s + Math.max(1,num(q.points,1)), 0);
  pointsBox.textContent = String(maxRaw);

  questions.forEach((q,idx)=>{
    const card = document.createElement("div");
    card.className = "qcard";
    card.dataset.qid = q.id;

    card.innerHTML = `
      <div class="qhead">
        <div class="qtitle">${idx+1}. ${q.title || "—"}</div>
        <div class="qmeta">
          <span class="badge">${q.type}</span>
          <span class="badge">${q.correctionMode === "manual" ? "🟡 يدوي" : "⚡ تلقائي"}</span>
          <span class="badge">الدرجة: ${Math.max(1,num(q.points,1))}</span>
        </div>
      </div>
      <div class="opts"></div>
    `;

    const opts = card.querySelector(".opts");

    if (q.type === "tf"){
      opts.innerHTML = `
        <label class="opt">
          <input type="radio" name="q_${q.id}" value="true">
          <span>True</span>
        </label>
        <label class="opt">
          <input type="radio" name="q_${q.id}" value="false">
          <span>False</span>
        </label>
      `;
      opts.querySelectorAll("input").forEach(inp=>{
        inp.addEventListener("change", ()=> onAnswer(q.id, inp.value));
      });
    } else if (q.type === "mcq"){
      const ops = (q.options && q.options.length) ? q.options : ["", "", "", ""];
      opts.innerHTML = ops.map((o,i)=>`
        <label class="opt">
          <input type="radio" name="q_${q.id}" value="${o}">
          <span>${o || `خيار ${i+1}`}</span>
        </label>
      `).join("");
      opts.querySelectorAll("input").forEach(inp=>{
        inp.addEventListener("change", ()=> onAnswer(q.id, inp.value));
      });
    } else {
      opts.innerHTML = `<textarea placeholder="اكتب إجابتك هنا..."></textarea>`;
      const ta = opts.querySelector("textarea");
      ta.addEventListener("input", ()=> onAnswer(q.id, ta.value));
    }

    questionsBox.appendChild(card);
  });

  btnSubmit.disabled = false;
}

let saveTimer = null;
function onAnswer(qid, value){
  answers[qid] = value;

  saveHint.textContent = "…جاري الحفظ";
  clearTimeout(saveTimer);
  saveTimer = setTimeout(async ()=>{
    if (!attemptRef) return;
    try{
      await updateDoc(attemptRef, {
        answers,
        updatedAt: serverTimestamp()
      });
      saveHint.textContent = "✅ تم الحفظ";
    }catch(e){
      console.error(e);
      saveHint.textContent = "⚠️ فشل الحفظ";
    }
  }, 450);
}

async function checkAlreadyAttempted(employeeId){
  attemptId = `${activeExamId}__${employeeId}`;
  attemptRef = doc(db,"exam_attempts",attemptId);
  const snap = await getDoc(attemptRef);
  return snap.exists() ? snap.data() : null;
}

function startTimer(durationMin){
  const total = Math.max(1, num(durationMin, 20)) * 60;
  startedAtMs = Date.now();
  clearInterval(timerInt);

  timerInt = setInterval(()=>{
    const passed = Math.floor((Date.now() - startedAtMs)/1000);
    const left = Math.max(0, total - passed);
    timerEl.textContent = formatTime(left);

    if (left <= 0){
      clearInterval(timerInt);
      btnSubmit.click();
    }
  }, 1000);
}

function calcAutoRaw(){
  let autoRaw = 0;
  let maxRaw = 0;

  questions.forEach(q=>{
    const max = Math.max(1, num(q.points,1));
    maxRaw += max;

    const ans = answers[q.id] ?? "";
    if (q.correctionMode === "manual") return;

    let correct = false;
    if (q.type === "tf"){
      const a = parseTF(ans);
      const c = parseTF(q.correctAnswer);
      if (a !== null && c !== null) correct = (a === c);
      else correct = sameText(ans, q.correctAnswer);
    } else if (q.type === "mcq"){
      correct = sameText(ans, q.correctAnswer);
    } else {
      if (q.correctAnswer) correct = sameText(ans, q.correctAnswer);
    }

    if (correct) autoRaw += max;
  });

  return {autoRaw, maxRaw};
}

// ===============================
// Start Exam
// ===============================
btnStart.onclick = async ()=>{
  const name = empName.value.trim();
  const id = empId.value.trim();
  const section = empSection.value;

  if (!name || !id){
    startHint.textContent = "⚠️ اكتب الاسم والرقم الوظيفي";
    return;
  }

  btnStart.disabled = true;
  startHint.textContent = "…جاري تحميل امتحان القسم";

  const loaded = await loadActiveExamForSection(section);
  if (!loaded){
    btnStart.disabled = false;
    startHint.textContent = "❌ لا يوجد امتحان فعال لقسمك";
    return;
  }

  startHint.textContent = "…جاري التحقق";
  const prev = await checkAlreadyAttempted(id);

  if (prev && (prev.status === "submitted" || prev.status === "finalized")){
    startHint.textContent = "❌ لقد أديت هذا الامتحان مسبقًا";
    return;
  }

  await setDoc(attemptRef, {
    examId: activeExamId,
    examTitle: exam.title || "",

    employeeName: name,
    employeeId: id,
    email: empEmail.value.trim() || "",
    section,

    status: "started",
    answers: prev?.answers || {},

    createdAt: prev?.createdAt || serverTimestamp(),
    startedAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  }, { merge: true });

  const after = await getDoc(attemptRef);
  answers = after.exists() ? (after.data().answers || {}) : {};

  renderQuestionsForSection(section);
  examCard.style.display = "block";
  startHint.textContent = "✅ بدأ الامتحان";

  startTimer(exam.durationMin ?? 20);

  // restore answers
  questions.forEach(q=>{
    const val = answers[q.id];
    if (val == null) return;

    const card = questionsBox.querySelector(`[data-qid="${q.id}"]`);
    if (!card) return;

    if (q.type === "tf" || q.type === "mcq"){
      card.querySelectorAll("input[type=radio]").forEach(r=>{
        if (String(r.value) === String(val)) r.checked = true;
      });
    } else {
      const ta = card.querySelector("textarea");
      if (ta) ta.value = String(val);
    }
  });

  btnStart.disabled = false;
};

// ===============================
// Submit Exam
// ===============================
btnSubmit.onclick = async ()=>{
  if (!attemptRef) return;

  btnSubmit.disabled = true;
  saveHint.textContent = "…جاري الإرسال";

  const {autoRaw, maxRaw} = calcAutoRaw();
  const manualRaw = 0;
  const earnedRaw = autoRaw + manualRaw;
  const totalScore = maxRaw ? Math.round((earnedRaw/maxRaw)*100) : 0;

  await updateDoc(attemptRef, {
    answers,
    status: "submitted",
    submittedAt: serverTimestamp(),
    autoRaw,
    manualRaw,
    maxRaw,
    earnedRaw,
    autoScore: maxRaw ? Math.round((autoRaw/maxRaw)*100) : 0,
    manualScore: 0,
    totalScore,
    passScore: exam.passScore ?? 60,
    timeSpentSec: Math.floor((Date.now() - startedAtMs)/1000),
    updatedAt: serverTimestamp()
  });

  finishOverlay.style.display = "flex";
  setTimeout(()=> location.href="dashboard.html", 2000);
};

// init
timerEl.textContent = "--:--";
examTitleEl.textContent = "امتحان";
examDescEl.textContent = "اختر القسم ثم ابدأ الامتحان";
