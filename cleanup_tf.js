import { db } from "./firebase.js";
import {
  collection,
  getDocs,
  doc,
  updateDoc
} from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

/* ===============================
   TF NORMALIZER (FINAL)
=============================== */
function normalizeTF(v) {
  if (v === true || v === "true" || v === "True" || v === 1 || v === "1" || v === "صح" || v === "صحيح")
    return true;

  if (v === false || v === "false" || v === "False" || v === 0 || v === "0" || v === "خطأ" || v === "خاطئ")

    return false;

  return v; // غير TF
}

/* ===============================
   CLEAN EXAMS (correctAnswer)
=============================== */
async function cleanExams() {
  const snap = await getDocs(collection(db, "exams"));

  for (const d of snap.docs) {
    const data = d.data();
    if (!Array.isArray(data.questions)) continue;

    let changed = false;

    const questions = data.questions.map(q => {
      if (q.type === "tf") {
        const fixed = normalizeTF(q.correctAnswer);
        if (fixed !== q.correctAnswer) {
          changed = true;
          return { ...q, correctAnswer: fixed };
        }
      }
      return q;
    });

    if (changed) {
      await updateDoc(doc(db, "exams", d.id), { questions });
      console.log("✅ Exam fixed:", d.id);
    }
  }
}

/* ===============================
   CLEAN ATTEMPTS (answers)
=============================== */
async function cleanAttempts() {
  const snap = await getDocs(collection(db, "exam_attempts"));

  for (const d of snap.docs) {
    const data = d.data();
    if (!data.answers) continue;

    let changed = false;
    const answers = {};

    for (const k in data.answers) {
      const fixed = normalizeTF(data.answers[k]);
      answers[k] = fixed;
      if (fixed !== data.answers[k]) changed = true;
    }

    if (changed) {
      await updateDoc(doc(db, "exam_attempts", d.id), { answers });
      console.log("✅ Attempt fixed:", d.id);
    }
  }
}

/* ===============================
   RUN
=============================== */
(async () => {
  console.log("🔥 Firestore TF Cleanup Started...");
  await cleanExams();
  await cleanAttempts();
  console.log("🎉 Cleanup Finished Successfully");
})();
