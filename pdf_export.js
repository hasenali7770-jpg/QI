// ========== PDF Export Script ==========
const RESULTS_KEY = "kb_exam_results";

function getQueryParam(key) {
  const url = new URL(window.location.href);
  return url.searchParams.get(key);
}

function loadReport() {
  const id = Number(getQueryParam("id"));
  const data = JSON.parse(localStorage.getItem(RESULTS_KEY) || "[]");

  const result = data.find(r => r.id === id);
  if (!result) {
    document.getElementById("report").innerHTML = "<h2>❌ لا يوجد تقرير.</h2>";
    return;
  }

  const totalQuestions = (result.answers || []).length;
  const totalMax = totalQuestions * 10;

  const manualTotal = (result.answers || [])
    .filter(a => a.manual)
    .reduce((sum, a) => sum + (Number(a.manualScore) || 0), 0);

  const finalScore = (Number(result.autoScore) || 0) + manualTotal;

  // ========== تعبئة بيانات الموظف ==========
  document.getElementById("employeeInfo").innerHTML = `
    👤 الموظف: <b>${result.employeeName}</b><br>
    🕒 وقت التسليم: ${new Date(result.submittedAt).toLocaleString("ar-IQ")}
  `;

  // ========== درجة الامتحان ==========
  document.getElementById("scoreInfo").innerHTML = `
    🔹 الدرجة التلقائية: ${result.autoScore}<br>
    🔹 مجموع الأسئلة اليدوية: ${manualTotal}<br>
    <b>🏁 الدرجة النهائية: ${finalScore} / ${totalMax}</b>
  `;

  // ========== عرض الإجابات ==========
  const answersBox = document.getElementById("answersBox");
  answersBox.innerHTML = "";

  result.answers.forEach((a, i) => {
    let html = `
      <div class="answer-block">
        <p><b>${i + 1}) ${a.text}</b></p>
        <p>إجابة الموظف: ${a.userAnswer || "—"}</p>
    `;

    // سؤال تلقائي
    if (a.autoCorrect !== null && a.autoCorrect !== undefined) {
      html += `
        <p class="${a.autoCorrect ? "correct" : "wrong"}">
          ${a.autoCorrect ? "✔ إجابة صحيحة" : "✘ إجابة خاطئة"}
        </p>
        <p>الإجابة الصحيحة: ${a.correctAnswer}</p>
      `;
    }

    // سؤال يدوي
    if (a.manual) {
      html += `
        <p class="manual-score">درجة التصحيح اليدوي: ${a.manualScore || 0} / 10</p>
      `;
    }

    html += `</div>`;
    answersBox.innerHTML += html;
  });
}

window.onload = loadReport;
