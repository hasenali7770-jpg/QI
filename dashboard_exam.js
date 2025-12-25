const RESULTS_KEY = "kb_exam_results";
let results = JSON.parse(localStorage.getItem(RESULTS_KEY) || "[]");

// DOM
document.getElementById("totalEmployees").innerText = results.length;

// استخراج الدرجات الكاملة
function getFinalScore(r) {
  const manual = r.answers
    .filter(a => a.manual)
    .reduce((s, a) => s + Number(a.manualScore || 0), 0);

  return r.autoScore + manual;
}

// حساب معدل النجاح والرسوب
let success = 0;
let fail = 0;
let totalScore = 0;

results.forEach(r => {
  const score = getFinalScore(r);
  totalScore += score;

  if (score >= 50) success++;
  else fail++;
});

// عرض النتائج
document.getElementById("successRate").innerText =
  results.length ? Math.round((success / results.length) * 100) + "%" : "0%";

document.getElementById("failRate").innerText =
  results.length ? Math.round((fail / results.length) * 100) + "%" : "0%";

document.getElementById("avgScore").innerText =
  results.length ? Math.round(totalScore / results.length) : 0;

// أفضل 3 موظفين
const top3 = [...results]
  .sort((a, b) => getFinalScore(b) - getFinalScore(a))
  .slice(0, 3);

const top3Box = document.getElementById("top3");

top3Box.innerHTML = top3.map((r, i) => `
  <div class="top3-item">
    <div class="top3-rank">#${i + 1}</div>
    <h3>${r.employeeName}</h3>
    <p>${getFinalScore(r)} / 100</p>
  </div>
`).join("");

// آخر طالب أدى الاختبار
if (results.length > 0) {
  const last = [...results].sort((a,b)=> new Date(b.submittedAt)-new Date(a.submittedAt))[0];
  document.getElementById("lastEmployeeBox").innerHTML = `
    <b>${last.employeeName}</b>
    <br>
    الدرجة: ${getFinalScore(last)}
    <br>
    الوقت: ${new Date(last.submittedAt).toLocaleString("ar-IQ")}
  `;
}

// رسم بياني: النجاح والرسوب
new Chart(document.getElementById("successFailChart"), {
  type: "pie",
  data: {
    labels: ["ناجحين", "راسبين"],
    datasets: [{
      data: [success, fail],
      backgroundColor: ["#22c55e", "#ef4444"]
    }]
  }
});

// رسم بياني: درجات الموظفين
new Chart(document.getElementById("scoresChart"), {
  type: "bar",
  data: {
    labels: results.map(r => r.employeeName),
    datasets: [{
      label: "الدرجة",
      data: results.map(r => getFinalScore(r)),
      backgroundColor: "#2961ff"
    }]
  }
});
