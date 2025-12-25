/* =====================
   GET DATA
===================== */
const kpiReports = JSON.parse(localStorage.getItem("kpi_reports") || "[]");
const tasks = JSON.parse(localStorage.getItem("tasks") || "[]"); // عدّل الاسم إذا مختلف

/* =====================
   CALCULATIONS
===================== */
const totalKPI = kpiReports.length;
const lockedKPI = kpiReports.filter(r => r.locked).length;

const lastKpiName = kpiReports.length
  ? kpiReports.sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))[0].title
  : "—";

const totalTasks = tasks.length;

/* =====================
   SET VALUES
===================== */
animateCounter("kpiCount", totalKPI);
animateCounter("tasksCount", totalTasks);
animateCounter("lockedCount", lockedKPI);

document.getElementById("lastKpi").innerText = lastKpiName;

/* =====================
   COUNTER ANIMATION
===================== */
function animateCounter(id, target) {
  const el = document.getElementById(id);
  let count = 0;
  const step = Math.ceil(target / 40);

  const interval = setInterval(() => {
    count += step;
    if (count >= target) {
      el.innerText = target;
      clearInterval(interval);
    } else {
      el.innerText = count;
    }
  }, 20);
}
