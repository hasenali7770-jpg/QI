import { db } from "./firebase.js";
import {
  collection,
  getDocs
} from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

/* ===============================
   Animated counter
================================ */
function animate(el, to) {
  let current = 0;
  const step = Math.max(1, Math.ceil(to / 40));

  const timer = setInterval(() => {
    current += step;
    if (current >= to) {
      el.textContent = to;
      clearInterval(timer);
    } else {
      el.textContent = current;
    }
  }, 25);
}

/* ===============================
   Generic line chart (single value)
================================ */
function drawLineChart(canvasId, total, color) {
  const ctx = document.getElementById(canvasId);

  new Chart(ctx, {
    type: "line",
    data: {
      labels: ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
      datasets: [{
        data: [
          Math.max(1, total - 10),
          Math.max(1, total - 7),
          Math.max(1, total - 5),
          Math.max(1, total - 3),
          Math.max(1, total - 1),
          total
        ],
        borderColor: color,
        backgroundColor: color.replace("1)", "0.12)"),
        fill: true,
        tension: 0.4,
        pointRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true } }
    }
  });
}

/* ===============================
   Build Exam Users Monthly Data
   (from exam_attempts)
================================ */
function buildExamUsersChartData(attemptsSnap) {
  const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  const monthMap = {};
  months.forEach(m => monthMap[m] = new Set());

  attemptsSnap.forEach(doc => {
    const d = doc.data();
    if (!d.createdAt || !d.userEmail) return;

    const date = d.createdAt.toDate();
    const month = date.toLocaleString("en", { month: "short" });

    if (monthMap[month]) {
      monthMap[month].add(d.userEmail); // بدون تكرار
    }
  });

  return months.map(m => monthMap[m].size);
}

/* ===============================
   Load dashboard data
================================ */
async function loadDashboard() {

  /* ===== Core collections ===== */
  const usersSnap   = await getDocs(collection(db, "users"));
  const shelvesSnap = await getDocs(collection(db, "shelves"));
  const newsSnap    = await getDocs(collection(db, "news"));
  const kpiSnap     = await getDocs(collection(db, "kpi_reports"));

  /* ===== Exam attempts (IMPORTANT) ===== */
  const attemptsSnap = await getDocs(collection(db, "exam_attempts"));

  /* ===============================
     Counters
  ============================== */
  animate(usersCount, usersSnap.size);
  animate(shelvesCount, shelvesSnap.size);
  animate(newsCount, newsSnap.size);
  animate(kpiCount, kpiSnap.size);

  /* ---- Exam users counter (unique) ---- */
  const uniqueExamUsers = new Set();
  attemptsSnap.forEach(doc => {
    const d = doc.data();
    if (d.userEmail) uniqueExamUsers.add(d.userEmail);
  });

  animate(
    document.getElementById("examUsersCount"),
    uniqueExamUsers.size
  );

  /* ===============================
     Charts
  ============================== */
  drawLineChart("usersChart", usersSnap.size, "rgba(0,56,168,1)");
  drawLineChart("shelvesChart", shelvesSnap.size, "rgba(0,194,168,1)");
  drawLineChart("booksChart", shelvesSnap.size * 3, "rgba(120,120,255,1)");
  drawLineChart("kpiChart", kpiSnap.size, "rgba(255,193,7,1)");

  /* ---- Exam users monthly chart ---- */
  const examUsersMonthly = buildExamUsersChartData(attemptsSnap);

  new Chart(document.getElementById("examUsersChart"), {
    type: "line",
    data: {
      labels: ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],
      datasets: [{
        data: examUsersMonthly,
        borderColor: "rgba(156,39,176,1)",
        backgroundColor: "rgba(156,39,176,0.12)",
        fill: true,
        tension: 0.4,
        pointRadius: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true } }
    }
  });
}

/* ===============================
   Init
================================ */
loadDashboard();
