import { db } from "./firebase.js";
import {
  collection,
  addDoc,
  serverTimestamp
} from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

const monthSelect = document.getElementById("monthSelect");
const kpiTitleInput = document.getElementById("kpiTitle");

window.saveReport = async function () {

  const rows = [];

  document.querySelectorAll("#kpiTable tbody tr").forEach(row => {
    const kpi = row.querySelector(".kpi-name").value;
    if (!kpi) return;

    rows.push({
      kpi,
      desc: row.querySelector(".kpi-desc").value,
      measure: row.querySelector(".kpi-measure").value,
      note: row.querySelector(".note").value,
      iw: row.querySelector(".iw").value,
      uw: row.querySelector(".uw").value,
      input: row.querySelector(".input").value,
      output: row.querySelector(".output").value,
      sla: row.querySelector(".sla").value
    });
  });

  if (!rows.length) {
    alert("❌ Add at least one KPI");
    return;
  }

  await addDoc(collection(db, "kpi_reports"), {
    title: kpiTitleInput.value || "",
    month: monthSelect.value,
    createdAt: serverTimestamp(),
    totalKpis: rows.length,
    rows
  });

  alert("✔ KPI saved to Firestore");
  location.href = "kpi_reports.html";
};

/* PDF */
window.exportPDF = function () {
  html2pdf().from(document.getElementById("kpiTable")).save("KPI_Report.pdf");
};

/* Excel */
window.exportExcel = function () {
  const tableHTML = document.getElementById("kpiTable").outerHTML;
  const blob = new Blob([tableHTML], { type: "application/vnd.ms-excel" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "KPI_Report.xls";
  a.click();
};
