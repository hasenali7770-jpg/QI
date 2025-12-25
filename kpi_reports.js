const body = document.getElementById("reportsBody");
const empty = document.getElementById("emptyState");

function loadReports() {
  const reports = JSON.parse(localStorage.getItem("kpi_reports") || "[]");
  body.innerHTML = "";

  if (reports.length === 0) {
    empty.style.display = "block";
    return;
  }

  empty.style.display = "none";

  reports.forEach(r => {
    body.innerHTML += `
      <tr>
        <td class="kpi-name">${r.title || "Untitled KPI"}</td>
        <td>${r.month}</td>
        <td>${r.createdBy}</td>
        <td>${new Date(r.createdAt).toLocaleString()}</td>
        <td class="actions">
          <button class="btn-edit" onclick="editReport('${r.id}')">Edit</button>
          <button class="btn-delete" onclick="deleteReport('${r.id}')">Delete</button>
        </td>
      </tr>
    `;
  });
}

window.editReport = function (id) {
  localStorage.setItem("edit_kpi_report", id);
  window.location.href = "kpi_productivity.html";
};

window.deleteReport = function (id) {
  if (!confirm("Delete this KPI report?")) return;

  let reports = JSON.parse(localStorage.getItem("kpi_reports") || "[]");
  reports = reports.filter(r => r.id !== id);
  localStorage.setItem("kpi_reports", JSON.stringify(reports));
  loadReports();
};

loadReports();
