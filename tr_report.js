import { db } from "./firebase.js";
import {
  collection,
  getDocs,
  updateDoc,
  deleteDoc,
  doc
} from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

/* ======================
   عناصر الصفحة
====================== */
const list = document.getElementById("list");
const modal = document.getElementById("reportModal");
const openReport = document.getElementById("openReport");
const closeReport = document.getElementById("closeReport");
const closeReportX = document.getElementById("closeReportX");
const runReport = document.getElementById("runReport");
const reportResult = document.getElementById("reportResult");

let employees = [];

/* ======================
   تحميل الموظفين
====================== */
async function loadEmployees() {
  list.innerHTML = "";
  employees = [];

  const snap = await getDocs(collection(db, "tr_employees"));

  snap.forEach(d => {
    const e = d.data();
    e._id = d.id;
    employees.push(e);

    list.innerHTML += `
      <div class="card">
        <b>${e.name}</b><br>
        ID: ${e.empId}<br>
        PH: ${e.ph}<br>
        Date: ${e.date}<br>
        Dep: ${e.dep || "—"}<br>

        <div class="card-row">
          Status:
          <select onchange="updateStatus('${d.id}', this.value)">
            <option value="Active" ${e.status === "Active" ? "selected" : ""}>Active</option>
            <option value="Inactive" ${e.status === "Inactive" ? "selected" : ""}>Inactive</option>
          </select>
        </div>

        <button class="delete-btn" onclick="deleteEmployee('${d.id}','${e.name}')">
          🗑 حذف الموظف
        </button>
      </div>
    `;
  });
}

await loadEmployees();

/* ======================
   تحديث الحالة
====================== */
window.updateStatus = async (id, status) => {
  await updateDoc(doc(db, "tr_employees", id), { status });
};

/* ======================
   حذف موظف
====================== */
window.deleteEmployee = async (id, name) => {
  const ok = confirm(`هل أنت متأكد من حذف الموظف:\n${name}`);
  if (!ok) return;

  try {
    await deleteDoc(doc(db, "tr_employees", id));
    alert("تم حذف الموظف بنجاح");
    loadEmployees();
  } catch (e) {
    alert("خطأ أثناء الحذف");
    console.error(e);
  }
};

/* ======================
   نافذة التقرير
====================== */
openReport.onclick = () => modal.classList.remove("hidden");
closeReport.onclick = () => modal.classList.add("hidden");
closeReportX.onclick = () => modal.classList.add("hidden");

/* ======================
   تشغيل التقرير
====================== */
runReport.onclick = () => {
  const dep = document.getElementById("rDep").value;
  const month = document.getElementById("rMonth").value;

  if (!dep || !month) {
    alert("اختر القسم والشهر");
    return;
  }

  const count = employees.filter(e => {
    if (e.dep !== dep) return false;
    return e.date?.startsWith(month);
  }).length;

  reportResult.innerText =
    `عدد الموظفين في قسم ${dep} خلال ${month} هو: ${count}`;
};
