import { db } from "./firebase.js";
import {
  collection,
  getDocs,
  doc,
  setDoc,
  getDoc
} from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

/* ======================
   Elements
====================== */
const empRows = document.getElementById("empRows");

const modal = document.getElementById("taskModal");
const modalTitle = document.getElementById("modalTitle");
const taskBody = document.getElementById("taskBody");

const addTaskBtn = document.getElementById("addTask");
const saveTasksBtn = document.getElementById("saveTasks");
const closeModalBtn = document.getElementById("closeModal");
const closeModalX = document.getElementById("closeModalX");

/* ======================
   State
====================== */
let currentEmp = null;
let currentTasks = [];

/* ======================
   Helpers
====================== */
function openModal() {
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
}
function closeModal() {
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
}
function escapeHtml(s="") {
  return String(s)
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

/* ======================
   Render Tasks
====================== */
function renderTasks(){
  taskBody.innerHTML = "";

  if (!currentTasks.length) {
    taskBody.innerHTML = `
      <tr>
        <td colspan="3" style="color:#64748b; padding:14px; text-align:center;">
          لا توجد Tasks — اضغط "إضافة Task"
        </td>
      </tr>
    `;
    return;
  }

  currentTasks.forEach((t,i)=>{
    taskBody.innerHTML += `
      <tr>
        <td>
          <input data-i="${i}" data-k="title" value="${escapeHtml(t.title)}" placeholder="اكتب اسم التاسك...">
        </td>
        <td>
          <select data-i="${i}" data-k="status">
            <option value="IN PROG" ${t.status==="IN PROG"?"selected":""}>IN PROG</option>
            <option value="DONE" ${t.status==="DONE"?"selected":""}>DONE</option>
          </select>
        </td>
        <td>
          <button class="icon-btn" data-del="${i}" title="حذف">✖</button>
        </td>
      </tr>
    `;
  });

  // inputs change
  taskBody.querySelectorAll("input[data-i]").forEach(inp=>{
    inp.addEventListener("input", (e)=>{
      const i = Number(e.target.dataset.i);
      currentTasks[i].title = e.target.value;
    });
  });

  // select change
  taskBody.querySelectorAll("select[data-i]").forEach(sel=>{
    sel.addEventListener("change", (e)=>{
      const i = Number(e.target.dataset.i);
      currentTasks[i].status = e.target.value;
    });
  });

  // delete row
  taskBody.querySelectorAll("button[data-del]").forEach(btn=>{
    btn.addEventListener("click", ()=>{
      const i = Number(btn.dataset.del);
      currentTasks.splice(i,1);
      renderTasks();
    });
  });
}

/* ======================
   Load employees from TR
====================== */
async function loadEmployees(){
  empRows.innerHTML = "";

  const snap = await getDocs(collection(db,"tr_employees"));
  snap.forEach(d=>{
    const e = d.data() || {};
    const name = e.name || "—";
    const empId = e.empId || d.id;

    const row = document.createElement("div");
    row.className = "row";
    row.innerHTML = `
      <div class="name">${escapeHtml(name)}</div>
      <div class="id">${escapeHtml(empId)}</div>
      <div><button class="btn btn-secondary">Tasks</button></div>
    `;

    row.querySelector("button").addEventListener("click", ()=> openTasks(empId, name));
    empRows.appendChild(row);
  });
}

await loadEmployees();

/* ======================
   Open tasks modal + load saved tasks
====================== */
async function openTasks(empId, name){
  currentEmp = { empId, name };
  modalTitle.textContent = `Tasks for ${name} (${empId})`;

  // load existing tasks
  currentTasks = [];
  const snap = await getDoc(doc(db, "tr_tasks", empId));
  if (snap.exists()) {
    currentTasks = snap.data().tasks || [];
  }

  renderTasks();
  openModal();
}

/* ======================
   Add task
====================== */
addTaskBtn.addEventListener("click", ()=>{
  currentTasks.push({ title:"", status:"IN PROG" });
  renderTasks();
});

/* ======================
   Save tasks
====================== */
saveTasksBtn.addEventListener("click", async ()=>{
  if (!currentEmp) return;

  // remove empty titles
  const cleaned = currentTasks
    .map(t => ({ title: (t.title||"").trim(), status: t.status==="DONE" ? "DONE" : "IN PROG" }))
    .filter(t => t.title.length);

  await setDoc(doc(db,"tr_tasks", currentEmp.empId), {
    empId: currentEmp.empId,
    name: currentEmp.name,
    tasks: cleaned
  });

  currentTasks = cleaned;
  closeModal();
});

/* ======================
   Close modal
====================== */
closeModalBtn.addEventListener("click", closeModal);
closeModalX.addEventListener("click", closeModal);

// close on outside click
modal.addEventListener("click", (e)=>{
  if (e.target === modal) closeModal();
});
