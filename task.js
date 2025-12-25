// ===============================
// Firebase
// ===============================
import { db } from "./firebase.js";
import {
  collection,
  addDoc,
  getDocs,
  updateDoc,
  deleteDoc,
  doc,
  serverTimestamp,
  query,
  orderBy
} from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

// ===============================
// 🔐 Admin Access Guard
// ===============================
import { getDoc } from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

async function checkAdminAccess() {
  const email = localStorage.getItem("kb_user_email");
  if (!email) {
    window.location.href = "login.html";
    return false;
  }

  const snap = await getDoc(doc(db, "users", email));
  if (!snap.exists() || snap.data().role !== "admin") {
    document.getElementById("taskPageContent").style.display = "none";
    document.getElementById("unauthorizedBox").style.display = "block";
    return false;
  }
  return true;
}

// ===============================
// Firestore Collection
// ===============================
const tasksCol = collection(db, "tasks");
let tasks = [];

// ===============================
// Elements
// ===============================
const colInProgress = document.getElementById("colInProgress");
const colDone = document.getElementById("colDone");
const countInProgress = document.getElementById("countInProgress");
const countDone = document.getElementById("countDone");

const openCreateBtn = document.getElementById("openCreateBtn");
const openReportBtn = document.getElementById("openReportBtn");

// ===============================
// Helpers
// ===============================
function computePercent(current, target) {
  if (!target || target <= 0) return 0;
  return Math.min(100, Math.floor((current / target) * 100));
}

function progressClass(p) {
  if (p < 40) return "progress-low";
  if (p < 70) return "progress-mid";
  return "progress-high";
}

function formatDateTime(d) {
  return new Date(d).toLocaleString("ar-IQ");
}

// ===============================
// Load Tasks (Firebase)
// ===============================
async function loadTasks() {
  tasks = [];
  const q = query(tasksCol, orderBy("createdAt", "desc"));
  const snap = await getDocs(q);
  snap.forEach(docSnap => {
    tasks.push({ id: docSnap.id, ...docSnap.data() });
  });
}

// ===============================
// Render Board
// ===============================
function renderBoard() {
  colInProgress.innerHTML = "";
  colDone.innerHTML = "";

  let inProg = 0, done = 0;

  tasks.forEach(task => {
    const card = document.createElement("div");
    card.className = "task-card";

    if (task.status === "done") card.classList.add("done");
    if (task.status === "failed") card.classList.add("failed");

    card.innerHTML = `
      <div class="task-title">${task.name}</div>

      <div class="task-meta">
        👤 ${task.employee}
        ${task.employeeId ? ` | 🆔 ${task.employeeId}` : ""}
      </div>

      <div class="task-row">
        🎯 ${task.current} / ${task.target}
        <span>${task.percent}%</span>
      </div>

      <div class="progress">
        <div class="progress-fill ${progressClass(task.percent)}"
             style="width:${task.percent}%"></div>
      </div>

      <div class="task-meta">
        ⏰ ${formatDateTime(task.deadline)}
      </div>
    `;

    // Actions
    const actions = document.createElement("div");
    actions.className = "card-actions";

    const btnUpdate = document.createElement("button");
    btnUpdate.className = "btn-small btn-update";
    btnUpdate.textContent = "تحديث";
    btnUpdate.onclick = e => {
      e.stopPropagation();
      incrementalUpdate(task);
    };

    const btnDelete = document.createElement("button");
    btnDelete.className = "btn-small btn-delete";
    btnDelete.textContent = "حذف";
    btnDelete.onclick = e => {
      e.stopPropagation();
      deleteTask(task.id);
    };

    actions.append(btnUpdate, btnDelete);
    card.appendChild(actions);

    if (task.status === "done") {
      colDone.appendChild(card);
      done++;
    } else {
      colInProgress.appendChild(card);
      inProg++;
    }
  });

  countInProgress.textContent = inProg;
  countDone.textContent = done;
}

// ===============================
// Create Task
// ===============================
async function createTaskFromModal() {
  const employee = cEmpName.value.trim();
  const employeeId = cEmpId.value.trim();
  const name = cTaskName.value.trim();
  const target = Number(cTargetValue.value);
  const current = Number(cCurrentValue.value || 0);
  const deadline = cDeadline.value;

  if (!employee || !name || !target || !deadline) {
    alert("أكمل الحقول المطلوبة");
    return;
  }

  const percent = computePercent(current, target);

  await addDoc(tasksCol, {
    name,
    employee,
    employeeId,
    target,
    current,
    percent,
    status: percent >= 100 ? "done" : "in-progress",
    deadline: new Date(deadline).toISOString(),
    createdAt: serverTimestamp(),
    history: []
  });

  await loadTasks();
  renderBoard();
}

// ===============================
// Increment Update
// ===============================
async function incrementalUpdate(task) {
  const inc = Number(prompt("أدخل مقدار الزيادة:", "1"));
  if (!inc || inc <= 0) return;

  const newCurrent = task.current + inc;
  const percent = computePercent(newCurrent, task.target);
  const status = percent >= 100 ? "done" : "in-progress";

  await updateDoc(doc(db, "tasks", task.id), {
    current: newCurrent,
    percent,
    status,
    history: [
      ...(task.history || []),
      {
        at: new Date().toISOString(),
        delta: inc
      }
    ]
  });

  await loadTasks();
  renderBoard();
}

// ===============================
// Delete Task
// ===============================
async function deleteTask(id) {
  if (!confirm("هل أنت متأكد من الحذف؟")) return;
  await deleteDoc(doc(db, "tasks", id));
  await loadTasks();
  renderBoard();
}

// ===============================
// Init
// ===============================
async function initTasksPage() {
  const allowed = await checkAdminAccess();
  if (!allowed) return;

  await loadTasks();
  renderBoard();
}

initTasksPage();
