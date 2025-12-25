import { db } from "./firebase.js";
import {
  doc,
  getDoc
} from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

const searchBtn = document.getElementById("searchBtn");
const searchId = document.getElementById("searchId");
const container = document.getElementById("tasksContainer");

searchBtn.onclick = async () => {
  const id = searchId.value.trim();
  container.innerHTML = "";

  if (!id) {
    alert("أدخل Employee ID");
    return;
  }

  const snap = await getDoc(doc(db, "tr_tasks", id));

  if (!snap.exists()) {
    container.innerHTML = `<div class="empty">لا توجد تاسكات لهذا الموظف</div>`;
    return;
  }

  const data = snap.data();

  if (!data.tasks || !data.tasks.length) {
    container.innerHTML = `<div class="empty">لا توجد تاسكات مسجلة</div>`;
    return;
  }

  data.tasks.forEach(t => {
    const statusClass = t.status === "DONE" ? "done" : "inprog";

    container.innerHTML += `
      <div class="task-card">
        <div class="task-title">${t.title}</div>
        <span class="status ${statusClass}">
          ${t.status}
        </span>
      </div>
    `;
  });
};
