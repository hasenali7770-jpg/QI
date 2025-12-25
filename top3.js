import { db } from "./firebase.js";
import {
  collection,
  addDoc,
  getDocs,
  deleteDoc,
  doc,
  getDoc,
  updateDoc,
  serverTimestamp,
  query,
  orderBy
} from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

/* =====================
   AUTH / ROLE
===================== */
let isAdmin = false;
let currentEmail = "";

async function checkAdmin() {
  currentEmail = localStorage.getItem("kb_user_email");
  if (!currentEmail) {
    window.location.href = "login.html";
    return;
  }

  const snap = await getDoc(doc(db, "users", currentEmail));
  const role = snap.exists() ? snap.data().role : "";

  isAdmin = String(role).toLowerCase() === "admin";
  document.getElementById("addTopBtn").style.display =
    isAdmin ? "inline-flex" : "none";
}

/* =====================
   LOAD
===================== */
let top3 = [];

async function loadTop3() {
  const q = query(
    collection(db, "top3"),
    orderBy("rank", "asc")
  );

  const snap = await getDocs(q);
  top3 = snap.docs.map(d => ({ id: d.id, ...d.data() }));

  renderTop3();
}

/* =====================
   RENDER
===================== */
function renderTop3() {
  const grid = document.getElementById("top3Grid");
  grid.innerHTML = "";

  top3.forEach(emp => {
    const adminBtns = isAdmin ? `
      <button class="edit-btn" onclick="editTop('${emp.id}')">تعديل</button>
      <button class="delete-btn" onclick="deleteTop('${emp.id}')">حذف</button>
    ` : "";

    grid.innerHTML += `
      <div class="top-card">

        <div class="top-img"
          style="background-image:url('${emp.image}');
                 background-size:cover;
                 background-position:center;">
        </div>

        <h3 class="emp-name">${emp.name}</h3>
        <p class="emp-id">ID: ${emp.empId}</p>

        <div class="rank-badge">المركز ${emp.rank}</div>

        <div class="btn-row">
          ${adminBtns}
        </div>

      </div>
    `;
  });
}

/* =====================
   POPUP
===================== */
function openAddPopup() {
  if (!isAdmin) return;
  popupTop3.style.display = "flex";
}

function closePopup() {
  popupTop3.style.display = "none";
  empName.value = "";
  empId.value = "";
  empImage.value = "";
}

/* =====================
   ADD
===================== */
async function saveEmployee() {
  if (!isAdmin) return;

  const name = empName.value.trim();
  const id = empId.value.trim();
  const rank = empRank.value;
  const file = empImage.files[0];

  if (!name || !id || !file) {
    alert("أكمل جميع البيانات");
    return;
  }

  const reader = new FileReader();
  reader.onloadend = async () => {
    await addDoc(collection(db, "top3"), {
      name,
      empId: id,
      rank,
      image: reader.result,
      createdAt: serverTimestamp(),
      createdBy: currentEmail
    });

    closePopup();
    loadTop3();
  };

  reader.readAsDataURL(file);
}

/* =====================
   EDIT
===================== */
async function editTop(docId) {
  if (!isAdmin) return;

  const emp = top3.find(e => e.id === docId);
  if (!emp) return;

  const name = prompt("اسم الموظف:", emp.name);
  if (!name) return;

  const empId = prompt("ID الموظف:", emp.empId);
  const rank = prompt("الترتيب (1-3):", emp.rank);

  await updateDoc(doc(db, "top3", docId), {
    name,
    empId,
    rank
  });

  loadTop3();
}

/* =====================
   DELETE
===================== */
async function deleteTop(docId) {
  if (!isAdmin) return;
  if (!confirm("هل تريد حذف هذا الموظف؟")) return;

  await deleteDoc(doc(db, "top3", docId));
  loadTop3();
}

/* =====================
   EXPOSE
===================== */
window.openAddPopup = openAddPopup;
window.closePopup = closePopup;
window.saveEmployee = saveEmployee;
window.editTop = editTop;
window.deleteTop = deleteTop;

/* =====================
   INIT
===================== */
await checkAdmin();
await loadTop3();
