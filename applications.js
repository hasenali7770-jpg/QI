/* ==============================
   Firebase Imports (Firestore فقط)
============================== */
import { db } from "./firebase.js";

import {
  collection,
  addDoc,
  getDocs,
  doc,
  getDoc,
  deleteDoc,
  serverTimestamp
} from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

/* ==============================
   DOM Elements
============================== */
const grid = document.getElementById("appsGrid");
const searchInput = document.getElementById("searchInput");
const addBtn = document.getElementById("addAppBtn");
const currentUserSpan = document.getElementById("currentUser");

/* ==============================
   State
============================== */
let isAdmin = false;
let allApps = [];

/* ==============================
   Helpers
============================== */
function esc(str = "") {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function openAddPopup() {
  document.getElementById("addPopup").style.display = "flex";
}

window.closePopup = function () {
  document.querySelectorAll(".popup-overlay").forEach(p => {
    p.style.display = "none";
  });

  document.getElementById("addTitle").value = "";
  document.getElementById("addDesc").value = "";
  document.getElementById("addLink").value = "";
};

/* ==============================
   Load User Role (Admin / User)
============================== */
async function loadCurrentUserRole() {
  const email = localStorage.getItem("kb_user_email");
  currentUserSpan.textContent = email ? email.split("@")[0] : "User";

  if (!email) {
    addBtn.style.display = "none";
    return;
  }

  const snap = await getDoc(doc(db, "users", email));
  if (!snap.exists()) {
    addBtn.style.display = "none";
    return;
  }

  isAdmin = snap.data().role?.toLowerCase() === "admin";
  addBtn.style.display = isAdmin ? "inline-flex" : "none";
}

/* ==============================
   Fetch Applications
============================== */
async function fetchApps() {
  const snap = await getDocs(collection(db, "apps"));
  allApps = snap.docs.map(d => ({ id: d.id, ...d.data() }));
  renderApps(allApps);
}

/* ==============================
   Render Applications
============================== */
function renderApps(list) {
  grid.innerHTML = "";

  list.forEach(app => {
    grid.innerHTML += `
      <div class="app-card">
        <div class="app-img"></div>

        <h3>${esc(app.title)}</h3>
        <p>${esc(app.desc)}</p>

        <a class="run-btn" href="${esc(app.link)}" target="_blank" rel="noopener">
          تشغيل
        </a>

        ${
          isAdmin
            ? `<div class="actions">
                 <button class="delete-btn" onclick="deleteApp('${app.id}')">
                   حذف
                 </button>
               </div>`
            : ""
        }
      </div>
    `;
  });
}

/* ==============================
   Search
============================== */
searchInput.addEventListener("input", () => {
  const term = searchInput.value.trim().toLowerCase();
  if (!term) {
    renderApps(allApps);
    return;
  }

  renderApps(
    allApps.filter(app =>
      app.title?.toLowerCase().includes(term)
    )
  );
});

/* ==============================
   Add Application (Admin)
============================== */
addBtn.addEventListener("click", () => {
  if (!isAdmin) return;
  openAddPopup();
});

document.getElementById("addSaveBtn").addEventListener("click", async () => {
  if (!isAdmin) return;

  const title = document.getElementById("addTitle").value.trim();
  const desc = document.getElementById("addDesc").value.trim();
  const link = document.getElementById("addLink").value.trim();

  if (!title || !desc || !link) {
    alert("يرجى ملء جميع الحقول");
    return;
  }

  await addDoc(collection(db, "apps"), {
    title,
    desc,
    link,
    createdAt: serverTimestamp()
  });

  closePopup();
  fetchApps();
});

/* ==============================
   Delete Application (Admin)
============================== */
window.deleteApp = async function (id) {
  if (!isAdmin) return;

  if (!confirm("هل تريد حذف هذا التطبيق؟")) return;

  await deleteDoc(doc(db, "apps", id));
  fetchApps();
};

/* ==============================
   Init
============================== */
await loadCurrentUserRole();
await fetchApps();
