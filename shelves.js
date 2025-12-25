import { db } from "./firebase.js";

import {
  collection,
  getDocs,
  addDoc,
  updateDoc,
  deleteDoc,
  doc,
  getDoc,
  serverTimestamp,
  query,
  orderBy
} from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

// ===============================
// Helpers (Search highlight)
// ===============================
function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function highlight(text, search) {
  if (!search || !text) return text;
  const pattern = new RegExp("(" + escapeRegExp(search) + ")", "gi");
  return text.replace(pattern, '<span class="highlight">$1</span>');
}

// ===============================
// Auth/Role (from Firestore users)
// ===============================
let isAdmin = false;
let currentEmail = "";

async function checkAdmin() {
  currentEmail = localStorage.getItem("kb_user_email") || "";
  if (!currentEmail) {
    // اذا ماكو ايميل مخزن، رجّعه للّوجن
    window.location.href = "login.html";
    return;
  }

  const userRef = doc(db, "users", currentEmail);
  const snap = await getDoc(userRef);

  const role = (snap.exists() ? (snap.data().role || "") : "");
  isAdmin = String(role).toLowerCase() === "admin";

  // اخفاء زر الاضافة لغير الادمن
  const addBtn = document.getElementById("addShelfBtn");
  if (addBtn) addBtn.style.display = isAdmin ? "inline-flex" : "none";
}

// ===============================
// Data
// ===============================
let shelves = []; // {id,title,desc,image}

// ===============================
// Load + Render
// ===============================
async function loadShelves() {
  const q = query(collection(db, "shelves"), orderBy("createdAt", "desc"));
  const snap = await getDocs(q);

  shelves = snap.docs.map(d => ({ id: d.id, ...d.data() }));
  renderShelves(document.querySelector(".shelves-search")?.value?.trim() || "");
}

function renderShelves(search = "") {
  const grid = document.getElementById("shelvesGrid");
  grid.innerHTML = "";

  const s = search.trim();
  const filtered = s
    ? shelves.filter(x =>
        (x.title || "").includes(s) || (x.desc || "").includes(s)
      )
    : shelves;

  filtered.forEach((shelf) => {
    const bg = shelf.image ? `background-image:url('${shelf.image}')` : "";
    const noImg = shelf.image ? "" : "no-img";

    // buttons حسب الصلاحية
    const adminButtons = isAdmin ? `
      <button class="edit-btn" onclick="editDetails('${shelf.id}')">تعديل</button>
      <button class="delete-btn" onclick="deleteShelf('${shelf.id}')">حذف</button>
    ` : "";

    grid.innerHTML += `
      <div class="shelf-card">
        <div class="shelf-img ${noImg}" style="${bg}"></div>

        <h3>${highlight(shelf.title || "", s)}</h3>
        <p>${highlight(shelf.desc || "", s)}</p>

        <div class="btn-row">
          <button class="view-btn" onclick="viewShelf('${shelf.id}')">عرض التفاصيل</button>
          ${adminButtons}
        </div>
      </div>
    `;
  });
}

// ===============================
// Events
// ===============================
document.querySelector(".shelves-search")?.addEventListener("input", function () {
  renderShelves(this.value.trim());
});

// ===============================
// View shelf
// ===============================
function viewShelf(id) {
  localStorage.setItem("selectedShelfId", id);
  window.location.href = "shelf_view.html";
}

// ===============================
// Add shelf (Admin only)
// ===============================
function openAddShelf() {
  if (!isAdmin) return;
  document.getElementById("popupAdd").style.display = "flex";
}

function closePopup() {
  document.getElementById("popupAdd").style.display = "none";
  document.getElementById("popupTitle").value = "";
  document.getElementById("popupDesc").value = "";
  document.getElementById("popupImage").value = "";
}

async function confirmAdd() {
  if (!isAdmin) return;

  const title = document.getElementById("popupTitle").value.trim();
  const desc = document.getElementById("popupDesc").value.trim();
  const file = document.getElementById("popupImage").files[0];

  if (!title) return alert("أدخل اسم الرف");

  const saveDoc = async (imageData = "") => {
    await addDoc(collection(db, "shelves"), {
      title,
      desc,
      image: imageData,
      createdAt: serverTimestamp(),
      createdBy: currentEmail
    });
    closePopup();
    await loadShelves();
  };

  if (file) {
    const reader = new FileReader();
    reader.onloadend = async () => {
      await saveDoc(reader.result);
    };
    reader.readAsDataURL(file);
  } else {
    await saveDoc("");
  }
}

// ===============================
// Edit shelf (Admin only)
// ===============================
let currentEditId = null;

async function editDetails(id) {
  if (!isAdmin) return;

  const shelf = shelves.find(x => x.id === id);
  if (!shelf) return;

  currentEditId = id;

  document.getElementById("editTitle").value = shelf.title || "";
  document.getElementById("editDesc").value = shelf.desc || "";
  document.getElementById("editImage").value = "";

  document.getElementById("popupEdit").style.display = "flex";
}

function closeEditPopup() {
  document.getElementById("popupEdit").style.display = "none";
  document.getElementById("editTitle").value = "";
  document.getElementById("editDesc").value = "";
  document.getElementById("editImage").value = "";
  currentEditId = null;
}

async function saveEdit() {
  if (!isAdmin) return;
  if (!currentEditId) return;

  const title = document.getElementById("editTitle").value.trim();
  const desc = document.getElementById("editDesc").value.trim();
  const file = document.getElementById("editImage").files[0];

  if (!title) return alert("أدخل اسم الرف");

  const ref = doc(db, "shelves", currentEditId);

  if (file) {
    const reader = new FileReader();
    reader.onloadend = async () => {
      await updateDoc(ref, { title, desc, image: reader.result });
      closeEditPopup();
      await loadShelves();
    };
    reader.readAsDataURL(file);
  } else {
    await updateDoc(ref, { title, desc });
    closeEditPopup();
    await loadShelves();
  }
}

// ===============================
// Delete shelf (Admin only)
// ===============================
async function deleteShelf(id) {
  if (!isAdmin) return;
  if (!confirm("هل تريد حذف هذا الرف؟")) return;

  await deleteDoc(doc(db, "shelves", id));
  await loadShelves();
}

// ===============================
// Expose for HTML onclick (Important)
// ===============================
window.openAddShelf = openAddShelf;
window.closePopup = closePopup;
window.confirmAdd = confirmAdd;

window.editDetails = editDetails;
window.saveEdit = saveEdit;
window.closeEditPopup = closeEditPopup;

window.deleteShelf = deleteShelf;
window.viewShelf = viewShelf;

// ===============================
// INIT
// ===============================
await checkAdmin();
await loadShelves();
