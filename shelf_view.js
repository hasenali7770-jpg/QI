import { db } from "./firebase.js";
import {
  doc,
  getDoc,
  collection,
  addDoc,
  getDocs,
  deleteDoc,
  updateDoc,
  serverTimestamp,
  query,
  orderBy
} from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

// ==========================
// Auth / Role
// ==========================
let isAdmin = false;
let currentEmail = "";

async function checkAdmin() {
  currentEmail = localStorage.getItem("kb_user_email") || "";
  if (!currentEmail) {
    window.location.href = "login.html";
    return;
  }

  const userSnap = await getDoc(doc(db, "users", currentEmail));
  const role = userSnap.exists() ? userSnap.data().role : "";
  isAdmin = String(role).toLowerCase() === "admin";

  document.getElementById("addCardBtn").style.display =
    isAdmin ? "inline-flex" : "none";
}

// ==========================
// Shelf
// ==========================
const shelfId = localStorage.getItem("selectedShelfId");
if (!shelfId) {
  alert("لم يتم تحديد رف");
  window.location.href = "shelves.html";
}

let cards = [];

// ==========================
// Load Shelf Info
// ==========================
async function loadShelf() {
  const snap = await getDoc(doc(db, "shelves", shelfId));
  if (!snap.exists()) return;

  document.getElementById("shelfTitle").textContent = snap.data().title;
  document.getElementById("shelfDesc").textContent = snap.data().desc || "";
}

// ==========================
// Load Cards
// ==========================
async function loadCards() {
  const q = query(
    collection(db, "shelves", shelfId, "cards"),
    orderBy("createdAt", "desc")
  );

  const snap = await getDocs(q);
  cards = snap.docs.map(d => ({ id: d.id, ...d.data() }));
  renderCards();
}

// ==========================
// Render Cards
// ==========================
function renderCards() {
  const grid = document.getElementById("cardsGrid");
  grid.innerHTML = "";

  cards.forEach(card => {
    const bg = card.image ? `background-image:url('${card.image}')` : "";

    const adminBtns = isAdmin ? `
      <button class="add-article-btn" onclick="openArticle('${card.id}')">إضافة مقال</button>
      <button class="edit-card" onclick="editCard('${card.id}')">تعديل</button>
      <button class="delete-card" onclick="deleteCard('${card.id}')">حذف</button>
    ` : "";

    grid.innerHTML += `
      <div class="card-box">
        <div class="card-img" style="${bg}"></div>

        <h3 class="card-title">${card.title}</h3>
        <p class="card-desc">${card.desc || ""}</p>

        <div class="card-btns">
          <button class="view-article-btn" onclick="viewArticle('${card.id}')">
            عرض المقال
          </button>
          ${adminBtns}
        </div>
      </div>
    `;
  });
}

// ==========================
// Add Card
// ==========================
function openAddCard() {
  if (!isAdmin) return;
  document.getElementById("popupCard").style.display = "flex";
}

function closeCardPopup() {
  document.getElementById("popupCard").style.display = "none";
  cardTitle.value = "";
  cardDesc.value = "";
  cardImage.value = "";
}

async function saveCard() {
  if (!isAdmin) return;

  const title = cardTitle.value.trim();
  const desc = cardDesc.value.trim();
  const file = cardImage.files[0];

  if (!title) return alert("أدخل عنوان البطاقة");

  const save = async (img = "") => {
    await addDoc(collection(db, "shelves", shelfId, "cards"), {
      title,
      desc,
      image: img,
      createdAt: serverTimestamp(),
      createdBy: currentEmail
    });

    closeCardPopup();
    loadCards();
  };

  if (file) {
    const r = new FileReader();
    r.onloadend = () => save(r.result);
    r.readAsDataURL(file);
  } else {
    save("");
  }
}

// ==========================
// Delete Card
// ==========================
async function deleteCard(id) {
  if (!isAdmin) return;
  if (!confirm("هل تريد حذف البطاقة؟")) return;

  await deleteDoc(doc(db, "shelves", shelfId, "cards", id));
  loadCards();
}

// ==========================
// Navigation
// ==========================
function openArticle(id) {
  localStorage.setItem("selectedCardId", id);
  window.location.href = "card_article.html";
}

function viewArticle(id) {
  localStorage.setItem("selectedCardId", id);
  window.location.href = "card_article_view.html";
}

// ==========================
// Expose (onclick)
// ==========================
window.openAddCard = openAddCard;
window.closeCardPopup = closeCardPopup;
window.saveCard = saveCard;
window.deleteCard = deleteCard;
window.openArticle = openArticle;
window.viewArticle = viewArticle;

// ==========================
// Init
// ==========================
await checkAdmin();
await loadShelf();
await loadCards();
