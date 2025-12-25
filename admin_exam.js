import { db } from "./firebase.js";
import {
  collection,
  getDocs,
  deleteDoc,
  doc,
  updateDoc,
  getDoc
} from "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

document.addEventListener("DOMContentLoaded", async () => {

  /* ===============================
     Admin Guard
  =============================== */
  const currentEmail = localStorage.getItem("kb_user_email") || "";
  if (!currentEmail) {
    location.href = "login.html";
    return;
  }

  const userSnap = await getDoc(doc(db, "users", currentEmail));
  const isAdmin =
    userSnap.exists() &&
    String(userSnap.data().role || "").toLowerCase() === "admin";

  if (!isAdmin) {
    alert("غير مخول");
    location.href = "dashboard.html";
    return;
  }



  /* ===============================
// 🔗 ضع رابط Google Apps Script هنا
  =============================== */


const btnSheet = document.getElementById("btnSheet");

// 🔗 ضع رابط Google Apps Script هنا
const SHEET_URL = "https://script.google.com/macros/s/AKfycby56wMOMBEBl5vp0T1rFeh657mdJxkw1RT6dkjbmJuZV7xk8GtPxNQtlFTFVfiUhTQxrA/exec";

btnSheet.onclick = async () => {
  if (!cache.length) {
    alert("❌ لا توجد بيانات للإرسال");
    return;
  }

  btnSheet.disabled = true;
  btnSheet.innerText = "⏳ جاري الإرسال...";

  try {
    const res = await fetch(SHEET_URL, {
      method: "POST",
      body: JSON.stringify(cache)
    });

    const text = await res.text();
    console.log("Google Sheet Response:", text);

    if (text.includes("success")) {
      alert("✅ تم إرسال البيانات إلى Google Sheet بنجاح");
    } else {
      alert("❌ رد غير متوقع من Google Sheet");
    }

  } catch (err) {
    console.error("Fetch Error:", err);
    alert("❌ فشل الاتصال مع Google Sheet");
  }

  btnSheet.disabled = false;
  btnSheet.innerText = "📤 Google Sheet";
};






  /* ===============================
     Elements
  =============================== */
  const tbody = document.getElementById("tbody");
  const btnExcel = document.getElementById("btnExcel");
  const btnPDF   = document.getElementById("btnPDF");
  const btnClear = document.getElementById("btnClear");
  const searchInput = document.getElementById("searchInput");
  const hint = document.getElementById("hint");

  let cache = [];

  /* ===============================
     Load Results
  =============================== */
  async function loadResults() {
    const snap = await getDocs(collection(db, "exam_attempts"));
    tbody.innerHTML = "";
    cache = [];

    const rows = snap.docs
      .map(d => ({ id: d.id, ...d.data() }))
      .filter(r => ["submitted", "finalized"].includes(r.status));

    hint.textContent = `عدد المحاولات: ${rows.length}`;

    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="7">لا توجد محاولات</td></tr>`;
      return;
    }

    rows
      .sort((a, b) => (b.submittedAt?.seconds || 0) - (a.submittedAt?.seconds || 0))
      .forEach(r => {

        const total = Number(r.totalScore || 0);
        const reviewLabel =
          r.status === "finalized" ? "مصحح" : "بانتظار التصحيح";

        /* ⭐ البيانات المستخدمة فقط في Excel / PDF */
        cache.push({
          الاسم: r.employeeName || "",
          الرقم: r.employeeId || "",
          القسم: r.section || "",
          الدرجة: total,
          "حالة التصحيح": reviewLabel,
          ملاحظة: r.adminNote || ""
        });

        tbody.innerHTML += `
          <tr>
            <td>${r.employeeName || "—"}</td>
            <td>${r.employeeId || "—"}</td>
            <td>${r.section || "—"}</td>
            <td>${total} / 100</td>
            <td class="${r.status === "finalized" ? "status-reviewed" : "status-pending"}">
              ${reviewLabel}
            </td>
            <td>
              <input class="note-input"
                value="${r.adminNote || ""}"
                placeholder="ملاحظة..."
                onchange="saveNote('${r.id}', this.value)">
            </td>
            <td>
              <button class="view-btn"
                onclick="openAttempt('${r.id}')">
                عرض التفاصيل
              </button>
            </td>
          </tr>
        `;
      });
  }

  /* ===============================
     Search
  =============================== */
  searchInput.oninput = () => {
    const q = (searchInput.value || "").toLowerCase();
    document.querySelectorAll("#tbody tr").forEach(tr => {
      tr.style.display = tr.innerText.toLowerCase().includes(q) ? "" : "none";
    });
  };

  /* ===============================
     Save Note
  =============================== */
  window.saveNote = async (id, val) => {
    await updateDoc(doc(db, "exam_attempts", id), { adminNote: val });
  };

  /* ===============================
     Export Excel ✅ WORKING
  =============================== */
  btnExcel.onclick = () => {
  if (!cache.length) {
    alert("❌ لا توجد بيانات للتصدير");
    return;
  }

  const ws = window.XLSX.utils.json_to_sheet(cache);
  const wb = window.XLSX.utils.book_new();

  window.XLSX.utils.book_append_sheet(wb, ws, "Exam Results");
  window.XLSX.writeFile(wb, "Exam_Results.xlsx");
};


  /* ===============================
     Export PDF
  =============================== */
  btnPDF.onclick = () => {
    const tableWrap = document.querySelector(".table-wrap");
    if (!tableWrap) {
      alert("لا توجد بيانات للتصدير");
      return;
    }

    html2pdf().set({
      margin: 8,
      filename: "Exam_Results.pdf",
      html2canvas: { scale: 2 },
      jsPDF: { unit: "mm", format: "a4", orientation: "landscape" }
    }).from(tableWrap).save();
  };

  /* ===============================
     Clear Finalized Results
  =============================== */
btnClear.onclick = async () => {
  const ok = confirm(
    "⚠️ سيتم حذف جميع نتائج الامتحانات (المكتملة وغير المكتملة) حتى لو كان الامتحان محذوف.\nهل أنت متأكد؟"
  );
  if (!ok) return;

  btnClear.disabled = true;
  btnClear.innerText = "⏳ جاري الحذف...";

  try {
    const snap = await getDocs(collection(db, "exam_attempts"));

    if (snap.empty) {
      alert("ℹ️ لا توجد نتائج للحذف");
      btnClear.disabled = false;
      btnClear.innerText = "🗑️ حذف النتائج";
      return;
    }

    let count = 0;

    for (const d of snap.docs) {
      await deleteDoc(doc(db, "exam_attempts", d.id));
      count++;
    }

    alert(`✅ تم حذف ${count} نتيجة بنجاح`);

    // تحديث الجدول
    loadResults();

  } catch (err) {
    console.error(err);
    alert("❌ حدث خطأ أثناء حذف النتائج");
  }

  btnClear.disabled = false;
  btnClear.innerText = "🗑️ حذف النتائج";
};


  /* ===============================
     Navigation
  =============================== */
  window.openAttempt = (id) => {
    localStorage.setItem("admin_selected_attempt", id);
    location.href = "admin_attempt.html";
  };

  /* ===============================
     Start
  =============================== */
  loadResults();
});
