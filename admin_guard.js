import { auth, db } from "./firebase.js";
import { onAuthStateChanged } from 
  "https://www.gstatic.com/firebasejs/10.7.2/firebase-auth.js";
import { doc, getDoc } from 
  "https://www.gstatic.com/firebasejs/10.7.2/firebase-firestore.js";

export function requireAdmin({ contentId, unauthorizedId }) {

  onAuthStateChanged(auth, async (user) => {

    if (!user) {
      showUnauthorized();
      return;
    }

    const snap = await getDoc(doc(db, "users", user.email));

    if (!snap.exists()) {
      showUnauthorized();
      return;
    }

    const data = snap.data();
    const role = (data.role || "").toLowerCase();

    if (role !== "admin") {
      showUnauthorized();
      return;
    }

    // ✔️ Admin → عرض الصفحة
    document.getElementById(contentId).style.display = "block";
  });

  function showUnauthorized() {
    if (contentId) document.getElementById(contentId).style.display = "none";
    if (unauthorizedId) document.getElementById(unauthorizedId).style.display = "flex";
  }
}
