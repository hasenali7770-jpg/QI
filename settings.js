// THEME UI
const switchEl = document.getElementById("themeSwitch");
const iconEl = document.getElementById("themeIcon");

function syncThemeUI(mode){
  if(mode === "dark"){
    switchEl.classList.add("active");
    iconEl.innerText = "☀️";
  }else{
    switchEl.classList.remove("active");
    iconEl.innerText = "🌙";
  }
}

syncThemeUI(window.KB_THEME.get());

window.toggleTheme = function(){
  window.KB_THEME.toggle();
};

window.addEventListener("kb-theme-changed", e=>{
  syncThemeUI(e.detail);
});

// USER INFO
const email = localStorage.getItem("kb_user_email") || "";
document.getElementById("userEmail").innerText = email;
document.getElementById("userName").innerText =
  email ? email.split("@")[0] : "—";

document.getElementById("userRole").innerText =
  (localStorage.getItem("kb_user_role") || "user").toUpperCase();
