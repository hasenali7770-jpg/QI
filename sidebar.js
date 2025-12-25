fetch("sidebar.html")
  .then(res => res.text())
  .then(html => {
    document.getElementById("sidebar").innerHTML = html;

    const sections = document.querySelectorAll(".section");
    const items = document.querySelectorAll(".item");
    const current = window.location.pathname.split("/").pop();

    sections.forEach(sec => {
      sec.querySelector(".section-header")
        .addEventListener("click", () => {
          sec.classList.toggle("open");
        });
    });

    items.forEach(item => {
      item.addEventListener("click", () => {
        window.location.href = item.dataset.page;
      });

      if (item.dataset.page === current) {
        item.classList.add("active");
        item.closest(".section").classList.add("open");
      }
    });
  });
