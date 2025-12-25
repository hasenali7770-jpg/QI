function exportAllReportsAsPDF(results) {
  if (!results || results.length === 0) {
    alert("لا توجد نتائج لتصديرها!");
    return;
  }

  results.forEach(r => {
    window.open(`pdf_export.html?id=${r.id}`, "_blank");
  });
}
