function exportExcelFromAdmin() {
  const data = JSON.parse(localStorage.getItem("kb_exam_results") || "[]");

  if (data.length === 0) {
    alert("لا توجد نتائج!");
    return;
  }

  let rows = [
    ["اسم الموظف", "الدرجة النهائية", "الوقت"]
  ];

  data.forEach(r => {
    const manual = r.answers.filter(a => a.manual).reduce((s,a)=>s+(a.manualScore||0),0);
    const finalScore = r.autoScore + manual;

    rows.push([
      r.employeeName,
      finalScore,
      new Date(r.submittedAt).toLocaleString("ar-IQ")
    ]);
  });

  let csv = rows.map(e => e.join(",")).join("\n");

  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = "exam_results.csv";
  a.click();
}
