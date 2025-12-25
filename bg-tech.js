const canvas = document.getElementById("techCanvas");
const ctx = canvas.getContext("2d");

let w, h, dpr;
let nodes = [];
let words = [];
let focusWord = null;
let focusTimer = 0;

const CONFIG = {
  NODE_COUNT: 80,
  LINK_DIST: 150,
};

const WORD_GROUPS = {
  NETWORK: ["NETWORK", "SWITCHING", "ROUTING"],
  IT: ["IT", "INFORMATION TECHNOLOGY"],
  SUPPORT: ["TECHNICAL SUPPORT", "BACK OFFICE"],
  SECURITY: ["SECURITY", "NOC"]
};

const GROUP_COLORS = {
  NETWORK: "#22d3ee",
  IT: "#60a5fa",
  SUPPORT: "#38bdf8",
  SECURITY: "#818cf8"
};

function rand(min, max) {
  return Math.random() * (max - min) + min;
}

function resize() {
  dpr = Math.min(window.devicePixelRatio || 1, 2);
  w = canvas.width = innerWidth * dpr;
  h = canvas.height = innerHeight * dpr;
  canvas.style.width = "100%";
  canvas.style.height = "100%";

  nodes = [];
  for (let i = 0; i < CONFIG.NODE_COUNT; i++) {
    nodes.push({
      x: rand(0, w),
      y: rand(0, h),
      vx: rand(-0.25, 0.25) * dpr,
      vy: rand(-0.25, 0.25) * dpr,
      r: rand(0.6, 1.4) * dpr,
      a: rand(0.12, 0.3)
    });
  }

  words = [];
  Object.keys(WORD_GROUPS).forEach((group, gi) => {
    WORD_GROUPS[group].forEach(txt => {
      words.push({
        text: txt,
        group,
        color: GROUP_COLORS[group],
        x: rand(w * 0.2 * gi, w * 0.2 * (gi + 2)),
        y: rand(0, h),
        vx: rand(-0.12, 0.12) * dpr,
        vy: rand(-0.12, 0.12) * dpr,
        size: txt.length < 6 ? 26 * dpr : 16 * dpr,
        alpha: 0.45,
        aura: 0
      });
    });
  });
}

canvas.addEventListener("click", e => {
  const r = canvas.getBoundingClientRect();
  const mx = (e.clientX - r.left) * dpr;
  const my = (e.clientY - r.top) * dpr;

  words.forEach(w => {
    const d = Math.hypot(w.x - mx, w.y - my);
    if (d < 70 * dpr) {
      focusWord = w;
      focusTimer = 60;
      w.aura = 1;
    }
  });
});

function draw() {
  ctx.clearRect(0, 0, w, h);

  // Network
  nodes.forEach(n => {
    n.x += n.vx;
    n.y += n.vy;
    if (n.x < -20) n.x = w + 20;
    if (n.x > w + 20) n.x = -20;
    if (n.y < -20) n.y = h + 20;
    if (n.y > h + 20) n.y = -20;
  });

  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j];
      const dist = Math.hypot(a.x - b.x, a.y - b.y);
      if (dist < CONFIG.LINK_DIST * dpr) {
        ctx.strokeStyle = `rgba(59,130,246,${(1 - dist / (CONFIG.LINK_DIST * dpr)) * 0.15})`;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();
      }
    }
  }

  nodes.forEach(n => {
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(255,255,255,${n.a})`;
    ctx.fill();
  });

  // Words + Aura
  words.forEach(wd => {
    wd.x += wd.vx;
    wd.y += wd.vy;

    if (wd.x < -80) wd.x = w + 80;
    if (wd.x > w + 80) wd.x = -80;
    if (wd.y < -80) wd.y = h + 80;
    if (wd.y > h + 80) wd.y = -80;

    if (wd.aura > 0) {
      ctx.beginPath();
      ctx.arc(wd.x, wd.y, 55 * dpr * wd.aura, 0, Math.PI * 2);
      ctx.strokeStyle = `${wd.color}55`;
      ctx.lineWidth = 2 * dpr;
      ctx.stroke();
      wd.aura *= 0.92;
    }

    ctx.save();
    ctx.globalAlpha = wd.alpha;
    ctx.shadowColor = wd.color;
    ctx.shadowBlur = 18 * dpr;
    ctx.fillStyle = wd.color;
    ctx.font = `700 ${wd.size}px Cairo`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(wd.text, wd.x, wd.y);
    ctx.restore();
  });

  // Focus Mode
  if (focusWord && focusTimer > 0) {
    focusTimer--;
    ctx.beginPath();
    ctx.arc(focusWord.x, focusWord.y, 90 * dpr, 0, Math.PI * 2);
    ctx.strokeStyle = `${focusWord.color}66`;
    ctx.lineWidth = 1.5 * dpr;
    ctx.stroke();
  }

  requestAnimationFrame(draw);
}

window.addEventListener("resize", resize);
resize();
draw();
