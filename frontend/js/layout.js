// Things every page shares: the top navigation, word-by-word headings, and scroll-in animations.

// A small version of the background as the logo: rings plus the four layer dots (CVE, CWE, CAPEC, ATT&CK)
function ring(r, seed) {
  let d = "";
  for (let s = 0; s <= 48; s++) {
    const a = (s / 48) * Math.PI * 2;
    const rr = r * (1 + 0.1 * Math.sin(3 * a + seed) + 0.05 * Math.sin(5 * a - seed));
    d += `${s ? "L" : "M"}${(16 + Math.cos(a) * rr).toFixed(2)},${(16 + Math.sin(a) * rr).toFixed(2)}`;
  }
  return d + "Z";
}
const LOGO = `<svg class="logo" viewBox="0 0 32 32" width="26" height="26" aria-hidden="true">
  <circle cx="16" cy="16" r="15" fill="#f5efe4" stroke="#e8dccb"/>
  <g class="logo-rings">${[4, 7.5, 11].map((r, i) => `<path d="${ring(r, i * 0.9)}" fill="none" stroke="#8b5cf6" opacity="0.7"/>`).join("")}</g>
  <circle cx="22" cy="8" r="1.8" fill="#f59e0b"/><circle cx="9" cy="12" r="1.8" fill="#ec4899"/>
  <circle cx="23" cy="21" r="1.8" fill="#8b5cf6"/><circle cx="13" cy="23" r="1.8" fill="#14b8a6"/>
</svg>`;

const PAGES = [["ask", "index.html", "Ask"], ["history", "history.html", "History"],
               ["insights", "insights.html", "Insights"], ["research", "research.html", "Research"]];

// Fills <nav id="nav" data-page="..."> with the logo and the page links
export function renderNav() {
  const nav = document.getElementById("nav");
  const current = nav.dataset.page;
  nav.className = "topnav";
  nav.innerHTML = `<a href="index.html" class="brand">${LOGO}Cyber Defense RAG</a>
    <div class="links">${PAGES.map(([key, href, label]) =>
      `<a href="${href}"${key === current ? ' aria-current="page"' : ""}>${label}</a>`).join("")}</div>`;
}

// Splits every heading with data-words into words; CSS makes each word rise in after the one before
export function splitWords() {
  document.querySelectorAll("[data-words]").forEach((el) => {
    el.innerHTML = el.textContent.trim().split(/\s+/).map((word, i) =>
      `<span class="word-mask"><span class="word" style="--i:${i}">${word}</span></span>`).join(" ");
  });
}

// Elements with data-reveal fade and rise in when scrolled into view (CSS plays it when "shown" is added).
// Numbers with data-count inside them count up from 0.
export function reveal(root = document) {
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add("shown");
      entry.target.querySelectorAll("[data-count]").forEach(countUp);
      observer.unobserve(entry.target); // play once
    }
  }, { rootMargin: "0px 0px -8% 0px" });
  root.querySelectorAll("[data-reveal]").forEach((el) => observer.observe(el));
}

// Counts an element's text from 0 up to its data-count in 1.5 seconds
function countUp(el) {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const end = Number(el.dataset.count);
  const suffix = el.dataset.suffix || "";
  const start = performance.now();
  function step(now) {
    const t = Math.min(1, (now - start) / 1500);
    const eased = 1 - (1 - t) ** 3; // fast at first, slow at the end
    el.textContent = Math.round(end * eased).toLocaleString("en-US") + suffix;
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}
