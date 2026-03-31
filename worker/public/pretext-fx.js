// pretext-fx.js — CRT phosphor sweep + scroll-triggered reveals
// The scanline brightens real DOM text as it passes, like a CRT refresh.
// Degrades gracefully: all content is static HTML, effects are enhancement only.

// ── CRT Phosphor Sweep ──────────────────────────────────────
// Thin scanline (CSS) sweeps down. As it passes each text element,
// that element briefly glows brighter then fades back — like phosphor
// being recharged by the electron beam.

function initPhosphorSweep() {
  const scanline = document.querySelector('.scanline');
  if (!scanline) return;

  // Collect all text-bearing elements worth illuminating
  const targets = document.querySelectorAll(
    '.hero h1, .hero-body p, .hero-stamp, .stat-num, .stat-label, ' +
    '.thesis p, .stack-card h2, .stack-card p, .stack-card .card-role, ' +
    '.compare-table td, .compare-table th, .cta-block h3, .cta-block p, ' +
    '.divider .tag, h2, h3'
  );

  // Pre-set transition on all targets
  targets.forEach(el => {
    el.style.transition = 'filter 0.6s ease-out';
    el.style.filter = 'brightness(1)';
  });

  function tick() {
    const scanRect = scanline.getBoundingClientRect();
    const scanMid = scanRect.top + scanRect.height / 2;

    for (const el of targets) {
      const rect = el.getBoundingClientRect();
      const elMid = rect.top + rect.height / 2;
      const dist = Math.abs(scanMid - elMid);

      if (dist < 60) {
        // Scanline is passing — brighten
        const intensity = 1 + 0.25 * (1 - dist / 60); // up to 1.25
        el.style.filter = `brightness(${intensity.toFixed(3)})`;
        el.style.transition = 'filter 0.15s ease-in';
      } else {
        // Fade back to normal
        el.style.filter = 'brightness(1)';
        el.style.transition = 'filter 0.6s ease-out';
      }
    }

    requestAnimationFrame(tick);
  }

  requestAnimationFrame(tick);
}

// ── Stat Number Decode ──────────────────────────────────────
// Characters scramble then resolve into final value.

function initStatDecode() {
  const GLYPHS = '0123456789ABCDEFabcdef/%#.:';
  const DECODE_DURATION = 800;
  const STAGGER_PER_CHAR = 60;

  function scramble(el) {
    const final = el.textContent.trim();
    const chars = [...final];
    const locked = new Array(chars.length).fill(false);
    const start = performance.now();

    el.style.visibility = 'visible';

    function tick(now) {
      const elapsed = now - start;
      let display = '';

      for (let i = 0; i < chars.length; i++) {
        const charLockTime = DECODE_DURATION - (chars.length - 1 - i) * STAGGER_PER_CHAR;
        if (elapsed >= charLockTime || locked[i]) {
          locked[i] = true;
          display += chars[i];
        } else if (chars[i] === ' ') {
          display += ' ';
        } else {
          display += GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
        }
      }

      el.textContent = display;

      if (locked.every(Boolean)) {
        el.textContent = final;
        return;
      }
      requestAnimationFrame(tick);
    }

    requestAnimationFrame(tick);
  }

  const stats = document.querySelectorAll('.stat-num');
  if (!stats.length) return;

  const originals = new Map();
  stats.forEach(el => {
    originals.set(el, el.textContent.trim());
    el.style.visibility = 'hidden';
  });

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const el = entry.target;
        observer.unobserve(el);
        const index = [...stats].indexOf(el);
        setTimeout(() => {
          el.textContent = originals.get(el);
          scramble(el);
        }, index * 120);
      }
    });
  }, { threshold: 0.5 });

  stats.forEach(el => observer.observe(el));
}

// ── Thesis text reveal ──────────────────────────────────────

function initThesisReveal() {
  const thesis = document.querySelector('.thesis p');
  if (!thesis) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        observer.unobserve(entry.target);
        revealThesis(entry.target);
      }
    });
  }, { threshold: 0.3 });

  observer.observe(thesis);
}

function revealThesis(el) {
  const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
  const textNodes = [];
  while (walker.nextNode()) textNodes.push(walker.currentNode);

  const spans = [];
  for (const node of textNodes) {
    const words = node.textContent.split(/(\s+)/);
    const frag = document.createDocumentFragment();
    for (const word of words) {
      if (/^\s+$/.test(word)) {
        frag.appendChild(document.createTextNode(word));
      } else {
        const span = document.createElement('span');
        span.textContent = word;
        span.style.opacity = '0';
        span.style.filter = 'blur(4px)';
        span.style.transition = 'opacity 0.4s ease, filter 0.4s ease';
        spans.push(span);
        frag.appendChild(span);
      }
    }
    node.parentNode.replaceChild(frag, node);
  }

  spans.forEach((span, i) => {
    setTimeout(() => {
      span.style.opacity = '1';
      span.style.filter = 'blur(0)';
    }, i * 50 + 100);
  });
}

// ── Compare table row reveal ────────────────────────────────

function initTableReveal() {
  const rows = document.querySelectorAll('.compare-table tbody tr');
  if (!rows.length) return;

  rows.forEach(row => {
    row.style.opacity = '0';
    row.style.transform = 'translateX(-12px)';
    row.style.transition = 'opacity 0.35s ease, transform 0.35s ease';
  });

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        observer.unobserve(entry.target);
        const index = [...rows].indexOf(entry.target);
        setTimeout(() => {
          entry.target.style.opacity = '1';
          entry.target.style.transform = 'translateX(0)';
        }, index * 80);
      }
    });
  }, { threshold: 0.1 });

  rows.forEach(row => observer.observe(row));
}

// ── "not me" final row pulse ────────────────────────────────

function initFinalRowPulse() {
  const lastRow = document.querySelector('.compare-table tbody tr:last-child');
  if (!lastRow) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        observer.unobserve(entry.target);
        setTimeout(() => {
          const cell = entry.target.querySelector('td:last-child');
          if (!cell) return;
          cell.style.transition = 'text-shadow 0.6s ease';
          cell.style.textShadow = '0 0 30px rgba(240, 208, 64, 0.8), 0 0 60px rgba(240, 208, 64, 0.4)';
          setTimeout(() => {
            cell.style.textShadow = '0 0 20px rgba(240, 208, 64, 0.4)';
          }, 800);
        }, 600);
      }
    });
  }, { threshold: 0.5 });

  observer.observe(lastRow);
}

// ── Init ────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  initPhosphorSweep();
  initStatDecode();
  initThesisReveal();
  initTableReveal();
  initFinalRowPulse();
});
