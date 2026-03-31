// pretext-fx.js — subtle data-stream + stat-decode effects
// Uses @chenglou/pretext for character-level text measurement.
// Degrades gracefully if pretext fails to load.

const DATA_FRAGMENTS = [
  'epoch:3 seqno:1847 keyId:a8f3e201',
  'CN=signet-authority,O=notme',
  'Ed25519 CA:TRUE pathlen:0',
  'bridgeCert authorityManage certMint',
  'sha256:e3b0c44298fc1c149afb',
  'OIDC sub:repo:agentic-research/*',
  'ttl:300s scope:agent revocable:true',
  'bundle:current sig:verified seqno:monotonic',
  '-----BEGIN CERTIFICATE-----',
  'proof-of-possession != bearer',
  'exp:1743400000 iat:1743399700',
  'keyUsage: keyCertSign cRLSign',
  'attestation:DSSE predicateType:dispatch/v1',
  'beadRef:sha256:4f2a8c..contentHash',
  'handoff:phase1->phase2 chain:linked',
  'revocation:epoch-based offline-first',
  '5-minute ephemeral. no renewal. expire.',
  'stolen cert = useless without key',
];

// ── Background Data Stream ──────────────────────────────────
// Subtle scrolling text behind content, like intercepted traffic.

function initDataStream() {
  const canvas = document.createElement('canvas');
  canvas.id = 'data-stream';
  Object.assign(canvas.style, {
    position: 'fixed',
    inset: '0',
    zIndex: '0',
    pointerEvents: 'none',
    opacity: '0',
    transition: 'opacity 3s ease',
  });
  document.body.insertBefore(canvas, document.body.firstChild);
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  // Columns of scrolling text
  const COL_COUNT = 3;
  const LINE_HEIGHT = 18;
  const SCROLL_SPEED = 0.15; // px per frame
  const FONT = '11px "DM Mono", monospace';
  const BASE_OPACITY = 0.025; // near-invisible normally
  const SCAN_BOOST = 12;      // multiplier when scanline passes
  const SCAN_WIDTH = 120;     // px height of the reveal zone
  const SCAN_SPEED = 0.012;   // fraction of screen height per frame
  const COLORS = [
    [0, 212, 232],   // cyan
    [232, 220, 200], // ink
    [240, 208, 64],  // yellow (rare)
  ];
  let scanY = -SCAN_WIDTH; // scanline y position

  let columns = [];
  let offset = 0;
  let raf;

  function resize() {
    const dpr = window.devicePixelRatio || 1;
    canvas.width = window.innerWidth * dpr;
    canvas.height = window.innerHeight * dpr;
    canvas.style.width = window.innerWidth + 'px';
    canvas.style.height = window.innerHeight + 'px';
    ctx.scale(dpr, dpr);

    // Build columns
    const colWidth = window.innerWidth / COL_COUNT;
    columns = [];
    for (let i = 0; i < COL_COUNT; i++) {
      const lines = [];
      const lineCount = Math.ceil(window.innerHeight / LINE_HEIGHT) + 20;
      for (let j = 0; j < lineCount; j++) {
        lines.push({
          text: DATA_FRAGMENTS[Math.floor(Math.random() * DATA_FRAGMENTS.length)],
          colorIdx: Math.random() < 0.08 ? 2 : Math.random() < 0.3 ? 0 : 1,
          speed: 0.8 + Math.random() * 0.4, // slight per-line speed variation
        });
      }
      columns.push({ x: colWidth * i + 20, lines });
    }
  }

  function draw() {
    const w = window.innerWidth;
    const h = window.innerHeight;
    ctx.clearRect(0, 0, w, h);
    ctx.font = FONT;
    ctx.textBaseline = 'top';

    // Advance scanline
    scanY += h * SCAN_SPEED;
    if (scanY > h + SCAN_WIDTH) scanY = -SCAN_WIDTH;

    for (const col of columns) {
      for (let i = 0; i < col.lines.length; i++) {
        const line = col.lines[i];
        const y = (i * LINE_HEIGHT - offset * line.speed) % (col.lines.length * LINE_HEIGHT);
        const yPos = y < 0 ? y + col.lines.length * LINE_HEIGHT : y;

        // Fade at edges
        let edgeAlpha = 1;
        if (yPos < 60) edgeAlpha = yPos / 60;
        if (yPos > h - 60) edgeAlpha = (h - yPos) / 60;
        if (edgeAlpha <= 0) continue;

        // Scanline proximity boost — text brightens as scanline passes
        const distFromScan = Math.abs(yPos - scanY);
        const scanFactor = distFromScan < SCAN_WIDTH
          ? (1 - distFromScan / SCAN_WIDTH) * SCAN_BOOST
          : 0;
        const opacity = BASE_OPACITY + BASE_OPACITY * scanFactor;

        const colorIdx = line.colorIdx;
        const [r, g, b] = COLORS[colorIdx];
        ctx.globalAlpha = edgeAlpha;
        ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${opacity})`;
        ctx.fillText(line.text, col.x, yPos);
      }
    }

    // Draw the scanline bar itself (subtle gradient)
    const grad = ctx.createLinearGradient(0, scanY - 2, 0, scanY + 4);
    grad.addColorStop(0, 'transparent');
    grad.addColorStop(0.4, 'rgba(0, 212, 232, 0.06)');
    grad.addColorStop(0.6, 'rgba(240, 208, 64, 0.03)');
    grad.addColorStop(1, 'transparent');
    ctx.globalAlpha = 1;
    ctx.fillStyle = grad;
    ctx.fillRect(0, scanY - 2, w, 6);

    offset += SCROLL_SPEED;
    raf = requestAnimationFrame(draw);
  }

  resize();
  window.addEventListener('resize', resize);

  // Fade in after page loads
  requestAnimationFrame(() => {
    canvas.style.opacity = '1';
    draw();
  });

  return () => {
    cancelAnimationFrame(raf);
    canvas.remove();
  };
}

// ── Stat Number Decode ──────────────────────────────────────
// Characters scramble then resolve into final value.

function initStatDecode() {
  const GLYPHS = '0123456789ABCDEFabcdef/%#.:→←↑↓∞≈≠±×÷';
  const DECODE_DURATION = 800; // ms total
  const STAGGER_PER_CHAR = 60;  // ms between each char locking

  function scramble(el) {
    const final = el.textContent.trim();
    const chars = [...final];
    const locked = new Array(chars.length).fill(false);
    const start = performance.now();

    // Hide original, show scramble
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

  // Observe stat numbers
  const stats = document.querySelectorAll('.stat-num');
  if (!stats.length) return;

  // Store original text and hide
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
        // Small delay for stagger between stats
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
// Characters materialize from noise, word by word.

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
  // Wrap each word (preserve HTML like <span> and <a>)
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

  // Stagger reveal
  spans.forEach((span, i) => {
    setTimeout(() => {
      span.style.opacity = '1';
      span.style.filter = 'blur(0)';
    }, i * 50 + 100);
  });
}

// ── Compare table row reveal ────────────────────────────────
// Rows slide in from left with stagger.

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
// The last compare row gets a brief yellow glow when revealed.

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
  // Respect reduced motion
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  initDataStream();
  initStatDecode();
  initThesisReveal();
  initTableReveal();
  initFinalRowPulse();
});
