/**
 * Shamir-Gate — Main UI
 * Eight-tab Shamir's Secret Sharing demo: Lesson, Gate, Polynomial, Security Proof,
 * AES Vault, Failure Lab, Real World, Adi Shamir.
 * All arithmetic: BigInt over GF(p). All randomness via crypto.getRandomValues. No float in math.
 */

import {
  generateShares,
  reconstructSecret,
  lagrangeAt0,
  lagrangeEvalAt,
  evalPoly,
  polyForSecret,
  modInverse,
} from './math';
import {
  secretToInt,
  intToSecret,
  generateAESKey,
  aesEncrypt,
  aesDecrypt,
  keyToInt,
  intToKey,
  toHex,
  AES_KEY_PRIME,
} from './crypto';
import { drawPolynomial, animatePolynomial } from './polynomial-canvas';
import { validateShareSet, type FailureCategory } from './shares';

// ── Theme ─────────────────────────────────────────────────────────
const THEME_KEY = 'cv-theme';

function initTheme(): void {
  const btn = document.getElementById('theme-toggle') as HTMLButtonElement;
  const update = () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    btn.textContent = isDark ? '☀️' : '🌙';
    btn.setAttribute('aria-label', isDark ? 'Switch to light theme' : 'Switch to dark theme');
  };
  btn.addEventListener('click', () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const next = isDark ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem(THEME_KEY, next);
    update();
  });
  update();
}

// ── Tab system ────────────────────────────────────────────────────
function initTabs(): void {
  const tabBtns = document.querySelectorAll<HTMLButtonElement>('.tab-btn');
  const tabPanels = document.querySelectorAll<HTMLDivElement>('.tab-panel');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => { b.setAttribute('aria-selected', 'false'); b.setAttribute('tabindex', '-1'); });
      tabPanels.forEach(p => p.classList.remove('active'));
      btn.setAttribute('aria-selected', 'true');
      btn.setAttribute('tabindex', '0');
      const target = btn.getAttribute('aria-controls');
      if (target) document.getElementById(target)?.classList.add('active');
    });
    btn.addEventListener('keydown', (e) => {
      const tabs = [...tabBtns];
      const idx = tabs.indexOf(btn);
      if (e.key === 'ArrowRight') { tabs[(idx + 1) % tabs.length].focus(); tabs[(idx + 1) % tabs.length].click(); }
      if (e.key === 'ArrowLeft')  { tabs[(idx - 1 + tabs.length) % tabs.length].focus(); tabs[(idx - 1 + tabs.length) % tabs.length].click(); }
    });
  });
}

// ── Helpers ───────────────────────────────────────────────────────
function el<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

function showResult(id: string, msg: string, type: 'success' | 'error'): void {
  const box = el(id);
  box.className = `result-box ${type}`;
  box.textContent = msg;
}

function serializeShare(x: bigint, y: bigint, p: bigint): string {
  return `${x}:${y}:${p}`;
}

// ── Tab 1: THE GATE ───────────────────────────────────────────────
interface GateState {
  n: number;
  t: number;
  genT: number; // threshold actually used at the last generation
  shares: Array<{ x: bigint; y: bigint }>;
  prime: bigint;
  submittedCount: number;
}

const gate: GateState = { n: 5, t: 3, genT: 3, shares: [], prime: 257n, submittedCount: 0 };

function updateLock(submitted: number, threshold: number): void {
  const svg = el('lock-svg');
  const label = el('lock-label');
  const statusMsg = submitted >= threshold ? 'Vault unlocked' : `Vault locked — ${submitted} of ${threshold} shares collected`;
  if (submitted >= threshold) {
    // NB: SVGElement.className is a read-only SVGAnimatedString — assigning a string
    // throws in strict mode. Must go through setAttribute/classList.
    svg.setAttribute('class', 'lock-svg unlocked');
    label.className = 'lock-label unlocked';
    label.textContent = '🔓 UNLOCKED';
  } else {
    svg.setAttribute('class', 'lock-svg locked');
    label.className = 'lock-label locked';
    label.textContent = '🔒 LOCKED';
  }
  svg.setAttribute('aria-label', statusMsg);
  el('lock-progress').textContent = `Shares collected: ${submitted} / ${threshold} needed`;
}

function updateSlots(n: number, submitted: number): void {
  const wrap = el('share-slots');
  wrap.innerHTML = '';
  for (let i = 0; i < n; i++) {
    const slot = document.createElement('div');
    slot.className = `share-slot${i < submitted ? ' filled' : ''}`;
    slot.textContent = i < submitted ? `S${i + 1}` : '';
    wrap.appendChild(slot);
  }
}

function initGateTab(): void {
  const tSlider = el<HTMLInputElement>('gate-t');
  const nSlider = el<HTMLInputElement>('gate-n');
  const tVal = el('gate-t-val');
  const nVal = el('gate-n-val');

  const syncSliders = () => {
    gate.t = parseInt(tSlider.value);
    gate.n = parseInt(nSlider.value);
    if (gate.n < gate.t) { gate.n = gate.t; nSlider.value = String(gate.n); }
    tVal.textContent = String(gate.t);
    nVal.textContent = String(gate.n);
    nSlider.min = String(gate.t);
    gate.submittedCount = 0;
    updateLock(0, gate.t);
    updateSlots(gate.n, 0);
  };

  tSlider.addEventListener('input', syncSliders);
  nSlider.addEventListener('input', syncSliders);
  syncSliders();

  el('gate-generate').addEventListener('click', async () => {
    const secretText = (el<HTMLInputElement>('gate-secret').value || 'My Secret').trim();
    const { value: secretInt, prime } = secretToInt(secretText);
    gate.prime = prime;
    gate.t = parseInt(tSlider.value);
    gate.n = parseInt(nSlider.value);

    try {
      const { shares, coefficients } = await generateShares(secretInt, gate.t, gate.n, prime);
      gate.shares = shares;
      gate.genT = gate.t;
      gate.submittedCount = 0;
      updateLock(0, gate.t);
      updateSlots(gate.n, 0);

      const list = el('gate-shares-list');
      list.innerHTML = '';
      shares.forEach((sh, i) => {
        const serialized = serializeShare(sh.x, sh.y, prime);
        const div = document.createElement('div');
        div.className = 'share-item';
        div.innerHTML = `
          <span class="share-label">Share ${i + 1}</span>
          <span class="share-val" title="${serialized}">${serialized.substring(0, 60)}${serialized.length > 60 ? '…' : ''}</span>
          <button type="button" aria-label="Copy share ${i + 1}">Copy</button>
        `;
        div.querySelector('button')!.addEventListener('click', () => {
          navigator.clipboard.writeText(serialized).catch(() => {});
        });
        list.appendChild(div);
      });
      el('gate-shares-display').style.display = 'block';

      const degree = gate.t - 1;
      const coeffStr = coefficients.map((c, i) => i === 0 ? `${c}` : `${c}x${i > 1 ? `^${i}` : ''}`).join(' + ');
      el('gate-meta').innerHTML = `
        Prime used: <span>p = ${prime}</span><br>
        Secret as integer: <span>${secretInt}</span><br>
        Polynomial degree: <span>${degree}</span> (= threshold - 1)<br>
        f(x) = <span>${coeffStr}</span> (mod p)
      `;
      el('gate-meta').style.display = 'block';
    } catch (e: unknown) {
      showResult('gate-result', `Error: ${(e as Error).message}`, 'error');
    }
  });

  el('gate-reconstruct').addEventListener('click', () => {
    const validation = validateShareSet(el<HTMLTextAreaElement>('gate-shares-input').value);
    if (!validation.ok) {
      showResult('gate-result', validation.message!, 'error');
      return;
    }
    const parsed = validation.shares;
    const p = validation.prime!;
    try {
      const secret = reconstructSecret(parsed.map(s => ({ x: s.x, y: s.y })), p);
      const text = intToSecret(secret);
      gate.submittedCount = Math.min(parsed.length, gate.n);
      updateLock(gate.submittedCount, gate.genT);
      updateSlots(gate.n, gate.submittedCount);

      // Below threshold, Lagrange still returns *a* number — but it is not the
      // secret. Surfacing this honestly is the core lesson: t−1 shares look just
      // as confident as t shares, yet reveal nothing about the true value.
      if (parsed.length < gate.genT) {
        showResult(
          'gate-result',
          `✗ Below threshold: ${parsed.length} of ${gate.genT} shares. ` +
          `Interpolation yields "${text}" (integer: ${secret}) — but this is NOT the secret. ` +
          `Every possible secret is equally consistent with these shares. Add more shares.`,
          'error'
        );
      } else {
        showResult('gate-result', `✓ Secret recovered: "${text}" (integer: ${secret})`, 'success');
      }
    } catch (e: unknown) {
      showResult('gate-result', `Error: ${(e as Error).message}`, 'error');
    }
  });

  // Prediction checkpoint: prime the learner before they try a sub-threshold set.
  el('gate-predict').appendChild(buildPrediction({
    question: 'You hold 2 of the 3 required shares and click Reconstruct. What happens?',
    options: ['The exact secret appears', 'A wrong value appears, looking just as valid', 'An error: not enough shares'],
    correct: 1,
    explain: 'Lagrange interpolation always returns <i>a</i> number; below the threshold it is simply the wrong one, with nothing to flag it. Try it above with 2 shares and watch.',
  }));
}

// ── Tab 2: POLYNOMIAL ──────────────────────────────────────────────
interface PolyState {
  secret: bigint;
  t: number;
  n: number;
  p: bigint;
  shares: Array<{ x: bigint; y: bigint }>;
  coefficients: bigint[];
  activeShares: Set<number>;
  cancelAnim: (() => void) | null;
  stepIndex: number;
  lagrangeSteps: string[];
  discrete: boolean; // viz mode: discrete field points vs. connected illustration line
}

const poly: PolyState = {
  secret: 42n, t: 2, n: 4, p: 257n,
  shares: [], coefficients: [], activeShares: new Set(),
  cancelAnim: null, stepIndex: 0, lagrangeSteps: [], discrete: false
};

function redrawPolyCanvas(): void {
  const canvas = el<HTMLCanvasElement>('poly-canvas');
  drawPolynomial(canvas, {
    width: 600, height: 380,
    prime: poly.p,
    secret: poly.secret,
    coefficients: poly.coefficients,
    shares: poly.shares,
    activeShares: poly.activeShares,
    threshold: poly.t,
    showFullCurve: true,
    discrete: poly.discrete,
  });
  const label = `Polynomial curve for secret=${poly.secret}, t=${poly.t}, n=${poly.n}, p=${poly.p}. ${poly.activeShares.size >= poly.t ? 'Threshold met.' : 'Below threshold.'}`;
  canvas.setAttribute('aria-label', label);
  renderPointsTable();
  updateLagrangeStepper();
}

// Text alternative to the canvas: a table of the plotted points, readable by
// screen readers and by anyone who parses tables faster than graphics.
function renderPointsTable(): void {
  const host = el('poly-points');
  if (poly.shares.length === 0) { host.innerHTML = ''; return; }
  const active = poly.activeShares;
  const met = active.size >= poly.t;
  const rows = poly.shares.map((s, i) => `
    <tr${active.has(i) ? ' class="row-active"' : ''}>
      <th scope="row">Share ${i + 1}</th>
      <td>${s.x}</td>
      <td>${s.y}</td>
      <td>${active.has(i) ? 'selected' : '—'}</td>
    </tr>`).join('');
  host.innerHTML = `
    <table class="points-table">
      <caption>Points on f(x) mod ${poly.p} — secret is f(0). ${active.size} of ${poly.t} needed selected (${met ? 'threshold met' : 'below threshold'}).</caption>
      <thead><tr><th scope="col">Point</th><th scope="col">x</th><th scope="col">f(x)</th><th scope="col">In use</th></tr></thead>
      <tbody>
        <tr class="row-secret"><th scope="row">Secret</th><td>0</td><td>${poly.secret}</td><td>hidden</td></tr>
        ${rows}
      </tbody>
    </table>`;
}

function buildLagrangeSteps(activePoints: Array<{ x: bigint; y: bigint }>, p: bigint): string[] {
  const steps: string[] = [];
  const k = activePoints.length;
  steps.push(`Using shares: ${activePoints.map(s => `(${s.x},${s.y})`).join(', ')}`);

  const liValues: bigint[] = [];
  for (let i = 0; i < k; i++) {
    const xi = activePoints[i].x;
    const numParts: string[] = [];
    const denParts: string[] = [];
    let num = 1n;
    let den = 1n;
    for (let j = 0; j < k; j++) {
      if (i === j) continue;
      const xj = activePoints[j].x;
      numParts.push(`(0-${xj})`);
      denParts.push(`(${xi}-${xj})`);
      num = (num * ((0n - xj + p) % p)) % p;
      den = (den * ((xi - xj + p) % p)) % p;
    }
    const inv = modInverse(den, p);
    const li = (num * inv) % p;
    liValues.push(li);
    steps.push(
      `L${i + 1}(0) = [${numParts.join('·')}] / [${denParts.join('·')}] mod ${p}\n` +
      `       = ${num} · ${inv} mod ${p} = <b>${li}</b>`
    );
  }

  const terms = activePoints.map((pt, i) => `${pt.y}·${liValues[i]}`).join(' + ');
  const secret = lagrangeAt0(activePoints, p);
  steps.push(`f(0) = ${terms} mod ${p}\n     = <span class="result">${secret} ✓</span>`);
  return steps;
}

function updateLagrangeStepper(): void {
  const stepper = el('lagrange-stepper');
  const activePoints = [...poly.activeShares].map(i => poly.shares[i]);
  if (activePoints.length < poly.t) {
    stepper.innerHTML = '<p style="color:var(--text-dim);font-family:var(--font-mono);font-size:.8rem">Select at least t shares to see Lagrange interpolation.</p>';
    poly.lagrangeSteps = [];
    poly.stepIndex = 0;
    return;
  }

  poly.lagrangeSteps = buildLagrangeSteps(activePoints, poly.p);
  poly.stepIndex = Math.min(poly.stepIndex, poly.lagrangeSteps.length - 1);

  const stepsHtml = poly.lagrangeSteps.slice(0, poly.stepIndex + 1).map((s) => `
    <div class="lagrange-step">${s.replace(/\n/g, '<br>').replace(/<b>(.*?)<\/b>/g, '<span class="highlight">$1</span>')}</div>
  `).join('');

  stepper.innerHTML = `
    <h3>Lagrange Interpolation at x=0</h3>
    ${stepsHtml}
    <div class="btn-row" style="margin-top:.75rem">
      ${poly.stepIndex < poly.lagrangeSteps.length - 1
        ? `<button class="btn-primary" id="lagrange-next">Next Step →</button>`
        : `<button class="btn-secondary" id="lagrange-reset">Restart</button>`}
    </div>
  `;
  el('lagrange-next')?.addEventListener('click', () => { poly.stepIndex++; updateLagrangeStepper(); });
  el('lagrange-reset')?.addEventListener('click', () => { poly.stepIndex = 0; updateLagrangeStepper(); });
}

function buildShareToggles(): void {
  const wrap = el('poly-share-toggles');
  wrap.innerHTML = '';
  poly.shares.forEach((sh, i) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `share-toggle-btn${poly.activeShares.has(i) ? ' active' : ''}`;
    btn.textContent = `${poly.activeShares.has(i) ? '●' : '○'} Share ${i + 1}: (${sh.x},${sh.y})`;
    btn.setAttribute('aria-pressed', String(poly.activeShares.has(i)));
    btn.addEventListener('click', () => {
      if (poly.activeShares.has(i)) poly.activeShares.delete(i);
      else poly.activeShares.add(i);
      poly.stepIndex = 0;
      buildShareToggles();
      redrawPolyCanvas();
    });
    btn.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); btn.click(); }
    });
    wrap.appendChild(btn);
  });
}

function initPolyTab(): void {
  const tSlider = el<HTMLInputElement>('poly-t');
  const nSlider = el<HTMLInputElement>('poly-n');
  const tVal = el('poly-t-val');
  const nVal = el('poly-n-val');
  const pSelect = el<HTMLSelectElement>('poly-p');

  const syncSliders = () => {
    poly.t = parseInt(tSlider.value);
    poly.n = parseInt(nSlider.value);
    if (poly.n < poly.t) { poly.n = poly.t; nSlider.value = String(poly.n); }
    tVal.textContent = String(poly.t);
    nVal.textContent = String(poly.n);
    nSlider.min = String(poly.t);
  };

  tSlider.addEventListener('input', syncSliders);
  nSlider.addEventListener('input', syncSliders);
  pSelect.addEventListener('change', () => { poly.p = BigInt(pSelect.value); });

  const vizToggle = el<HTMLInputElement>('poly-viz-toggle');
  vizToggle.addEventListener('change', () => {
    poly.discrete = vizToggle.checked;
    if (poly.shares.length > 0) redrawPolyCanvas();
  });

  syncSliders();

  el('poly-generate').addEventListener('click', async () => {
    if (poly.cancelAnim) poly.cancelAnim();
    const secretInput = parseInt((el<HTMLInputElement>('poly-secret').value).trim() || '42', 10);
    if (!Number.isFinite(secretInput) || secretInput < 0) {
      showResult('poly-result', 'Secret must be a non-negative integer.', 'error');
      return;
    }
    poly.secret = BigInt(secretInput);
    poly.p = BigInt(pSelect.value);
    poly.t = parseInt(tSlider.value);
    poly.n = parseInt(nSlider.value);

    if (poly.secret >= poly.p) {
      showResult('poly-result', `Secret must be < p (${poly.p}). Choose a smaller secret or larger p.`, 'error');
      return;
    }

    const { shares, coefficients } = await generateShares(poly.secret, poly.t, poly.n, poly.p);
    poly.shares = shares;
    poly.coefficients = coefficients;
    poly.activeShares = new Set([0]); // start with share 1 selected
    poly.stepIndex = 0;

    buildShareToggles();
    el('poly-canvas-area').style.display = 'block';

    // Honor prefers-reduced-motion: render the final curve immediately, no sweep.
    const reduceMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    if (reduceMotion) {
      redrawPolyCanvas();
      return;
    }

    const canvas = el<HTMLCanvasElement>('poly-canvas');
    poly.cancelAnim = animatePolynomial(canvas, {
      width: 600, height: 380,
      prime: poly.p,
      secret: poly.secret,
      coefficients: poly.coefficients,
      shares: poly.shares,
      activeShares: poly.activeShares,
      threshold: poly.t,
      showFullCurve: true,
    }, 800);

    setTimeout(() => { redrawPolyCanvas(); }, 850);
  });
}

// ── Tab 3: SECURITY PROOF ─────────────────────────────────────────
function initSecurityTab(): void {
  const proof_p = 257n;
  // Fixed shares for the proof (attacker observes these 2 of 3 needed)
  const proofShares = [{ x: 1n, y: 75n }, { x: 2n, y: 140n }];

  // Show the 3 alternate candidate polynomials
  const candidateSecrets = [0n, 42n, 200n];

  const list = el('proof-candidates');
  list.innerHTML = '';

  candidateSecrets.forEach(cs => {
    // Find polynomial passing through proofShares with f(0) = cs
    const allPts = [{ x: 0n, y: cs }, ...proofShares];
    // Compute a1, a2 from the 3 points via Lagrange
    // Polynomial coefficients just for display: evaluate at x=0,1,2 and back-compute
    // Display using Lagrange interpolated at several x to get coefficients
    const poly_at_1 = lagrangeEvalAt(allPts, 1n, proof_p);
    const poly_at_2 = lagrangeEvalAt(allPts, 2n, proof_p);
    // a0 = f(0)=cs, a1, a2: from f(1) and f(2)
    // f(1) = cs + a1 + a2 => checked
    const a0 = cs;
    // Use systems of 2 equations for a1, a2:
    // f(1) = a0 + a1 + a2 = poly_at_1
    // f(2) = a0 + 2a1 + 4a2 = poly_at_2
    // Subtract: a1 + 3a2 = poly_at_2 - poly_at_1 (mod p)
    // From first: a1 + a2 = poly_at_1 - a0
    const eq1 = ((poly_at_1 - a0) % proof_p + proof_p) % proof_p; // a1+a2
    const eq2 = ((poly_at_2 - a0) % proof_p + proof_p) % proof_p; // 2a1+4a2
    // 2*(a1+a2) = 2*eq1, subtract: 2a1+4a2 - 2a1-2a2 = 2a2 = eq2-2*eq1
    const twoA2 = ((eq2 - 2n * eq1) % proof_p + proof_p) % proof_p;
    const inv2 = modInverse(2n, proof_p);
    const a2 = (twoA2 * inv2) % proof_p;
    const a1 = ((eq1 - a2) % proof_p + proof_p) % proof_p;

    const div = document.createElement('div');
    div.className = 'candidate-poly';
    div.innerHTML = `
      <div class="cs-label">Secret = ${cs}:</div>
      <div class="cs-poly">f(x) = ${a0} + ${a1}x + ${a2}x² (mod ${proof_p})<br>
        f(1)=${poly_at_1} ✓ &nbsp; f(2)=${poly_at_2} ✓</div>
      <div class="cs-check">consistent ✓</div>
    `;
    list.appendChild(div);
  });

  // Draw the proof canvas showing all 3 curves through the same 2 share points
  const canvas = el<HTMLCanvasElement>('proof-canvas');
  canvas.width = 600;
  canvas.height = 320;
  const ctx = canvas.getContext('2d')!;
  ctx.fillStyle = '#0a0a14';
  ctx.fillRect(0, 0, 600, 320);

  const PAD = 60;
  const xMax = 4;
  const yMax = proof_p;
  const toX = (x: number) => PAD + (x / xMax) * (600 - 2 * PAD);
  const toY = (y: bigint) => (320 - PAD) - (Number(y * 1000n / yMax) / 1000) * (320 - 2 * PAD);

  // axes
  ctx.strokeStyle = '#334466';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(toX(0), PAD - 10); ctx.lineTo(toX(0), 320 - PAD + 10);
  ctx.moveTo(PAD - 10, toY(0n)); ctx.lineTo(600 - PAD + 10, toY(0n));
  ctx.stroke();

  const colors = ['rgba(0,180,255,0.6)', 'rgba(0,255,136,0.6)', 'rgba(255,160,0,0.6)'];

  candidateSecrets.forEach((cs, ci) => {
    const pts = [{ x: 0n, y: cs }, ...proofShares];
    ctx.strokeStyle = colors[ci];
    ctx.lineWidth = 2;
    ctx.setLineDash(ci === 1 ? [] : [5, 4]);
    ctx.beginPath();
    let first = true;
    // Sample over the SAME x-domain we plot ([0, xMax]); GF(p) is defined only at
    // integers, so we evaluate at each integer x and connect with straight lines.
    // This is what makes every candidate curve pass exactly through the shares.
    for (let x = 0; x <= 40; x++) {
      const logicalX = (x / 40) * xMax;
      const xB = BigInt(Math.round(logicalX));
      const yV = lagrangeEvalAt(pts, xB, proof_p);
      const px = toX(logicalX);
      const py = toY(yV);
      if (first) { ctx.moveTo(px, py); first = false; }
      else ctx.lineTo(px, py);
    }
    ctx.stroke();
    ctx.setLineDash([]);

    // y-intercept label
    ctx.fillStyle = colors[ci];
    ctx.font = 'bold 11px monospace';
    ctx.fillText(`f(0)=${cs}`, toX(0) + 4, toY(cs) - 5);
  });

  // share points
  proofShares.forEach(sh => {
    const px = toX(Number(sh.x));
    const py = toY(sh.y);
    ctx.fillStyle = '#ffd700';
    ctx.beginPath();
    ctx.arc(px, py, 7, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = '#ffd700';
    ctx.font = '10px monospace';
    ctx.fillText(`(${sh.x},${sh.y})`, px + 8, py + 4);
  });

  ctx.fillStyle = '#445566';
  ctx.font = '10px monospace';
  ctx.fillText('All three polynomials pass through the known shares. Which is real?', PAD, 315);

  // ── Interactive proof lab: test ANY candidate secret yourself ──
  const tested = new Set<string>();
  const fieldSize = Number(proof_p); // 257 candidate secrets in [0, 256]
  const input = el<HTMLInputElement>('proof-candidate');
  const out = el('proof-lab-out');
  const counter = el('proof-lab-counter');

  const updateCounter = () => {
    counter.textContent =
      `You have verified ${tested.size} secret${tested.size === 1 ? '' : 's'} — all consistent. ` +
      `Observed shares eliminate 0 of ${fieldSize} possible secrets.`;
  };
  updateCounter();

  el('proof-check').addEventListener('click', () => {
    const raw = parseInt(input.value.trim(), 10);
    if (!Number.isFinite(raw) || raw < 0 || raw > fieldSize - 1) {
      out.className = 'result-box error';
      out.textContent = `Enter a candidate secret in [0, ${fieldSize - 1}].`;
      return;
    }
    const S = BigInt(raw);
    const coeffs = polyForSecret(proofShares, S, proof_p);
    const at1 = evalPoly(coeffs, 1n, proof_p);
    const at2 = evalPoly(coeffs, 2n, proof_p);
    const consistent = at1 === 75n && at2 === 140n;
    tested.add(String(S));
    updateCounter();

    out.className = `result-box ${consistent ? 'success' : 'error'}`;
    out.innerHTML = consistent
      ? `✓ Secret = ${S}: f(x) = ${coeffs[0]} + ${coeffs[1]}x + ${coeffs[2]}x² (mod ${proof_p}) ` +
        `→ f(1)=${at1}, f(2)=${at2}. Passes through both observed shares — indistinguishable from the real secret.`
      : `Unexpected: f(1)=${at1}, f(2)=${at2}.`;
  });
}

// ── Tab 4: AES VAULT ──────────────────────────────────────────────
interface AesVaultState {
  key: Uint8Array | null;
  ciphertext: string;
  iv: string;
  shares: Array<{ x: bigint; y: bigint }>;
  t: number;
  n: number;
  genT: number; // threshold actually used at the last key split
}

const vault: AesVaultState = { key: null, ciphertext: '', iv: '', shares: [], t: 3, n: 5, genT: 3 };

function initAesTab(): void {
  const tSlider = el<HTMLInputElement>('aes-t');
  const nSlider = el<HTMLInputElement>('aes-n');
  const tVal = el('aes-t-val');
  const nVal = el('aes-n-val');

  const sync = () => {
    vault.t = parseInt(tSlider.value);
    vault.n = parseInt(nSlider.value);
    if (vault.n < vault.t) { vault.n = vault.t; nSlider.value = String(vault.n); }
    tVal.textContent = String(vault.t);
    nVal.textContent = String(vault.n);
    nSlider.min = String(vault.t);
  };
  tSlider.addEventListener('input', sync);
  nSlider.addEventListener('input', sync);
  sync();

  el('aes-generate').addEventListener('click', async () => {
    const message = (el<HTMLInputElement>('aes-message').value || 'Top secret document').trim();
    vault.t = parseInt(tSlider.value);
    vault.n = parseInt(nSlider.value);
    vault.genT = vault.t;

    try {
      vault.key = await generateAESKey();
      const { ciphertext, iv } = await aesEncrypt(vault.key, message);
      vault.ciphertext = ciphertext;
      vault.iv = iv;

      const keyInt = keyToInt(vault.key);
      const { shares } = await generateShares(keyInt, vault.t, vault.n, AES_KEY_PRIME);
      vault.shares = shares;

      const keyHex = toHex(vault.key);
      el('aes-key-display').innerHTML = `
        <div class="hex-display">${keyHex.substring(0, 16)}…${keyHex.substring(48)}</div>
      `;
      el('aes-cipher-display').innerHTML = `
        <div><b style="color:var(--text-dim);font-family:var(--font-mono);font-size:.75rem">CIPHERTEXT:</b>
        <div class="hex-display">${ciphertext.substring(0, 64)}…</div></div>
        <div><b style="color:var(--text-dim);font-family:var(--font-mono);font-size:.75rem">IV:</b>
        <div class="hex-display">${iv}</div></div>
      `;

      const list = el('aes-shares-list');
      list.innerHTML = '';
      shares.forEach((sh, i) => {
        const ser = serializeShare(sh.x, sh.y, AES_KEY_PRIME);
        const div = document.createElement('div');
        div.className = 'share-item';
        div.innerHTML = `
          <span class="share-label">Share ${i + 1}</span>
          <span class="share-val" title="${ser}">${ser.substring(0, 40)}…</span>
          <button type="button" aria-label="Copy share ${i + 1}">Copy</button>
        `;
        div.querySelector('button')!.addEventListener('click', () => {
          navigator.clipboard.writeText(ser).catch(() => {});
        });
        list.appendChild(div);
      });
      el('aes-step2-result').style.display = 'block';
    } catch (e: unknown) {
      showResult('aes-result', `Error: ${(e as Error).message}`, 'error');
    }
  });

  el('aes-decrypt').addEventListener('click', async () => {
    const validation = validateShareSet(el<HTMLTextAreaElement>('aes-shares-input').value);
    if (!validation.ok) {
      showResult('aes-result', validation.message!, 'error');
      return;
    }
    const parsed = validation.shares;
    if (parsed.length < vault.genT) {
      showResult('aes-result', `Need at least ${vault.genT} shares (got ${parsed.length}).`, 'error');
      return;
    }
    const cipher = (el<HTMLInputElement>('aes-decrypt-cipher').value || vault.ciphertext).trim();
    const ivVal = (el<HTMLInputElement>('aes-decrypt-iv').value || vault.iv).trim();
    if (!cipher || !ivVal) { showResult('aes-result', 'Paste ciphertext and IV first, or run Step 2 first.', 'error'); return; }

    try {
      const reconstructedInt = reconstructSecret(parsed.map(s => ({ x: s.x, y: s.y })), AES_KEY_PRIME);
      const reconstructedKey = intToKey(reconstructedInt);
      const plaintext = await aesDecrypt(reconstructedKey, cipher, ivVal);
      showResult('aes-result', `✓ Decrypted: "${plaintext}"`, 'success');
    } catch (e: unknown) {
      showResult('aes-result', `Decryption failed: ${(e as Error).message}`, 'error');
    }
  });
}

// ── Prediction checkpoints ────────────────────────────────────────
// "Predict before reveal" turns watching into learning. Reusable across the
// Gate tab and the guided Lesson.
interface PredictionConfig {
  question: string;
  options: string[];
  correct: number; // index of the correct option
  explain: string; // HTML revealed after answering
}

function buildPrediction(cfg: PredictionConfig): HTMLElement {
  const wrap = document.createElement('div');
  wrap.className = 'predict';

  const q = document.createElement('p');
  q.className = 'predict-q';
  q.innerHTML = `🤔 <b>Predict first:</b> ${cfg.question}`;

  const opts = document.createElement('div');
  opts.className = 'predict-options';

  const reveal = document.createElement('div');
  reveal.className = 'predict-reveal';
  reveal.hidden = true;
  reveal.setAttribute('role', 'status');
  reveal.setAttribute('aria-live', 'polite');

  cfg.options.forEach((opt, i) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'predict-opt';
    b.textContent = opt;
    b.addEventListener('click', () => {
      opts.querySelectorAll('button').forEach((bb, j) => {
        const button = bb as HTMLButtonElement;
        button.disabled = true;
        if (j === cfg.correct) button.classList.add('correct');
        else if (j === i) button.classList.add('incorrect');
      });
      reveal.hidden = false;
      reveal.innerHTML =
        (i === cfg.correct ? '<b class="ok">✓ Correct.</b> ' : '<b class="no">✗ Not quite.</b> ') + cfg.explain;
    });
    opts.appendChild(b);
  });

  wrap.append(q, opts, reveal);
  return wrap;
}

// ── Lesson (guided arc) ───────────────────────────────────────────
interface LessonStep { title: string; body: string; predict?: PredictionConfig; }

function getLessonSteps(): LessonStep[] {
  const p = 257n;
  const coeffs = [42n, 17n, 5n]; // f(x) = 42 + 17x + 5x² mod 257 — secret 42, t = 3
  const f = (x: bigint) => evalPoly(coeffs, x, p);
  const shares = [1n, 2n, 3n, 4n, 5n].map(x => ({ x, y: f(x) }));
  const shareStr = shares.map(s => `(${s.x}, ${s.y})`).join(', ');
  const below = lagrangeAt0([shares[0], shares[1]], p); // 2 of 3 → wrong

  return [
    {
      title: '1 · Encode the secret as a number',
      body: `Shamir's scheme works on numbers, so first turn the secret into one. A short text
        secret becomes its UTF-8 bytes read as a big-endian integer. Here we'll use the
        integer <b>42</b> directly to keep the arithmetic readable.`,
    },
    {
      title: '2 · Pick a prime field GF(p)',
      body: `All arithmetic happens modulo a prime <b>p</b>. We use <b>p = 257</b>. The prime must be
        larger than the secret (so the secret fits) and larger than n (so every share gets a
        distinct x). A prime is required so that every non-zero value has a modular inverse —
        which is what makes division, and therefore interpolation, work.`,
      predict: {
        question: 'Why must p be larger than the secret?',
        options: ['So shares look random', 'So the secret fits in the field [0, p)', 'So reconstruction is faster'],
        correct: 1,
        explain: 'Everything is reduced mod p, so a secret ≥ p would collapse to secret mod p — a different value. The field must be able to represent the secret exactly.',
      },
    },
    {
      title: '3 · Build a degree t−1 polynomial',
      body: `For a threshold of <b>t = 3</b>, build a degree-2 polynomial whose constant term is the
        secret and whose other coefficients are random:
        <div class="lesson-math">f(x) = 42 + 17·x + 5·x²  (mod 257)</div>
        The secret is <b>f(0) = 42</b>. The degree is exactly t−1, which is why it takes t points
        to pin the curve down.`,
    },
    {
      title: '4 · Generate shares as points on the curve',
      body: `Each share is a point <b>(x, f(x) mod p)</b> for x = 1, 2, 3, …, n. Evaluating f at
        x = 1..5 gives the five shares:
        <div class="lesson-math">${shareStr}</div>
        Hand each point to a different custodian. No single point reveals the curve.`,
    },
    {
      title: '5 · Try fewer than t shares',
      body: `With only <b>2</b> of the 3 required shares, interpolation still returns a number —
        here it produces <b>${below}</b>, which is <i>not</i> 42. Worse, nothing flags it as wrong.
        Below the threshold every secret in [0, 256] is equally consistent with what you hold.`,
      predict: {
        question: 'Do 2 of these shares reveal more about the secret than 1 share does?',
        options: ['Yes — each share narrows it down', 'No — until you reach t, you learn nothing'],
        correct: 1,
        explain: 'This is the heart of the theorem. Any set of t−1 or fewer shares is consistent with every possible secret, so additional sub-threshold shares add zero information.',
      },
    },
    {
      title: '6 · Reconstruct with t shares',
      body: `Collect any <b>3</b> shares and run Lagrange interpolation at x = 0. Because three points
        uniquely determine a degree-2 polynomial, you recover the exact curve — and its constant
        term <b>f(0) = 42</b>. The "Polynomial" tab animates this step by step.`,
    },
    {
      title: '7 · Split a key, not the message',
      body: `In practice you don't secret-share a whole file. You encrypt the data with AES, then
        secret-share the short AES <b>key</b>. The "AES Vault" tab does exactly this: encrypt →
        split the key → reconstruct the key from t shares → decrypt.`,
      predict: {
        question: 'When you combine AES with Shamir, what does Shamir actually protect?',
        options: ['The ciphertext', 'The AES key', 'Both equally'],
        correct: 1,
        explain: 'AES-GCM protects the data; Shamir protects custody of the key. Keeping the two roles distinct is the canonical pattern — don\'t use Shamir as a bulk file cipher.',
      },
    },
    {
      title: '8 · Know what SSS does NOT solve',
      body: `Plain Shamir assumes an honest dealer and honest shares. It does <b>not</b> detect a bad
        dealer, verify that a share is valid, authenticate who submitted a share, prevent share
        copying, protect metadata, or recover from too many lost shares. Those need more machinery:
        <b>VSS</b> / Feldman–Pedersen commitments for verifiable shares, <b>FROST</b> for threshold
        signatures without ever reconstructing the key, and HSM ceremonies for operational custody.
        See the "Failure Lab" tab to trigger several of these limits yourself.`,
    },
  ];
}

let lessonIndex = 0;
const LESSON_STEPS = getLessonSteps();

function renderLesson(): void {
  const step = LESSON_STEPS[lessonIndex];
  const host = el('lesson-body');
  host.innerHTML = `
    <div class="lesson-progress" role="status" aria-live="polite">Step ${lessonIndex + 1} of ${LESSON_STEPS.length}</div>
    <h3>${step.title}</h3>
    <div class="lesson-text">${step.body}</div>
  `;
  if (step.predict) host.appendChild(buildPrediction(step.predict));

  const nav = el('lesson-nav');
  nav.innerHTML = `
    <button class="btn-secondary" id="lesson-back" type="button" ${lessonIndex === 0 ? 'disabled' : ''}>← Back</button>
    ${lessonIndex < LESSON_STEPS.length - 1
      ? `<button class="btn-primary" id="lesson-next" type="button">Next →</button>`
      : `<button class="btn-secondary" id="lesson-restart" type="button">↻ Start over</button>`}
  `;
  el('lesson-back')?.addEventListener('click', () => { if (lessonIndex > 0) { lessonIndex--; renderLesson(); } });
  el('lesson-next')?.addEventListener('click', () => { if (lessonIndex < LESSON_STEPS.length - 1) { lessonIndex++; renderLesson(); } });
  el('lesson-restart')?.addEventListener('click', () => { lessonIndex = 0; renderLesson(); });
}

function initLessonTab(): void {
  renderLesson();
}

// ── Failure Lab ───────────────────────────────────────────────────
// Let learners break things safely, then classify the failure: is it the data
// format, the field math, the cryptography, or the operational process?
const CATEGORY_LABEL: Record<FailureCategory, string> = {
  formatting: 'FORMATTING',
  mathematical: 'MATHEMATICAL',
  cryptographic: 'CRYPTOGRAPHIC',
  operational: 'OPERATIONAL',
};

function categoryBadge(cat: FailureCategory): string {
  return `<span class="cat-badge cat-${cat}">${CATEGORY_LABEL[cat]}</span>`;
}

interface FailScenario {
  label: string;
  run: () => Promise<{ category: FailureCategory; detail: string }>;
}

function initFailureLab(): void {
  // A fixed reference split so the "wrong answer" cases can name the true secret.
  const p = 257n;
  const coeffs = [42n, 17n, 5n]; // secret 42, t = 3
  const ref = [1n, 2n, 3n, 4n, 5n].map(x => ({ x, y: evalPoly(coeffs, x, p) }));

  const scenarios: FailScenario[] = [
    {
      label: 'Duplicate x-coordinates',
      run: async () => {
        const v = validateShareSet(`${ref[0].x}:${ref[0].y}:257\n${ref[0].x}:99:257`);
        return { category: v.category!, detail: v.message! };
      },
    },
    {
      label: 'Shares from different splits',
      run: async () => {
        const v = validateShareSet('1:75:257\n2:140:263');
        return { category: v.category!, detail: v.message! };
      },
    },
    {
      label: 'Malformed share text',
      run: async () => {
        const v = validateShareSet('1:75:257\nnot-a-share');
        return { category: v.category!, detail: v.message! };
      },
    },
    {
      label: 'Fewer than t shares',
      run: async () => {
        const got = lagrangeAt0([ref[0], ref[1]], p); // 2 of 3
        return {
          category: 'mathematical',
          detail: `Two of three shares interpolate to ${got}, but the real secret is 42. ` +
            `No error is raised — t−1 shares produce a confident, wrong answer. The threshold is the whole point.`,
        };
      },
    },
    {
      label: 'Secret larger than p',
      run: async () => {
        try {
          await generateShares(300n, 2, 3, 257n);
          return { category: 'mathematical', detail: 'Unexpectedly succeeded.' };
        } catch (e) {
          return {
            category: 'mathematical',
            detail: `generateShares rejected it: "${(e as Error).message}". 300 cannot be represented in GF(257); ` +
              `the field must be larger than the secret.`,
          };
        }
      },
    },
    {
      label: 'One corrupted digit',
      run: async () => {
        const corrupted = [{ x: ref[0].x, y: (ref[0].y + 1n) % p }, ref[1], ref[2]];
        const got = lagrangeAt0(corrupted, p);
        return {
          category: 'operational',
          detail: `One digit of a share was changed. Reconstruction returned ${got} instead of 42 — silently. ` +
            `Plain x:y:p shares carry no integrity check, so a transcription error yields a wrong secret with no warning. ` +
            `This is why operational share formats add a checksum.`,
        };
      },
    },
    {
      label: 'Wrong AES IV',
      run: async () => {
        const key = await generateAESKey();
        const { ciphertext, iv } = await aesEncrypt(key, 'launch at dawn');
        const wrongIv = (iv[0] === '0' ? 'f' : '0') + iv.slice(1);
        try {
          await aesDecrypt(key, ciphertext, wrongIv);
          return { category: 'cryptographic', detail: 'Unexpectedly succeeded.' };
        } catch {
          return {
            category: 'cryptographic',
            detail: 'Right key, wrong IV → AES-GCM authentication failed and refused to return any plaintext. ' +
              'GCM verifies integrity before it will decrypt.',
          };
        }
      },
    },
    {
      label: 'Wrong AES key share',
      run: async () => {
        const key = await generateAESKey();
        const { ciphertext, iv } = await aesEncrypt(key, 'launch at dawn');
        const { shares } = await generateShares(keyToInt(key), 3, 5, AES_KEY_PRIME);
        const bad = [{ x: shares[0].x, y: (shares[0].y + 1n) % AES_KEY_PRIME }, shares[1], shares[2]];
        const wrongKey = intToKey(reconstructSecret(bad, AES_KEY_PRIME));
        try {
          await aesDecrypt(wrongKey, ciphertext, iv);
          return { category: 'cryptographic', detail: 'Unexpectedly succeeded.' };
        } catch {
          return {
            category: 'cryptographic',
            detail: 'One corrupted key share reconstructs the wrong key. AES-GCM then fails authentication ' +
              'rather than returning garbage plaintext — the failure is caught, not silent.',
          };
        }
      },
    },
  ];

  const grid = el('fail-scenarios');
  scenarios.forEach(sc => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn-secondary fail-btn';
    b.textContent = sc.label;
    b.addEventListener('click', async () => {
      const out = el('fail-output');
      out.innerHTML = '<p class="fail-running">Running…</p>';
      try {
        const r = await sc.run();
        out.innerHTML = `<div class="fail-result">${categoryBadge(r.category)}<p>${r.detail}</p></div>`;
      } catch (e) {
        out.innerHTML = `<div class="fail-result">${categoryBadge('operational')}<p>Unexpected: ${(e as Error).message}</p></div>`;
      }
    });
    grid.appendChild(b);
  });
}

// ── Render the HTML shell ─────────────────────────────────────────
function renderShell(): void {
  const app = document.getElementById('app')!;
  app.innerHTML = `
<header class="cl-hero" id="main-content">
  <div class="cl-hero-main">
    <h1 class="cl-hero-title">Shamir Gate</h1>
    <p class="cl-hero-sub">Shamir's Secret Sharing · t-of-n · GF(p) · Lagrange</p>
    <p class="cl-hero-desc">Split a secret into n shares as points on a degree-(t−1) polynomial over GF(p), then watch t of them reconstruct it via Lagrange interpolation while fewer stay locked.</p>
  </div>
  <aside class="cl-hero-why" aria-label="Why it matters">
    <span class="cl-hero-why-label">WHY IT MATTERS</span>
    <p class="cl-hero-why-text">No single keyholder can leak or lose the secret, and any t trustees can recover it. That trade-off underpins crypto-wallet custody, root-key escrow, and quorum access controls where fewer than t shares reveal nothing at all.</p>
  </aside>
  <button class="theme-toggle" id="theme-toggle" type="button" aria-label="Toggle theme">☀️</button>
</header>

<div class="tabs-wrap">
  <div class="tab-list" role="tablist" aria-label="Demo sections">
    <button class="tab-btn" role="tab" aria-selected="true"  aria-controls="tab-lesson"  id="btn-lesson"  tabindex="0">Lesson</button>
    <button class="tab-btn" role="tab" aria-selected="false" aria-controls="tab-gate"     id="btn-gate"     tabindex="-1">The Gate</button>
    <button class="tab-btn" role="tab" aria-selected="false" aria-controls="tab-poly"     id="btn-poly"     tabindex="-1">Polynomial</button>
    <button class="tab-btn" role="tab" aria-selected="false" aria-controls="tab-proof"    id="btn-proof"    tabindex="-1">Security Proof</button>
    <button class="tab-btn" role="tab" aria-selected="false" aria-controls="tab-aes"      id="btn-aes"      tabindex="-1">AES Vault</button>
    <button class="tab-btn" role="tab" aria-selected="false" aria-controls="tab-fail"     id="btn-fail"     tabindex="-1">Failure Lab</button>
    <button class="tab-btn" role="tab" aria-selected="false" aria-controls="tab-rw"       id="btn-rw"       tabindex="-1">Real World</button>
    <button class="tab-btn" role="tab" aria-selected="false" aria-controls="tab-shamir"   id="btn-shamir"   tabindex="-1">Adi Shamir</button>
  </div>

  <!-- ── TAB 0: LESSON (guided arc) ── -->
  <div class="tab-panel active" id="tab-lesson" role="tabpanel" aria-labelledby="btn-lesson" tabindex="0">
    <div class="lesson-wrap">
      <p class="lesson-intro">A guided walk through Shamir's Secret Sharing — encode, split, fail below
      threshold, reconstruct, and learn the boundary between the math and a real custody system.
      Predict at each checkpoint before revealing the answer.</p>
      <div class="panel lesson-panel">
        <div id="lesson-body"></div>
        <div class="btn-row lesson-nav" id="lesson-nav" style="margin-top:1.25rem"></div>
      </div>
    </div>
  </div>

  <!-- ── TAB 1: THE GATE ── -->
  <div class="tab-panel" id="tab-gate" role="tabpanel" aria-labelledby="btn-gate" tabindex="0">
    <div class="two-col">
      <div class="panel">
        <h3>Vault Status</h3>
        <div class="vault-wrap">
          <svg id="lock-svg" class="lock-svg locked" viewBox="0 0 80 100" xmlns="http://www.w3.org/2000/svg"
               role="img" aria-label="Vault locked — 0 of 3 shares collected">
            <path class="lock-shackle-path" d="M20 40 V28 A20 20 0 0 1 60 28 V40" />
            <rect class="lock-body-rect" x="10" y="40" width="60" height="50" rx="6" />
            <path class="keyhole-path" d="M40 58 m-7 0 a7 7 0 1 1 14 0 a7 7 0 0 1 -14 0 M37 65 h6 l-1 14 h-4 z" />
          </svg>
          <div id="lock-label" class="lock-label locked">🔒 LOCKED</div>
          <div id="lock-progress" class="progress-line" role="status" aria-live="polite">Shares collected: <span>0</span> / 3 needed</div>
          <div class="share-slots" id="share-slots"></div>
        </div>
      </div>

      <div class="panel">
        <h3>Configure &amp; Generate</h3>
        <div class="field-group">
          <label for="gate-t">Threshold (t):</label>
          <div class="slider-row">
            <input type="range" id="gate-t" min="2" max="10" value="3">
            <span class="slider-val" id="gate-t-val">3</span>
          </div>
        </div>
        <div class="field-group">
          <label for="gate-n">Total shares (n):</label>
          <div class="slider-row">
            <input type="range" id="gate-n" min="3" max="15" value="5">
            <span class="slider-val" id="gate-n-val">5</span>
          </div>
        </div>
        <div class="field-group">
          <label for="gate-secret">Secret:</label>
          <input type="text" id="gate-secret" value="My Secret" placeholder="Enter secret text">
        </div>
        <button class="btn-primary" id="gate-generate" type="button">Generate Shares</button>

        <div id="gate-shares-display" style="display:none;margin-top:1.25rem">
          <h3>Generated Shares</h3>
          <div class="shares-list" id="gate-shares-list"></div>
          <div class="meta-box" id="gate-meta" style="display:none"></div>
        </div>

        <div style="margin-top:1.5rem;padding-top:1.25rem;border-top:1px solid var(--border)">
          <h3>Reconstruct Secret</h3>
          <div class="field-group">
            <label for="gate-shares-input">Paste shares (one per line):</label>
            <textarea id="gate-shares-input" placeholder="1:847392:65537&#10;2:293847:65537&#10;..."></textarea>
          </div>
          <button class="btn-secondary" id="gate-reconstruct" type="button">Reconstruct</button>
          <div class="result-box" id="gate-result" role="status" aria-live="polite"></div>
          <div id="gate-predict" style="margin-top:1rem"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ── TAB 2: POLYNOMIAL ── -->
  <div class="tab-panel" id="tab-poly" role="tabpanel" aria-labelledby="btn-poly" tabindex="0">
    <div class="poly-layout">
      <div class="panel">
        <h3>Configure</h3>
        <div class="field-group">
          <label for="poly-secret">Secret (integer):</label>
          <input type="number" id="poly-secret" value="42" min="0">
          <span style="font-size:.72rem;color:var(--text-dim);font-family:var(--font-mono)">Uses integer directly for clean viz</span>
        </div>
        <div class="field-group">
          <label for="poly-t">Threshold (t):</label>
          <div class="slider-row">
            <input type="range" id="poly-t" min="2" max="5" value="2">
            <span class="slider-val" id="poly-t-val">2</span>
          </div>
        </div>
        <div class="field-group">
          <label for="poly-n">Total shares (n):</label>
          <div class="slider-row">
            <input type="range" id="poly-n" min="2" max="8" value="4">
            <span class="slider-val" id="poly-n-val">4</span>
          </div>
        </div>
        <div class="field-group">
          <label for="poly-p">Prime p:</label>
          <select id="poly-p">
            <option value="257">257 (8-bit range)</option>
            <option value="1021">1021 (10-bit range)</option>
            <option value="65537">65537 (16-bit range)</option>
          </select>
        </div>
        <div class="btn-row">
          <button class="btn-primary" id="poly-generate" type="button">Generate &amp; Animate</button>
        </div>
        <div class="result-box" id="poly-result" role="status" aria-live="polite"></div>
      </div>

      <div>
        <div id="poly-canvas-area" style="display:none">
          <div class="poly-canvas-wrap">
            <canvas id="poly-canvas" role="img" aria-label="Polynomial curve visualization"></canvas>
          </div>
          <label class="viz-toggle">
            <input type="checkbox" id="poly-viz-toggle">
            Discrete field points only (GF(p) is defined only at integer x; the line is an illustration)
          </label>
          <div class="share-toggles" id="poly-share-toggles"></div>
          <div id="poly-points" class="points-wrap"></div>
        </div>
      </div>
    </div>

    <div class="lagrange-stepper" id="lagrange-stepper">
      <p style="color:var(--text-dim);font-family:var(--font-mono);font-size:.8rem">Generate shares to see Lagrange interpolation.</p>
    </div>
  </div>

  <!-- ── TAB 3: SECURITY PROOF ── -->
  <div class="tab-panel" id="tab-proof" role="tabpanel" aria-labelledby="btn-proof" tabindex="0">
    <div class="proof-setup">
      <h2>Why t-1 Shares Reveal Nothing</h2>
      <p style="color:var(--text-dim);margin-bottom:1rem">
        Threshold: t = 3. Attacker observes 2 shares (= t-1).<br>
        Known shares: <b style="color:var(--gold)">(1, 75)</b> and <b style="color:var(--gold)">(2, 140)</b>. Prime: p = 257.
      </p>
      <p style="color:var(--text-dim);margin-bottom:.75rem">
        For every possible secret S ∈ [0, 256], there exists exactly one degree-2 polynomial
        that passes through (1,75) and (2,140) with f(0) = S. Here are three examples:
      </p>
      <div id="proof-candidates"></div>
    </div>

    <div class="proof-lab panel">
      <h3>Try it yourself</h3>
      <p style="color:var(--text-dim);font-size:.82rem;margin-bottom:.75rem">
        Type <em>any</em> secret in [0, 256]. We'll build the unique degree-2 polynomial through
        (1,75) and (2,140) with that secret at f(0) — and show it fits the observed shares just as well.
      </p>
      <div class="proof-lab-row">
        <input type="number" id="proof-candidate" min="0" max="256" value="123" aria-label="Candidate secret">
        <button class="btn-primary" id="proof-check" type="button">Check candidate</button>
      </div>
      <div class="result-box" id="proof-lab-out" role="status" aria-live="polite" style="display:block"></div>
      <p class="proof-lab-counter" id="proof-lab-counter" role="status" aria-live="polite"></p>
    </div>

    <div class="proof-canvas-wrap">
      <canvas id="proof-canvas" role="img" aria-label="Three polynomials consistent with the same two shares, each reaching a different secret at x=0"></canvas>
    </div>

    <div class="theorem-box">
      <h3>Theorem (Shamir, 1979)</h3>
      <p>Any t-1 shares are consistent with every possible secret S ∈ GF(p).
      The shares provide <b>zero bits of information</b> about S.</p>
      <p style="margin-top:.75rem">
        This is <b style="color:var(--cyan)">unconditional security</b> — it holds against adversaries with
        <b>infinite computational power</b>. Unlike RSA or AES, no assumption about
        computational hardness is required.
      </p>
      <p style="color:var(--text-dim);margin-top:.75rem;font-size:.75rem">
        RSA: "hard to factor" — assumption, could be broken.<br>
        Shamir: "impossible to determine" — mathematical certainty.
      </p>
    </div>
  </div>

  <!-- ── TAB 4: AES VAULT ── -->
  <div class="tab-panel" id="tab-aes" role="tabpanel" aria-labelledby="btn-aes" tabindex="0">
    <div class="concept-callout">
      <h3>Three different jobs — keep them straight</h3>
      <div class="concept-grid">
        <div><b>Encryption</b><span>AES-256-GCM protects the <em>data</em>.</span></div>
        <div><b>Secret sharing</b><span>Shamir splits a <em>value</em> into t-of-n shares.</span></div>
        <div><b>Key custody</b><span>Here, the value being shared is the AES <em>key</em>.</span></div>
      </div>
      <p class="concept-pattern">Canonical pattern: <b>encrypt the data with AES, then secret-share the key.</b>
      Shamir is not a bulk file cipher — you share the short key, not the whole message.</p>
    </div>

    <div class="step-block">
      <div class="step-num">Step 1 — Configure</div>
      <h3>Encrypt a Message with a Split Key</h3>
      <div class="two-col">
        <div>
          <div class="field-group">
            <label for="aes-t">Threshold (t):</label>
            <div class="slider-row">
              <input type="range" id="aes-t" min="2" max="8" value="3">
              <span class="slider-val" id="aes-t-val">3</span>
            </div>
          </div>
          <div class="field-group">
            <label for="aes-n">Total shares (n):</label>
            <div class="slider-row">
              <input type="range" id="aes-n" min="3" max="12" value="5">
              <span class="slider-val" id="aes-n-val">5</span>
            </div>
          </div>
        </div>
        <div>
          <div class="field-group">
            <label for="aes-message">Message:</label>
            <input type="text" id="aes-message" value="Top secret document" placeholder="Message to encrypt">
          </div>
          <button class="btn-primary" id="aes-generate" type="button">Generate Key &amp; Split</button>
        </div>
      </div>
    </div>

    <div class="step-block" id="aes-step2-result" style="display:none">
      <div class="step-num">Step 2 — Key &amp; Shares</div>
      <h3>AES-256 Key (32 bytes)</h3>
      <div id="aes-key-display"></div>
      <div id="aes-cipher-display" style="margin-top:.75rem"></div>
      <h3 style="margin-top:1rem">Key Shares (prime: 2²⁵⁶+297)</h3>
      <div class="shares-list" id="aes-shares-list"></div>
    </div>

    <div class="step-block">
      <div class="step-num">Step 3 — Decrypt</div>
      <h3>Reconstruct Key &amp; Decrypt</h3>
      <div class="field-group">
        <label for="aes-decrypt-cipher">Ciphertext (hex, leave blank to use generated):</label>
        <input type="text" id="aes-decrypt-cipher" placeholder="(auto-filled from Step 2)">
      </div>
      <div class="field-group">
        <label for="aes-decrypt-iv">IV (hex, leave blank to use generated):</label>
        <input type="text" id="aes-decrypt-iv" placeholder="(auto-filled from Step 2)">
      </div>
      <div class="field-group">
        <label for="aes-shares-input">Paste t key shares (one per line):</label>
        <textarea id="aes-shares-input" placeholder="1:8472...:11579...&#10;2:2938...:11579..."></textarea>
      </div>
      <button class="btn-secondary" id="aes-decrypt" type="button">Reconstruct Key &amp; Decrypt</button>
      <div class="result-box" id="aes-result" role="status" aria-live="polite"></div>
    </div>

    <div class="security-note">
      <strong>⚠ In production:</strong> each share goes to a different custodian.
      No single custodian has the key. Requires t custodians to cooperate to decrypt.<br>
      Used in: HSMs, nuclear launch protocols, certificate authorities,
      cryptocurrency cold storage, FROST threshold signatures.
    </div>

    <div class="disclaimer">
      <strong>Not a custody product.</strong> This demo implements the math of Shamir Secret Sharing
      and uses real browser cryptography for AES-GCM. It is not a complete key-custody system.
      Production systems also need authenticated share formats, identity, audit logs, secure storage,
      key ceremonies, backups, verifiable shares (VSS), and incident procedures.
    </div>
  </div>

  <!-- ── TAB 4b: FAILURE LAB ── -->
  <div class="tab-panel" id="tab-fail" role="tabpanel" aria-labelledby="btn-fail" tabindex="0">
    <div class="panel">
      <h3>Break it on purpose</h3>
      <p style="color:var(--text-dim);font-size:.85rem;margin-bottom:1rem">
        Each button triggers a real failure, then classifies it. Learning to tell these four apart —
        <b class="cat-formatting-t">formatting</b>, <b class="cat-mathematical-t">mathematical</b>,
        <b class="cat-cryptographic-t">cryptographic</b>, and <b class="cat-operational-t">operational</b> —
        is half of debugging a threshold system.
      </p>
      <div class="fail-grid" id="fail-scenarios"></div>
      <div id="fail-output" class="fail-output-box" role="status" aria-live="polite"></div>
    </div>
  </div>

  <!-- ── TAB 5: REAL WORLD ── -->
  <div class="tab-panel" id="tab-rw" role="tabpanel" aria-labelledby="btn-rw" tabindex="0">
    <div class="rw-grid">
      ${[
        ['01', 'FROST Threshold Signatures (RFC 9591)',
         'Shamir underlies FROST — a threshold signature scheme where any t-of-n signers can produce a valid Ed25519 signature without any single party holding the private key. Used in cryptocurrency wallets and decentralized key management.',
         '→ See crypto-lab-frost-threshold'],
        ['02', 'Hardware Security Modules (HSMs)',
         'Enterprise HSMs (Thales, nCipher) use Shamir to split the HSM master key across multiple administrators. Requires t admins to be physically present to initialize or restore the HSM.',
         ''],
        ['03', 'Certificate Authority Key Ceremonies',
         'Major CAs (including root CAs trusted by browsers) split their root private key using Shamir. Key ceremonies require multiple key holders in a secure facility to reconstruct the CA key.',
         ''],
        ['04', 'Cryptocurrency Cold Storage',
         'Bitcoin multisig wallets use threshold schemes related to Shamir. Some cold storage protocols split the seed phrase using SSS so no single backup location holds the full secret.',
         ''],
        ['05', 'Nuclear Launch Authorization',
         'The two-person integrity rule for nuclear launch codes is conceptually equivalent to t=2 Shamir — two separate key holders must cooperate to authorize launch. Cryptographic implementations use formal SSS.',
         ''],
        ['06', 'Multi-Party Computation (MPC)',
         'Shamir secret sharing is a fundamental building block for MPC protocols including SPDZ and BGW. Secure Aggregation in federated learning (Google Gboard) uses Shamir.',
         '→ See crypto-lab-silent-tally'],
      ].map(([num, title, body, link]) => `
        <div class="rw-card">
          <div class="rw-card-header">
            <span class="rw-card-num">${num}</span>
            <span class="rw-card-title">${title}</span>
          </div>
          <div class="rw-card-body">
            ${body}
            ${link ? `<span class="rw-card-link">${link}</span>` : ''}
          </div>
        </div>
      `).join('')}
    </div>

    <div class="sources">
      <h3>Sources &amp; standards</h3>
      <ul>
        <li>Adi Shamir, "How to Share a Secret," <i>Communications of the ACM</i> 22(11), 1979.</li>
        <li>G. R. Blakley, "Safeguarding Cryptographic Keys," AFIPS 1979 (independent, geometric scheme).</li>
        <li>RFC 9591 — The Flexible Round-Optimized Schnorr Threshold (FROST) signature scheme, 2024.</li>
        <li>NIST SP 800-38D — Galois/Counter Mode (GCM) for authenticated encryption.</li>
        <li>Feldman (1987) and Pedersen (1991) — Verifiable Secret Sharing commitments.</li>
      </ul>
    </div>
  </div>

  <!-- ── TAB 6: ADI SHAMIR ── -->
  <div class="tab-panel" id="tab-shamir" role="tabpanel" aria-labelledby="btn-shamir" tabindex="0">
    <div class="bio-wrap">
      <div>
        <div class="bio-avatar" role="img" aria-label="Geometric portrait of Adi Shamir">
          <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
            <circle cx="50" cy="35" r="22" fill="#1e2040" stroke="#ffd700" stroke-width="2"/>
            <polygon points="50,18 68,50 32,50" fill="none" stroke="#00d4ff" stroke-width="1.5"/>
            <circle cx="50" cy="35" r="8" fill="#ffd700" opacity=".6"/>
            <rect x="22" y="55" width="56" height="35" rx="10" fill="#1e2040" stroke="#2a2d6a" stroke-width="1.5"/>
            <line x1="50" y1="55" x2="50" y2="90" stroke="#00d4ff" stroke-width="1" opacity=".4"/>
          </svg>
        </div>
      </div>
      <div class="bio-content">
        <h2>Adi Shamir — The S in RSA</h2>
        <p class="bio-sub">Born 1952, Tel Aviv · Weizmann Institute of Science</p>

        <div class="bio-section">
          <h3>The RSA Paper (1977)</h3>
          <p>With Ron Rivest and Len Adleman, Shamir co-invented RSA encryption — the first practical public-key cryptosystem. The S in RSA is his.</p>
        </div>

        <div class="bio-section">
          <h3>Secret Sharing (1979)</h3>
          <p>Two years after RSA, Shamir published "How to Share a Secret" in Communications of the ACM. The paper is two pages long (CACM 22(11), pp. 612–613). It introduced the polynomial-based scheme demonstrated in this demo. Independent of Shamir, George Blakley published a geometrically-equivalent scheme the same year.</p>
        </div>

        <div class="bio-section">
          <h3>Differential Cryptanalysis (1990)</h3>
          <p>With Eli Biham, Shamir co-invented differential cryptanalysis — the first systematic technique for attacking block ciphers. It broke DES and shaped the design of AES.</p>
        </div>

        <div class="bio-section">
          <h3>Fiat-Shamir Heuristic</h3>
          <p>Shamir's work on zero-knowledge proofs in the 1980s — particularly the Fiat-Shamir transform — underpins modern ZK proof systems used in SNARK-based blockchains.</p>
        </div>

        <div class="bio-section">
          <h3>RC4 / WEP Attack (2001)</h3>
          <p>Shamir attacked RC4 (with Fluhrer and Mantin), leading to the WEP vulnerability that broke Wi-Fi security in the early 2000s.</p>
        </div>

        <div class="bio-quote">
          "Cryptography is typically bypassed, not penetrated."
        </div>
      </div>
    </div>
  </div>
</div>
`;
}

// ── Bootstrap ─────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  renderShell();
  initTheme();
  initTabs();
  initLessonTab();
  initGateTab();
  initPolyTab();
  initAesTab();
  initFailureLab();
  // Security proof is static — render on load
  // Wait one tick so DOM is ready
  setTimeout(() => initSecurityTab(), 0);
});

