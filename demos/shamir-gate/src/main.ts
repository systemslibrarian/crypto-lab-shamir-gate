/**
 * Shamir-Gate — Main UI
 * Six-tab Shamir's Secret Sharing demo.
 * All arithmetic: BigInt over GF(p). All randomness via crypto.getRandomValues. No float in math.
 */

import {
  generateShares,
  reconstructSecret,
  lagrangeAt0,
  lagrangeEvalAt,
  evalPoly,
  modInverse,
  choosePrime,
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

function deserializeShare(s: string): { x: bigint; y: bigint; p: bigint } | null {
  const parts = s.trim().split(':');
  if (parts.length < 3) return null;
  try { return { x: BigInt(parts[0]), y: BigInt(parts[1]), p: BigInt(parts[2]) }; }
  catch { return null; }
}

// ── Tab 1: THE GATE ───────────────────────────────────────────────
interface GateState {
  n: number;
  t: number;
  shares: Array<{ x: bigint; y: bigint }>;
  prime: bigint;
  submittedCount: number;
}

const gate: GateState = { n: 5, t: 3, shares: [], prime: 257n, submittedCount: 0 };

function updateLock(submitted: number, threshold: number): void {
  const svg = el('lock-svg');
  const label = el('lock-label');
  const statusMsg = submitted >= threshold ? 'Vault unlocked' : `Vault locked — ${submitted} of ${threshold} shares collected`;
  if (submitted >= threshold) {
    svg.className = 'lock-svg unlocked';
    label.className = 'lock-label unlocked';
    label.textContent = '🔓 UNLOCKED';
  } else {
    svg.className = 'lock-svg locked';
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
          <button type="button">Copy</button>
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
    const lines = (el<HTMLTextAreaElement>('gate-shares-input').value).trim().split('\n').filter(Boolean);
    const parsed = lines.map(l => deserializeShare(l)).filter(Boolean) as Array<{ x: bigint; y: bigint; p: bigint }>;
    if (parsed.length === 0) { showResult('gate-result', 'No valid shares found.', 'error'); return; }
    const p = parsed[0].p;
    try {
      const secret = reconstructSecret(parsed.map(s => ({ x: s.x, y: s.y })), p);
      const text = intToSecret(secret);
      gate.submittedCount = Math.min(parsed.length, gate.n);
      updateLock(gate.submittedCount, gate.t);
      updateSlots(gate.n, gate.submittedCount);
      showResult('gate-result', `✓ Secret recovered: "${text}" (integer: ${secret})`, 'success');
    } catch (e: unknown) {
      showResult('gate-result', `Error: ${(e as Error).message}`, 'error');
    }
  });
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
}

const poly: PolyState = {
  secret: 42n, t: 2, n: 4, p: 257n,
  shares: [], coefficients: [], activeShares: new Set(),
  cancelAnim: null, stepIndex: 0, lagrangeSteps: []
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
  });
  const label = `Polynomial curve for secret=${poly.secret}, t=${poly.t}, n=${poly.n}, p=${poly.p}. ${poly.activeShares.size >= poly.t ? 'Threshold met.' : 'Below threshold.'}`;
  canvas.setAttribute('aria-label', label);
  updateLagrangeStepper();
}

function buildLagrangeSteps(activePoints: Array<{ x: bigint; y: bigint }>, p: bigint): string[] {
  const steps: string[] = [];
  const k = activePoints.length;
  steps.push(`Using shares: ${activePoints.map(s => `(${s.x},${s.y})`).join(', ')}`);

  const liValues: bigint[] = [];
  for (let i = 0; i < k; i++) {
    const xi = activePoints[i].x;
    const yi = activePoints[i].y;
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

  const stepsHtml = poly.lagrangeSteps.slice(0, poly.stepIndex + 1).map((s, i) => `
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
  syncSliders();

  el('poly-generate').addEventListener('click', async () => {
    if (poly.cancelAnim) poly.cancelAnim();
    const secretInput = parseInt((el<HTMLInputElement>('poly-secret').value) || '42');
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
  const proof_t = 3;
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
    for (let x = 0; x <= 40; x++) {
      const xB = BigInt(Math.round((x / 40) * 30));
      const limitX = xB >= proof_p ? proof_p - 1n : xB;
      const yV = lagrangeEvalAt(pts, limitX, proof_p);
      const px = toX(x / 40 * xMax);
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
}

// ── Tab 4: AES VAULT ──────────────────────────────────────────────
interface AesVaultState {
  key: Uint8Array | null;
  ciphertext: string;
  iv: string;
  shares: Array<{ x: bigint; y: bigint }>;
  t: number;
  n: number;
}

const vault: AesVaultState = { key: null, ciphertext: '', iv: '', shares: [], t: 3, n: 5 };

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
          <button type="button">Copy</button>
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
    const lines = (el<HTMLTextAreaElement>('aes-shares-input').value).trim().split('\n').filter(Boolean);
    const parsed = lines.map(l => deserializeShare(l)).filter(Boolean) as Array<{ x: bigint; y: bigint; p: bigint }>;
    if (parsed.length < vault.t) {
      showResult('aes-result', `Need at least ${vault.t} shares (got ${parsed.length}).`, 'error');
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

// ── Render the HTML shell ─────────────────────────────────────────
function renderShell(): void {
  const app = document.getElementById('app')!;
  app.innerHTML = `
<header class="site-header" id="main-content">
  <div class="header-text">
    <h1>Shamir-Gate</h1>
    <p>Shamir's Secret Sharing — GF(p) polynomial, Lagrange interpolation, AES-256-GCM vault</p>
  </div>
  <button class="theme-toggle" id="theme-toggle" type="button" aria-label="Toggle theme">☀️</button>
</header>

<div class="tabs-wrap">
  <div class="tab-list" role="tablist" aria-label="Demo sections">
    <button class="tab-btn" role="tab" aria-selected="true"  aria-controls="tab-gate"     id="btn-gate"     tabindex="0">The Gate</button>
    <button class="tab-btn" role="tab" aria-selected="false" aria-controls="tab-poly"     id="btn-poly"     tabindex="-1">Polynomial</button>
    <button class="tab-btn" role="tab" aria-selected="false" aria-controls="tab-proof"    id="btn-proof"    tabindex="-1">Security Proof</button>
    <button class="tab-btn" role="tab" aria-selected="false" aria-controls="tab-aes"      id="btn-aes"      tabindex="-1">AES Vault</button>
    <button class="tab-btn" role="tab" aria-selected="false" aria-controls="tab-rw"       id="btn-rw"       tabindex="-1">Real World</button>
    <button class="tab-btn" role="tab" aria-selected="false" aria-controls="tab-shamir"   id="btn-shamir"   tabindex="-1">Adi Shamir</button>
  </div>

  <!-- ── TAB 1: THE GATE ── -->
  <div class="tab-panel active" id="tab-gate" role="tabpanel" aria-labelledby="btn-gate" tabindex="0">
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
          <div id="lock-progress" class="progress-line">Shares collected: <span>0</span> / 3 needed</div>
          <div class="share-slots" id="share-slots"></div>
        </div>
      </div>

      <div class="panel">
        <h3>Configure &amp; Generate</h3>
        <div class="field-group">
          <label for="gate-t">Threshold (t):</label>
          <div class="slider-row">
            <input type="range" id="gate-t" min="2" max="10" value="3" aria-valuenow="3" aria-valuemin="2" aria-valuemax="10">
            <span class="slider-val" id="gate-t-val">3</span>
          </div>
        </div>
        <div class="field-group">
          <label for="gate-n">Total shares (n):</label>
          <div class="slider-row">
            <input type="range" id="gate-n" min="3" max="15" value="5" aria-valuenow="5" aria-valuemin="3" aria-valuemax="15">
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
          <div class="result-box" id="gate-result"></div>
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
        <div class="result-box" id="poly-result"></div>
      </div>

      <div>
        <div id="poly-canvas-area" style="display:none">
          <div class="poly-canvas-wrap">
            <canvas id="poly-canvas" role="img" aria-label="Polynomial curve visualization"></canvas>
          </div>
          <div class="share-toggles" id="poly-share-toggles"></div>
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
      <div class="result-box" id="aes-result"></div>
    </div>

    <div class="security-note">
      <strong>⚠ In production:</strong> each share goes to a different custodian.
      No single custodian has the key. Requires t custodians to cooperate to decrypt.<br>
      Used in: HSMs, nuclear launch protocols, certificate authorities,
      cryptocurrency cold storage, FROST threshold signatures.
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
  </div>

  <!-- ── TAB 6: ADI SHAMIR ── -->
  <div class="tab-panel" id="tab-shamir" role="tabpanel" aria-labelledby="btn-shamir" tabindex="0">
    <div class="bio-wrap">
      <div>
        <div class="bio-avatar" aria-label="Geometric portrait of Adi Shamir">
          <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
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
          <p>Two years after RSA, Shamir published "How to Share a Secret" in Communications of the ACM. The paper is four pages long. It introduced the polynomial-based scheme demonstrated in this demo. Independent of Shamir, George Blakley published a geometrically-equivalent scheme the same year.</p>
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
  initGateTab();
  initPolyTab();
  initAesTab();
  // Security proof is static — render on load
  // Wait one tick so DOM is ready
  setTimeout(() => initSecurityTab(), 0);
});

