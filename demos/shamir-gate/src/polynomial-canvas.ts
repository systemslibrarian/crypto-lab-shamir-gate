/**
 * Polynomial visualization canvas for Shamir's Secret Sharing Demo.
 *
 * Renders the polynomial over GF(p) with:
 * - The polynomial curve (cyan)
 * - The secret point at (0, secret) in gold
 * - Share points (green = active, gray = inactive)
 * - Reconstructed polynomial when shares ≥ t (magenta)
 * - Multiple candidate polynomials when shares < t (dim cyan variants)
 *   each passing through the same shares but hitting a DIFFERENT f(0)
 */

import { evalPoly, lagrangeEvalAt, lagrangeAt0 } from './math';

export interface PolyCanvasConfig {
  width: number;
  height: number;
  prime: bigint;
  secret: bigint;
  coefficients: bigint[];
  shares: Array<{ x: bigint; y: bigint }>;
  activeShares: Set<number>; // which share indices (0-based) are selected
  threshold: number;
  showFullCurve: boolean;
}

const PAD = 60;
const COLOR_CURVE = '#00d4ff';
const COLOR_SECRET = '#ffd700';
const COLOR_ACTIVE = '#00ff88';
const COLOR_INACTIVE = '#444466';
const COLOR_RECONSTRUCTED = '#ff00ff';
const COLOR_CANDIDATE_A = 'rgba(0,180,255,0.45)';
const COLOR_CANDIDATE_B = 'rgba(100,255,180,0.45)';
const COLOR_CANDIDATE_C = 'rgba(255,140,0,0.45)';
const COLOR_AXIS = '#334466';

export function drawPolynomial(canvas: HTMLCanvasElement, config: PolyCanvasConfig): void {
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const { width, height, prime: p, secret, coefficients, shares, activeShares, threshold } = config;

  canvas.width = width;
  canvas.height = height;

  // Clear
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = '#0a0a14';
  ctx.fillRect(0, 0, width, height);

  const n = shares.length;
  const xRange = n + 1; // show x from 0 to n+1
  const yRange = p;

  // Coordinate transform: logical (x, y) → canvas pixel
  function toPixelX(x: number): number {
    return PAD + ((x / xRange) * (width - 2 * PAD));
  }
  function toPixelY(y: bigint): number {
    // Map [0, p) to [height-PAD, PAD] (inverted y)
    const frac = Number((y * 1000000n) / yRange) / 1000000;
    return (height - PAD) - frac * (height - 2 * PAD);
  }

  // Draw axes
  ctx.strokeStyle = COLOR_AXIS;
  ctx.lineWidth = 1;
  ctx.beginPath();
  // Y axis at x=0
  ctx.moveTo(toPixelX(0), PAD - 10);
  ctx.lineTo(toPixelX(0), height - PAD + 10);
  // X axis at y=0
  ctx.moveTo(PAD - 10, toPixelY(0n));
  ctx.lineTo(width - PAD + 10, toPixelY(0n));
  ctx.stroke();

  // Axis labels
  ctx.fillStyle = '#556688';
  ctx.font = '11px monospace';
  ctx.fillText('0', toPixelX(0) - 12, toPixelY(0n) + 4);
  ctx.fillText(`p=${p.toString().length > 8 ? p.toString().substring(0, 6) + '…' : p}`, toPixelX(0) - 10, PAD - 14);
  ctx.fillText('x', width - PAD + 14, toPixelY(0n) + 4);

  // Wrapping note
  ctx.fillStyle = '#445566';
  ctx.font = '10px monospace';
  ctx.fillText('y values are mod p — curve wraps. Arithmetic is still exact.', PAD + 4, height - 8);

  const activeSel = [...activeShares];
  const activePoints = activeSel.map(i => shares[i]);
  const belowThreshold = activePoints.length < threshold;

  // Draw candidate curves (when below threshold)
  if (belowThreshold && activePoints.length > 0) {
    // Pick 3 candidate secrets evenly spread across [0, p)
    const candidateSecrets: bigint[] = [];
    const step = p / 4n;
    for (let i = 1; i <= 3; i++) {
      let cs = (BigInt(i) * step) % p;
      // avoid the real secret
      if (cs === secret) cs = (cs + step / 3n) % p;
      candidateSecrets.push(cs);
    }
    const candidateColors = [COLOR_CANDIDATE_A, COLOR_CANDIDATE_B, COLOR_CANDIDATE_C];

    for (let ci = 0; ci < candidateSecrets.length; ci++) {
      const cs = candidateSecrets[ci];
      // Build point set: (0, cs) + all active share points
      const pts = [{ x: 0n, y: cs }, ...activePoints];
      ctx.strokeStyle = candidateColors[ci];
      ctx.lineWidth = 1.5;
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      let first = true;
      for (let xi = 0; xi <= xRange * 20; xi++) {
        const xFrac = xi / 20;
        const xBig = BigInt(Math.round(xFrac * 10)) % (p - 1n) + 1n;
        const actualX = (xFrac === 0) ? 0n : xBig;
        const yVal = lagrangeEvalAt(pts, actualX, p);
        const px = toPixelX(xFrac);
        const py = toPixelY(yVal);
        if (first) { ctx.moveTo(px, py); first = false; }
        else ctx.lineTo(px, py);
      }
      ctx.stroke();
      ctx.setLineDash([]);

      // Label the y-intercept
      const interceptY = toPixelY(cs);
      ctx.fillStyle = candidateColors[ci];
      ctx.font = '10px monospace';
      ctx.fillText(`f(0)=${cs}`, toPixelX(0) + 4, interceptY - 4);
    }

    // Banner
    drawBanner(ctx, width, '✗ Below threshold — secret indeterminate', '#ff3366');
  } else if (!belowThreshold && activePoints.length >= threshold) {
    // Draw reconstructed polynomial (magenta)
    const recSecret = lagrangeAt0(activePoints, p);
    const pts = activePoints;

    ctx.strokeStyle = COLOR_RECONSTRUCTED;
    ctx.lineWidth = 2;
    ctx.beginPath();
    let first = true;
    const steps = (n + 1) * 40;
    for (let si = 0; si <= steps; si++) {
      const xFrac = (si / steps) * xRange;
      const xBig = floatToBigIntX(xFrac, p);
      const yVal = lagrangeEvalAt(pts, xBig, p);
      const px = toPixelX(xFrac);
      const py = toPixelY(yVal);
      if (first) { ctx.moveTo(px, py); first = false; }
      else ctx.lineTo(px, py);
    }
    ctx.stroke();

    // Gold dot at reconstructed f(0)
    const recPx = toPixelX(0);
    const recPy = toPixelY(recSecret);
    ctx.fillStyle = COLOR_SECRET;
    ctx.beginPath();
    ctx.arc(recPx, recPy, 7, 0, Math.PI * 2);
    ctx.fill();

    drawBanner(ctx, width, `✓ Threshold met — secret = ${recSecret}`, '#00ff88');
  }

  // Draw main polynomial curve
  if (coefficients.length > 0) {
    ctx.strokeStyle = COLOR_CURVE;
    ctx.lineWidth = 2;
    ctx.beginPath();
    let first = true;
    const steps = (n + 1) * 40;
    for (let si = 0; si <= steps; si++) {
      const xFrac = (si / steps) * xRange;
      const xBig = floatToBigIntX(xFrac, p);
      const yVal = evalPoly(coefficients, xBig, p);
      const px = toPixelX(xFrac);
      const py = toPixelY(yVal);
      if (first) { ctx.moveTo(px, py); first = false; }
      else ctx.lineTo(px, py);
    }
    ctx.stroke();
  }

  // Draw share points
  for (let i = 0; i < shares.length; i++) {
    const share = shares[i];
    const px = toPixelX(Number(share.x));
    const py = toPixelY(share.y);
    const isActive = activeShares.has(i);

    ctx.fillStyle = isActive ? COLOR_ACTIVE : COLOR_INACTIVE;
    ctx.beginPath();
    ctx.arc(px, py, 6, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle = isActive ? COLOR_ACTIVE : '#667788';
    ctx.font = '11px monospace';
    ctx.fillText(`S${i + 1}`, px - 4, py - 10);
  }

  // Draw secret point (0, secret)
  const spx = toPixelX(0);
  const spy = toPixelY(secret);
  ctx.fillStyle = COLOR_SECRET;
  ctx.beginPath();
  ctx.arc(spx, spy, 8, 0, Math.PI * 2);
  ctx.fill();

  // Label
  ctx.fillStyle = COLOR_SECRET;
  ctx.font = 'bold 12px monospace';
  ctx.fillText(`Secret = f(0) = ${secret}`, spx + 12, spy + 4);
}

/**
 * Animate the polynomial drawing from left to right.
 * Returns a cleanup function to cancel the animation.
 */
export function animatePolynomial(
  canvas: HTMLCanvasElement,
  config: PolyCanvasConfig,
  durationMs: number
): () => void {
  let cancelled = false;
  const start = performance.now();

  const { coefficients, shares, prime: p, threshold, activeShares } = config;
  const n = shares.length;
  const xRange = n + 1;
  const PAD_L = PAD;
  const w = config.width;
  const h = config.height;

  function toPixelX(x: number): number {
    return PAD_L + ((x / xRange) * (w - 2 * PAD_L));
  }
  function toPixelY(y: bigint): number {
    const frac = Number((y * 1000000n) / p) / 1000000;
    return (h - PAD_L) - frac * (h - 2 * PAD_L);
  }

  function frame(now: number) {
    if (cancelled) return;
    const elapsed = now - start;
    const progress = Math.min(elapsed / durationMs, 1);

    // Draw base
    drawPolynomial(canvas, config);

    // Overdraw animated portion of curve
    if (coefficients.length > 0 && progress < 1) {
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      const steps = Math.floor((xRange * 40) * progress);
      const totalSteps = xRange * 40;
      ctx.strokeStyle = '#00d4ff';
      ctx.lineWidth = 2.5;
      ctx.beginPath();
      let first = true;
      for (let si = 0; si <= steps; si++) {
        const xFrac = (si / totalSteps) * xRange;
        const xBig = floatToBigIntX(xFrac, p);
        const yVal = evalPoly(coefficients, xBig, p);
        const px = toPixelX(xFrac);
        const py = toPixelY(yVal);
        if (first) { ctx.moveTo(px, py); first = false; }
        else ctx.lineTo(px, py);
      }
      ctx.stroke();
    }

    if (progress < 1) {
      requestAnimationFrame(frame);
    }
  }

  requestAnimationFrame(frame);
  return () => { cancelled = true; };
}

// Helper: convert a floating-point x coordinate to a BigInt for polynomial eval.
// For integer x values, this is exact. For fractional, we use the nearest integer.
function floatToBigIntX(xFrac: number, _p: bigint): bigint {
  // We sample at integer points for the curve, interpolating visually
  // by rounding to nearest integer x in [0, n+1]
  return BigInt(Math.round(xFrac));
}

function drawBanner(ctx: CanvasRenderingContext2D, width: number, text: string, color: string) {
  ctx.fillStyle = color + '22';
  ctx.fillRect(PAD, 8, width - 2 * PAD, 28);
  ctx.fillStyle = color;
  ctx.font = 'bold 13px monospace';
  ctx.fillText(text, PAD + 10, 28);
}
