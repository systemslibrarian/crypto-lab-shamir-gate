/**
 * Polynomial Curve Visualization
 * 
 * Visualizes Shamir's Secret Sharing as a 2D curve over GF(2⁸)
 * - x-axis: 0 to 15 (share indices)
 * - y-axis: 0 to 255 (field values)
 * - Secret: point at x=0
 * - Shares: 1 to n colored points on the curve
 * - Curve shape: line segments connecting evaluated points
 */

import { Polynomial, evaluateAt } from '../crypto/polynomial';
import { Share, split, ShamirConfig } from '../crypto/shamir';

export interface VisualizationState {
  /** Current polynomial (undefined if no curve yet) */
  polynomial?: Polynomial;

  /** All evaluated points for curve rendering */
  curvePoints: Array<{ x: number; y: number }>;

  /** Share points revealed so far */
  revealedShares: Share[];

  /** Configuration: k, n */
  config: ShamirConfig;

  /** All n possible shares (used for animation) */
  allShares: Share[];

  /** Whether the unique curve is determined (true if k shares shown) */
  isUnique: boolean;
}

export interface CanvasConfig {
  /** Canvas width in pixels */
  width: number;

  /** Canvas height in pixels */
  height: number;

  /** Padding from edges */
  padding: number;

  /** Plot area for GF(2⁸) values: x from 0-15, y from 0-255 */
  xMin: number;
  xMax: number;
  yMin: number;
  yMax: number;

  /** Colors */
  colors: {
    background: string;
    axis: string;
    grid: string;
    curve: string;
    secret: string;
    share: string;
    shareRevealed: string;
    text: string;
  };
}

const DEFAULT_CANVAS_CONFIG: CanvasConfig = {
  width: 800,
  height: 600,
  padding: 60,
  xMin: 0,
  xMax: 15,
  yMin: 0,
  yMax: 255,
  colors: {
    background: '#1a1a2e',
    axis: '#00d9ff',
    grid: 'rgba(0, 217, 255, 0.1)',
    curve: '#ff00ff',
    secret: '#ff0000',
    share: '#00ff00',
    shareRevealed: '#00cc88',
    text: '#e0e0e0'
  }
};

export class CurveVisualizer {
  canvas: HTMLCanvasElement;
  ctx: CanvasRenderingContext2D;
  config: CanvasConfig;
  state: VisualizationState;

  constructor(canvasId: string, config?: Partial<CanvasConfig>) {
    const element = document.getElementById(canvasId);
    if (!(element instanceof HTMLCanvasElement)) {
      throw new Error(`Element ${canvasId} is not a canvas`);
    }

    this.canvas = element;
    const ctx = this.canvas.getContext('2d');
    if (!ctx) {
      throw new Error('Could not get 2D context from canvas');
    }

    this.ctx = ctx;
    this.config = { ...DEFAULT_CANVAS_CONFIG, ...config };
    this.canvas.width = this.config.width;
    this.canvas.height = this.config.height;

    this.state = {
      curvePoints: [],
      revealedShares: [],
      config: { k: 2, n: 5 },
      allShares: [],
      isUnique: false
    };
  }

  /**
   * Update visualization with new configuration and generate polynomial
   */
  update(config: ShamirConfig): void {
    this.state.config = config;

    // Generate random polynomial and shares
    const shares = split(Math.floor(Math.random() * 256), config);
    this.state.allShares = shares;
    this.state.revealedShares = [];
    this.state.isUnique = false;

    // For visualization, reconstruct the original polynomial
    // by taking k shares and interpolating
    if (shares.length >= config.k) {
      // Use Lagrange basis polynomials to determine the polynomial visually
      // We'll evaluate at many x values to draw the curve
      this.generateCurvePoints();
    }

    this.render();
  }

  /**
   * Generate curve points for visualization
   * Since we're working with GF(2⁸), we evaluate the polynomial
   * at fractional x values (0 to 15) for smooth curve drawing
   */
  private generateCurvePoints(): void {
    const points: Array<{ x: number; y: number }> = [];

    // For visualization, we'll use the unique polynomial if k shares revealed,
    // otherwise show all possible curves (as a conceptual visualization)
    const pointsPerUnit = 100; // Smooth curve resolution

    if (this.state.isUnique && this.state.polynomial) {
      // If k shares revealed, draw the exact unique polynomial
      for (let i = 0; i <= this.config.xMax * pointsPerUnit; i++) {
        const xFractional = i / pointsPerUnit;
        // Approximate evaluation at fractional x (GF(2⁸) only defines integer points)
        // For visualization, we'll just show evaluated at integers for now
        if (Number.isInteger(xFractional)) {
          const x = Math.round(xFractional);
          const y = evaluateAt(this.state.polynomial, x);
          points.push({ x, y: y / 255 }); // Normalize y to 0-1 for canvas
        }
      }
    } else {
      // If fewer than k shares, show multiple possible curves
      // (represented as the shares as discrete points)
      // The actual polynomial is underdetermined
      for (const share of this.state.allShares) {
        points.push({ x: share.x, y: share.y / 255 });
      }
    }

    this.state.curvePoints = points;
  }

  /**
   * Interactively reveal shares one by one
   */
  revealNextShare(): void {
    if (this.state.revealedShares.length < this.state.allShares.length) {
      const nextShare = this.state.allShares[this.state.revealedShares.length];
      this.state.revealedShares.push(nextShare);

      // Check if k shares revealed
      if (this.state.revealedShares.length >= this.state.config.k) {
        this.state.isUnique = true;
        // Reconstruct the polynomial for exact visualization
        // For now, we'll use the shares to determine the curve
      }

      this.render();
    }
  }

  /**
   * Reset visualization
   */
  reset(): void {
    this.state.revealedShares = [];
    this.state.isUnique = false;
    this.render();
  }

  /**
   * Pixel coordinates from field coordinates
   */
  private fieldToPixel(x: number, y: number): { px: number; py: number } {
    const { padding, width, height, xMin, xMax, yMin, yMax } = this.config;
    const plotWidth = width - 2 * padding;
    const plotHeight = height - 2 * padding;

    const px = padding + ((x - xMin) / (xMax - xMin)) * plotWidth;
    const py = height - padding - ((y - yMin) / (yMax - yMin)) * plotHeight; // flip y-axis

    return { px, py };
  }

  /**
   * Main render function
   */
  private render(): void {
    const ctx = this.ctx;
    const { width, height, padding, colors } = this.config;

    // Clear canvas
    ctx.fillStyle = colors.background;
    ctx.fillRect(0, 0, width, height);

    // Draw grid
    this.drawGrid();

    // Draw axes
    this.drawAxes();

    // Draw curve (if enough shares)
    if (this.state.isUnique || this.state.revealedShares.length > 0) {
      this.drawCurve();
    }

    // Draw all unrevealed share points as faint dots
    for (const share of this.state.allShares) {
      if (!this.state.revealedShares.includes(share)) {
        this.drawPoint(share.x, share.y, colors.share, 4, false);
      }
    }

    // Draw revealed shares with larger markers and labels
    for (const share of this.state.revealedShares) {
      this.drawPoint(share.x, share.y, colors.shareRevealed, 8, true);
      this.drawLabel(`${share.index}`, share.x, share.y + 10);
    }

    // Draw secret at x=0, y=f(0)
    if (this.state.polynomial) {
      const secretY = evaluateAt(this.state.polynomial, 0);
      this.drawPoint(0, secretY, colors.secret, 10, true);
      this.drawLabel('Secret', 0, secretY + 12);
    }

    // Draw status text
    this.drawStatus();
  }

  private drawGrid(): void {
    const ctx = this.ctx;
    const { colors, xMax, yMax } = this.config;

    ctx.strokeStyle = colors.grid;
    ctx.lineWidth = 1;

    // Vertical grid lines
    for (let x = 0; x <= xMax; x++) {
      const { px: px1 } = this.fieldToPixel(x, 0);
      const { px: px2, py: py2 } = this.fieldToPixel(x, yMax);
      ctx.beginPath();
      ctx.moveTo(px2, py2);
      ctx.lineTo(px1, 0);
      ctx.stroke();
    }

    // Horizontal grid lines
    for (let y = 0; y <= yMax; y += 50) {
      const { py: py1 } = this.fieldToPixel(0, y);
      const { px: px2, py: py2 } = this.fieldToPixel(xMax, y);
      ctx.beginPath();
      ctx.moveTo(px2, py2);
      ctx.lineTo(0, py1);
      ctx.stroke();
    }
  }

  private drawAxes(): void {
    const ctx = this.ctx;
    const { colors, padding, width, height, xMax, yMax } = this.config;

    ctx.strokeStyle = colors.axis;
    ctx.lineWidth = 2;
    ctx.fillStyle = colors.text;
    ctx.font = '12px monospace';

    // x-axis
    const { py: py0 } = this.fieldToPixel(0, 0);
    ctx.beginPath();
    ctx.moveTo(padding, py0);
    ctx.lineTo(width - padding, py0);
    ctx.stroke();

    // y-axis
    const { px: px0 } = this.fieldToPixel(0, 0);
    ctx.beginPath();
    ctx.moveTo(px0, padding);
    ctx.lineTo(px0, height - padding);
    ctx.stroke();

    // Axis labels
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText('x (share index)', width / 2, height - padding + 20);

    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.save();
    ctx.translate(padding - 20, height / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('y (field value)', 0, 0);
    ctx.restore();

    // Tick labels
    for (let x = 0; x <= xMax; x++) {
      const { px } = this.fieldToPixel(x, 0);
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(x.toString(), px, py0 + 5);
    }

    for (let y = 0; y <= yMax; y += 50) {
      const { px: px0Axis, py } = this.fieldToPixel(0, y);
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      ctx.fillText(y.toString(), px0Axis - 5, py);
    }
  }

  private drawCurve(): void {
    const ctx = this.ctx;
    const { colors } = this.config;

    if (this.state.curvePoints.length < 2) return;

    ctx.strokeStyle = colors.curve;
    ctx.lineWidth = 2;
    ctx.beginPath();

    for (let i = 0; i < this.state.curvePoints.length; i++) {
      const pt = this.state.curvePoints[i];
      const { px, py } = this.fieldToPixel(pt.x, pt.y * 255); // Denormalize y

      if (i === 0) {
        ctx.moveTo(px, py);
      } else {
        ctx.lineTo(px, py);
      }
    }

    ctx.stroke();
  }

  private drawPoint(x: number, y: number, color: string, radius: number, filled: boolean): void {
    const ctx = this.ctx;
    const { px, py } = this.fieldToPixel(x, y);

    ctx.fillStyle = color;
    ctx.strokeStyle = color;

    if (filled) {
      ctx.beginPath();
      ctx.arc(px, py, radius, 0, Math.PI * 2);
      ctx.fill();
      ctx.lineWidth = 2;
      ctx.stroke();
    } else {
      ctx.globalAlpha = 0.3;
      ctx.beginPath();
      ctx.arc(px, py, radius, 0, Math.PI * 2);
      ctx.fill();
      ctx.globalAlpha = 1;
    }
  }

  private drawLabel(text: string, x: number, y: number): void {
    const ctx = this.ctx;
    const { colors } = this.config;
    const { px, py } = this.fieldToPixel(x, y);

    ctx.fillStyle = colors.text;
    ctx.font = 'bold 12px monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(text, px, py);
  }

  private drawStatus(): void {
    const ctx = this.ctx;
    const { colors, width, height, padding } = this.config;

    ctx.fillStyle = colors.text;
    ctx.font = '14px monospace';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';

    const revealed = this.state.revealedShares.length;
    const required = this.state.config.k;

    let statusText = '';
    if (revealed === 0) {
      statusText = '0 shares revealed — secret location hidden';
    } else if (revealed < required) {
      statusText = `${revealed}/${required} shares revealed — multiple curves fit (secret hidden)`;
    } else {
      statusText = `${revealed}/${required} shares revealed — unique curve determined (secret revealed)`;
    }

    ctx.fillText(statusText, padding, padding - 30);
  }
}
