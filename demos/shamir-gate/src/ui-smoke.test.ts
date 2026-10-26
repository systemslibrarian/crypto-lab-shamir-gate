// @vitest-environment jsdom
import { describe, it, expect, beforeAll } from 'vitest';

// jsdom has no canvas; hand back a no-op 2D context so render code doesn't throw.
const noopCtx = new Proxy({}, { get: () => () => {}, set: () => true });
(HTMLCanvasElement.prototype as unknown as { getContext: () => unknown }).getContext = () => noopCtx;

beforeAll(async () => {
  document.body.innerHTML = '<div id="app"></div>';
  await import('./main'); // registers the DOMContentLoaded bootstrap
  document.dispatchEvent(new Event('DOMContentLoaded'));
  await new Promise(r => setTimeout(r, 0)); // let the security tab's setTimeout(0) run
});

const $ = (id: string) => document.getElementById(id);

describe('UI smoke — the shell and every tab mount without errors', () => {
  it('renders all nine tabs', () => {
    expect(document.querySelectorAll('.tab-btn')).toHaveLength(9);
    ['tab-lesson', 'tab-gate', 'tab-poly', 'tab-proof', 'tab-visual', 'tab-aes', 'tab-fail', 'tab-rw', 'tab-shamir']
      .forEach(id => expect($(id), id).not.toBeNull());
  });

  it('lands on the Lesson tab with content and nav', () => {
    expect($('tab-lesson')!.classList.contains('active')).toBe(true);
    expect($('lesson-body')!.querySelector('h3')).not.toBeNull();
    expect($('lesson-nav')!.querySelector('button')).not.toBeNull();
  });
});

describe('UI smoke — visual secret sharing', () => {
  it('generates, reconstructs, proves full distributions, runs controls, and retires stale results', async () => {
    expect($('visual-source-grid')!.querySelectorAll('.visual-source-cell')).toHaveLength(64);
    expect(($('visual-stack-or') as HTMLButtonElement).disabled).toBe(true);

    $('visual-generate')!.click();
    await new Promise(r => setTimeout(r, 0));
    expect($('visual-share-1')!.querySelector('[data-visual-grid="share-1"]')).not.toBeNull();
    expect($('visual-share-2')!.querySelector('[data-visual-grid="share-2"]')).not.toBeNull();
    expect(($('visual-stack-or') as HTMLButtonElement).disabled).toBe(false);

    $('visual-stack-or')!.click();
    $('visual-stack-xor')!.click();
    $('visual-prove')!.click();
    $('visual-controls')!.click();
    expect($('visual-or-output')!.querySelector('[data-visual-grid="or-stack"]')).not.toBeNull();
    expect($('visual-xor-output')!.querySelector('[data-visual-grid="xor-view"]')).not.toBeNull();
    expect($('visual-distribution')!.querySelectorAll('#visual-distribution-table tbody tr')).toHaveLength(12);
    expect($('visual-distribution')!.textContent).toContain('same complete block distribution');
    expect($('visual-negative-controls')!.textContent).toContain('Mask reuse leaks relations');
    expect($('visual-negative-controls')!.textContent).toContain('Both aligned shares are required');
    expect($('tab-visual')!.textContent).toContain('Physical transparencies combine with Boolean OR');
    expect($('tab-visual')!.textContent).toContain('XOR is not physical transparency stacking');
    expect($('tab-visual')!.textContent).toContain('The two shares together reveal the image');

    const firstSourcePixel = $('visual-source-grid')!.querySelector<HTMLButtonElement>('.visual-source-cell')!;
    firstSourcePixel.click();
    expect(($('visual-stack-or') as HTMLButtonElement).disabled).toBe(true);
    expect($('visual-or-output')!.querySelector('[data-visual-grid="or-stack"]')).toBeNull();
    expect($('visual-distribution')!.querySelector('#visual-distribution-table')).toBeNull();
    expect($('visual-live')!.textContent).toContain('retired');
  });
});

describe('UI smoke — prediction checkpoints', () => {
  it('reveals feedback after answering a lesson prediction', () => {
    const opt = $('lesson-body')!.querySelector<HTMLButtonElement>('.predict-opt');
    // Step 1 has no prediction; advance until one appears.
    let guard = 0;
    while (!$('lesson-body')!.querySelector('.predict-opt') && guard++ < 10) {
      $('lesson-next')!.click();
    }
    const firstOpt = $('lesson-body')!.querySelector<HTMLButtonElement>('.predict-opt');
    expect(firstOpt).not.toBeNull();
    firstOpt!.click();
    const reveal = $('lesson-body')!.querySelector<HTMLElement>('.predict-reveal');
    expect(reveal!.hidden).toBe(false);
    void opt;
  });

  it('mounts the standalone Gate prediction', () => {
    expect($('gate-predict')!.querySelector('.predict')).not.toBeNull();
  });
});

describe('UI smoke — interactive proof lab', () => {
  it('confirms an arbitrary candidate secret is consistent and counts it', () => {
    ($('proof-candidate') as HTMLInputElement).value = '200';
    $('proof-check')!.click();
    expect($('proof-lab-out')!.className).toContain('success');
    expect($('proof-lab-counter')!.textContent).toContain('eliminate 0 of 257');
  });
});

describe('UI smoke — failure lab', () => {
  it('renders all eight failure scenarios', () => {
    expect($('fail-scenarios')!.querySelectorAll('.fail-btn')).toHaveLength(8);
  });

  it('classifies the duplicate-x scenario as MATHEMATICAL', async () => {
    const btn = [...$('fail-scenarios')!.querySelectorAll<HTMLButtonElement>('.fail-btn')]
      .find(b => /duplicate/i.test(b.textContent || ''))!;
    btn.click();
    await new Promise(r => setTimeout(r, 0));
    expect($('fail-output')!.querySelector('.cat-mathematical')).not.toBeNull();
  });
});

describe('UI smoke — polynomial points table + viz toggle exist', () => {
  it('has the canvas, viz toggle, and points-table host', () => {
    expect($('poly-canvas')).not.toBeNull();
    expect($('poly-viz-toggle')).not.toBeNull();
    expect($('poly-points')).not.toBeNull();
  });
});
