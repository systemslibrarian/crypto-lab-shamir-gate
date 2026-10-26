import {
  VISUAL_PATTERNS,
  analyzeVisualBasis,
  blockKey,
  enumerateSingleShareDistributions,
  generateVisualShares,
  hammingWeight,
  matrixBits,
  reconstructExpanded,
  reuseOneMask,
  scrambleOnly,
  stackSharing,
  type Bit,
  type BitMatrix,
  type VisualSharing,
} from './visual';

interface VisualState {
  size: number;
  source: BitMatrix;
  sharing: VisualSharing | null;
  selectedPixel: number;
}

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing visual-sharing element #${id}`);
  return element as T;
}

function defaultSource(size: number): BitMatrix {
  return Array.from({ length: size }, (_, row) =>
    Array.from({ length: size }, (_, column) => (
      row === column || row + column === size - 1 || (row === size - 2 && column > 0 && column < size - 1)
        ? 1
        : 0
    ) as Bit),
  );
}

function sourceLabel(bit: Bit): string {
  return bit === 1 ? 'black' : 'white';
}

function setStatus(message: string): void {
  byId('visual-live').textContent = message;
}

function renderMatrix(hostId: string, matrix: BitMatrix, label: string, key: string): void {
  const host = byId(hostId);
  const grid = document.createElement('div');
  grid.className = 'visual-pixel-grid';
  grid.style.setProperty('--visual-columns', String(matrix[0].length));
  grid.setAttribute('role', 'img');
  grid.setAttribute('aria-label', `${label}: ${matrix.length} rows by ${matrix[0].length} columns; 1 is black and 0 is transparent.`);
  grid.setAttribute('data-visual-grid', key);
  for (const bit of matrix.flat()) {
    const cell = document.createElement('span');
    cell.className = `visual-subpixel ${bit === 1 ? 'is-black' : 'is-clear'}`;
    cell.setAttribute('aria-hidden', 'true');
    cell.dataset.bit = String(bit);
    grid.appendChild(cell);
  }
  const bits = document.createElement('pre');
  bits.className = 'visual-bits';
  bits.dataset.visualMatrix = key;
  bits.setAttribute('aria-label', `${label} binary rows`);
  bits.textContent = matrixBits(matrix);
  host.replaceChildren(grid, bits);
}

function placeholder(hostId: string, text: string): void {
  const paragraph = document.createElement('p');
  paragraph.className = 'visual-placeholder';
  paragraph.textContent = text;
  byId(hostId).replaceChildren(paragraph);
}

function actionButtons(enabled: boolean): void {
  for (const id of ['visual-stack-or', 'visual-stack-xor', 'visual-prove', 'visual-controls']) {
    byId<HTMLButtonElement>(id).disabled = !enabled;
  }
}

function clearDerivedResults(): void {
  placeholder('visual-or-output', 'Stack with OR to compute the physical transparency result.');
  placeholder('visual-xor-output', 'Compare XOR to compute the separate digital result.');
  placeholder('visual-distribution', 'Run the exact six-case distribution proof.');
  placeholder('visual-negative-controls', 'Run the mask-reuse, scramble-only, and missing-share controls.');
  byId('visual-trace').textContent = 'Generate shares to trace one source pixel.';
  byId('visual-parameters').textContent = '';
}

function retireSharing(state: VisualState, reason: string): void {
  state.sharing = null;
  actionButtons(false);
  placeholder('visual-share-1', 'Generate shares from the current source.');
  placeholder('visual-share-2', 'Generate shares from the current source.');
  clearDerivedResults();
  setStatus(`${reason} Previous masks, reconstructions, distributions, and verdicts were retired.`);
}

function renderSource(state: VisualState): void {
  const host = byId('visual-source-grid');
  const grid = document.createElement('div');
  grid.className = 'visual-source-grid';
  grid.style.setProperty('--visual-columns', String(state.size));
  grid.setAttribute('role', 'group');
  grid.setAttribute('aria-label', `${state.size} by ${state.size} editable binary source image`);
  state.source.forEach((row, rowIndex) => row.forEach((bit, columnIndex) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `visual-source-cell ${bit === 1 ? 'is-black' : 'is-clear'}`;
    button.dataset.row = String(rowIndex);
    button.dataset.column = String(columnIndex);
    button.setAttribute('aria-pressed', String(bit === 1));
    button.setAttribute('aria-label', `Row ${rowIndex + 1}, column ${columnIndex + 1}: ${sourceLabel(bit)}; activate to toggle`);
    button.addEventListener('click', () => {
      state.source[rowIndex][columnIndex] = bit === 1 ? 0 : 1;
      renderSource(state);
      retireSharing(state, `Source pixel ${rowIndex + 1},${columnIndex + 1} changed.`);
    });
    grid.appendChild(button);
  }));
  const bits = document.createElement('pre');
  bits.className = 'visual-bits';
  bits.dataset.visualMatrix = 'source';
  bits.setAttribute('aria-label', 'Source image binary rows');
  bits.textContent = matrixBits(state.source);
  host.replaceChildren(grid, bits);
}

function renderTraceSelector(state: VisualState): void {
  const select = byId<HTMLSelectElement>('visual-selected-pixel');
  select.replaceChildren();
  for (let index = 0; index < state.size * state.size; index += 1) {
    const row = Math.floor(index / state.size);
    const column = index % state.size;
    const option = document.createElement('option');
    option.value = String(index);
    option.textContent = `row ${row + 1}, column ${column + 1}`;
    select.appendChild(option);
  }
  state.selectedPixel = Math.min(state.selectedPixel, state.size * state.size - 1);
  select.value = String(state.selectedPixel);
}

function renderTrace(state: VisualState): void {
  const sharing = state.sharing;
  if (!sharing) return;
  const index = state.selectedPixel;
  const row = Math.floor(index / sharing.width);
  const column = index % sharing.width;
  const source = sharing.source[row][column];
  const patternIndex = sharing.patternIndices[index];
  const share1 = sharing.share1Blocks[index];
  const share2 = sharing.share2Blocks[index];
  const physical = source === 0 ? 'same pattern' : 'complementary pattern';
  byId('visual-trace').innerHTML = `
    <strong>Selected source pixel:</strong> row ${row + 1}, column ${column + 1} = ${sourceLabel(source)} (${source}).<br>
    Uniform choice ${patternIndex + 1}/6: P = <code>${blockKey(VISUAL_PATTERNS[patternIndex])}</code>.<br>
    Share 1 = <code>${blockKey(share1)}</code>; share 2 = <code>${blockKey(share2)}</code> (${physical}).
  `;
}

function renderDistributionProof(): void {
  const rows = enumerateSingleShareDistributions();
  const body = rows.map((row) => `
    <tr data-share="${row.share}" data-pattern="${row.pattern}">
      <th scope="row">Share ${row.share}</th>
      <td><code>${row.pattern}</code></td>
      <td data-color="white">${row.whiteCount}/${row.denominator}</td>
      <td data-color="black">${row.blackCount}/${row.denominator}</td>
    </tr>`).join('');
  byId('visual-distribution').innerHTML = `
    <div class="visual-proof-result" data-proof="full-block-distribution">
      <p><strong>Exact result:</strong> each labeled share has the same complete block distribution for a white or black source pixel: every weight-two pattern occurs with probability 1/6.</p>
      <div class="visual-table-wrap">
        <table class="visual-table" id="visual-distribution-table">
          <caption>Complete enumeration of all six masks; probabilities are exact counts, not estimates.</caption>
          <thead><tr><th scope="col">Labeled share</th><th scope="col">Four-bit block</th><th scope="col">Given white</th><th scope="col">Given black</th></tr></thead>
          <tbody>${body}</tbody>
        </table>
      </div>
      <p>Therefore one correctly generated share reveals no source-pixel information in this binary scheme. With a fresh independent mask per pixel, the same equality extends to the full image distribution. Equal black-cell totals alone would not prove that stronger statement; the table compares every full block.</p>
    </div>`;
}

function renderNegativeControls(state: VisualState): void {
  if (!state.sharing) return;
  const reuse = reuseOneMask([0, 0, 1, 1], 0);
  const candidateA: Bit[] = [1, 1, 0, 0, 0, 0, 0, 0];
  const candidateB: Bit[] = [1, 1, 1, 1, 1, 0, 0, 0];
  const reverse = candidateA.map((_, index) => candidateA.length - index - 1);
  const scrambledA = scrambleOnly(candidateA, reverse);
  const scrambledB = scrambleOnly(candidateB, reverse);
  let missingShareResult = '';
  try {
    reconstructExpanded(state.sharing.share1, null, 'or');
    missingShareResult = 'Incorrectly reconstructed with one share.';
  } catch (error) {
    missingShareResult = (error as Error).message;
  }
  byId('visual-negative-controls').innerHTML = `
    <div class="visual-control-cards">
      <section class="visual-control-card" data-control="mask-reuse">
        <h4>Mask reuse leaks relations</h4>
        <p>Source <code>0011</code>, reused P = <code>0011</code>, share 2 blocks =
        <code>${reuse.share2.map(blockKey).join(' ')}</code>. Adjacent relations are
        <strong>${reuse.relations.join(', ')}</strong>: equal source pixels make equal blocks and a changed source pixel makes the complement.</p>
      </section>
      <section class="visual-control-card" data-control="scramble-only">
        <h4>Scrambling positions is not secrecy</h4>
        <p>The two candidate images retain ${hammingWeight(scrambledA)} and ${hammingWeight(scrambledB)} black pixels after the same position permutation. Their histograms still distinguish them.</p>
      </section>
      <section class="visual-control-card" data-control="missing-share">
        <h4>One share cannot reconstruct</h4>
        <p>${missingShareResult}</p>
      </section>
    </div>`;
}

function initState(): VisualState {
  const size = 8;
  return { size, source: defaultSource(size), sharing: null, selectedPixel: 0 };
}

export function initVisualTab(): void {
  const state = initState();
  renderSource(state);
  renderTraceSelector(state);
  actionButtons(false);
  clearDerivedResults();
  placeholder('visual-share-1', 'Generate shares from the current source.');
  placeholder('visual-share-2', 'Generate shares from the current source.');

  byId<HTMLSelectElement>('visual-size').addEventListener('change', (event) => {
    const size = Number((event.currentTarget as HTMLSelectElement).value);
    state.size = size;
    state.source = defaultSource(size);
    state.selectedPixel = 0;
    renderSource(state);
    renderTraceSelector(state);
    retireSharing(state, `Grid resized to ${size} by ${size}.`);
  });

  byId('visual-clear').addEventListener('click', () => {
    state.source = Array.from({ length: state.size }, () => Array<Bit>(state.size).fill(0));
    renderSource(state);
    retireSharing(state, 'Source cleared.');
  });

  byId('visual-invert').addEventListener('click', () => {
    state.source = state.source.map((row) => row.map((bit) => (bit === 1 ? 0 : 1) as Bit));
    renderSource(state);
    retireSharing(state, 'Source inverted.');
  });

  byId<HTMLSelectElement>('visual-selected-pixel').addEventListener('change', (event) => {
    state.selectedPixel = Number((event.currentTarget as HTMLSelectElement).value);
    renderTrace(state);
  });

  byId('visual-generate').addEventListener('click', async () => {
    const button = byId<HTMLButtonElement>('visual-generate');
    button.disabled = true;
    setStatus('Drawing one independent uniform mask for every source pixel.');
    try {
      state.sharing = await generateVisualShares(state.source);
      renderMatrix('visual-share-1', state.sharing.share1, 'Share 1', 'share-1');
      renderMatrix('visual-share-2', state.sharing.share2, 'Share 2', 'share-2');
      clearDerivedResults();
      renderTrace(state);
      actionButtons(true);
      setStatus(`${state.size * state.size} fresh masks drawn. Each share contains exactly ${state.size * state.size * 2} black subpixels.`);
    } catch (error) {
      retireSharing(state, `Generation failed: ${(error as Error).message}`);
    } finally {
      button.disabled = false;
    }
  });

  byId('visual-stack-or').addEventListener('click', () => {
    if (!state.sharing) return;
    const physical = stackSharing(state.sharing, 'or');
    renderMatrix('visual-or-output', physical, 'Physical OR stack', 'or-stack');
    const basis = analyzeVisualBasis();
    byId('visual-parameters').textContent = `Derived from the basis: white OR weight ${basis.whiteOrWeight}/${basis.pixelExpansion}; black OR weight ${basis.blackOrWeight}/${basis.pixelExpansion}; pixel expansion m=${basis.pixelExpansion}; relative contrast alpha=${basis.contrastNumerator}/${basis.contrastDenominator}.`;
    setStatus('Physical OR stack recomputed from the two displayed share matrices.');
  });

  byId('visual-stack-xor').addEventListener('click', () => {
    if (!state.sharing) return;
    const digital = stackSharing(state.sharing, 'xor');
    renderMatrix('visual-xor-output', digital, 'Digital XOR comparison', 'xor-view');
    setStatus('Digital XOR comparison recomputed. XOR is not physical transparency stacking.');
  });

  byId('visual-prove').addEventListener('click', () => {
    renderDistributionProof();
    setStatus('All 24 labeled-share/color/mask outcomes were enumerated exactly.');
  });

  byId('visual-controls').addEventListener('click', () => {
    renderNegativeControls(state);
    setStatus('Negative controls recomputed from the displayed sharing and fixed counterexamples.');
  });
}

export function visualPanelHtml(): string {
  return `
  <div class="tab-panel" id="tab-visual" role="tabpanel" aria-labelledby="btn-visual" tabindex="0">
    <div class="visual-intro panel">
      <h2>Visual Secret Sharing: exact 2-of-2 construction</h2>
      <p>Each source pixel becomes four subpixels in each share. A fresh uniform pattern P is chosen from the six weight-two blocks. White uses P/P; black uses P/complement(P). Physical transparencies combine with Boolean OR, so black ink cannot cancel.</p>
      <dl class="visual-parameters-list">
        <div><dt>Threshold</dt><dd>2 of 2</dd></div>
        <div><dt>Pixel expansion</dt><dd>m = 4</dd></div>
        <div><dt>Pattern choices</dt><dd>6, equiprobable</dd></div>
        <div><dt>Per-share block weight</dt><dd>2 black of 4</dd></div>
      </dl>
    </div>

    <div class="visual-toolbar panel">
      <div class="field-group">
        <label for="visual-size">Source grid size</label>
        <select id="visual-size"><option value="4">4 by 4</option><option value="6">6 by 6</option><option value="8" selected>8 by 8</option></select>
      </div>
      <div class="btn-row">
        <button class="btn-secondary" id="visual-clear" type="button">Clear source</button>
        <button class="btn-secondary" id="visual-invert" type="button">Invert source</button>
        <button class="btn-primary" id="visual-generate" type="button">Generate fresh shares</button>
      </div>
      <p id="visual-live" class="visual-live" role="status" aria-live="polite">Edit the binary source, then generate two shares.</p>
    </div>

    <div class="visual-three-col">
      <section class="panel visual-card">
        <h3>Binary source</h3>
        <p>Activate a cell to toggle white/black. The text rows are the exact accessible representation.</p>
        <div id="visual-source-grid"></div>
      </section>
      <section class="panel visual-card">
        <h3>Share 1</h3>
        <p>Exactly two black subpixels per source pixel.</p>
        <div id="visual-share-1"></div>
      </section>
      <section class="panel visual-card">
        <h3>Share 2</h3>
        <p>Same block for white; complementary block for black.</p>
        <div id="visual-share-2"></div>
      </section>
    </div>

    <section class="panel visual-trace-panel">
      <h3>Trace one pixel</h3>
      <div class="field-group visual-pixel-picker"><label for="visual-selected-pixel">Selected source pixel</label><select id="visual-selected-pixel"></select></div>
      <p id="visual-trace" class="visual-trace"></p>
    </section>

    <div class="visual-actions panel">
      <h3>Reconstruct and prove</h3>
      <div class="btn-row">
        <button class="btn-primary" id="visual-stack-or" type="button">Stack with OR</button>
        <button class="btn-secondary" id="visual-stack-xor" type="button">Compare digital XOR</button>
        <button class="btn-secondary" id="visual-prove" type="button">Prove one-share privacy</button>
        <button class="btn-secondary" id="visual-controls" type="button">Run negative controls</button>
      </div>
    </div>

    <div class="visual-two-col">
      <section class="panel visual-card">
        <h3>Physical OR stack</h3>
        <div id="visual-or-output"></div>
        <p id="visual-parameters" class="visual-parameter-result"></p>
      </section>
      <section class="panel visual-card">
        <h3>Digital XOR comparison</h3>
        <div id="visual-xor-output"></div>
        <p class="visual-boundary">XOR gives exact 0/1 blocks here, but XOR is not physical transparency stacking: aligned printed transparencies compute OR.</p>
      </section>
    </div>

    <section class="panel visual-result-section">
      <h3>Exact one-share distribution</h3>
      <div id="visual-distribution"></div>
    </section>

    <section class="panel visual-result-section">
      <h3>Controls: what the guarantee does not cover</h3>
      <div id="visual-negative-controls"></div>
    </section>

    <section class="panel visual-comparison">
      <h3>Visual sharing is not polynomial Shamir with pictures</h3>
      <div class="visual-table-wrap"><table class="visual-table">
        <thead><tr><th scope="col">Property</th><th scope="col">Visual construction here</th><th scope="col">Polynomial Shamir elsewhere in this lab</th></tr></thead>
        <tbody>
          <tr><th scope="row">Shared object</th><td>Binary image pixels</td><td>Field element or encoded secret</td></tr>
          <tr><th scope="row">Reconstruction</th><td>Physical OR of two aligned shares</td><td>Lagrange interpolation of at least t points</td></tr>
          <tr><th scope="row">Threshold</th><td>Fixed 2 of 2</td><td>Configurable t of n</td></tr>
          <tr><th scope="row">Output</th><td>Contrast image; source white remains 50% black</td><td>Exact original field element</td></tr>
          <tr><th scope="row">Expansion</th><td>Four subpixels per source pixel</td><td>No analogous pixel expansion</td></tr>
        </tbody>
      </table></div>
    </section>

    <div class="disclaimer visual-limitations">
      <strong>Bounded teaching model.</strong> This is binary 2-of-2 visual secret sharing, not general k-of-n, grayscale, color, or progressive visual cryptography. It provides confidentiality for one correctly generated share under fresh per-pixel masks, but no authenticity. It assumes exact alignment and does not model printing, opacity, scaling, rotation, dot gain, display gamma, or registration error. Both shares reveal the image by design. The browser retains the source and both shares, so it is not an operational share-distribution system.
    </div>
    <div class="sources">
      <h3>Primary source</h3>
      <ul><li>Moni Naor and Adi Shamir, <a href="https://doi.org/10.1007/BFb0053419" target="_blank" rel="noopener">“Visual Cryptography,” EUROCRYPT 1994</a>, Sections 2–3. Section 2 defines contrast and security through the full restricted-matrix distributions; Section 3 gives the 2-of-2 identical/complementary construction and recommends four subpixels in a 2 by 2 block to preserve aspect ratio.</li></ul>
    </div>
  </div>`;
}
