/**
 * Main UI and application logic for shamir-gate
 * 
 * Implements 5-tab interface:
 * 1. The Gate — vault door metaphor
 * 2. Polynomial Visualizer — curve visualization
 * 3. Security Proof — information-theoretic security demonstration
 * 4. Real-world Uses — portfolio connections
 * 5. Adi Shamir — attribution and historical context
 */

import { CurveVisualizer } from './visualization/curve';
import { verifyGF256 } from './crypto/gf256';
import { verifyPolynomial } from './crypto/polynomial';
import { verifyShamir } from './crypto/shamir';
import { verifySecurityProof } from './crypto/security-proof';
import { split, reconstruct, splitSecret, reconstructSecret, serializeShare, deserializeShare, ShamirConfig } from './crypto/shamir';
import { findAllConsistentSecrets } from './crypto/security-proof';
import { generateAESKey, exportKey, importKey, encryptAES, decryptAES, getKeyFingerprint } from './crypto/aes';

let currentVisualizer: CurveVisualizer | null = null;

// State for AES protection demo
let currentEncryptedMessage: { ciphertext: string; iv: string } | null = null;
let currentKeyShares: Array<{ k: number; n: number; index: number; yValues: Uint8Array }> | null = null;
let currentKeyFingerprint: string = '';

document.addEventListener('DOMContentLoaded', () => {
  // Verify all cryptographic primitives
  const cryptoTests = {
    'GF(2⁸) Arithmetic': verifyGF256(),
    'Polynomial Evaluation': verifyPolynomial(),
    'Shamir SSS': verifyShamir(),
    'Security Proof': verifySecurityProof()
  };

  console.log('=== Shamir-Gate Cryptographic Verification ===');
  for (const [test, passed] of Object.entries(cryptoTests)) {
    console.log(`${test}: ${passed ? '✓ PASS' : '✗ FAIL'}`);
  }

  // Initialize UI
  initializeUI();
});

function initializeUI(): void {
  const root = document.getElementById('app');
  if (!root) return;

  root.innerHTML = `
    <div class="container">
      <header>
        <h1>Shamir-Gate</h1>
        <p>Interactive Shamir's Secret Sharing Cryptographic Demo</p>
      </header>

      <div class="tabs-container">
        <div class="tabs" role="tablist" aria-label="Demo sections">
          <button class="tab-button active" data-tab="gate" role="tab" aria-selected="true" aria-controls="gate-tab" id="tab-gate">The Gate</button>
          <button class="tab-button" data-tab="visualizer" role="tab" aria-selected="false" aria-controls="visualizer-tab" id="tab-visualizer" tabindex="-1">Polynomial Visualizer</button>
          <button class="tab-button" data-tab="security" role="tab" aria-selected="false" aria-controls="security-tab" id="tab-security" tabindex="-1">Security Proof</button>
          <button class="tab-button" data-tab="uses" role="tab" aria-selected="false" aria-controls="uses-tab" id="tab-uses" tabindex="-1">Real-world Uses</button>
          <button class="tab-button" data-tab="about" role="tab" aria-selected="false" aria-controls="about-tab" id="tab-about" tabindex="-1">Adi Shamir</button>
        </div>

        <div class="tab-content active" id="gate-tab" role="tabpanel" aria-labelledby="tab-gate" tabindex="0">
          <h2 id="main-content">The Vault Gate</h2>
          <div class="gate-section">
            <div class="gate-visualization">
              <div class="vault-door"></div>
              <div class="lock-status" id="lock-status" role="status" aria-live="polite">🔒 LOCKED</div>
            </div>
            
            <div class="controls">
              <div class="config-section">
                <h3>Configure Threshold</h3>
                <div class="field-group">
                  <label for="k-slider">Threshold (k):</label>
                  <input type="range" id="k-slider" min="2" max="6" value="2" aria-valuenow="2" aria-valuemin="2" aria-valuemax="6" />
                  <output for="k-slider" id="k-value">2</output>
                </div>
                <div class="field-group">
                  <label for="n-slider">Total Shares (n):</label>
                  <input type="range" id="n-slider" min="2" max="10" value="3" aria-valuenow="3" aria-valuemin="2" aria-valuemax="10" />
                  <output for="n-slider" id="n-value">3</output>
                </div>
              </div>

              <div class="generate-section">
                <h3>Generate Shares</h3>
                <label for="secret-input" class="sr-only">Secret value</label>
                <input type="text" id="secret-input" placeholder="Enter secret (text or hex)" value="MySecret" aria-label="Secret value to split" />
                <button id="generate-btn">Generate Shares</button>
              </div>

              <div class="shares-display" id="shares-display" style="display: none;">
                <h3>Share Strings</h3>
                <div id="shares-list"></div>
              </div>

              <div class="reconstruct-section">
                <h3>Reconstruct Secret</h3>
                <label for="shares-input" class="sr-only">Paste share strings</label>
                <textarea id="shares-input" placeholder="Paste k share strings (one per line)" aria-label="Share strings for reconstruction"></textarea>
                <button id="reconstruct-btn">Reconstruct</button>
                <div id="result-display" role="status" aria-live="polite"></div>
              </div>

              <div class="aes-section" style="margin-top: 2rem; border-top: 2px solid rgba(0, 217, 255, 0.2); padding-top: 2rem;">
                <h3>🔐 Protect a Message with AES-256</h3>
                <p style="color: #a0a0c0; font-size: 0.9rem;">Demonstrates the canonical pattern: Generate AES key → Encrypt message → Split key with SSS → Share split key.</p>
                <label for="message-input" class="sr-only">Message to encrypt</label>
                <input type="text" id="message-input" placeholder="Enter message to encrypt" value="Topsecret data" aria-label="Message to encrypt" />
                <button id="encrypt-btn">Encrypt &amp; Split Key</button>
                <div id="crypto-display" style="display: none;">
                  <h4 style="color: #00ff00; margin-top: 1rem;">Encrypted Message</h4>
                  <div class="share-string" id="ciphertext-display" style="word-break: break-all; color: #00d9ff;"></div>
                  <h4 style="color: #00ff00; margin-top: 1rem;">Key Fingerprint</h4>
                  <div class="share-string" id="fingerprint-display" style="font-family: monospace;"></div>
                  <h4 style="color: #00ff00; margin-top: 1rem;">Key Shares</h4>
                  <div id="key-shares-list"></div>
                </div>
                <hr style="border: none; border-top: 1px solid rgba(0, 217, 255, 0.2); margin: 1.5rem 0;" />
                <h3>Decrypt Message</h3>
                <p style="color: #a0a0c0; font-size: 0.9rem;">Reconstruct the AES key from k key shares, then decrypt the message.</p>
                <label for="key-shares-input" class="sr-only">Key shares for decryption</label>
                <textarea id="key-shares-input" placeholder="Paste k key shares (one per line)" aria-label="Key shares for decryption"></textarea>
                <button id="decrypt-btn">Reconstruct Key &amp; Decrypt</button>
                <div id="decrypt-result" role="status" aria-live="polite"></div>
              </div>
            </div>
          </div>
        </div>

        <div class="tab-content" id="visualizer-tab" role="tabpanel" aria-labelledby="tab-visualizer" tabindex="0">
          <h2>Polynomial Curve Visualization</h2>
          <p>Watch how shares reveal the polynomial curve that hides the secret.</p>
          <canvas id="curve-canvas" role="img" aria-label="Polynomial curve visualization showing secret sharing points over GF(2⁸). Use the Reveal and Reset buttons below to interact."></canvas>
          <div class="viz-controls">
            <button id="reveal-btn">Reveal Next Share</button>
            <button id="reset-btn">Reset</button>
          </div>
        </div>

        <div class="tab-content" id="security-tab" role="tabpanel" aria-labelledby="tab-security" tabindex="0">
          <h2>Information-Theoretic Security</h2>
          <p>With fewer than k shares, every possible secret is equally likely — perfect secrecy.</p>
          <div class="security-demo">
            <div class="field-group">
              <label for="security-slider">Shares to reveal (0 to k-1):</label>
              <input type="range" id="security-slider" min="0" max="2" value="0" aria-valuenow="0" aria-valuemin="0" aria-valuemax="2" />
              <output for="security-slider" id="security-count">0</output>
            </div>
            <button id="security-btn">Check Consistent Secrets</button>
            <div id="security-result" role="status" aria-live="polite"></div>
          </div>
        </div>

        <div class="tab-content" id="uses-tab" role="tabpanel" aria-labelledby="tab-uses" tabindex="0">
          <h2>Real-world Applications</h2>
          <div class="uses-grid">
            <div class="use-card">
              <h3>Hardware Security Modules (HSM)</h3>
              <p>Master key ceremonies split encryption keys across multiple parties for distributed authority.</p>
            </div>
            <div class="use-card">
              <h3>Bitcoin Multisig</h3>
              <p>While Bitcoin uses threshold signatures (FROST), Shamir SSS provides key-level threshold splitting.</p>
            </div>
            <div class="use-card">
              <h3>Signal's Sealed Sender</h3>
              <p>End-to-end encrypted messaging can use SSS to split decryption keys for multi-device scenarios.</p>
            </div>
            <div class="use-card">
              <h3>Nuclear Launch Codes (Historical)</h3>
              <p>Two-person integrity rule: secret codes split so no single person can launch.</p>
            </div>
            <div class="use-card" style="background: rgba(100, 100, 150, 0.3); border: 2px solid #00d9ff;">
              <h3>Portfolio Demos</h3>
              <p><strong>frost-threshold:</strong> FROST protocol uses Shamir SSS for distributed key generation.<br/>
              <strong>silent-tally:</strong> Additive homomorphic SSS for multi-party computation.<br/>
              <strong>quantum-vault-kpqc:</strong> Threshold file encryption using SSS for key splitting.</p>
            </div>
          </div>
        </div>

        <div class="tab-content" id="about-tab" role="tabpanel" aria-labelledby="tab-about" tabindex="0">
          <h2>Adi Shamir</h2>
          <div class="about-card">
            <div class="about-header">
              <h3>Adi Shamir</h3>
              <p>Weizmann Institute of Science, Israel</p>
            </div>
            <div class="about-content">
              <p><strong>Credentials:</strong> The "S" in RSA (Rivest, Shamir, Adleman) — one of the three inventors of RSA encryption (1977).</p>
              
              <p><strong>Shamir's Secret Sharing (1979):</strong> Published in Communications of the ACM, Vol. 22, No. 11, pp. 612-613.</p>
              
              <p><strong>Mathematical Significance:</strong> SSS demonstrates threshold cryptography using polynomial interpolation over finite fields. With k-of-n threshold, any k shares uniquely reconstruct the secret, while k-1 shares reveal nothing (information-theoretic security).</p>
              
              <p><strong>Cryptographic Lineage:</strong> Israeli cryptography legacy includes Eli Biham (Technion, Israel), co-discoverer of differential cryptanalysis, designer of Serpent.</p>
              
              <p><strong>Citation:</strong> A. Shamir. "How to Share a Secret." Communications of the ACM, Vol. 22, No. 11, pp. 612-613, November 1979.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;

  // Attach event listeners
  attachTabHandlers();
  attachGateHandlers();
  attachVisualizerHandlers();
  attachSecurityHandlers();
  attachSliderHandlers();
}

function activateTab(button: Element): void {
  const tabButtons = document.querySelectorAll('.tab-button');
  const tabContents = document.querySelectorAll('.tab-content');
  const tabName = button.getAttribute('data-tab');

  // Remove active from all
  tabButtons.forEach((b) => {
    b.classList.remove('active');
    b.setAttribute('aria-selected', 'false');
    b.setAttribute('tabindex', '-1');
  });
  tabContents.forEach((c) => c.classList.remove('active'));

  // Add active to clicked tab
  button.classList.add('active');
  button.setAttribute('aria-selected', 'true');
  button.setAttribute('tabindex', '0');
  const activeTab = document.getElementById(`${tabName}-tab`);
  if (activeTab) {
    activeTab.classList.add('active');

    // Initialize visualizer if switching to visualizer tab
    if (tabName === 'visualizer' && !currentVisualizer) {
      setTimeout(() => {
        const canvas = document.getElementById('curve-canvas') as HTMLCanvasElement;
        if (canvas) {
          currentVisualizer = new CurveVisualizer('curve-canvas', {
            width: 800,
            height: 500
          });
          currentVisualizer.update({ k: 2, n: 5 });
        }
      }, 0);
    }
  }
}

function attachTabHandlers(): void {
  const tabButtons = document.querySelectorAll('.tab-button');
  const tabList = document.querySelector('[role="tablist"]');

  tabButtons.forEach((button) => {
    button.addEventListener('click', () => activateTab(button));
  });

  // Keyboard navigation: arrow keys move between tabs
  tabList?.addEventListener('keydown', (e) => {
    const event = e as KeyboardEvent;
    const tabs = Array.from(tabButtons);
    const currentIndex = tabs.findIndex((t) => t.getAttribute('aria-selected') === 'true');
    let nextIndex = currentIndex;

    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      event.preventDefault();
      nextIndex = (currentIndex + 1) % tabs.length;
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      event.preventDefault();
      nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
    } else if (event.key === 'Home') {
      event.preventDefault();
      nextIndex = 0;
    } else if (event.key === 'End') {
      event.preventDefault();
      nextIndex = tabs.length - 1;
    }

    if (nextIndex !== currentIndex) {
      activateTab(tabs[nextIndex]);
      (tabs[nextIndex] as HTMLElement).focus();
    }
  });
}

function attachGateHandlers(): void {
  const kSlider = document.getElementById('k-slider') as HTMLInputElement;
  const nSlider = document.getElementById('n-slider') as HTMLInputElement;
  const generateBtn = document.getElementById('generate-btn') as HTMLButtonElement;
  const reconstructBtn = document.getElementById('reconstruct-btn') as HTMLButtonElement;
  const secretInput = document.getElementById('secret-input') as HTMLInputElement;
  const sharesInput = document.getElementById('shares-input') as HTMLTextAreaElement;

  kSlider?.addEventListener('change', () => {
    const k = parseInt(kSlider.value, 10);
    const n = parseInt(nSlider.value, 10);
    document.getElementById('k-value')!.textContent = k.toString();
    if (n < k) {
      nSlider.value = k.toString();
      document.getElementById('n-value')!.textContent = k.toString();
    }
  });

  nSlider?.addEventListener('change', () => {
    document.getElementById('n-value')!.textContent = nSlider.value;
  });

  generateBtn?.addEventListener('click', () => {
    const secret = secretInput.value || 'Secret';
    const k = parseInt(kSlider.value, 10);
    const n = parseInt(nSlider.value, 10);

    // Convert secret to bytes
    const secretBytes = new TextEncoder().encode(secret);

    // Split using Shamir SSS
    const config: ShamirConfig = { k, n };
    const shareSets = splitSecret(secretBytes, config);

    // Serialize shares
    const shareStrings = shareSets.map((share) => serializeShare(share));

    // Display shares
    const sharesList = document.getElementById('shares-list')!;
    sharesList.innerHTML = shareStrings.map((s) => `<div class="share-string">${s}</div>`).join('');
    document.getElementById('shares-display')!.style.display = 'block';

    // Update lock status
    updateLockStatus(0, k);
  });

  reconstructBtn?.addEventListener('click', () => {
    const shareStrs = sharesInput.value
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    try {
      const shares = shareStrs.map((s) => deserializeShare(s));

      if (shares.length < 2) {
        throw new Error('Need at least 2 shares');
      }

      // Check k
      const k = shares[0].k;
      if (shares.length < k) {
        document.getElementById('result-display')!.innerHTML = `
          <p style="color: #ff6666;">❌ Need ${k} shares to reconstruct, provided ${shares.length}</p>
        `;
        updateLockStatus(shares.length, k);
        return;
      }

      // Reconstruct
      const recovered = reconstructSecret(
        shares as any,
        k
      );

      const recoveredStr = new TextDecoder().decode(recovered);
      document.getElementById('result-display')!.innerHTML = `
        <p style="color: #00ff00;">✓ Secret reconstructed: <strong>${recoveredStr}</strong></p>
      `;
      updateLockStatus(shares.length, k);
    } catch (err) {
      document.getElementById('result-display')!.innerHTML = `
        <p style="color: #ff6666;">❌ Error: ${err instanceof Error ? err.message : 'Invalid share format'}</p>
      `;
    }
  });

  // AES handlers
  const encryptBtn = document.getElementById('encrypt-btn') as HTMLButtonElement;
  const decryptBtn = document.getElementById('decrypt-btn') as HTMLButtonElement;
  const messageInput = document.getElementById('message-input') as HTMLInputElement;
  const keySharesInput = document.getElementById('key-shares-input') as HTMLTextAreaElement;

  encryptBtn?.addEventListener('click', async () => {
    const message = messageInput.value || 'Secret message';
    const k = parseInt(kSlider.value, 10);
    const n = parseInt(nSlider.value, 10);

    try {
      encryptBtn.disabled = true;
      encryptBtn.textContent = 'Processing...';

      // Generate AES key
      const aesKey = await generateAESKey();
      const keyBytes = await exportKey(aesKey);

      // Encrypt message
      const encrypted = await encryptAES(aesKey, message);
      currentEncryptedMessage = encrypted;

      // Get key fingerprint
      currentKeyFingerprint = await getKeyFingerprint(keyBytes);

      // Split key into shares
      const config: ShamirConfig = { k, n };
      const keyShares = splitSecret(keyBytes, config);
      currentKeyShares = keyShares;

      // Serialize key shares
      const keyShareStrings = keyShares.map((share) => serializeShare(share));

      // Display results
      document.getElementById('ciphertext-display')!.textContent =
        'IV: ' + encrypted.iv + '\nCiphertext: ' + encrypted.ciphertext;
      document.getElementById('fingerprint-display')!.textContent = currentKeyFingerprint;

      const keySharesList = document.getElementById('key-shares-list')!;
      keySharesList.innerHTML = keyShareStrings
        .map((s) => `<div class="share-string" style="color: #00d9ff;">${s}</div>`)
        .join('');

      document.getElementById('crypto-display')!.style.display = 'block';

      encryptBtn.disabled = false;
      encryptBtn.textContent = 'Encrypt & Split Key';
    } catch (err) {
      alert('Error encrypting: ' + (err instanceof Error ? err.message : 'Unknown error'));
      encryptBtn.disabled = false;
      encryptBtn.textContent = 'Encrypt & Split Key';
    }
  });

  decryptBtn?.addEventListener('click', async () => {
    if (!currentEncryptedMessage) {
      alert('No encrypted message. Encrypt a message first.');
      return;
    }

    const keyShareStrs = keySharesInput.value
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    try {
      decryptBtn.disabled = true;
      decryptBtn.textContent = 'Processing...';

      const keyShares = keyShareStrs.map((s) => deserializeShare(s));

      if (keyShares.length < 2) {
        throw new Error('Need at least 2 shares');
      }

      const k = keyShares[0].k;
      if (keyShares.length < k) {
        document.getElementById('decrypt-result')!.innerHTML = `
          <p style="color: #ff6666;">❌ Need ${k} key shares to reconstruct, provided ${keyShares.length}</p>
        `;
        decryptBtn.disabled = false;
        decryptBtn.textContent = 'Reconstruct Key & Decrypt';
        return;
      }

      // Reconstruct key
      const reconstructedKeyBytes = reconstructSecret(keyShares as any, k);
      const reconstructedKey = await importKey(reconstructedKeyBytes);

      // Decrypt message
      const decrypted = await decryptAES(reconstructedKey, currentEncryptedMessage.ciphertext, currentEncryptedMessage.iv);

      document.getElementById('decrypt-result')!.innerHTML = `
        <p style="color: #00ff00;">✓ Message decrypted: <strong>${decrypted}</strong></p>
      `;

      decryptBtn.disabled = false;
      decryptBtn.textContent = 'Reconstruct Key & Decrypt';
    } catch (err) {
      document.getElementById('decrypt-result')!.innerHTML = `
        <p style="color: #ff6666;">❌ Error: ${err instanceof Error ? err.message : 'Decryption failed'}</p>
      `;
      decryptBtn.disabled = false;
      decryptBtn.textContent = 'Reconstruct Key & Decrypt';
    }
  });
}

function attachVisualizerHandlers(): void {
  const revealBtn = document.getElementById('reveal-btn') as HTMLButtonElement;
  const resetBtn = document.getElementById('reset-btn') as HTMLButtonElement;

  revealBtn?.addEventListener('click', () => {
    if (currentVisualizer) {
      currentVisualizer.revealNextShare();
    }
  });

  resetBtn?.addEventListener('click', () => {
    if (currentVisualizer) {
      currentVisualizer.reset();
    }
  });
}

function attachSecurityHandlers(): void {
  const slider = document.getElementById('security-slider') as HTMLInputElement;
  const btn = document.getElementById('security-btn') as HTMLButtonElement;
  const countSpan = document.getElementById('security-count')!;

  slider?.addEventListener('change', () => {
    countSpan.textContent = slider.value;
  });

  btn?.addEventListener('click', () => {
    const numShares = parseInt(slider.value, 10);
    const shares = split(42 % 256, { k: 3, n: 5 });
    const selectedShares = shares.slice(0, numShares);

    const consistent = findAllConsistentSecrets(selectedShares, 3);

    const resultDiv = document.getElementById('security-result')!;
    resultDiv.innerHTML = `
      <p><strong>Reveals ${numShares} shares from a 3-of-5 scheme:</strong></p>
      <p>${consistent.length} out of 256 possible secrets are consistent with these shares.</p>
      ${numShares < 3 ? '<p style="color: #ff0;">With fewer than k=3 shares, all 256 secrets are equally likely (perfect secrecy).</p>' : '<p style="color: #0f0;">With all k=3 shares, exactly 1 secret is consistent (unique recovery).</p>'}
    `;
  });
}

function attachSliderHandlers(): void {
  const kSlider = document.getElementById('k-slider') as HTMLInputElement;
  const nSlider = document.getElementById('n-slider') as HTMLInputElement;

  kSlider?.addEventListener('input', () => {
    const k = parseInt(kSlider.value, 10);
    document.getElementById('k-value')!.textContent = k.toString();
    kSlider.setAttribute('aria-valuenow', k.toString());
  });

  nSlider?.addEventListener('input', () => {
    document.getElementById('n-value')!.textContent = nSlider.value;
    nSlider.setAttribute('aria-valuenow', nSlider.value);
  });

  const secSlider = document.getElementById('security-slider') as HTMLInputElement;
  secSlider?.addEventListener('input', () => {
    secSlider.setAttribute('aria-valuenow', secSlider.value);
  });
}

function updateLockStatus(revealed: number, required: number): void {
  const status = document.getElementById('lock-status')!;
  if (revealed >= required) {
    status.textContent = '🔓 UNLOCKED';
    status.style.color = '#00ff00';
  } else {
    status.textContent = `🔒 LOCKED (${revealed}/${required})`;
    status.style.color = '#ff0000';
  }
}

export { verifyGF256, verifyPolynomial, verifyShamir, verifySecurityProof };
