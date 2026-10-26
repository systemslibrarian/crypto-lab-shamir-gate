import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const derivedNpmCli = join(process.execPath, '..', '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js');
const npmCli = process.env.npm_execpath && existsSync(process.env.npm_execpath)
  ? process.env.npm_execpath
  : derivedNpmCli;
const testArgs = [
  npmCli,
  'exec',
  '--',
  'vitest',
  'run',
  'src/visual.test.ts',
  'src/ui-smoke.test.ts',
];

const mutations = [
  {
    name: 'white and black share-2 rules swapped',
    file: 'src/visual.ts',
    from: 'share2: source === 0 ? [...pattern] as Block : complementBlock(pattern),',
    to: 'share2: source === 1 ? [...pattern] as Block : complementBlock(pattern),',
  },
  {
    name: 'physical stack changed from OR to XOR',
    file: 'src/visual.ts',
    from: '? (bit | share2[rowIndex][columnIndex]) as Bit',
    to: '? (bit ^ share2[rowIndex][columnIndex]) as Bit',
  },
  {
    name: 'basis admits a weight-one pattern',
    file: 'src/visual.ts',
    from: '  [0, 0, 1, 1],',
    to: '  [0, 0, 0, 1],',
  },
  {
    name: 'one of six pattern outcomes removed',
    file: 'src/visual.ts',
    from: '  [1, 1, 0, 0],\n',
    to: '',
  },
  {
    name: 'uniform rejection sampler replaced with byte modulo six',
    file: 'src/visual.ts',
    from: 'const value = await draw(0n, BigInt(VISUAL_PATTERNS.length));',
    to: 'const value = (await draw(0n, 256n)) % BigInt(VISUAL_PATTERNS.length);',
  },
  {
    name: 'one mask reused across the image',
    file: 'src/visual.ts',
    from: 'const patternIndex = await samplePatternIndex(draw);',
    to: 'const patternIndex = patternIndices[0] ?? await samplePatternIndex(draw);',
  },
  {
    name: 'share 2 keyed by a pattern bit instead of the source pixel',
    file: 'src/visual.ts',
    from: 'const sourceBit = source[Math.floor(index / width)][index % width];',
    to: 'const sourceBit = pattern[0];',
  },
  {
    name: 'contrast difference hardcoded instead of derived',
    file: 'src/visual.ts',
    from: 'const difference = blackOrWeight - whiteOrWeight;',
    to: 'const difference = 2;',
  },
  {
    name: 'mismatched share dimensions allowed to zip',
    file: 'src/visual.ts',
    from: 'if (left.width !== right.width || left.height !== right.height) {',
    to: 'if (false && (left.width !== right.width || left.height !== right.height)) {',
  },
  {
    name: 'one missing share no longer refused at the boundary',
    file: 'src/visual.ts',
    from: 'if (!share1Input || !share2Input) {',
    to: 'if (!share1Input && !share2Input) {',
  },
  {
    name: 'invalid pattern weight accepted',
    file: 'src/visual.ts',
    from: "  if (hammingWeight(pattern) !== 2) {\n    throw new Error('Every visual-share pattern must contain exactly two black subpixels.');\n  }",
    to: '  if (false && hammingWeight(pattern) !== 2) {\n    throw new Error(\'Every visual-share pattern must contain exactly two black subpixels.\');\n  }',
  },
  {
    name: 'input change preserves stale derived verdicts',
    file: 'src/visual-ui.ts',
    from: "  placeholder('visual-share-2', 'Generate shares from the current source.');\n  clearDerivedResults();\n  setStatus(`${reason} Previous masks, reconstructions, distributions, and verdicts were retired.`);",
    to: "  placeholder('visual-share-2', 'Generate shares from the current source.');\n  setStatus(`${reason} Previous masks, reconstructions, distributions, and verdicts were retired.`);",
  },
  {
    name: 'digital XOR mislabeled as physical stacking',
    file: 'src/visual-ui.ts',
    from: 'XOR is not physical transparency stacking:',
    to: 'XOR is physical transparency stacking:',
  },
  {
    name: 'marginals mislabeled as the full privacy proof',
    file: 'src/visual-ui.ts',
    from: 'same complete block distribution',
    to: 'same per-subpixel marginals',
  },
];

function runOwnedTests() {
  return spawnSync(process.execPath, testArgs, {
    cwd: root,
    env: { ...process.env, CI: '1' },
    encoding: 'utf8',
    timeout: 60_000,
  });
}

function failWithRun(label, run) {
  console.error(`${label} FAILED`);
  if (run.stdout) console.error(run.stdout);
  if (run.stderr) console.error(run.stderr);
  process.exit(1);
}

const baseline = runOwnedTests();
if (baseline.status !== 0) failWithRun('baseline: unmutated copy', baseline);
console.log('baseline: unmutated copy PASSES');

let caught = 0;
for (const mutation of mutations) {
  const path = join(root, mutation.file);
  const original = readFileSync(path, 'utf8');
  const occurrences = original.split(mutation.from).length - 1;
  if (occurrences !== 1) {
    console.error(`mutation setup FAILED: ${mutation.name} matched ${occurrences} times`);
    process.exit(1);
  }
  try {
    writeFileSync(path, original.replace(mutation.from, mutation.to));
    const run = runOwnedTests();
    if (run.status === 0) {
      console.error(`SURVIVED: ${mutation.name}`);
      process.exitCode = 1;
    } else {
      caught += 1;
      console.log(`caught: ${mutation.name}`);
    }
  } finally {
    writeFileSync(path, original);
  }
  if (readFileSync(path, 'utf8') !== original) {
    console.error(`restoration FAILED: ${mutation.name}`);
    process.exit(1);
  }
  if (process.exitCode) process.exit(process.exitCode);
}

const restored = runOwnedTests();
if (restored.status !== 0) failWithRun('restored baseline', restored);
console.log(`all ${caught} mutation(s) caught`);
