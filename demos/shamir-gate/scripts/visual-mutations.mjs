// Clean-baseline mutation gate for the visual-sharing exhibit.
//
// Fourteen recipes over `src/visual.ts` and `src/visual-ui.ts`. Until
// 2026-10-27 this runner counted ANY non-zero exit of the two owned test files
// as a kill, so a mutant that failed to compile, or a test run that crashed,
// would have been reported as "caught". It now follows the fleet pattern
// (Attestation Gate, Matsui Line, Residue Gate, Shelf Oracle): for every recipe
// it proves, in order,
//
//   1. the unmodified copy passes the WHOLE unit suite and builds,
//   2. the named owning test is green on the unmodified copy,
//   3. the patch produces a NON-EMPTY source change and the production bundle
//      hash moves (a mutation the build never picked up proves nothing),
//   4. the named owning test goes RED on a test failure -- a timeout, a crash,
//      a missing module or a type error is NOT a kill,
//   5. the source is restored byte for byte, the bundle hash returns to the
//      baseline, and the owning test is green again.
//
// Owners were chosen from observed kills, not from prose: each recipe was
// applied and the two owned specs run with the JSON reporter, and the owner
// is one of the tests that failed with an assertion. Eleven are owned by
// `src/visual.test.ts` and three by the jsdom smoke test in
// `src/ui-smoke.test.ts`.
//
// Run from demos/shamir-gate (or anywhere; the script changes to its package):
//   node scripts/visual-mutations.mjs [mutation name]

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { stripVTControlCharacters } from 'node:util';
import process from 'node:process';

process.chdir(join(dirname(fileURLToPath(import.meta.url)), '..'));

const VISUAL = 'src/visual.ts';
const VISUAL_UI = 'src/visual-ui.ts';
const VISUAL_SPEC = 'src/visual.test.ts';
const SMOKE_SPEC = 'src/ui-smoke.test.ts';

const unit = (spec, test) => ({ runner: 'vitest', spec, test });
const SMOKE_OWNER = 'generates, reconstructs, proves full distributions, runs controls, and retires stale results';

const mutations = [
  {
    name: 'white and black share-2 rules swapped',
    file: VISUAL,
    anchor: 'share2: source === 0 ? [...pattern] as Block : complementBlock(pattern),',
    replacement: 'share2: source === 1 ? [...pattern] as Block : complementBlock(pattern),',
    ...unit(VISUAL_SPEC, 'uses identical rows for white and complementary rows for black'),
  },
  {
    name: 'physical stack changed from OR to XOR',
    file: VISUAL,
    anchor: '? (bit | share2[rowIndex][columnIndex]) as Bit',
    replacement: '? (bit ^ share2[rowIndex][columnIndex]) as Bit',
    ...unit(VISUAL_SPEC, 'draws independently for every pixel and round-trips solely from the shares'),
  },
  {
    name: 'basis admits a weight-one pattern',
    file: VISUAL,
    anchor: '  [0, 0, 1, 1],',
    replacement: '  [0, 0, 0, 1],',
    ...unit(VISUAL_SPEC, 'enumerates exactly the six distinct weight-two patterns in canonical order'),
  },
  {
    name: 'one of six pattern outcomes removed',
    file: VISUAL,
    anchor: '  [1, 1, 0, 0],\n',
    replacement: '',
    ...unit(VISUAL_SPEC, 'enumerates exactly the six distinct weight-two patterns in canonical order'),
  },
  {
    name: 'uniform rejection sampler replaced with byte modulo six',
    file: VISUAL,
    anchor: 'const value = await draw(0n, BigInt(VISUAL_PATTERNS.length));',
    replacement: 'const value = (await draw(0n, 256n)) % BigInt(VISUAL_PATTERNS.length);',
    ...unit(VISUAL_SPEC, 'uses rejection sampling through randomBigInt rather than byte modulo six'),
  },
  {
    name: 'one mask reused across the image',
    file: VISUAL,
    anchor: 'const patternIndex = await samplePatternIndex(draw);',
    replacement: 'const patternIndex = patternIndices[0] ?? await samplePatternIndex(draw);',
    ...unit(VISUAL_SPEC, 'draws independently for every pixel and round-trips solely from the shares'),
  },
  {
    name: 'share 2 keyed by a pattern bit instead of the source pixel',
    file: VISUAL,
    anchor: 'const sourceBit = source[Math.floor(index / width)][index % width];',
    replacement: 'const sourceBit = pattern[0];',
    ...unit(VISUAL_SPEC, 'draws independently for every pixel and round-trips solely from the shares'),
  },
  {
    name: 'contrast difference hardcoded instead of derived',
    file: VISUAL,
    anchor: 'const difference = blackOrWeight - whiteOrWeight;',
    replacement: 'const difference = 2;',
    ...unit(VISUAL_SPEC, 'derives pixel expansion and one-half contrast from the basis blocks'),
  },
  {
    name: 'mismatched share dimensions allowed to zip',
    file: VISUAL,
    anchor: 'if (left.width !== right.width || left.height !== right.height) {',
    replacement: 'if (false && (left.width !== right.width || left.height !== right.height)) {',
    ...unit(VISUAL_SPEC, 'refuses missing, malformed and mismatched shares instead of truncating'),
  },
  {
    name: 'one missing share no longer refused at the boundary',
    file: VISUAL,
    anchor: 'if (!share1Input || !share2Input) {',
    replacement: 'if (!share1Input && !share2Input) {',
    ...unit(VISUAL_SPEC, 'refuses missing, malformed and mismatched shares instead of truncating'),
  },
  {
    name: 'invalid pattern weight accepted',
    file: VISUAL,
    anchor: "  if (hammingWeight(pattern) !== 2) {\n    throw new Error('Every visual-share pattern must contain exactly two black subpixels.');\n  }",
    replacement: "  if (false && hammingWeight(pattern) !== 2) {\n    throw new Error('Every visual-share pattern must contain exactly two black subpixels.');\n  }",
    ...unit(VISUAL_SPEC, 'keeps either labeled share weight two for both source colors'),
  },
  {
    name: 'input change preserves stale derived verdicts',
    file: VISUAL_UI,
    anchor: "  placeholder('visual-share-2', 'Generate shares from the current source.');\n  clearDerivedResults();\n  setStatus(`${reason} Previous masks, reconstructions, distributions, and verdicts were retired.`);",
    replacement: "  placeholder('visual-share-2', 'Generate shares from the current source.');\n  setStatus(`${reason} Previous masks, reconstructions, distributions, and verdicts were retired.`);",
    ...unit(SMOKE_SPEC, SMOKE_OWNER),
  },
  {
    name: 'digital XOR mislabeled as physical stacking',
    file: VISUAL_UI,
    anchor: 'XOR is not physical transparency stacking:',
    replacement: 'XOR is physical transparency stacking:',
    ...unit(SMOKE_SPEC, SMOKE_OWNER),
  },
  {
    name: 'marginals mislabeled as the full privacy proof',
    file: VISUAL_UI,
    anchor: 'same complete block distribution',
    replacement: 'same per-subpixel marginals',
    ...unit(SMOKE_SPEC, SMOKE_OWNER),
  },
];

const INFRASTRUCTURE = /No test files found|Cannot find module|Failed to load url|Unhandled Error|error TS\d+|Test timed out|Test timeout of/;

function run(command, args, timeout) {
  const child = spawnSync(command, args, {
    encoding: 'utf8',
    env: { ...process.env, CI: '1', NO_COLOR: '1' },
    maxBuffer: 32 * 1024 * 1024,
    timeout,
  });
  return {
    ok: child.status === 0 && !child.error && !child.signal,
    status: child.status,
    signal: child.signal,
    error: child.error,
    output: stripVTControlCharacters(`${child.stdout ?? ''}${child.stderr ?? ''}`),
  };
}

function requirePass(result, label) {
  if (!result.ok) {
    throw new Error(`${label} failed (status ${result.status}, signal ${result.signal ?? 'none'}):\n${result.output.slice(-4000)}`);
  }
}

/** `npm run build` runs the publish-request control, typechecks and bundles. */
function build() {
  requirePass(run('npm', ['run', 'build'], 300_000), 'build');
}

/** Hash of every emitted asset (JavaScript, CSS and source map). */
function bundleHash() {
  const dir = 'dist/assets';
  const files = readdirSync(dir).filter((file) => statSync(join(dir, file)).isFile()).sort();
  if (files.length === 0) throw new Error('build produced no assets');
  const hash = createHash('sha256');
  for (const file of files) hash.update(file).update(readFileSync(join(dir, file)));
  return hash.digest('hex');
}

const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function owningTest(mutation) {
  return run('npx', ['vitest', 'run', mutation.spec, '-t', escapeRegex(mutation.test)], 300_000);
}

function requireNamedGreen(result, mutation, label) {
  requirePass(result, label);
  if (!/Tests\s+1 passed\b/.test(result.output) || /\d+ failed\b/.test(result.output)) {
    throw new Error(`${label} did not execute exactly one passing test:\n${result.output.slice(-3000)}`);
  }
}

function requireNamedRed(result, mutation) {
  if (result.ok) throw new Error(`${mutation.name}: mutation SURVIVED its owning test`);
  if (INFRASTRUCTURE.test(result.output)) {
    throw new Error(`${mutation.name}: an infrastructure failure or timeout is not a kill:\n${result.output.slice(-3000)}`);
  }
  if (!result.output.includes(mutation.test)) {
    throw new Error(`${mutation.name}: the failure did not name its owning test:\n${result.output.slice(-3000)}`);
  }
  if (!/Tests\s+1 failed\b/.test(result.output)) {
    throw new Error(`${mutation.name}: the owning test did not fail exactly once:\n${result.output.slice(-3000)}`);
  }
  // A kill is a test FAILURE: an expect() assertion, or the code under test
  // throwing into the test body. Both are reported as failed tests; what is
  // excluded is everything the INFRASTRUCTURE pattern names above.
}

const requested = process.argv[2];
const selected = requested ? mutations.filter((mutation) => mutation.name === requested) : mutations;
if (selected.length === 0) throw new Error(`unknown mutation: ${requested}`);

const files = [...new Set(selected.map((mutation) => mutation.file))];
if (run('git', ['diff', '--quiet', 'HEAD', '--', ...files], 60_000).status !== 0) {
  throw new Error('commit the mutated source files before replaying mutations; the harness restores from disk, not from git');
}

build();
const baseline = bundleHash();
// The WHOLE unit suite: a baseline scoped to the mutated files would stay green
// while a mutation broke something elsewhere, and the restore control at the
// end would agree with it.
requirePass(run('npx', ['vitest', 'run'], 600_000), 'unmutated unit baseline');
console.log('baseline: unmutated copy PASSES');

const evidence = [];
for (const [index, mutation] of selected.entries()) {
  const original = readFileSync(mutation.file, 'utf8');
  if (original.split(mutation.anchor).length !== 2) {
    throw new Error(`${mutation.name}: the anchor must occur exactly once in ${mutation.file}`);
  }
  requireNamedGreen(owningTest(mutation), mutation, `${mutation.name}: named baseline`);
  let record;
  try {
    const changed = original.replace(mutation.anchor, mutation.replacement);
    if (changed === original) throw new Error(`${mutation.name}: the patch changed nothing`);
    writeFileSync(mutation.file, changed);
    const diff = run('git', ['diff', '--no-ext-diff', '--', mutation.file], 60_000);
    if (diff.output.trim() === '') throw new Error(`${mutation.name}: the source diff was empty`);
    build();
    const mutant = bundleHash();
    if (mutant === baseline) throw new Error(`${mutation.name}: the production bundle did not change`);
    const red = owningTest(mutation);
    requireNamedRed(red, mutation);
    record = {
      name: mutation.name,
      file: mutation.file,
      runner: mutation.runner,
      spec: mutation.spec,
      owningTest: mutation.test,
      baselineGreen: true,
      sourceDiffNonEmpty: true,
      baselineBundle: baseline,
      mutantBundle: mutant,
      bundleMoved: true,
      owningTestRed: true,
      failureExcerpt: red.output.split('\n').filter((line) => /expect|Error|✗|×|FAIL/.test(line)).slice(0, 6),
    };
    console.log(`caught ${index + 1}/${selected.length}: ${mutation.name} -> ${mutation.test}`);
  } finally {
    writeFileSync(mutation.file, original);
    if (readFileSync(mutation.file, 'utf8') !== original) {
      throw new Error(`${mutation.name}: source was not restored byte for byte`);
    }
    build();
    if (bundleHash() !== baseline) throw new Error(`${mutation.name}: restored bundle differs from the baseline`);
  }
  requireNamedGreen(owningTest(mutation), mutation, `${mutation.name}: restored baseline`);
  record.restoredGreen = true;
  evidence.push(record);
  writeFileSync('mutation-evidence.json', `${JSON.stringify(evidence, null, 2)}\n`);
}

requirePass(run('npx', ['vitest', 'run'], 600_000), 'restored unit baseline');
console.log(`all ${evidence.length} of ${selected.length} mutation(s) caught; sources and production bundle restored byte for byte`);
