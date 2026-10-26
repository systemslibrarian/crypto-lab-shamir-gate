import { expect, test, type Page } from '@playwright/test';

type Matrix = number[][];

async function openVisual(page: Page): Promise<void> {
  await page.goto('.');
  await page.locator('#btn-visual').click();
  await expect(page.locator('#tab-visual')).toHaveClass(/active/);
}

async function readMatrix(page: Page, key: string): Promise<Matrix> {
  const text = await page.locator(`[data-visual-matrix="${key}"]`).textContent();
  if (!text) throw new Error(`Missing visible bit matrix ${key}`);
  return text.trim().split(/\s+/).map((row) => [...row].map(Number));
}

function block(matrix: Matrix, row: number, column: number): number[] {
  return [
    matrix[row * 2][column * 2],
    matrix[row * 2][column * 2 + 1],
    matrix[row * 2 + 1][column * 2],
    matrix[row * 2 + 1][column * 2 + 1],
  ];
}

const weight = (bits: readonly number[]): number => bits.reduce((sum, bit) => sum + bit, 0);

test('visual shares derive every displayed relation and reconstruction from rendered bits', async ({ page }) => {
  await openVisual(page);
  await page.locator('#visual-generate').click();
  await expect(page.locator('[data-visual-matrix="share-2"]')).toBeVisible();

  const source = await readMatrix(page, 'source');
  const share1 = await readMatrix(page, 'share-1');
  const share2 = await readMatrix(page, 'share-2');
  expect(source).toHaveLength(8);
  expect(source.every((row) => row.length === 8)).toBe(true);
  expect(share1).toHaveLength(16);
  expect(share2).toHaveLength(16);
  expect(share1.every((row) => row.length === 16)).toBe(true);
  expect(share2.every((row) => row.length === 16)).toBe(true);

  for (let row = 0; row < source.length; row += 1) {
    for (let column = 0; column < source[row].length; column += 1) {
      const first = block(share1, row, column);
      const second = block(share2, row, column);
      expect(weight(first)).toBe(2);
      expect(weight(second)).toBe(2);
      if (source[row][column] === 0) {
        expect(second).toEqual(first);
      } else {
        expect(second).toEqual(first.map((bit) => 1 - bit));
      }
    }
  }
  expect(weight(share1.flat())).toBe(2 * source.length * source[0].length);
  expect(weight(share2.flat())).toBe(2 * source.length * source[0].length);

  await page.locator('#visual-stack-or').click();
  await page.locator('#visual-stack-xor').click();
  const orStack = await readMatrix(page, 'or-stack');
  const xorView = await readMatrix(page, 'xor-view');
  for (let row = 0; row < share1.length; row += 1) {
    for (let column = 0; column < share1[row].length; column += 1) {
      expect(orStack[row][column]).toBe(share1[row][column] | share2[row][column]);
      expect(xorView[row][column]).toBe(share1[row][column] ^ share2[row][column]);
    }
  }
  for (let row = 0; row < source.length; row += 1) {
    for (let column = 0; column < source[row].length; column += 1) {
      expect(weight(block(orStack, row, column))).toBe(source[row][column] === 0 ? 2 : 4);
      expect(weight(block(xorView, row, column))).toBe(source[row][column] === 0 ? 0 : 4);
    }
  }
  await expect(page.locator('#visual-parameters')).toContainText('pixel expansion m=4');
  await expect(page.locator('#visual-parameters')).toContainText('relative contrast alpha=1/2');
  await expect(page.locator('.visual-boundary')).toContainText('XOR is not physical transparency stacking');
});

test('visual privacy proof enumerates full labeled-share distributions and controls', async ({ page }) => {
  await openVisual(page);
  await page.locator('#visual-generate').click();
  await expect(page.locator('[data-visual-matrix="share-1"]')).toBeVisible();
  await page.locator('#visual-prove').click();

  const rows = page.locator('#visual-distribution-table tbody tr');
  await expect(rows).toHaveCount(12);
  for (let index = 0; index < 12; index += 1) {
    const row = rows.nth(index);
    await expect(row.locator('[data-color="white"]')).toHaveText('1/6');
    await expect(row.locator('[data-color="black"]')).toHaveText('1/6');
  }
  const patterns = await rows.evaluateAll((elements) => elements.map((element) => ({
    share: element.getAttribute('data-share'),
    pattern: element.getAttribute('data-pattern'),
  })));
  for (const share of ['1', '2']) {
    const selected = patterns.filter((row) => row.share === share).map((row) => row.pattern);
    expect(selected).toEqual(['0011', '0101', '0110', '1001', '1010', '1100']);
  }
  await expect(page.locator('[data-proof="full-block-distribution"]')).toContainText('same complete block distribution');
  await expect(page.locator('[data-proof="full-block-distribution"]')).toContainText('Equal black-cell totals alone would not prove');

  await page.locator('#visual-controls').click();
  await expect(page.locator('[data-control="mask-reuse"]')).toContainText('0011 0011 1100 1100');
  await expect(page.locator('[data-control="mask-reuse"]')).toContainText('equal, complement, equal');
  await expect(page.locator('[data-control="scramble-only"]')).toContainText('retain 2 and 5 black pixels');
  await expect(page.locator('[data-control="missing-share"]')).toContainText('Both aligned shares are required');
});

test('visual results retire on input changes and the tab remains keyboard/reflow usable', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 900 });
  await page.goto('.');
  await page.locator('#btn-lesson').focus();
  for (let step = 0; step < 4; step += 1) await page.keyboard.press('ArrowRight');
  await expect(page.locator('#btn-visual')).toHaveAttribute('aria-selected', 'true');

  await page.locator('#visual-generate').click();
  await expect(page.locator('[data-visual-matrix="share-1"]')).toBeVisible();
  await page.locator('#visual-stack-or').click();
  await page.locator('#visual-prove').click();
  await expect(page.locator('#visual-distribution-table')).toBeVisible();

  await page.locator('.visual-source-cell').first().click();
  await expect(page.locator('#visual-stack-or')).toBeDisabled();
  await expect(page.locator('[data-visual-matrix="or-stack"]')).toHaveCount(0);
  await expect(page.locator('#visual-distribution-table')).toHaveCount(0);
  await expect(page.locator('#visual-live')).toContainText('retired');

  await page.locator('#visual-size').selectOption('4');
  await expect(page.locator('.visual-source-cell')).toHaveCount(16);
  await page.locator('#visual-generate').click();
  await expect(page.locator('[data-visual-matrix="share-2"]')).toBeVisible();
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    page: document.documentElement.scrollWidth,
  }));
  expect(dimensions.page).toBeLessThanOrEqual(dimensions.viewport);
});
