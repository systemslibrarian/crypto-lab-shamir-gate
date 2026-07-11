import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate. Scans the whole page in both themes with every
 * tab panel revealed, every collapsible expanded, and the live demos driven so
 * dynamically-injected result regions are also scanned.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      transition:none!important;
      animation:none!important;
    }`,
  });
}

async function revealEverything(page: Page): Promise<void> {
  await page.evaluate(() => {
    // Show every tab panel (they are display:none unless .active).
    for (const panel of document.querySelectorAll('.tab-panel')) {
      panel.classList.add('active');
    }
    // Open any <details> (belt-and-suspenders; this lab class-toggles instead).
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    // Un-hide inline display:none result containers so their injected content
    // is laid out and scannable.
    for (const el of document.querySelectorAll<HTMLElement>('[style*="display:none"], [style*="display: none"]')) {
      el.style.display = 'block';
    }
  });
}

async function driveDemos(page: Page): Promise<void> {
  // Fire every primary/secondary action button so async output regions
  // (role=status / aria-live) get populated, then scan the results too.
  const buttonIds = [
    '#gate-generate',
    '#gate-reconstruct',
    '#poly-generate',
    '#proof-check',
    '#aes-generate',
    '#aes-decrypt',
  ];
  for (const id of buttonIds) {
    const btn = page.locator(id);
    if (await btn.count()) {
      await btn.first().click({ timeout: 5000 }).catch(() => {});
    }
  }
  // Failure lab scenario buttons are injected into #fail-scenarios.
  const failBtns = page.locator('#fail-scenarios button');
  const failCount = await failBtns.count();
  if (failCount > 0) {
    await failBtns.first().click({ timeout: 5000 }).catch(() => {});
  }
  // Give async crypto (AES-GCM) / animations a moment to settle.
  await page.waitForTimeout(600);
}

async function scan(page: Page): Promise<void> {
  await neutralizeMotion(page);
  await revealEverything(page);
  await driveDemos(page);
  await revealEverything(page);
  await neutralizeMotion(page);

  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('.tab-list').waitFor();
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('.tab-list').waitFor();
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await scan(page);
});
