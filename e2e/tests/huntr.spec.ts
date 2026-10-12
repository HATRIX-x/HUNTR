import { test, expect } from '@playwright/test';

// End-to-end tests for the HUNTR dashboard, driven through a real Chromium.
// The server is booted by the `webServer` block in playwright.config.ts on the
// dedicated test port; baseURL points at it, so page.goto('/') loads the UI and
// page.request.* exercises the engine API through the browser's own fetch stack.

test.describe('dashboard loads and renders', () => {
  test('core chrome is present', async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on('console', (m) => m.type() === 'error' && consoleErrors.push(m.text()));
    page.on('pageerror', (e) => consoleErrors.push(String(e)));

    await page.goto('/');
    await expect(page).toHaveTitle(/HUNTR/);
    await expect(page.locator('#logo')).toContainText('HUNTR');
    await expect(page.locator('#scope-ta')).toBeVisible();      // scope input
    await expect(page.locator('#hunt-btn')).toBeVisible();      // Start hunt

    // A broken script (e.g. a bad escaper edit) shows up here before anything else.
    expect(consoleErrors, `console errors on load:\n${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('advanced (auth) panel toggles open', async ({ page }) => {
    await page.goto('/');
    await page.locator('#adv-btn').click();
    await expect(page.locator('#adv-panel')).toBeVisible();
  });
});

test.describe('live scope preview (deterministic, as-you-type)', () => {
  const PAGE = [
    'In scope:',
    '*.acme.com',
    'https://api.acme.com/v2',
    'Out of scope:',
    'legacy.acme.com',
    'Rewards: Critical $5000. PoC required.',
  ].join('\n');

  test('typing a program page renders the parsed scope with types and in/out split', async ({ page }) => {
    await page.goto('/');
    const pv = page.locator('#scope-preview');
    await expect(pv).toBeHidden();              // nothing shown before input
    await page.fill('#scope-ta', PAGE);         // fill fires input -> debounced parse

    // the preview appears and lists the real assets, correctly typed
    await expect(pv).toBeVisible();
    await expect(pv).toContainText('*.acme.com');
    await expect(pv).toContainText('api.acme.com/v2');
    await expect(pv).toContainText('2 in scope');
    await expect(pv).toContainText('out of scope');
    await expect(pv).toContainText('legacy.acme.com');
    // prose never becomes an asset (the whole point vs whitespace-splitting)
    await expect(pv).not.toContainText('Rewards:');
    // a WEB and an API type pill are rendered
    await expect(pv.locator('.sp-pill.web').first()).toBeVisible();
    await expect(pv.locator('.sp-pill.api').first()).toBeVisible();
    await expect(pv.locator('.sp-pill.deny').first()).toBeVisible();
  });

  test('clearing the box hides the preview again', async ({ page }) => {
    await page.goto('/');
    await page.fill('#scope-ta', PAGE);
    await expect(page.locator('#scope-preview')).toBeVisible();
    await page.fill('#scope-ta', '');
    await expect(page.locator('#scope-preview')).toBeHidden();
  });
});

test.describe('regression: API base follows the served origin (not hardcoded :8899)', () => {
  // huntr-ui.html used to hardcode `const API='http://127.0.0.1:8899'`, so serving
  // on any other port left every button talking to the wrong instance. It now uses
  // location.origin — assert the page agrees with the port we actually served on.
  test('the page API base equals the origin it was served from', async ({ page, baseURL }) => {
    await page.goto('/');
    // `const API` at the top of a <script> is a global *lexical* binding, so it
    // is not a property of window — read it by name via eval in the page realm.
    const api = await page.evaluate(() => eval('typeof API !== "undefined" ? API : null'));
    expect(api).toBe(new URL(baseURL!).origin);
  });
});

test.describe('regression: server rejects malformed input instead of crashing', () => {
  // These used to kill the request thread with an unhandled exception (connection
  // reset, no response). They must now return a clean 4xx.
  test('non-object JSON body -> 400, not a dropped connection', async ({ request }) => {
    const res = await request.post('/api/hunt/start', {
      headers: { 'Content-Type': 'application/json' },
      data: ['not', 'an', 'object'] as any,
    });
    expect(res.status()).toBe(400);
  });

  test('blank/whitespace target -> 400 (no silent "default" workspace)', async ({ request }) => {
    const res = await request.post('/api/hunt/start', { data: { target: '   ' } });
    expect(res.status()).toBe(400);
  });

  test('bad base64 on mobile upload -> 400, not a binascii crash', async ({ request }) => {
    const res = await request.post('/api/mobile/upload', {
      data: { filename: 'x.apk', data_b64: '@@@not valid base64@@@' },
    });
    expect(res.status()).toBe(400);
  });

  test('slow GET with no target -> 400 fast (no hang on the backend tool)', async ({ request }) => {
    const res = await request.get('/api/hunt/kgraph', { timeout: 10_000 });
    expect(res.status()).toBe(400);
  });
});
