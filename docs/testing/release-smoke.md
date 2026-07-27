# Release Smoke Test: cryptoscan

Manual pre-release walkthrough. Run this before every deploy or publish.
Use real keyboard and mouse input, not synthetic events. Record the actual
output, not a summary.

## 1. Build and start clean

- [ ] Fresh install succeeds (`npm ci` or equivalent) with no errors.
- [ ] Build succeeds (`npm run build`).
- [ ] App starts locally (`npm run dev`) with no console errors.

## 2. Core user paths

List the three most important things a real visitor does on this site or
with this tool, then walk each one by hand.

- [ ] Path 1:
- [ ] Path 2:
- [ ] Path 3:

## 3. Accessibility and audience fit

CSNP serves non-technical and vulnerable users. Verify the experience holds
for them.

- [ ] Plain language: no unexplained jargon in user-facing copy.
- [ ] Keyboard navigable: every interactive element reachable by Tab.
- [ ] Screen-reader labels present on buttons, links, and form fields.
- [ ] Color contrast meets WCAG AA.

## 4. Responsive parity

- [ ] Mobile (375px): nav, menus, and layout all work.
- [ ] Desktop (1280px): no overflow or broken grids.
- [ ] Dark mode (if supported) renders correctly.

## 5. Data and links

- [ ] Every download link resolves (no 404s).
- [ ] Any displayed number or statistic traces to a real source.
- [ ] No placeholder or fabricated content shipped.

## 6. Security

- [ ] No secrets in the bundle or committed files.
- [ ] `.env` and credential files are gitignored and excluded.
- [ ] Forms validate and sanitize input.

## Result

- Date:
- Tester:
- Verdict: PASS / FAIL
- Notes:
