'use strict';
/**
 * Tests for the interaction between the data-loading overlay and the
 * data-confirm-message modal in app/static/js/app.js.
 *
 * Regression: a form carrying BOTH attributes wired two submit listeners. The
 * data-loading one raised the overlay (z-index 9999); the data-confirm-message
 * one then called preventDefault() and opened the modal (Bootstrap z-index
 * 1055). Result: a stuck "Applying template..." spinner covering an
 * unclickable confirm dialog, and the POST never left the browser.
 *
 * Run:
 *   node tests/js/test_confirm_loading.js
 */
const assert = require('assert');
const { Element, makeDocument, makeBootstrap, loadAppJs } = require('./dom_stub');

// ---------------------------------------------------------------------------
// Minimal test harness (no external dependencies)
// ---------------------------------------------------------------------------
let passed = 0, failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓  ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗  ${name}`);
    console.error(`     ${err.message}`);
    failed++;
  }
}

/**
 * Build a document containing one form plus the shared confirm modal.
 * @param {object} attrs - attributes to put on the form
 */
function setup(attrs) {
  const form = new Element('form', attrs);
  const overlay = new Element('div', {}, ['loading-overlay', 'd-none']);
  const msgEl = new Element('div', {}, ['loading-message']);
  overlay.querySelector = sel => (sel === '.loading-message' ? msgEl : null);

  const modal = new Element('div', { id: 'confirmModal' });
  const modalBody = new Element('div', { id: 'confirmModalBody' });
  const modalBtn = new Element('button', { id: 'confirmModalBtn' });

  const routes = {
    'form[data-loading]': form.hasAttribute('data-loading') ? [form] : [],
    'form[data-confirm-message]': form.hasAttribute('data-confirm-message') ? [form] : [],
    '[data-confirm]': [],
    '.toast': [],
    'form.needs-validation': [],
    '[data-search-target]': [],
    '[data-bs-toggle="tooltip"]': [],
    '.navbar-nav .nav-link': [],
  };
  const ids = {
    globalLoadingOverlay: overlay,
    confirmModal: modal,
    confirmModalBody: modalBody,
    confirmModalBtn: modalBtn,
  };

  const doc = makeDocument(routes, ids);
  const bootstrap = makeBootstrap();
  loadAppJs(doc, bootstrap);
  return { form, overlay, msgEl, modal, modalBtn, modalBody, bootstrap };
}

const overlayVisible = overlay => !overlay.classList.contains('d-none');

// ---------------------------------------------------------------------------
console.log('\nConfirm modal + loading overlay');
// ---------------------------------------------------------------------------

test('form with BOTH attributes: submit does not raise the overlay', () => {
  const { form, overlay } = setup({
    'data-loading': 'Applying template...',
    'data-confirm-message': 'Apply this template?',
  });
  form.dispatch('submit');
  assert.ok(!overlayVisible(overlay),
    'overlay was raised over the confirm modal (the original bug)');
});

test('form with BOTH attributes: submit is cancelled and the modal opens', () => {
  const { form, modal, bootstrap } = setup({
    'data-loading': 'Applying template...',
    'data-confirm-message': 'Apply this template?',
  });
  const notPrevented = form.dispatch('submit');
  assert.ok(!notPrevented, 'submit should be preventDefault()ed pending confirmation');
  assert.ok(modal._modal.visible, 'confirm modal should be shown');
  assert.strictEqual(bootstrap._shown.length, 1);
});

test('confirming raises the overlay with the form\'s data-loading message', () => {
  const { form, overlay, msgEl, modalBtn } = setup({
    'data-loading': 'Applying template...',
    'data-confirm-message': 'Apply this template?',
  });
  form.dispatch('submit');
  modalBtn.dispatch('click');
  assert.ok(overlayVisible(overlay), 'overlay should be raised once confirmed');
  assert.strictEqual(msgEl.textContent, 'Applying template...');
});

test('confirming actually submits the form', () => {
  const { form, modalBtn } = setup({
    'data-loading': 'Applying template...',
    'data-confirm-message': 'Apply this template?',
  });
  form.dispatch('submit');
  assert.strictEqual(form.submitted, 0, 'must not submit before confirmation');
  modalBtn.dispatch('click');
  assert.strictEqual(form.submitted, 1, 'should submit exactly once after confirmation');
});

test('data-confirm-message survives the submit (no attribute leak)', () => {
  const { form, modalBtn } = setup({
    'data-loading': 'Applying template...',
    'data-confirm-message': 'Apply this template?',
  });
  form.dispatch('submit');
  modalBtn.dispatch('click');
  assert.strictEqual(form.getAttribute('data-confirm-message'), 'Apply this template?',
    'attribute should be restored so the next submit is still gated');
});

test('dismissing the modal submits nothing and leaves no overlay', () => {
  const { form, overlay, modal } = setup({
    'data-loading': 'Applying template...',
    'data-confirm-message': 'Apply this template?',
  });
  form.dispatch('submit');
  modal.dispatch('hidden.bs.modal');
  assert.strictEqual(form.submitted, 0, 'cancelling must not submit');
  assert.ok(!overlayVisible(overlay), 'cancelling must leave no stuck spinner');
});

test('cancel then confirm does not submit a stale form', () => {
  const { form, modal, modalBtn } = setup({
    'data-loading': 'Applying template...',
    'data-confirm-message': 'Apply this template?',
  });
  form.dispatch('submit');
  modal.dispatch('hidden.bs.modal');   // user dismissed
  modalBtn.dispatch('click');          // stray confirm click
  assert.strictEqual(form.submitted, 0, 'pendingForm should have been cleared');
});

// ---------------------------------------------------------------------------
console.log('\nUnaffected forms still behave');
// ---------------------------------------------------------------------------

test('data-loading alone still raises the overlay on submit', () => {
  const { form, overlay, msgEl } = setup({ 'data-loading': 'Saving...' });
  form.dispatch('submit');
  assert.ok(overlayVisible(overlay), 'plain data-loading forms must still show the spinner');
  assert.strictEqual(msgEl.textContent, 'Saving...');
});

test('data-confirm-message alone still gates submit without an overlay', () => {
  const { form, overlay, modal, modalBtn } = setup({ 'data-confirm-message': 'Delete?' });
  const notPrevented = form.dispatch('submit');
  assert.ok(!notPrevented, 'submit should be cancelled pending confirmation');
  assert.ok(modal._modal.visible);
  modalBtn.dispatch('click');
  assert.strictEqual(form.submitted, 1);
  assert.ok(!overlayVisible(overlay),
    'no data-loading means no overlay, even after confirming');
});

// ---------------------------------------------------------------------------
console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
