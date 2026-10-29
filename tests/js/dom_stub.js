'use strict';
/**
 * Minimal DOM/Bootstrap shim for exercising app/static/js/app.js under plain
 * Node, with no jsdom dependency (matching test_config_transformer.js, which
 * is also dependency-free).
 *
 * This implements only the surface app.js actually touches at DOMContentLoaded:
 * element classList/attributes, addEventListener/dispatch, a selector router
 * keyed on the literal selector strings app.js passes, and stubs for the
 * bootstrap Modal/Toast/Tooltip constructors.
 */

class ClassList {
  constructor(el) { this.el = el; }
  _set() { return (this.el._classes = this.el._classes || new Set()); }
  add(...c) { c.forEach(x => this._set().add(x)); }
  remove(...c) { c.forEach(x => this._set().delete(x)); }
  contains(c) { return this._set().has(c); }
}

class Element {
  constructor(tag, attrs, classes) {
    this.tagName = (tag || 'div').toUpperCase();
    this._attrs = Object.assign({}, attrs || {});
    this._classes = new Set(classes || []);
    this._listeners = {};
    this.classList = new ClassList(this);
    this.style = {};
    this.textContent = '';
    this.value = '';
    this.checked = false;
    this.disabled = false;
    // Set by tests to control checkValidity()
    this._valid = true;
    // Records native form.submit() calls — the thing we most want to assert on
    this.submitted = 0;
  }

  getAttribute(n) { return Object.prototype.hasOwnProperty.call(this._attrs, n) ? this._attrs[n] : null; }
  setAttribute(n, v) { this._attrs[n] = String(v); }
  removeAttribute(n) { delete this._attrs[n]; }
  hasAttribute(n) { return Object.prototype.hasOwnProperty.call(this._attrs, n); }

  addEventListener(type, fn) { (this._listeners[type] = this._listeners[type] || []).push(fn); }

  /** Dispatch an event; returns false if a handler called preventDefault(). */
  dispatch(type, extra) {
    let defaultPrevented = false;
    const evt = Object.assign({
      type,
      target: this,
      preventDefault() { defaultPrevented = true; },
      stopPropagation() {},
    }, extra || {});
    (this._listeners[type] || []).forEach(fn => fn.call(this, evt));
    return !defaultPrevented;
  }

  checkValidity() { return this._valid; }
  closest() { return null; }
  querySelector() { return null; }
  querySelectorAll() { return []; }

  /**
   * Native submit(): per the HTML spec this does NOT fire submit listeners.
   * app.js relies on that, so the shim must model it faithfully.
   */
  submit() { this.submitted++; }
}

/**
 * @param {object} routes - map of selector string -> array of Elements
 * @param {object} ids    - map of element id -> Element
 */
function makeDocument(routes, ids) {
  const body = new Element('body', { 'data-authenticated': 'false' });
  body.appendChild = () => {};
  body.removeChild = () => {};
  const doc = {
    _listeners: {},
    body: body,
    documentElement: new Element('html', { 'data-bs-theme': 'light' }),
    createElement: tag => new Element(tag),
    execCommand: () => {},
    querySelectorAll(sel) { return routes[sel] || []; },
    querySelector(sel) { return (routes[sel] || [])[0] || null; },
    getElementById(id) { return ids[id] || null; },
    addEventListener(type, fn) { (doc._listeners[type] = doc._listeners[type] || []).push(fn); },
    /** Run the DOMContentLoaded handlers app.js registers at load. */
    ready() { (doc._listeners['DOMContentLoaded'] || []).forEach(fn => fn()); },
  };
  return doc;
}

/** Bootstrap stubs. Modal records show/hide so tests can assert visibility. */
function makeBootstrap() {
  const shown = [];
  class Modal {
    constructor(el) { this.el = el; this.visible = false; el._modal = this; }
    show() { this.visible = true; shown.push(this.el); }
    hide() { this.visible = false; }
  }
  class Toast { constructor(el) { this.el = el; } show() {} }
  class Tooltip { constructor(el) { this.el = el; } }
  return { Modal, Toast, Tooltip, _shown: shown };
}

/**
 * Load app/static/js/app.js into a sandbox wired to the given document.
 * Returns the sandbox so tests can inspect window.showLoading etc.
 */
function loadAppJs(doc, bootstrap) {
  const fs = require('fs');
  const path = require('path');
  const vm = require('vm');
  const src = fs.readFileSync(
    path.join(__dirname, '..', '..', 'app', 'static', 'js', 'app.js'), 'utf8');

  const sandbox = {
    document: doc,
    bootstrap: bootstrap,
    console: console,
    setTimeout: () => 0,
    clearTimeout: () => {},
    fetch: () => Promise.resolve(),
  };
  sandbox.window = sandbox;
  sandbox.window.location = { pathname: '/', href: '' };
  sandbox.localStorage = {
    _d: {},
    getItem(k) { return Object.prototype.hasOwnProperty.call(this._d, k) ? this._d[k] : null; },
    setItem(k, v) { this._d[k] = String(v); },
  };
  sandbox.navigator = {};
  sandbox.FormData = class { append() {} };
  sandbox.ResizeObserver = null;
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox);
  doc.ready();
  return sandbox;
}

module.exports = { Element, makeDocument, makeBootstrap, loadAppJs };
