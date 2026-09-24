/*
 * engine-wasm.js — the real engine.
 *
 * This is the thin half of the boundary. The Rust crate `crates/odr-wasm`
 * exposes one object whose every method returns a JSON string; this file
 * parses those strings and presents exactly the interface written down in
 * ../ENGINE-API.md, so that js/app.js cannot tell which engine it is talking
 * to. engine-mock.js implements the same contract in JavaScript and is kept as
 * the reference implementation — swapping between them is one import line in
 * js/app.js.
 *
 * Why strings rather than objects: a string crosses the wasm boundary once, as
 * a length-prefixed copy, and the browser's own JSON parser builds the object
 * graph in native code. Handing back a live JS object from Rust means one
 * boundary crossing per property, and a page of 3,500 frames has a lot of
 * properties. Measured: parsing a full drill-4.1 traffic list this way is
 * single-digit milliseconds.
 *
 * NOTHING HERE TOUCHES THE NETWORK. The only request the page ever makes is
 * the static fetch of pkg/odr_wasm_bg.wasm from its own origin.
 */

import init, { Engine } from '../pkg/odr_wasm.js';

export const ENGINE_KIND = 'wasm';
export const ENGINE_API_VERSION = 3;

/**
 * Memoise a JSON-returning call against the engine's mutation counter.
 *
 * The site calls frames(), timeline() and configGroups() several times inside a
 * single render, and stateAt() on every animation frame. None of those change
 * anything, so a cache keyed on engine.version is safe by construction: any
 * mutation bumps the version and the whole cache is dropped.
 */
function memoiser(engine) {
  let atVersion = -1;
  let cache = new Map();
  return function memo(key, produce) {
    const v = engine.version;
    if (v !== atVersion) {
      atVersion = v;
      cache = new Map();
    }
    if (cache.has(key)) return cache.get(key);
    const value = produce();
    cache.set(key, value);
    return value;
  };
}

class WasmEngine {
  constructor(engine) {
    this._e = engine;
    this._memo = memoiser(engine);
  }

  get version() {
    return this._e.version;
  }

  /* ---- §1 catalogue ---- */

  catalog() {
    return this._memo('catalog', () => JSON.parse(this._e.catalog()));
  }

  getDrill(id) {
    return this._memo(`drill:${id}`, () => JSON.parse(this._e.getDrill(id)));
  }

  /* ---- §2 session ---- */

  loadDrill(drillId, band) {
    const s = JSON.parse(this._e.loadDrill(drillId, band || 'bronze'));
    const err = this._e.lastError();
    if (err) console.warn('[odr] engine:', err);
    return s;
  }

  loadSandbox(scenarioId) {
    return JSON.parse(this._e.loadSandbox(scenarioId ?? undefined));
  }

  get session() {
    return this._memo('session', () => JSON.parse(this._e.session));
  }

  setBand(band) {
    return JSON.parse(this._e.setBand(band));
  }

  /* ---- §3 configuration ---- */

  configGroups() {
    return this._memo('config', () => JSON.parse(this._e.configGroups()));
  }

  setConfig(groupId, fieldId, value) {
    return JSON.parse(this._e.setConfig(groupId, fieldId, String(value)));
  }

  resetConfig() {
    return JSON.parse(this._e.resetConfig());
  }

  /* ---- §4 topology and taps ---- */

  topology() {
    return this._memo('topology', () => JSON.parse(this._e.topology()));
  }

  addTap({ linkId, mode }) {
    return JSON.parse(this._e.addTap(linkId, mode));
  }

  setTapMode(tapId, mode) {
    return JSON.parse(this._e.setTapMode(tapId, mode));
  }

  removeTap(tapId) {
    return JSON.parse(this._e.removeTap(tapId));
  }

  /* ---- §5 time ---- */

  duration() {
    return this._e.duration();
  }

  nextEventUs(tUs) {
    return this._e.nextEventUs(tUs);
  }

  prevEventUs(tUs) {
    return this._e.prevEventUs(tUs);
  }

  stateAt(tUs) {
    // Rounded to the millisecond for the cache key: the site calls this on
    // every animation frame and a state change is never finer than that.
    const key = `state:${Math.round(tUs / 1000)}`;
    return this._memo(key, () => JSON.parse(this._e.stateAt(tUs)));
  }

  markers() {
    return this._memo('markers', () => JSON.parse(this._e.markers()));
  }

  /* ---- §6 traffic ---- */

  frames({ fromUs = 0, toUs = Infinity, collapseIdle = false, filter = null, limit = 4000 } = {}) {
    const to = Number.isFinite(toUs) ? toUs : -1;
    const key = `frames:${fromUs}:${to}:${collapseIdle}:${filter || ''}:${limit}`;
    return this._memo(key, () =>
      JSON.parse(this._e.frames(fromUs, to, !!collapseIdle, filter || undefined, limit)));
  }

  frame(id) {
    return this._memo(`frame:${id}`, () => JSON.parse(this._e.frame(id)));
  }

  /* ---- §7 timeline ---- */

  timeline({ fromUs = 0, toUs = null, bins = 600, collapseIdle = false } = {}) {
    const to = toUs === null || !Number.isFinite(toUs) ? -1 : toUs;
    const key = `timeline:${fromUs}:${to}:${bins}:${collapseIdle}`;
    return this._memo(key, () =>
      JSON.parse(this._e.timeline(fromUs, to, bins, !!collapseIdle)));
  }

  /* ---- §9 flags ---- */

  flag() {
    return this._memo('flag', () => JSON.parse(this._e.flag()));
  }

  observe(action) {
    if (!action) return;
    this._e.observe(action.type || '', String(action.fieldId ?? action.frameId ?? action.text ?? ''), Number(action.tUs ?? 0));
  }

  /** The typed claim this drill takes, as a form the engine composed. */
  submission() {
    return this._memo('submission', () => JSON.parse(this._e.submission()));
  }

  submitField(id, value) {
    return JSON.parse(this._e.submitField(String(id), String(value)));
  }

  clearSubmission() {
    return JSON.parse(this._e.clearSubmission());
  }

  /* ---- §10 long-running attacks ---- */

  get tasks() {
    // The site only asks how many there are, so this is a length-carrying
    // stand-in rather than a second copy of the task states.
    return new Array(this._e.taskCount());
  }

  taskStates(elapsedMs) {
    // Deliberately NOT memoised: the whole point of the bar is that it moves.
    return JSON.parse(this._e.taskStates(Number(elapsedMs) || 0));
  }

  startTask(id) {
    return JSON.parse(this._e.startTask(id));
  }
}

export async function createEngine(/* options */) {
  await init();
  return new WasmEngine(new Engine());
}
