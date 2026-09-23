/*
 * store.js — progress, in this browser and nowhere else.
 *
 * Every access is wrapped: a private window, a browser with site data blocked,
 * or a quota error must leave the range fully usable. If storage is
 * unavailable the range runs from an in-memory copy and says so once, rather
 * than throwing and taking the interface down with it.
 */

const KEY = 'odr.progress.v1';

let memory = { completed: {}, band: 'bronze', lastDrill: '1.1', theme: null };
let usable = true;

function read() {
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return { ...memory };
    const parsed = JSON.parse(raw);
    return {
      completed: parsed.completed && typeof parsed.completed === 'object' ? parsed.completed : {},
      band: typeof parsed.band === 'string' ? parsed.band : 'bronze',
      lastDrill: typeof parsed.lastDrill === 'string' ? parsed.lastDrill : '1.1',
      theme: parsed.theme === 'dark' || parsed.theme === 'light' ? parsed.theme : null,
    };
  } catch (err) {
    usable = false;
    return { ...memory };
  }
}

function write(state) {
  memory = state;
  try {
    window.localStorage.setItem(KEY, JSON.stringify(state));
  } catch (err) {
    usable = false;
  }
}

export const store = {
  get available() { return usable; },

  all() { return read(); },

  isComplete(drillId) {
    const s = read();
    return !!s.completed[drillId];
  },

  markComplete(drillId, band) {
    const s = read();
    const prev = s.completed[drillId];
    s.completed[drillId] = { band, at: prev && prev.at ? prev.at : new Date().toISOString().slice(0, 10) };
    write(s);
    return s;
  },

  completedCount() { return Object.keys(read().completed).length; },

  setBand(band) { const s = read(); s.band = band; write(s); },
  band() { return read().band; },

  setLastDrill(id) { const s = read(); s.lastDrill = id; write(s); },
  lastDrill() { return read().lastDrill; },

  setTheme(theme) { const s = read(); s.theme = theme; write(s); },
  theme() { return read().theme; },

  reset() { write({ completed: {}, band: 'bronze', lastDrill: '1.1', theme: read().theme }); },
};
