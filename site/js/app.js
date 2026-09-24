/*
 * app.js — wiring.
 *
 * The ONE line that chooses the engine is the import below. Everything
 * downstream talks to the interface described in ../ENGINE-API.md and knows
 * nothing about how the engine is implemented.
 *
 *   './engine-wasm.js'  — crates/odr-wasm, the real engine. Needs site/pkg,
 *                         built by `wasm-pack build crates/odr-wasm
 *                         --target web --out-dir ../../site/pkg`.
 *   './engine-mock.js'  — the reference implementation, in JavaScript. No Rust
 *                         toolchain, no build step. Useful for working on the
 *                         interface itself.
 *
 * Both are verified to run this file unchanged.
 */

import { createEngine } from './engine-wasm.js';

import { $, el, clear, fmtT, fmtTShort, trapFocus } from './util.js';
import { store } from './store.js';
import { renderTopology } from './ui/topology.js';
import { renderLanes, renderMarkers, positionCursor, collapseStateText } from './ui/timeline.js';
import { renderTraffic, followCursor } from './ui/traffic.js';
import { renderInspector } from './ui/inspector.js';
import { renderConfig, renderBenchState } from './ui/config.js';
import { renderCourse } from './ui/course.js';
import { renderDrill, renderTasks } from './ui/drill.js';
import { renderSubmission } from './ui/submission.js';

const engine = await createEngine();

const state = {
  cursorUs: 0,
  running: false,
  speed: 1,
  collapseIdle: false,        // DECIDED: non-sticky. Reset on every drill load.
  selectedFrameId: null,
  filter: '',
  band: store.band() || 'bronze',
  lastDoor: 'closed',
  taskStart: Date.now(),
};

const refs = {
  session: $('#session-line'),
  benchstate: $('#benchstate'),
  topology: $('#topology-host'),
  clock: $('#clock'),
  lanes: $('#lanes'),
  markers: $('#markers'),
  scrub: $('#scrub'),
  collapseBtn: $('#btn-collapse'),
  collapseState: $('#collapse-state'),
  honesty: $('#honesty-note'),
  trafficRows: $('#traffic-rows'),
  trafficCount: $('#traffic-count'),
  inspector: $('#inspector-host'),
  inspectorCount: $('#inspector-count'),
  tasks: $('#tasks'),
  courseBody: $('#course-body'),
  configBody: $('#config-body'),
  drill: {
    id: $('#drill-id'), title: $('#drill-h'), summary: $('#drill-summary'),
    objective: $('#drill-objective'), band: $('#drill-band'),
    guidance: $('#drill-guidance'), hints: $('#drill-hints'), flag: $('#flagcard'),
    submit: $('#drill-submit'),
    bandButtons: Array.from(document.querySelectorAll('[data-band]')),
  },
};

/* ---------------------------------------------------------------- *
 * Theme
 * ---------------------------------------------------------------- */

const savedTheme = store.theme();
if (savedTheme) document.documentElement.dataset.theme = savedTheme;

$('#btn-theme').addEventListener('click', () => {
  const current = document.documentElement.dataset.theme
    || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  store.setTheme(next);
});

/* ---------------------------------------------------------------- *
 * Loading a drill
 * ---------------------------------------------------------------- */

function loadDrill(id, band) {
  if (band) state.band = band;
  engine.loadDrill(id, state.band);
  state.cursorUs = 0;
  state.running = false;
  state.selectedFrameId = null;
  state.collapseIdle = false;      // non-sticky, every time
  state.taskStart = Date.now();
  store.setLastDrill(id);
  renderAll();
  renderInspector(refs.inspector, { frame: null });
}

function loadSandbox() {
  engine.loadSandbox('osdp-clear');
  state.cursorUs = 0;
  state.running = false;
  state.selectedFrameId = null;
  state.collapseIdle = false;
  renderAll();
  renderInspector(refs.inspector, { frame: null });
}

/* ---------------------------------------------------------------- *
 * Rendering
 * ---------------------------------------------------------------- */

function renderAll() {
  const session = engine.session;
  const duration = engine.duration();
  const drill = session.drillId ? engine.getDrill(session.drillId) : null;

  refs.session.innerHTML = '';
  refs.session.append(
    session.sandbox ? 'Free play · ' : 'Drill ',
    el('strong', {}, session.title),
    ` · scenario ${session.scenarioId}`,
  );

  renderBenchStateStrip();
  renderTopologyView();
  renderTimelineView();
  renderTrafficView();
  renderDrillView(drill);
  renderConfigView();
  renderCourseView();
  refreshCursorUI();
}

function renderBenchStateStrip() {
  renderBenchState(refs.benchstate, {
    groups: engine.configGroups(),
    onOpen: (groupId) => openConfig(groupId),
  });
}

function renderTopologyView() {
  renderTopology(refs.topology, {
    topology: engine.topology(),
    state: engine.stateAt(state.cursorUs),
    onNode: (node) => openConfig(node.configGroup),
    onLink: () => openConfig('taps'),
    onTap: () => openConfig('taps'),
  });
}

function renderTimelineView() {
  const duration = engine.duration();
  const timeline = engine.timeline({ bins: 600, collapseIdle: state.collapseIdle });
  renderLanes(refs.lanes, {
    timeline, cursorUs: state.cursorUs, durationUs: duration,
    onSeek: (t) => seek(t),
  });
  renderMarkers(refs.markers, {
    markers: timeline.markers, durationUs: duration, onSeek: (t) => seek(t),
  });
  refs.scrub.max = String(duration);
  refs.scrub.step = '1000';
  refs.collapseBtn.setAttribute('aria-pressed', String(state.collapseIdle));
  refs.collapseState.textContent = collapseStateText(state.collapseIdle ? timeline.collapsed : null);
  refs.honesty.className = 'honesty-note' + (state.collapseIdle ? '' : ' honesty-note--honest');
  refs.honesty.textContent = state.collapseIdle
    ? 'You collapsed the idle polling. The bus is still carrying every one of those frames — the picture above is now yours, not the bus\'s. This resets when you open another drill.'
    : 'Honest density: every frame the bus carried is drawn. A real OSDP link polls tens of times a second and looks like this. That density is the finding in drill 4.1.';
}

function renderTrafficView() {
  const result = engine.frames({ collapseIdle: state.collapseIdle, filter: state.filter || null });
  renderTraffic(refs.trafficRows, {
    result, cursorUs: state.cursorUs, selectedId: state.selectedFrameId,
    onSelect: selectFrame,
  });
  refs.trafficCount.textContent = state.collapseIdle && result.collapsed
    ? `${result.rows.length} shown · ${result.collapsed.hiddenFrames} hidden`
    : `${result.total} frames`;
  rowsChanged();
}

function renderDrillView(drill) {
  const flag = engine.flag();
  const complete = drill ? store.isComplete(drill.id) : false;
  if (flag.earned && drill && !complete) {
    store.markComplete(drill.id, state.band);
    renderCourseView();
    updateCourseProgress();
  }
  renderDrill(refs.drill, { drill, band: state.band, flag, complete });
  renderSubmission(refs.drill.submit, {
    // engine.submission() is a v2 call. The reference implementation in
    // engine-mock.js is v1 and does not have it, and the site is expected to
    // run on either.
    spec: drill && engine.submission ? engine.submission() : null,
    onField: (id, value) => {
      if (engine.submitField) engine.submitField(id, value);
      // A Module 5 rule set is RUN rather than compared, so the bench itself
      // changes: re-read everything rather than only the flag card.
      refreshBench();
    },
    onClear: () => { if (engine.clearSubmission) engine.clearSubmission(); refreshBench(); },
  });
  renderTasks(refs.tasks, {
    tasks: engine.taskStates(Date.now() - state.taskStart),
    onStart: (id) => { engine.startTask(id); renderDrillView(drill); },
  });
}

function renderConfigView() {
  renderConfig(refs.configBody, {
    groups: engine.configGroups(),
    topology: engine.topology(),
    openGroupId: openConfig.pendingGroup,
    onSet: (g, f, v) => {
      const res = engine.setConfig(g, f, v);
      // The engine may refuse. Surfacing the reason is the contract (§3): a
      // control that silently discarded input would be worse than no control.
      if (res && res.ok === false) notify(res.error);
      refreshBench();
    },
    onTap: (linkId, mode, tapId) => {
      const res = mode === 'remove'
        ? engine.removeTap(tapId)
        : engine.addTap({ linkId, mode });
      if (res && res.ok === false) notify(res.error);
      // Taps gate what the bus carries, so the traffic and the timeline change too.
      refreshBench();
    },
  });
}

/** Say something the engine refused, without a dialog the keyboard has to escape. */
function notify(message) {
  if (!message) return;
  const host = $('#notice');
  host.textContent = message;
  host.hidden = false;
  clearTimeout(notify.timer);
  notify.timer = setTimeout(() => { host.hidden = true; }, 9000);
}

/** Anything that changes the bench: re-read everything the engine reports. */
function refreshBench() {
  renderBenchStateStrip();
  renderTopologyView();
  renderTimelineView();
  renderTrafficView();
  renderConfigView();
  renderDrillView(engine.session.drillId ? engine.getDrill(engine.session.drillId) : null);
  refreshCursorUI();
}

function renderCourseView() {
  const completed = store.all().completed;
  renderCourse(refs.courseBody, {
    catalog: engine.catalog(),
    completed,
    currentId: engine.session.drillId,
    onPick: (id) => { closeDrawer(); loadDrill(id); },
  });
}

function updateCourseProgress() {
  const cat = engine.catalog();
  const done = store.completedCount();
  $('#course-progress').textContent = `${done}/${cat.drillCount}`;
  const sum = $('#course-summary');
  if (sum) sum.textContent = store.available ? '' : 'storage unavailable — progress will not persist';
}

/* ---------------------------------------------------------------- *
 * Cursor
 * ---------------------------------------------------------------- */

// The traffic list is in time order and the cursor moves monotonically most of
// the time, so "which rows are in the past" changes by a handful of rows per
// animation frame. Walking all of them every frame costs ~24 ms on the 3,552
// frames of a Module 5 day; walking only the ones that crossed costs nothing.
// The index is reset by rowsChanged() whenever the list is rebuilt.
let lastPastIndex = -1;
let cursorRows = [];

function rowsChanged() {
  cursorRows = Array.from(refs.trafficRows.querySelectorAll('tr[data-t]'));
  lastPastIndex = -1;
  for (const row of cursorRows) row.classList.add('row--future');
}

function refreshCursorUI() {
  const duration = engine.duration();
  refs.clock.textContent = `t = ${fmtT(state.cursorUs)} s`;
  refs.scrub.value = String(Math.round(state.cursorUs));
  refs.scrub.setAttribute('aria-valuetext', `${fmtTShort(state.cursorUs)} seconds of ${fmtTShort(duration)}`);
  positionCursor(refs.lanes, state.cursorUs, duration);

  const st = engine.stateAt(state.cursorUs);
  if (st.door !== state.lastDoor) {
    state.lastDoor = st.door;
    renderTopologyView();
  }

  // Dim frames that have not happened yet, touching only the rows the cursor
  // just crossed rather than every row in the list.
  while (lastPastIndex + 1 < cursorRows.length
         && Number(cursorRows[lastPastIndex + 1].dataset.t) <= state.cursorUs) {
    lastPastIndex += 1;
    cursorRows[lastPastIndex].classList.remove('row--future');
  }
  while (lastPastIndex >= 0
         && Number(cursorRows[lastPastIndex].dataset.t) > state.cursorUs) {
    cursorRows[lastPastIndex].classList.add('row--future');
    lastPastIndex -= 1;
  }
}

function seek(tUs) {
  state.cursorUs = Math.max(0, Math.min(engine.duration(), tUs));
  engine.observe({ type: 'cursor', tUs: state.cursorUs });
  refreshCursorUI();
  renderDrillView(engine.session.drillId ? engine.getDrill(engine.session.drillId) : null);
}

function selectFrame(id) {
  state.selectedFrameId = id;
  const frame = engine.frame(id);
  if (!frame) return;
  if (frame.tUs > state.cursorUs) seek(frame.tUs);
  for (const tr of refs.trafficRows.querySelectorAll('tr[aria-selected="true"]')) tr.setAttribute('aria-selected', 'false');
  const row = refs.trafficRows.querySelector(`tr[data-frame-id="${id}"]`);
  if (row) row.setAttribute('aria-selected', 'true');
  refs.inspectorCount.textContent = `frame ${id} · ${frame.bytes.length} bytes`;
  renderInspector(refs.inspector, {
    frame,
    onFieldOpen: (fieldId) => {
      engine.observe({ type: 'field_opened', fieldId });
      renderDrillView(engine.session.drillId ? engine.getDrill(engine.session.drillId) : null);
    },
  });
  renderDrillView(engine.session.drillId ? engine.getDrill(engine.session.drillId) : null);
}

/* ---------------------------------------------------------------- *
 * Transport
 * ---------------------------------------------------------------- */

let rafId = null;
let lastTick = 0;

function tick(now) {
  if (!state.running) return;
  const dt = lastTick ? now - lastTick : 16;
  lastTick = now;
  state.cursorUs += dt * 1000 * state.speed;
  if (state.cursorUs >= engine.duration()) {
    state.cursorUs = engine.duration();
    setRunning(false);
    seek(state.cursorUs);
    return;
  }
  refreshCursorUI();
  rafId = requestAnimationFrame(tick);
}

let flagPoll = null;

function setRunning(on) {
  state.running = on;
  $('#btn-run').textContent = on ? '⏸ Pause' : '▶ Run';
  $('#btn-run').setAttribute('aria-pressed', String(on));
  if (on) { lastTick = 0; rafId = requestAnimationFrame(tick); }
  else if (rafId) { cancelAnimationFrame(rafId); rafId = null; seek(state.cursorUs); }
}

$('#btn-run').addEventListener('click', () => setRunning(!state.running));
$('#btn-start').addEventListener('click', () => { setRunning(false); seek(0); });
$('#btn-end').addEventListener('click', () => { setRunning(false); seek(engine.duration()); });
$('#btn-stepfwd').addEventListener('click', () => { setRunning(false); seek(engine.nextEventUs(state.cursorUs)); followCursor(refs.trafficRows, state.cursorUs); });
$('#btn-stepback').addEventListener('click', () => { setRunning(false); seek(engine.prevEventUs(state.cursorUs)); followCursor(refs.trafficRows, state.cursorUs); });
$('#speed').addEventListener('change', (e) => { state.speed = Number(e.target.value); });
refs.scrub.addEventListener('input', (e) => { setRunning(false); seek(Number(e.target.value)); });

refs.collapseBtn.addEventListener('click', () => {
  state.collapseIdle = !state.collapseIdle;
  renderTimelineView();
  renderTrafficView();
  refreshCursorUI();
});

$('#traffic-filter').addEventListener('input', (e) => {
  state.filter = e.target.value.trim();
  renderTrafficView();
  refreshCursorUI();
});

for (const b of refs.drill.bandButtons) {
  b.addEventListener('click', () => {
    state.band = b.dataset.band;
    store.setBand(state.band);
    const id = engine.session.drillId;
    if (id) loadDrill(id, state.band);
    else renderDrillView(null);
  });
}

/* ---------------------------------------------------------------- *
 * Keyboard
 * ---------------------------------------------------------------- */

document.addEventListener('keydown', (e) => {
  const active = document.activeElement;
  const tag = active && active.tagName;
  if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') return;
  if (document.querySelector('.drawer.is-open')) return;
  // Space and Enter belong to whatever is focused. Stealing them would make a
  // focused button do two things at once.
  const activatable = tag === 'BUTTON' || tag === 'A' || tag === 'SUMMARY'
    || (active && active.getAttribute && active.getAttribute('role') === 'button');
  if (activatable && (e.key === ' ' || e.key === 'Enter')) return;
  switch (e.key) {
    case ' ': e.preventDefault(); setRunning(!state.running); break;
    case 'ArrowRight': if (!e.shiftKey) { e.preventDefault(); setRunning(false); seek(engine.nextEventUs(state.cursorUs)); followCursor(refs.trafficRows, state.cursorUs); } break;
    case 'ArrowLeft': if (!e.shiftKey) { e.preventDefault(); setRunning(false); seek(engine.prevEventUs(state.cursorUs)); followCursor(refs.trafficRows, state.cursorUs); } break;
    case 'Home': e.preventDefault(); setRunning(false); seek(0); break;
    case 'End': e.preventDefault(); setRunning(false); seek(engine.duration()); break;
    case 'c': case 'C': refs.collapseBtn.click(); break;
    default: break;
  }
});

/* ---------------------------------------------------------------- *
 * Drawers
 * ---------------------------------------------------------------- */

let releaseTrap = null;
let lastFocus = null;

function openDrawer(drawer) {
  closeDrawer();
  lastFocus = document.activeElement;
  drawer.hidden = false;
  drawer.classList.add('is-open');
  const first = drawer.querySelector('button, input, select, [tabindex]');
  if (first) first.focus();
  releaseTrap = trapFocus(drawer, closeDrawer);
}

function closeDrawer() {
  for (const d of document.querySelectorAll('.drawer.is-open')) {
    d.classList.remove('is-open');
    d.hidden = true;
  }
  if (releaseTrap) { releaseTrap(); releaseTrap = null; }
  if (lastFocus && lastFocus.focus) { lastFocus.focus(); lastFocus = null; }
}

function openConfig(groupId) {
  openConfig.pendingGroup = groupId === 'taps' ? null : groupId;
  renderConfigView();
  openDrawer($('#config-drawer'));
  const target = groupId === 'taps' ? $('#cfg-taps') : $(`#cfg-${groupId}`);
  if (target) { target.open = true; target.scrollIntoView({ block: 'nearest' }); }
}
openConfig.pendingGroup = null;

$('#btn-course').addEventListener('click', () => { renderCourseView(); openDrawer($('#course-drawer')); });
$('#btn-config').addEventListener('click', () => openConfig('security'));
$('#btn-sandbox').addEventListener('click', () => { closeDrawer(); loadSandbox(); });
for (const b of document.querySelectorAll('[data-close-drawer], .drawer__scrim')) {
  b.addEventListener('click', closeDrawer);
}

/* ---------------------------------------------------------------- *
 * Long-running tasks tick slowly and forever, which is the point.
 * ---------------------------------------------------------------- */

setInterval(() => {
  if (!engine.tasks.length) return;
  renderTasks(refs.tasks, {
    tasks: engine.taskStates(Date.now() - state.taskStart),
    onStart: (id) => { engine.startTask(id); renderDrillView(engine.session.drillId ? engine.getDrill(engine.session.drillId) : null); },
  });
}, 1000);

/* ---------------------------------------------------------------- *
 * Boot
 * ---------------------------------------------------------------- */

loadDrill(store.lastDrill() || '1.1', state.band);
updateCourseProgress();

if (!store.available) {
  refs.session.append(el('span', { style: 'color:var(--warn)' }, ' · storage blocked, progress will not persist'));
}

// Handy while developing; harmless in production and touches no network.
window.ODR = { engine, state, loadDrill };
