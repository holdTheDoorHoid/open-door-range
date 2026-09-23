/*
 * timeline.js — one time axis for RF, wire, bus and door state.
 *
 * DECIDED (docs/UI.md): honest by default. The bus lane draws every frame the
 * link actually carried, so a learner's first sight of OSDP is the solid bar a
 * real bus produces. "Collapse idle polling" is offered prominently, it is not
 * sticky between drills, and while it is on the interface keeps saying so.
 */

import { el, svg, clear, fmtTShort } from '../util.js';

export function renderLanes(host, { timeline, cursorUs, durationUs, onSeek }) {
  clear(host);
  for (const lane of timeline.lanes) {
    host.append(el('span', { class: 'lane__label', id: `lane-label-${lane.id}` }, lane.label));
    const track = el('div', { class: `lane__track lane--${lane.id}` });
    track.append(lane.type === 'density' ? densitySvg(lane, timeline) : stateSvg(lane, timeline));
    track.append(el('div', { class: 'cursorline', dataset: { cursor: '1' } }));
    track.addEventListener('click', (e) => {
      const r = track.getBoundingClientRect();
      onSeek(Math.max(0, Math.min(durationUs, ((e.clientX - r.left) / r.width) * durationUs)));
    });
    host.append(track);
  }
  positionCursor(host, cursorUs, durationUs);
}

function densitySvg(lane, timeline) {
  const n = lane.bins.length;
  const max = Math.max(1, ...lane.bins);
  const s = svg('svg', { viewBox: `0 0 ${n} 22`, preserveAspectRatio: 'none', 'aria-hidden': 'true' });
  const total = lane.bins.reduce((a, b) => a + b, 0);
  for (let i = 0; i < n; i++) {
    const v = lane.bins[i];
    if (!v) continue;
    const h = Math.max(3, Math.round((v / max) * 22));
    s.append(svg('rect', { class: 'lane__bar', x: i, y: 22 - h, width: 1, height: h }));
  }
  s.setAttribute('aria-label', `${lane.label} lane, ${total} frames`);
  return s;
}

function stateSvg(lane, timeline) {
  const span = Math.max(1, timeline.toUs - timeline.fromUs);
  const s = svg('svg', { viewBox: '0 0 1000 22', preserveAspectRatio: 'none', 'aria-hidden': 'true' });
  for (const seg of lane.segments) {
    const x = ((seg.fromUs - timeline.fromUs) / span) * 1000;
    const w = Math.max(1, ((seg.toUs - seg.fromUs) / span) * 1000);
    s.append(svg('rect', {
      class: seg.state === 'open' ? 'seg-open' : 'seg-closed',
      x, y: 3, width: w, height: 16, 'stroke-width': 1,
    }));
  }
  return s;
}

export function positionCursor(host, cursorUs, durationUs) {
  const pct = Math.max(0, Math.min(100, (cursorUs / durationUs) * 100));
  for (const line of host.querySelectorAll('[data-cursor]')) line.style.left = `${pct}%`;
}

export function renderMarkers(host, { markers, durationUs, onSeek }) {
  clear(host);
  // Space them out: markers within 3% of each other would stack illegibly on a
  // projector, so only the first of a cluster keeps its text.
  let lastPct = -99;
  for (const m of markers) {
    const pct = (m.tUs / durationUs) * 100;
    const crowded = pct - lastPct < 6;
    if (!crowded) lastPct = pct;
    const glyph = { grant: '✔', deny: '✘', attack: '⚑', card: '◉', handshake: '⇄' }[m.kind] || '•';
    const b = el('button', {
      class: `marker marker--${m.kind}`,
      style: `left:${pct}%`,
      title: `t=${fmtTShort(m.tUs)} s — ${m.label}`,
      'aria-label': `Jump to ${m.label} at ${fmtTShort(m.tUs)} seconds`,
      onclick: () => onSeek(m.tUs),
    }, el('span', { class: 'marker__glyph' }, glyph), crowded ? '' : ' ' + m.label);
    host.append(b);
  }
}

export function collapseStateText(collapsed) {
  if (!collapsed) return 'off — showing every frame';
  return `ON — ${collapsed.hiddenFrames} idle POLL/ACK frames hidden in ${collapsed.spans.length} spans`;
}
