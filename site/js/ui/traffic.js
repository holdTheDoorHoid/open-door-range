/*
 * traffic.js — the timestamped frame list. Wireshark's arrangement, because a
 * practitioner already knows it.
 */

import { el, clear, fmtTShort, DIR_LABEL, LINE_LABEL } from '../util.js';

export function renderTraffic(tbody, { result, cursorUs, selectedId, filter, onSelect }) {
  clear(tbody);
  const rows = result.rows;
  for (const r of rows) {
    if (r.collapsed) {
      const tr = el('tr', { class: 'row--collapsed', tabindex: '-1' },
        el('td', { class: 't', role: 'gridcell' }, fmtTShort(r.tUs)),
        el('td', { role: 'gridcell' }, 'BUS'),
        el('td', { role: 'gridcell' }, '—'),
        el('td', { role: 'gridcell' }, '⋯'),
        el('td', { class: 'sum', role: 'gridcell' }, r.summary));
      tbody.append(tr);
      continue;
    }
    const future = r.tUs > cursorUs;
    const tr = el('tr', {
      class: [r.origin === 'attacker' ? 'row--attacker' : '', future ? 'row--future' : ''].filter(Boolean).join(' '),
      tabindex: '0',
      role: 'row',
      'aria-selected': r.id === selectedId ? 'true' : 'false',
      dataset: { frameId: r.id, t: String(r.tUs) },
      onclick: () => onSelect(r.id),
      onkeydown: (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(r.id); }
        else if (e.key === 'ArrowDown') { e.preventDefault(); moveFocus(tr, 1); }
        else if (e.key === 'ArrowUp') { e.preventDefault(); moveFocus(tr, -1); }
      },
    },
      el('td', { class: 't', role: 'gridcell' }, fmtTShort(r.tUs)),
      el('td', { role: 'gridcell' }, LINE_LABEL[r.line] || r.line),
      el('td', { class: 'dir', role: 'gridcell' }, DIR_LABEL[r.dir] || r.dir),
      el('td', { class: 'lbl', role: 'gridcell' }, r.label,
        r.secure && r.secure.active ? el('span', { class: 'badge-sec', title: r.secure.scs }, ' ', r.secure.encrypted ? '◆' : '◇', r.secure.scs.replace('SCS_', '')) : null),
      el('td', { class: 'sum', role: 'gridcell' }, r.summary));
    tbody.append(tr);
  }
  if (!rows.length) {
    // Three different empty states, and telling them apart matters: a filter
    // that hid everything is the learner's own doing; a drill with no bus
    // traffic at all (the Module 0 card attacks happen off the wire) is not a
    // fault and there is nothing to "run" into existence.
    let msg;
    if (filter) {
      msg = 'Nothing matches the filter. Clear it to see every frame.';
    } else if (result.total === 0) {
      msg = 'No bus traffic in this drill — the attack happens off the wire, not on it. The result is in the flag panel below.';
    } else {
      msg = 'Nothing here yet. Run the bench to generate traffic.';
    }
    tbody.append(el('tr', { role: 'row' }, el('td', { role: 'gridcell', colspan: '5', style: 'padding:1rem;color:var(--text-muted)' }, msg)));
  }
}

function moveFocus(tr, delta) {
  const rows = Array.from(tr.parentElement.querySelectorAll('tr[tabindex="0"]'));
  const i = rows.indexOf(tr);
  const next = rows[i + delta];
  if (next) { next.focus(); next.click(); }
}

export function scrollToFrame(tbody, frameId) {
  const row = tbody.querySelector(`tr[data-frame-id="${frameId}"]`);
  if (row) row.scrollIntoView({ block: 'nearest' });
}

/** Follow the cursor: keep the newest frame at or before the cursor in view. */
export function followCursor(tbody, cursorUs) {
  const rows = Array.from(tbody.querySelectorAll('tr[data-t]'));
  let last = null;
  for (const r of rows) { if (Number(r.dataset.t) <= cursorUs) last = r; else break; }
  if (last) last.scrollIntoView({ block: 'nearest' });
}
