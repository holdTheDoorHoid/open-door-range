/*
 * course.js — the six modules and every drill in them, with completion read
 * back from localStorage. Progress lives in this browser and goes nowhere.
 */

import { el, clear } from '../util.js';

export function renderCourse(host, { catalog, completed, currentId, onPick }) {
  clear(host);
  const total = catalog.modules.reduce((a, m) => a + m.drills.length, 0);
  const done = catalog.modules.reduce((a, m) => a + m.drills.filter((d) => completed[d.id]).length, 0);

  host.append(el('p', { style: 'font-size:var(--fs-sm);color:var(--text-muted);margin-top:0' },
    `${done} of ${total} drills complete. Progress is stored in this browser only — no account, nothing sent anywhere. Clearing site data clears it.`));

  for (const m of catalog.modules) {
    const mDone = m.drills.filter((d) => completed[d.id]).length;
    const box = el('section', { class: 'module' });
    box.append(el('div', { class: 'module__hd' },
      el('h3', {}, `Module ${m.number} — ${m.title}`),
      el('span', { class: 'module__count' }, `${mDone}/${m.drills.length}`)));
    box.append(el('p', { class: 'module__blurb' }, m.blurb));
    const list = el('ul', { class: 'drilllist' });
    for (const d of m.drills) {
      const isDone = !!completed[d.id];
      list.append(el('li', {}, el('button', {
        class: 'drillbtn',
        'aria-current': d.id === currentId ? 'true' : null,
        onclick: () => onPick(d.id),
      },
        el('span', { class: 'drillbtn__done', 'aria-hidden': 'true' }, isDone ? '✔' : '○'),
        el('span', { class: 'drillbtn__id' }, d.id),
        el('span', { class: 'drillbtn__title' }, d.title,
          isDone ? el('span', { class: 'visually-hidden' }, ' (complete)') : null,
          !d.simulated ? el('span', { style: 'color:var(--text-faint);font-weight:400' }, ' — reference, not simulated') : null),
        el('span', { class: `band band--${d.band}` }, d.band))));
    }
    box.append(list);
    host.append(box);
  }

  host.append(el('p', { style: 'font-size:var(--fs-xs);color:var(--text-faint)' },
    'Difficulty changes the guidance in the drill panel. The bench is identical in all three bands.'));
}
