/*
 * drill.js — objective, hint on request, flag state.
 *
 * Bronze pre-places the taps and names the control to touch. Silver gives the
 * objective and hints if asked. Gold gives the objective and nothing else.
 * None of them change the bench.
 */

import { el, clear, fmtBig } from '../util.js';

export function renderDrill(refs, { drill, band, flag, complete }) {
  refs.id.textContent = drill ? drill.id : '';
  refs.title.textContent = drill ? drill.title : 'Free play';
  refs.summary.textContent = drill ? drill.summary : 'No drill loaded. The bench is yours — the same instrument the course drives.';
  refs.objective.textContent = drill ? drill.objective : 'Poke at it.';
  refs.band.textContent = drill ? `designed for ${drill.band}` : '—';
  refs.band.className = 'band band--' + (drill ? drill.band : 'silver');
  refs.band.title = 'The band this drill was written for. The selector beside it changes the guidance you get; it never changes the bench.';

  for (const b of refs.bandButtons) {
    b.setAttribute('aria-pressed', String(b.dataset.band === band));
  }

  // ---- guidance ------------------------------------------------------
  clear(refs.guidance);
  if (drill && band === 'bronze' && drill.guidance.bronze.length) {
    refs.guidance.append(el('p', { style: 'font-size:var(--fs-xs);text-transform:uppercase;letter-spacing:.08em;color:var(--text-faint);margin:0 0 .2rem' }, 'Bronze — step by step'));
    refs.guidance.append(el('ol', { class: 'steps' }, ...drill.guidance.bronze.map((s) => el('li', {}, s))));
  } else if (drill && band === 'gold') {
    refs.guidance.append(el('p', { style: 'color:var(--text-muted);font-size:var(--fs-sm)' },
      'Gold: the objective above, and nothing else. No steps, no hints.'));
  } else if (drill) {
    refs.guidance.append(el('p', { style: 'color:var(--text-muted);font-size:var(--fs-sm)' },
      'Silver: the objective above. Hints are available if you ask for them.'));
  }
  if (drill && drill.note) {
    refs.guidance.append(el('p', { class: 'hint' }, drill.note));
  }

  // ---- hints ---------------------------------------------------------
  clear(refs.hints);
  if (drill && band !== 'gold' && drill.hints.length) {
    const shown = [];
    const btn = el('button', { class: 'btn' }, `Show a hint (${drill.hints.length} available)`);
    const box = el('div');
    btn.addEventListener('click', () => {
      const next = drill.hints[shown.length];
      if (next === undefined) return;
      shown.push(next);
      box.append(el('p', { class: 'hint' }, next));
      btn.textContent = shown.length >= drill.hints.length
        ? 'No more hints' : `Show another hint (${drill.hints.length - shown.length} left)`;
      btn.disabled = shown.length >= drill.hints.length;
    });
    refs.hints.append(btn, box);
  } else if (drill && band === 'gold') {
    refs.hints.append(el('p', { style: 'font-size:var(--fs-sm);color:var(--text-faint)' }, 'Hints are withheld at Gold.'));
  }

  // ---- flag ----------------------------------------------------------
  clear(refs.flag);
  const earned = flag.earned || complete;
  refs.flag.className = 'flagcard' + (earned ? ' flagcard--earned' : '');
  refs.flag.append(el('div', { class: 'flagcard__state' },
    el('span', { class: 'flagcard__glyph', 'aria-hidden': 'true' }, earned ? '⚑' : '○'),
    el('span', {}, earned ? 'FLAG EARNED' : (flag.simulated === false ? 'REFERENCE — no flag' : 'Flag not yet earned'))));
  refs.flag.append(el('p', { class: 'flagcard__pred' },
    el('strong', {}, 'Predicate: '), flag.predicate || '—'));
  if (flag.evidence && flag.evidence.length) {
    refs.flag.append(el('p', { style: 'font-size:var(--fs-xs);margin:.2rem 0 0;color:var(--text-muted)' }, 'Engine evidence:'));
    refs.flag.append(el('ul', {}, ...flag.evidence.map((e) => el('li', {}, e))));
  }
  if (!earned && flag.outstanding && flag.outstanding.length) {
    refs.flag.append(el('p', { style: 'font-size:var(--fs-xs);margin:.4rem 0 0;color:var(--text-muted)' }, 'Outstanding:'));
    refs.flag.append(el('ul', {}, ...flag.outstanding.map((e) => el('li', {}, e))));
  }
  if (complete && !flag.earned) {
    refs.flag.append(el('p', { style: 'font-size:var(--fs-xs);color:var(--text-muted);margin:.4rem 0 0' },
      'Recorded complete in this browser on an earlier run.'));
  }
}

/**
 * The calendar date the bar would finish on.
 *
 * The engine produces a DURATION and stops there, deliberately: it has no wall
 * clock and no epoch, and inventing one to print "27 March 2035" would be the
 * engine claiming to know something it does not. docs/UI.md decided the date is
 * rendered in full, so the site — which does have a clock — adds it. This is
 * the only wall-clock arithmetic on this side of the boundary and nothing a
 * flag depends on reads it.
 */
function projectedDate(remainingSeconds, projected) {
  // engine-mock.js, the v1 reference implementation, already puts a date in
  // `projected`. Do not print two.
  if (typeof projected === 'string' && projected.includes(' — ')) return '';
  if (!Number.isFinite(remainingSeconds) || remainingSeconds <= 0) return '';
  const years = remainingSeconds / (365.2425 * 24 * 3600);
  if (years >= 8000) {
    return ` — the year ${Math.round(new Date().getFullYear() + years).toLocaleString('en-GB')} CE`;
  }
  const when = new Date(Date.now() + remainingSeconds * 1000)
    .toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
  return ` — finishing ${when}`;
}

export function renderTasks(host, { tasks, onStart }) {
  clear(host);
  for (const t of tasks) {
    const box = el('div', { class: 'task' });
    box.append(el('div', { class: 'task__label' }, t.label));
    const fill = el('div', { class: 'task__fill', style: `width:${Math.min(100, t.fraction * 100).toFixed(8)}%` });
    box.append(el('div', {
      class: 'task__bar', role: 'progressbar',
      'aria-valuemin': '0', 'aria-valuemax': '100',
      'aria-valuenow': (t.fraction * 100).toFixed(6),
      'aria-label': t.label,
    }, fill));
    box.append(el('p', { class: 'task__meta' },
      `${fmtBig(t.done)} / ${fmtBig(t.total)} — ${(t.fraction * 100).toPrecision(3)}% — `,
      el('strong', {}, t.projected),
      projectedDate(t.remainingSeconds, t.projected)));
    box.append(el('p', { class: 'task__note' }, t.note));
    if (!t.shortDone) {
      box.append(el('button', { class: 'btn', onclick: () => onStart(t.id) }, `Run the ${t.shortLabel}`));
    } else {
      box.append(el('p', { class: 'task__note' },
        el('strong', {}, '✔ The shortened run finished. '),
        'The bar above is the real one. It is still going, and it will still be going when you close the tab.'));
    }
    host.append(box);
  }
}
