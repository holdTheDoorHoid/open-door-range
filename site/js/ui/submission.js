/*
 * submission.js — the typed claim a drill takes.
 *
 * DESIGN.md §3: drills do not check typed answers, and a flag is earned when
 * the engine's own state satisfies a predicate. Seven drills legitimately ask
 * the learner to *say* something anyway — a facility code, a set of byte
 * offsets, sixteen bytes of cryptogram, a list of times — and those are claims
 * checked against values the engine generated from its seed. A different seed
 * gives a different correct answer, and there is nothing to look up.
 *
 * The engine composes this form. Drill 2.1's field list comes from the layout
 * of the frame that actually crossed the bus, so nothing here knows what an
 * OSDP frame contains; it knows how to draw a label and an input.
 *
 * Nothing is submitted anywhere. Every keystroke goes to the engine in this
 * tab and the flag is re-evaluated in place.
 */

import { el, clear } from '../util.js';

export function renderSubmission(host, { spec, onField, onClear }) {
  clear(host);
  if (!spec) return;

  const box = el('section', { class: 'submitbox', 'aria-labelledby': 'submit-h' });
  box.append(el('h3', { id: 'submit-h' }, 'What this drill asks you for'));
  box.append(el('p', { class: 'submitbox__prompt' }, spec.prompt));

  if (!spec.fields.length) {
    box.append(el('p', { class: 'help' }, 'Nothing to fill in yet — run the bench first.'));
    host.append(box);
    return;
  }

  const grid = el('div', { class: 'submitgrid' });
  for (const f of spec.fields) {
    const id = `sub-${f.id}`;
    let control;
    if (f.type === 'boolean') {
      control = el('input', {
        type: 'checkbox', id, checked: f.value === 'true' ? true : null,
        onchange: (e) => onField(f.id, e.target.checked ? 'true' : 'false'),
      });
    } else if (f.type === 'select') {
      control = el('select', { id, onchange: (e) => onField(f.id, e.target.value) },
        ...(f.options || []).map(([v, label]) =>
          el('option', { value: v, selected: String(f.value) === String(v) ? true : null }, label)));
    } else {
      control = el('input', {
        type: f.type === 'number' ? 'number' : 'text',
        id,
        value: f.value || '',
        // Committed on change rather than on every keystroke: the flag card
        // re-renders underneath and stealing focus mid-word would be rude.
        onchange: (e) => onField(f.id, e.target.value),
      });
    }
    grid.append(el('div', { class: 'submitfield' },
      el('label', { for: id }, f.label),
      control,
      f.help ? el('p', { class: 'help' }, f.help) : null));
  }
  box.append(grid);
  box.append(el('button', { class: 'btn btn--ghost', onclick: () => onClear() }, 'Clear what I entered'));
  box.append(el('p', { class: 'help' },
    'Checked against what this session’s engine actually produced, not against a stored answer. '
    + 'The verdict and the reasons below come from the engine.'));
  host.append(box);
}
