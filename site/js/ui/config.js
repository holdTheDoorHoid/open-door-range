/*
 * config.js — collapse, never remove.
 *
 * A folded group still states the thing that matters on its summary line. The
 * same summary lines are mirrored into the always-visible bench strip at the
 * top of the page, so a learner wondering why their replay failed can see that
 * Secure Channel is on without opening anything at all.
 */

import { el, clear } from '../util.js';

const TAP_MODES = [
  ['none', 'No tap', 'The link runs untouched.'],
  ['sniff', 'Sniff', 'Listen only. The link is not cut and nothing is written to it.'],
  ['inject', 'Inject', 'Listen, and write frames of your own onto the link.'],
  ['inline', 'Inline (implant)', 'The link is CUT and everything passes through the tap. This is the one that can rewrite a frame in flight.'],
];

export function renderConfig(host, { groups, topology, openGroupId, onSet, onTap }) {
  clear(host);

  // ---- taps -----------------------------------------------------------
  const tapBox = el('details', { class: 'cfggroup', open: true, id: 'cfg-taps' });
  const tapSummaryLine = topology.taps.length
    ? topology.taps.map((t) => `${t.mode} on ${t.linkId.replace('-', ' → ')}`).join(' · ')
    : 'none placed';
  tapBox.append(el('summary', {},
    el('span', { class: 'twisty', 'aria-hidden': 'true' }),
    el('span', {},
      el('span', { class: 'cfgsummary__title' }, 'Taps'), ' ',
      el('span', { class: 'cfgsummary__line' }, tapSummaryLine))));
  const tapFields = el('div', { class: 'cfgfields' });
  for (const link of topology.links.filter((l) => l.tappable)) {
    const current = topology.taps.find((t) => t.linkId === link.id);
    const fs = el('fieldset', { style: 'border:1px solid var(--border);border-radius:var(--radius);margin:0 0 var(--sp-3);padding:var(--sp-2)' });
    fs.append(el('legend', { style: 'font-size:var(--fs-sm);font-weight:600' }, link.id.replace('-', ' → ')));
    for (const [mode, label, help] of TAP_MODES) {
      const id = `tap-${link.id}-${mode}`;
      const checked = (current ? current.mode : 'none') === mode;
      const row = el('div', { style: 'margin-bottom:var(--sp-1)' },
        el('input', {
          type: 'radio', name: `tap-${link.id}`, id, value: mode, checked: checked || null,
          onchange: () => onTap(link.id, mode),
        }),
        ' ', el('label', { for: id, style: 'font-size:var(--fs-sm);font-weight:600' }, label),
        el('p', { class: 'help', style: 'margin:0 0 0 1.6em' }, help));
      fs.append(row);
    }
    tapFields.append(fs);
  }
  tapBox.append(tapFields);
  host.append(tapBox);

  // ---- everything else ------------------------------------------------
  for (const g of groups) {
    const box = el('details', {
      class: 'cfggroup' + (g.alert ? ' cfggroup--alert' : ''),
      id: `cfg-${g.id}`,
      open: g.id === openGroupId ? true : null,
    });
    box.append(el('summary', {},
      el('span', { class: 'twisty', 'aria-hidden': 'true' }),
      el('span', {},
        el('span', { class: 'cfgsummary__title' }, g.title), ' ',
        el('span', { class: 'cfgsummary__line' }, g.summary))));

    const fields = el('div', { class: 'cfgfields' });
    for (const f of g.fields) {
      const id = `f-${g.id}-${f.id}`;
      let control;
      if (f.type === 'boolean') {
        control = el('input', {
          type: 'checkbox', id, checked: f.value ? true : null,
          onchange: (e) => onSet(g.id, f.id, e.target.checked),
        });
      } else if (f.type === 'select') {
        control = el('select', { id, onchange: (e) => onSet(g.id, f.id, e.target.value) },
          ...f.options.map(([v, label]) => el('option', { value: v, selected: String(f.value) === String(v) ? true : null }, label)));
      } else {
        control = el('input', {
          type: 'number', id, value: f.value, min: f.min, max: f.max,
          onchange: (e) => onSet(g.id, f.id, e.target.value),
        });
      }
      fields.append(el('div', { class: 'cfgfield' }, el('label', { for: id }, f.label), control));
      if (f.help) fields.append(el('p', { class: 'help' }, f.help));
    }
    box.append(fields);
    host.append(box);
  }
}

export function renderBenchState(host, { groups, onOpen }) {
  clear(host);
  host.append(el('span', { class: 'benchstate__label' }, 'Bench'));
  for (const g of groups) {
    host.append(el('button', {
      class: 'chip' + (g.alert ? ' chip--alert' : (g.id === 'security' ? ' chip--on' : '')),
      onclick: () => onOpen(g.id),
      title: `Open the ${g.title} panel`,
    },
      el('span', { class: 'chip__k' }, g.title + ':'),
      el('span', { class: 'chip__v' }, g.summary)));
  }
}
