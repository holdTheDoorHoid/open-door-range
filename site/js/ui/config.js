/*
 * config.js — collapse, never remove.
 *
 * A folded group still states the thing that matters on its summary line. The
 * same summary lines are mirrored into the always-visible bench strip at the
 * top of the page, so a learner wondering why their replay failed can see that
 * Secure Channel is on without opening anything at all.
 *
 * MORE THAN ONE TAP MAY SIT ON A LINK. Drill 4.3 needs an inline implant and a
 * separate passive analyser on the same pair — which is what a real operator
 * carries and what odr-bus allows — so the taps for a link are a list you add
 * to and remove from, not a single choice. Two taps in the same mode are
 * refused by the engine, because two identical probes are not a second
 * capability.
 *
 * FIELDS THE ENGINE MARKS `fixed` ARE RENDERED DISABLED, with the engine's own
 * sentence underneath. A bench is assembled from a scenario and a seed, and a
 * control that pretended to change one after the fact would be the interface
 * lying about what it does — which is the thing docs/UI.md's "collapse, never
 * remove" rule exists to prevent.
 */

import { el, clear } from '../util.js';

const TAP_MODES = [
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
    const fitted = topology.taps.filter((t) => t.linkId === link.id);
    const fs = el('fieldset', { style: 'border:1px solid var(--border);border-radius:var(--radius);margin:0 0 var(--sp-3);padding:var(--sp-2)' });
    fs.append(el('legend', { style: 'font-size:var(--fs-sm);font-weight:600' }, link.id.replace('-', ' → ')));

    if (fitted.length) {
      const list = el('ul', { style: 'list-style:none;margin:0 0 var(--sp-2);padding:0' });
      for (const tap of fitted) {
        const help = (TAP_MODES.find(([m]) => m === tap.mode) || [])[2] || '';
        list.append(el('li', { style: 'display:flex;gap:var(--sp-2);align-items:baseline;margin-bottom:var(--sp-1)' },
          el('strong', { style: 'font-size:var(--fs-sm)' }, tap.mode.toUpperCase()),
          tap.prePlaced ? el('span', { class: 'chip__k' }, 'placed by Bronze') : null,
          el('span', { class: 'help', style: 'flex:1;margin:0' }, help),
          el('button', { class: 'btn btn--ghost', onclick: () => onTap(link.id, 'remove', tap.id) }, 'Remove')));
      }
      fs.append(list);
    } else {
      fs.append(el('p', { class: 'help', style: 'margin:0 0 var(--sp-2)' }, 'Nothing clipped on. The link runs untouched.'));
    }

    const add = el('div', { class: 'seg', role: 'group', 'aria-label': `Add a tap to ${link.id}` });
    for (const [mode, label, help] of TAP_MODES) {
      const already = fitted.some((t) => t.mode === mode);
      add.append(el('button', {
        class: 'btn',
        disabled: already || null,
        title: already ? `There is already a ${mode} tap on this link.` : help,
        onclick: () => onTap(link.id, mode),
      }, `+ ${label}`));
    }
    fs.append(add);
    fs.append(el('p', { class: 'help', style: 'margin-top:var(--sp-1)' },
      'More than one tap can sit on a pair. Drill 4.3 needs two: an implant in the path and a separate analyser listening to it.'));
    tapFields.append(fs);
  }
  tapBox.append(tapFields);
  host.append(tapBox);

  // ---- everything else ------------------------------------------------
  // The engine reports most of these and will not be asked to change them.
  // Said once, here, rather than repeated under every control.
  const fixed = groups.flatMap((g) => g.fields).find((f) => f.fixed);
  if (fixed) {
    host.append(el('p', { class: 'help help--fixed', style: 'margin:0 0 var(--sp-3);max-width:60ch' },
      fixed.fixedReason));
  }

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
      if (f.fixed) {
        // The engine reports this value and cannot be asked to change it.
        // Showing it as text rather than as a dead control is the honest
        // rendering: it is still visible, it is just not yours to set.
        control = el('output', { id, class: 'cfgvalue' },
          f.type === 'boolean' ? (f.value ? 'yes' : 'no') : String(f.value));
      } else if (f.type === 'boolean') {
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
      fields.append(el('div', { class: 'cfgfield' },
        el('label', { for: id }, f.label, f.critical ? el('span', { class: 'chip--alert', style: 'margin-left:.4em' }, '▲') : null),
        control));
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
