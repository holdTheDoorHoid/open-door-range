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
 * THE CONTROLS ARE LIVE AGAIN (contract v3). The engine composes the option
 * list — which options this bench accepts, their legal values and what each one
 * does — and this file renders it. It carries no list of its own: a control
 * here that the engine had not offered would be a second, divergent statement
 * of what a bench is.
 *
 * TWO KINDS OF "NO", AND THEY LOOK DIFFERENT.
 *
 *   `fixed`   — the bench genuinely cannot express this, or it is a value read
 *               off the run rather than a setting. Rendered as TEXT, with the
 *               engine's own sentence under it. A disabled input that looked
 *               settable would be the interface telling a small lie.
 *
 *   `warning` — the setting is real and it would break the drill that is
 *               loaded. Rendered as a LIVE control with the warning beside it,
 *               because docs/UI.md records the owner's feedback as prefer
 *               warning over blocking. Watching a drill stop working when you
 *               turn its defence on is the exercise, not an accident.
 */

import { el, clear } from '../util.js';

const TAP_MODES = [
  ['sniff', 'Sniff', 'Listen only. The link is not cut and nothing is written to it.'],
  ['inject', 'Inject', 'Listen, and write frames of your own onto the link.'],
  ['inline', 'Inline (implant)', 'The link is CUT and everything passes through the tap. This is the one that can rewrite a frame in flight.'],
];

export function renderConfig(host, { groups, topology, openGroupId, onSet, onReset, onTap }) {
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

  // ---- the bench itself -----------------------------------------------
  const changed = groups.reduce((n, g) => n + g.fields.filter((f) => f.changed).length, 0);
  if (changed && onReset) {
    // One move back to the bench the scenario defines, which is the bench the
    // drill's guidance was written against.
    host.append(el('div', { class: 'notice', style: 'margin:0 0 var(--sp-3)', role: 'status' },
      el('span', {}, `You have changed ${changed} setting${changed === 1 ? '' : 's'} on this bench. `),
      el('button', { class: 'btn btn--ghost', onclick: () => onReset() }, 'Reset to the bench’s own settings')));
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
    for (const f of g.fields) fields.append(...renderField(g, f, onSet));
    box.append(fields);
    host.append(box);
  }
}

/** One field: its label, its control, its help, and anything it costs. */
function renderField(g, f, onSet) {
  const id = `f-${g.id}-${f.id}`;
  const out = [];
  let control;

  if (f.fixed) {
    // The engine reports this value and cannot be asked to change it. Showing
    // it as text rather than as a dead control is the honest rendering: it is
    // still visible, it is just not yours to set.
    control = el('output', { id, class: 'cfgvalue' }, displayValue(f));
  } else if (f.type === 'boolean') {
    control = el('input', {
      type: 'checkbox', id, checked: f.value ? true : null,
      'aria-describedby': f.warning ? `${id}-warn` : null,
      onchange: (e) => onSet(g.id, f.id, e.target.checked),
    });
  } else if (f.type === 'select') {
    control = el('select', {
      id,
      'aria-describedby': f.warning ? `${id}-warn` : null,
      onchange: (e) => onSet(g.id, f.id, e.target.value),
    }, ...(f.options || []).map(([v, label]) =>
      el('option', { value: v, selected: String(f.value) === String(v) ? true : null }, label)));
  } else {
    control = el('input', {
      type: 'number', id, value: f.value, min: f.min, max: f.max,
      'aria-describedby': f.warning ? `${id}-warn` : null,
      onchange: (e) => onSet(g.id, f.id, e.target.value),
    });
  }

  const label = el('label', { for: id }, f.label);
  // Never colour alone (docs/UI.md, accessibility): the shape and the word
  // carry it too.
  if (f.critical) label.append(el('span', { class: 'chip--alert', style: 'margin-left:.4em' }, '▲'));
  if (f.changed) label.append(el('span', { class: 'chip__k', style: 'margin-left:.4em' }, 'changed'));

  const row = el('div', { class: 'cfgfield' }, label, control);
  if (f.unit && !f.fixed && f.type === 'number') {
    row.append(el('span', { class: 'help', style: 'margin:0;grid-column:2' }, f.unit));
  }
  out.push(row);

  if (f.help) out.push(el('p', { class: 'help' }, f.help));
  if (f.warning) {
    // Said plainly, next to the control, with the control still live.
    out.push(el('p', {
      id: `${id}-warn`, class: 'notice', role: 'status',
      style: 'margin:0 0 var(--sp-2);font-size:var(--fs-xs)',
    }, el('strong', {}, '▲ '), f.warning));
  }
  if (f.fixed && f.fixedReason) {
    out.push(el('p', { class: 'help help--fixed' }, f.fixedReason));
  }
  return out;
}

function displayValue(f) {
  if (f.type === 'boolean') return f.value ? 'yes' : 'no';
  const match = (f.options || []).find(([v]) => String(v) === String(f.value));
  return match ? match[1] : String(f.value);
}

export function renderBenchState(host, { groups, onOpen }) {
  clear(host);
  host.append(el('span', { class: 'benchstate__label' }, 'Bench'));
  for (const g of groups) {
    const touched = g.fields.some((f) => f.changed);
    host.append(el('button', {
      class: 'chip' + (g.alert ? ' chip--alert' : (g.id === 'security' ? ' chip--on' : '')),
      onclick: () => onOpen(g.id),
      title: `Open the ${g.title} panel`,
    },
      el('span', { class: 'chip__k' }, g.title + ':'),
      el('span', { class: 'chip__v' }, g.summary),
      // The strip has to keep showing anything that changes behaviour, and
      // "somebody moved this" is part of that.
      touched ? el('span', { class: 'chip__k', style: 'margin-left:.4em' }, '· changed') : null));
  }
}
