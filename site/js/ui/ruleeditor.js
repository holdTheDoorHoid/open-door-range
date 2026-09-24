/*
 * ruleeditor.js — Module 5's rule builder.
 *
 * docs/CURRICULUM.md drill 5.2 says *build* a detection rule:
 *
 *   "Build a detection rule that catches the downgrade and does not fire on a
 *    genuine legacy reader being added to the bus."
 *
 * So this is a builder, not a menu. The learner selects rules, tunes their
 * parameters, runs the set against the engine's generated day, and reads a
 * score that shows its reasoning: every true positive with the frames that
 * justify it, every attack missed, and every false positive named — including
 * which benign event it fired on. That last part is the whole module. A
 * learner who only sees "precision 83%" has been taught to chase a number.
 *
 * NOTHING HERE KNOWS WHAT A RULE IS. The catalogue — ids, labels, what each
 * rule catches, what it will false-positive on, every parameter and every
 * legal bound — comes from engine.ruleCatalog(), which renders
 * odr_detect::catalog::RULES. A bound changed in the engine cannot go stale
 * here, because there is no copy of it here to go stale.
 *
 * docs/UI.md, two rules this panel keeps:
 *
 *   COLLAPSE, NEVER REMOVE. Every rule in the catalogue is listed whether it
 *   is selected or not, and every rule's row states what it is even when its
 *   parameters are folded away. A parameter that has been moved off its
 *   default says so on the folded summary line, because a control that is
 *   changing the result while out of sight is how a learner ends up with a
 *   mental model that does not match what they are looking at.
 *
 *   PREFER WARNING OVER BLOCKING. A refused composition is shown with the
 *   engine's own sentence and nothing is silently dropped. A set that will
 *   obviously score badly is run anyway: watching it score badly is the
 *   lesson.
 *
 * Nothing leaves the origin. Every call is to the engine in this tab.
 */

import { el, clear } from '../util.js';

/* ---------------------------------------------------------------- *
 * State that has to survive a re-render
 *
 * The drill panel re-renders on every cursor move, so a naive rebuild would
 * wipe a half-edited threshold and steal focus mid-keystroke. The draft, the
 * open/closed folds and the focused control are kept here and restored.
 * ---------------------------------------------------------------- */

const ui = {
  draft: null,        // { [ruleId]: { params } | null } — null means not selected
  dirty: false,       // edited since the last run
  open: new Set(),    // rule ids whose parameters are unfolded
  sections: new Set(['caught', 'falsePositives', 'missed']),
  signature: null,    // what the DOM currently reflects
  refocus: null,      // id of the control to put the caret back in
};

/** A fresh draft from what the engine says is selected. */
function draftFrom(catalog) {
  const draft = {};
  for (const rule of catalog.rules) {
    draft[rule.id] = rule.selected
      ? Object.fromEntries(rule.params.map((p) => [p.id, p.value]))
      : null;
  }
  return draft;
}

/** The composition string the engine parses. Defaults are left out. */
function encode(catalog, draft) {
  const parts = [];
  for (const rule of catalog.rules) {
    const params = draft[rule.id];
    if (!params) continue;
    const changed = rule.params
      .filter((p) => Number(params[p.id]) !== Number(p.default))
      .map((p) => `${p.id}=${Number(params[p.id])}`);
    parts.push(changed.length ? `${rule.id}:${changed.join(',')}` : rule.id);
  }
  return parts.join(';');
}

/* ---------------------------------------------------------------- *
 * Formatting
 * ---------------------------------------------------------------- */

/** Microseconds in the largest unit that keeps it readable, exactly. */
function fmtDuration(us) {
  const n = Number(us);
  if (!Number.isFinite(n)) return '—';
  if (n === 0) return '0';
  if (n % 1e6 === 0) return `${n / 1e6} s`;
  if (n % 1e3 === 0) return `${n / 1e3} ms`;
  return `${n} µs`;
}

function fmtT(us) {
  return `${(Number(us) / 1e6).toFixed(3)} s`;
}

/** A duration as a latency, which reads better as "after 5.0 s". */
function fmtLatency(us) {
  const n = Number(us);
  if (!n) return 'at the earliest honest moment';
  return `after ${(n / 1e6).toFixed(3)} s`;
}

/* ---------------------------------------------------------------- *
 * The engine adapter
 *
 * engine-wasm.js is the thin wrapper around the compiled crate and does not
 * yet forward the v4 rule-editor calls (see ENGINE-API.md §13). Until it
 * does, fall through to the wasm object it holds, which has them. The mock
 * implements them on the wrapper itself, so it takes the first branch.
 * ---------------------------------------------------------------- */

function adapter(engine) {
  if (!engine) return null;
  const raw = engine._e;
  const has = (name) => typeof engine[name] === 'function';
  const rawHas = (name) => raw && typeof raw[name] === 'function';
  if (!has('ruleCatalog') && !rawHas('ruleCatalog')) return null;
  const call = (name, ...args) => (has(name)
    ? engine[name](...args)
    : JSON.parse(raw[name](...args) || 'null'));
  return {
    ruleCatalog: () => call('ruleCatalog'),
    setRules: (text) => call('setRules', text),
    detection: () => call('detection'),
  };
}

/* ---------------------------------------------------------------- *
 * Entry point
 * ---------------------------------------------------------------- */

/**
 * Draw the rule builder into `host`.
 *
 * `onChange` is called after a run, so the surrounding panel can re-read the
 * flag — running a rule set is what a Module 5 drill's submission *is*.
 */
export function renderRuleEditor(host, { engine, onChange }) {
  injectStyles();
  const api = adapter(engine);
  if (!api) {
    // An engine older than v4. Say so rather than drawing a dead panel.
    if (host.dataset.state !== 'unsupported') {
      host.dataset.state = 'unsupported';
      clear(host);
      host.append(el('section', { class: 'odr-re' },
        el('p', { class: 'odr-re__warn' },
          'This engine does not expose the rule catalogue (ENGINE-API.md §13, added in v4), '
          + 'so the rule builder cannot be drawn. The rule-set selector above still works.')));
    }
    return;
  }
  host.dataset.state = 'ok';

  const catalog = api.ruleCatalog();
  const detection = api.detection();
  if (!ui.draft) ui.draft = draftFrom(catalog);

  // Rebuild only when something actually changed, so typing in a threshold is
  // not interrupted by the cursor moving along the timeline.
  const signature = JSON.stringify([
    engine.version, ui.dirty, ui.draft,
    [...ui.open].sort(), [...ui.sections].sort(),
    detection && detection.ruleSet && detection.ruleSet.text,
    detection && detection.error,
  ]);
  if (signature === ui.signature && host.firstChild) return;
  ui.signature = signature;

  const run = () => {
    const text = encode(catalog, ui.draft);
    const res = api.setRules(text);
    if (res && res.ok === false) {
      ui.lastError = res.error;
    } else {
      ui.lastError = null;
      ui.dirty = false;
      ui.draft = null;          // adopt whatever the engine now holds
    }
    ui.signature = null;
    if (onChange) onChange();
  };

  clear(host);
  const box = el('section', { class: 'odr-re', 'aria-labelledby': 'odr-re-h' });
  box.append(el('h3', { id: 'odr-re-h' }, 'Detection rule builder'));
  box.append(el('p', { class: 'odr-re__lede' },
    'Drill 5.2 asks you to ', el('strong', {}, 'build'), ' a rule, not pick one. Select the rules '
    + 'you want, tune them, and run the set against a generated day of traffic that contains both '
    + 'attacks and benign events. The answer key is never shown to the rules.'));

  box.append(presetsRow(catalog, run));
  box.append(statusLine(catalog, detection));
  const warning = warnings(detection);
  if (warning) box.append(warning);

  box.append(ruleList(catalog));
  box.append(runRow(catalog, detection, run));
  box.append(results(detection));
  host.append(box);

  if (ui.refocus) {
    const target = host.querySelector(`#${CSS.escape(ui.refocus)}`);
    ui.refocus = null;
    if (target && target.focus) target.focus();
  }
}

/* ---------------------------------------------------------------- *
 * Header pieces
 * ---------------------------------------------------------------- */

function presetsRow(catalog, run) {
  const row = el('div', { class: 'odr-re__presets' });
  row.append(el('span', { class: 'odr-re__presetlabel' }, 'Start from:'));
  for (const preset of catalog.presets) {
    row.append(el('button', {
      class: 'btn odr-re__preset',
      type: 'button',
      title: preset.help,
      'aria-pressed': String(catalog.selection.preset === preset.id && !ui.dirty),
      onclick: () => {
        ui.draft = draftFrom(withPreset(catalog, preset));
        ui.dirty = false;
        ui.signature = null;
        run();
      },
    }, preset.label));
  }
  return row;
}

/**
 * The catalogue as it would look with `preset` selected.
 *
 * The preset's own text is the authority — it came from the engine — so this
 * parses it rather than guessing which rules a preset contains.
 */
function withPreset(catalog, preset) {
  const wanted = new Map();
  for (const entry of (preset.text || '').split(';')) {
    const part = entry.trim();
    if (!part) continue;
    const colon = part.indexOf(':');
    const id = colon < 0 ? part : part.slice(0, colon);
    const params = {};
    if (colon >= 0) {
      for (const a of part.slice(colon + 1).split(',')) {
        const eq = a.indexOf('=');
        if (eq > 0) params[a.slice(0, eq).trim()] = Number(a.slice(eq + 1));
      }
    }
    wanted.set(id.trim(), params);
  }
  return {
    rules: catalog.rules.map((r) => {
      const chosen = wanted.get(r.id);
      return {
        ...r,
        selected: !!chosen,
        params: r.params.map((p) => ({
          ...p,
          value: chosen && chosen[p.id] !== undefined ? chosen[p.id] : p.default,
        })),
      };
    }),
  };
}

function statusLine(catalog, detection) {
  const selected = catalog.rules.filter((r) => ui.draft[r.id]).length;
  const tuned = catalog.rules.filter((r) => {
    const params = ui.draft[r.id];
    return params && r.params.some((p) => Number(params[p.id]) !== Number(p.default));
  }).map((r) => r.id);

  const running = detection && detection.ruleSet ? detection.ruleSet : null;
  const line = el('p', { class: 'odr-re__status' });
  line.append(el('strong', {}, `${selected} rule${selected === 1 ? '' : 's'} selected`));
  if (tuned.length) line.append(`, ${tuned.length} tuned off its default (${tuned.join(', ')})`);
  line.append('. ');
  if (ui.dirty) {
    line.append(el('span', { class: 'odr-re__dirty' },
      '⚠ Edited since the last run — the score below is from the set named next, not the one above.'));
    line.append(' ');
  }
  if (running) {
    line.append(el('span', { class: 'odr-re__running' },
      'Running: ',
      el('code', {}, running.preset ? `${running.preset} preset` : (running.text || 'nothing at all'))));
  }
  return line;
}

function warnings(detection) {
  if (!detection) return null;
  const messages = [];
  if (ui.lastError) messages.push(`The engine refused that rule set: ${ui.lastError}`);
  if (detection.error) messages.push(detection.error);
  if (detection.probeOnLink === false) {
    messages.push('No probe is clipped to the reader → controller link, so there is no capture to '
      + 'run rules against. A monitor that is not there sees nothing — which is the honest floor, '
      + 'not a bug. Place a sniff tap and run again.');
  }
  if (detection.evidenceChecks === false) {
    messages.push('A finding cites frames that do not say what it claims. That is a bug in a '
      + 'detector, and the report is not checkable.');
  }
  if (!messages.length) return null;
  return el('div', { class: 'odr-re__warn', role: 'status' },
    ...messages.map((m) => el('p', {}, m)));
}

/* ---------------------------------------------------------------- *
 * The rules
 * ---------------------------------------------------------------- */

function ruleList(catalog) {
  const list = el('div', { class: 'odr-re__rules' });
  for (const rule of catalog.rules) list.append(ruleRow(rule));
  return list;
}

function ruleRow(rule) {
  const params = ui.draft[rule.id];
  const selected = !!params;
  const changed = selected
    ? rule.params.filter((p) => Number(params[p.id]) !== Number(p.default))
    : [];

  const wrap = el('div', { class: `odr-re__rule${selected ? ' is-on' : ''}` });

  const toggleId = `odr-re-on-${rule.id}`;
  const head = el('div', { class: 'odr-re__rulehead' });
  head.append(el('input', {
    type: 'checkbox', id: toggleId, checked: selected ? true : null,
    onchange: (e) => {
      ui.draft[rule.id] = e.target.checked
        ? Object.fromEntries(rule.params.map((p) => [p.id, p.value]))
        : null;
      if (e.target.checked) ui.open.add(rule.id);
      ui.dirty = true;
      ui.refocus = toggleId;
      ui.signature = null;
      rerender();
    },
  }));
  head.append(el('label', { for: toggleId, class: 'odr-re__rulelabel' }, rule.label));
  head.append(el('code', { class: 'odr-re__ruleid' }, rule.id));
  if (changed.length) {
    // COLLAPSE NEVER REMOVE: a tuned parameter says so on the folded line.
    head.append(el('span', { class: 'odr-re__tuned' },
      `tuned: ${changed.map((p) => `${p.id}=${paramText(p, params[p.id])}`).join(', ')}`));
  }
  wrap.append(head);

  wrap.append(el('p', { class: 'odr-re__catches' },
    el('span', { class: 'odr-re__tag odr-re__tag--catch' }, 'catches'), ' ', rule.catches));
  wrap.append(el('p', { class: 'odr-re__fp' },
    el('span', { class: 'odr-re__tag odr-re__tag--fp' }, 'fires on'), ' ', rule.falsePositives));

  if (rule.params.length) {
    const fold = el('details', {
      class: 'odr-re__params',
      open: ui.open.has(rule.id) ? true : null,
      ontoggle: (e) => {
        if (e.target.open) ui.open.add(rule.id); else ui.open.delete(rule.id);
      },
    });
    fold.append(el('summary', {},
      `${rule.params.length} parameter${rule.params.length === 1 ? '' : 's'}`,
      changed.length ? ` · ${changed.length} changed` : ' · all at their defaults'));
    const grid = el('div', { class: 'odr-re__paramgrid' });
    for (const p of rule.params) grid.append(paramControl(rule, p, selected));
    fold.append(grid);
    wrap.append(fold);
  }
  return wrap;
}

function paramText(param, value) {
  return param.type === 'toggle'
    ? (Number(value) ? 'on' : 'off')
    : (param.type === 'duration' ? fmtDuration(value) : String(value));
}

function paramControl(rule, param, selected) {
  const params = ui.draft[rule.id];
  const value = params ? params[param.id] : param.value;
  const id = `odr-re-p-${rule.id}-${param.id}`;
  const set = (raw) => {
    if (!ui.draft[rule.id]) return;
    const n = Number(raw);
    if (!Number.isFinite(n)) return;
    // The bound is the engine's. Clamping here keeps the control honest
    // rather than sending something the engine will refuse.
    ui.draft[rule.id][param.id] = Math.min(param.max, Math.max(param.min, Math.round(n)));
    ui.dirty = true;
    ui.refocus = id;
    ui.signature = null;
    rerender();
  };

  let control;
  if (param.type === 'toggle') {
    control = el('input', {
      type: 'checkbox', id, disabled: selected ? null : true,
      checked: Number(value) ? true : null,
      onchange: (e) => set(e.target.checked ? 1 : 0),
    });
  } else {
    control = el('input', {
      type: 'number', id, disabled: selected ? null : true,
      value: String(value), min: String(param.min), max: String(param.max),
      step: param.type === 'duration' ? '1000' : '1',
      onchange: (e) => set(e.target.value),
    });
  }

  const row = el('div', { class: 'odr-re__param' });
  row.append(el('label', { for: id }, param.label));
  const line = el('div', { class: 'odr-re__paramline' }, control);
  if (param.type !== 'toggle') {
    line.append(el('span', { class: 'odr-re__range' },
      param.type === 'duration'
        ? `${fmtDuration(value)} · ${fmtDuration(param.min)}–${fmtDuration(param.max)}`
        : `${param.min}–${param.max}`));
  }
  line.append(el('span', { class: 'odr-re__default' },
    Number(value) === Number(param.default)
      ? 'default'
      : `default ${paramText(param, param.default)}`));
  row.append(line);
  row.append(el('p', { class: 'odr-re__help' }, param.help));
  return row;
}

function runRow(catalog, detection, run) {
  const row = el('div', { class: 'odr-re__runrow' });
  row.append(el('button', {
    class: 'btn btn--primary odr-re__run', type: 'button', onclick: run,
  }, ui.dirty ? '▶ Run the edited set against the day' : '▶ Run against the generated day'));
  row.append(el('button', {
    class: 'btn btn--ghost', type: 'button',
    onclick: () => { ui.draft = draftFrom({ rules: catalog.rules.map((r) => ({ ...r, selected: false })) }); ui.dirty = true; ui.signature = null; rerender(); },
  }, 'Clear every rule'));
  row.append(el('span', { class: 'odr-re__runnote' },
    detection && detection.ran
      ? 'Scored against an answer key built from the scenario script, not from what any rule found.'
      : 'Nothing has been run yet. The empty set is the honest floor: it catches nothing and cries wolf about nothing.'));
  return row;
}

/* ---------------------------------------------------------------- *
 * The score, with its reasoning
 * ---------------------------------------------------------------- */

function results(d) {
  const box = el('div', { class: 'odr-re__results' });
  if (!d) {
    box.append(el('p', { class: 'odr-re__help' }, 'This drill is not scored against a day.'));
    return box;
  }

  const s = d.score;
  const grid = el('div', { class: 'odr-re__score' });
  const stat = (label, value, note, tone) => grid.append(el('div', { class: `odr-re__stat${tone ? ` odr-re__stat--${tone}` : ''}` },
    el('span', { class: 'odr-re__statv' }, value),
    el('span', { class: 'odr-re__statl' }, label),
    note ? el('span', { class: 'odr-re__statn' }, note) : null));

  stat('precision', `${s.precisionPct}%`, 'of what it reported was real');
  stat('recall', `${s.recallPct}%`, 'of what was there was caught');
  stat('true positives', String(s.truePositives), 'attacks and weaknesses found');
  stat('false positives', String(s.falsePositives),
    s.quietOnBenign ? 'none on benign traffic' : 'some on benign traffic',
    s.falsePositives ? 'bad' : null);
  stat('missed', String(s.falseNegatives), 'in the key, not reported', s.falseNegatives ? 'bad' : null);
  stat('ambiguous', String(s.ambiguous), 'real, and undecidable from the wire');
  stat('worst time to detect', fmtT(s.worstTimeToDetectUs), 'after the earliest honest moment');
  box.append(grid);

  box.append(el('p', { class: `odr-re__verdict${s.quietOnBenign ? '' : ' odr-re__verdict--bad'}` },
    s.quietOnBenign
      ? '✔ Quiet on benign traffic: nothing that was not an attack was called one.'
      : '✖ Not quiet on benign traffic: this set called at least one benign event an attack. '
        + 'A rule set that catches less and never cries wolf is a better rule set than one that '
        + 'catches more and does.'));

  box.append(section('falsePositives', `False positives (${s.falsePositives})`,
    d.falsePositives, s.falsePositives, falsePositiveRow,
    'Every finding that matched nothing in the answer key. The ones naming a benign event are the '
    + 'ones that matter: that is your rule firing on something a building does on an ordinary day.'));

  box.append(section('caught', `Caught (${s.truePositives})`,
    d.caught, s.truePositives, hitRow,
    'Each with the frames that justify it and how long after the earliest honest moment it could '
    + 'be said. A rule that catches everything six hours late has caught nothing.'));

  box.append(section('missed', `Missed (${s.falseNegatives})`,
    d.missed, s.falseNegatives, missedRow,
    'In the answer key, and not reported. Either no selected rule emits that signal, or the one '
    + 'that does is tuned past it.'));

  box.append(section('ambiguousHits', `Ambiguous (${s.ambiguous})`,
    d.ambiguousHits, s.ambiguous, hitRow,
    'Real observations whose cause the wire does not carry — a CMD_KEYSET is both the worst thing '
    + 'on a bus and undecidable. Counted in neither precision nor recall: you are neither rewarded '
    + 'for reporting one nor punished for it, which is exactly the position a defender is in.'));

  box.append(section('benign', `Benign events planted in this day (${(d.benign || []).length})`,
    d.benign, (d.benign || []).length, benignRow,
    'These are in the traffic on purpose. A scorer with no benign traffic teaches a learner to '
    + 'alert on everything.'));

  if (d.episodes && d.episodes.length) {
    box.append(section('episodes', `The day, episode by episode (${d.episodes.length})`,
      d.episodes, d.episodes.length, episodeRow,
      'Each episode is its own world, captured from one passive probe and concatenated with a '
      + 'minute of silence between them.'));
  }
  return box;
}

/** A foldable list that always states its full count, capped or not. */
function section(key, title, items, total, row, blurb) {
  const list = items || [];
  const fold = el('details', {
    class: 'odr-re__section',
    open: ui.sections.has(key) && list.length ? true : null,
    ontoggle: (e) => { if (e.target.open) ui.sections.add(key); else ui.sections.delete(key); },
  });
  fold.append(el('summary', {}, title,
    list.length < total ? ` — showing ${list.length} of ${total}` : ''));
  fold.append(el('p', { class: 'odr-re__help' }, blurb));
  if (!list.length) {
    fold.append(el('p', { class: 'odr-re__none' }, 'None.'));
    return fold;
  }
  for (const item of list) fold.append(row(item));
  if (list.length < total) {
    fold.append(el('p', { class: 'odr-re__none' },
      `${total - list.length} more are in the score above and are not drawn here — the engine caps `
      + 'the list rather than sending thousands of findings into a render path.'));
  }
  return fold;
}

function findingHead(f) {
  return el('div', { class: 'odr-re__fhead' },
    el('code', { class: 'odr-re__signal' }, f.signal),
    el('span', { class: 'odr-re__badge' }, `${f.severity} / ${f.confidence}`),
    el('span', { class: 'odr-re__t' }, fmtT(f.tUs)),
    f.episode ? el('span', { class: 'odr-re__ep' }, `episode: ${f.episode.id}`) : null);
}

function hitRow(h) {
  const row = el('div', { class: 'odr-re__finding' });
  row.append(findingHead(h));
  row.append(el('p', { class: 'odr-re__flabel' },
    el('span', { class: 'odr-re__tag odr-re__tag--ok' }, h.verdict || 'caught'), ' ', h.label || h.describes));
  if (h.latencyUs !== undefined) {
    row.append(el('p', { class: 'odr-re__help' }, `Reported ${fmtLatency(h.latencyUs)}.`));
  }
  row.append(why(h));
  return row;
}

function falsePositiveRow(f) {
  const row = el('div', { class: `odr-re__finding${f.benign ? ' odr-re__finding--bad' : ''}` });
  row.append(findingHead(f));
  row.append(el('p', { class: 'odr-re__flabel' },
    el('span', { class: 'odr-re__tag odr-re__tag--fp' }, f.benign ? 'fired on a benign event' : 'matched nothing'),
    ' ',
    f.benign || `${f.describes} — but nothing in the key expected it here, which is usually a tuning problem rather than a logic one.`));
  row.append(why(f));
  return row;
}

function missedRow(m) {
  const row = el('div', { class: 'odr-re__finding odr-re__finding--bad' });
  row.append(el('div', { class: 'odr-re__fhead' },
    el('code', { class: 'odr-re__signal' }, m.signal),
    el('span', { class: 'odr-re__badge' }, m.verdict),
    el('span', { class: 'odr-re__t' }, fmtT(m.tUs)),
    m.episode ? el('span', { class: 'odr-re__ep' }, `episode: ${m.episode.id}`) : null));
  row.append(el('p', { class: 'odr-re__flabel' },
    el('span', { class: 'odr-re__tag odr-re__tag--fp' }, 'missed'), ' ', m.label));
  row.append(el('p', { class: 'odr-re__help' }, m.describes));
  return row;
}

function benignRow(b) {
  const row = el('div', { class: 'odr-re__finding' });
  row.append(el('div', { class: 'odr-re__fhead' },
    el('span', { class: 'odr-re__t' }, fmtT(b.tUs)),
    el('span', { class: 'odr-re__badge' }, `lasts ${fmtDuration(b.durationUs)}`),
    b.looksLike ? el('code', { class: 'odr-re__signal' }, `looks like ${b.looksLike}`) : null,
    b.episode ? el('span', { class: 'odr-re__ep' }, `episode: ${b.episode.id}`) : null));
  row.append(el('p', { class: 'odr-re__flabel' }, b.label));
  return row;
}

function episodeRow(e) {
  const row = el('div', { class: 'odr-re__finding' });
  row.append(el('div', { class: 'odr-re__fhead' },
    el('code', { class: 'odr-re__signal' }, e.id),
    el('span', { class: 'odr-re__t' }, `${fmtT(e.startUs)} → ${fmtT(e.endUs)}`)));
  row.append(el('p', { class: 'odr-re__flabel' }, e.describes));
  return row;
}

/**
 * The reasoning, and the frames it cites.
 *
 * This is the part Module 5 is actually about. odr-detect's rule is that a
 * finding with no evidence is an opinion, and the citations are checkable:
 * each names an index into the capture, a timestamp, and the octets.
 */
function why(f) {
  const fold = el('details', { class: 'odr-re__why' });
  fold.append(el('summary', {}, `why — ${f.frameCount || (f.frames || []).length} frame(s) cited`));
  if (f.note) fold.append(el('p', { class: 'odr-re__note' }, f.note));
  for (const r of f.frames || []) {
    fold.append(el('div', { class: 'odr-re__frame' },
      el('span', { class: 'odr-re__frameix' }, `#${r.index}`),
      el('span', { class: 'odr-re__t' }, fmtT(r.tUs)),
      el('span', { class: 'odr-re__framesum' }, r.summary),
      el('code', { class: 'odr-re__hex' }, r.hex)));
  }
  if ((f.frames || []).length < (f.frameCount || 0)) {
    fold.append(el('p', { class: 'odr-re__none' },
      `${f.frameCount - f.frames.length} further cited frame(s) are not drawn here.`));
  }
  return fold;
}

/* ---------------------------------------------------------------- *
 * Re-render plumbing
 * ---------------------------------------------------------------- */

let lastArgs = null;

/** Remember how to redraw, so a control can ask for it. */
export function rememberHost(host, props) {
  lastArgs = [host, props];
}

function rerender() {
  if (lastArgs) renderRuleEditor(lastArgs[0], lastArgs[1]);
}

/** Drop the editor's draft. Called when a different drill is loaded. */
export function resetRuleEditor() {
  ui.draft = null;
  ui.dirty = false;
  ui.lastError = null;
  ui.signature = null;
}

/* ---------------------------------------------------------------- *
 * Styles
 *
 * Injected rather than written into css/app.css so this panel owns its own
 * appearance and can be lifted out whole. Everything is namespaced odr-re-*
 * and every colour is one of the site's tokens, so light and dark both work
 * and colour is never the only carrier of meaning — each state also has a
 * word or a glyph.
 * ---------------------------------------------------------------- */

const STYLE_ID = 'odr-re-styles';

function injectStyles() {
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement('style');
  style.id = STYLE_ID;
  style.textContent = `
.odr-re { border: 1px solid var(--border); border-radius: var(--radius-lg);
  background: var(--surface-2); padding: var(--sp-3); margin: var(--sp-3) 0; }
.odr-re h3 { font-size: var(--fs-md); margin-bottom: var(--sp-1); }
.odr-re__lede, .odr-re__status { font-size: var(--fs-sm); color: var(--text-muted); margin: var(--sp-2) 0; }
.odr-re__dirty { color: var(--warn); font-weight: 600; }
.odr-re__running code { font-family: var(--font-mono); font-size: var(--fs-xs);
  background: var(--surface-3); padding: 0 .3em; border-radius: 3px; word-break: break-all; }
.odr-re__presets { display: flex; flex-wrap: wrap; gap: var(--sp-2); align-items: center; margin: var(--sp-2) 0; }
.odr-re__presetlabel { font-size: var(--fs-xs); text-transform: uppercase;
  letter-spacing: .08em; color: var(--text-faint); }
.odr-re__warn { border-left: 3px solid var(--warn); background: var(--warn-soft);
  color: var(--text); padding: var(--sp-2) var(--sp-3); border-radius: var(--radius);
  font-size: var(--fs-sm); margin: var(--sp-2) 0; }
.odr-re__warn p { margin: .2rem 0; }

.odr-re__rules { display: grid; gap: var(--sp-2); margin: var(--sp-3) 0; }
.odr-re__rule { border: 1px solid var(--border); border-radius: var(--radius);
  background: var(--surface); padding: var(--sp-2) var(--sp-3); opacity: .72; }
.odr-re__rule.is-on { opacity: 1; border-color: var(--accent); }
.odr-re__rulehead { display: flex; flex-wrap: wrap; align-items: center; gap: var(--sp-2); }
.odr-re__rulelabel { font-weight: 600; cursor: pointer; }
.odr-re__ruleid { font-family: var(--font-mono); font-size: var(--fs-xs);
  color: var(--text-faint); background: var(--surface-3); padding: 0 .35em; border-radius: 3px; }
.odr-re__tuned { font-size: var(--fs-xs); color: var(--warn); font-weight: 600; }
.odr-re__catches, .odr-re__fp { font-size: var(--fs-xs); color: var(--text-muted); margin: .25rem 0 0; }
.odr-re__tag { font-size: var(--fs-xs); text-transform: uppercase; letter-spacing: .06em;
  font-weight: 700; padding: 0 .35em; border-radius: 3px; }
.odr-re__tag--catch { background: var(--grant-soft); color: var(--grant); }
.odr-re__tag--fp { background: var(--attack-soft); color: var(--attack); }
.odr-re__tag--ok { background: var(--accent-soft); color: var(--accent-text); }
.odr-re__params { margin-top: var(--sp-2); }
.odr-re__params > summary { font-size: var(--fs-xs); color: var(--text-faint); cursor: pointer; }
.odr-re__paramgrid { display: grid; gap: var(--sp-2); margin-top: var(--sp-2);
  padding-left: var(--sp-3); border-left: 2px solid var(--border); }
.odr-re__param label { font-size: var(--fs-sm); font-weight: 550; }
.odr-re__paramline { display: flex; flex-wrap: wrap; align-items: center; gap: var(--sp-2); }
.odr-re__paramline input[type=number] { width: 11ch; background: var(--surface);
  border: 1px solid var(--border-strong); border-radius: 4px; padding: .2em .4em; }
.odr-re__range, .odr-re__default { font-size: var(--fs-xs); color: var(--text-faint);
  font-family: var(--font-mono); }
.odr-re__help { font-size: var(--fs-xs); color: var(--text-muted); margin: .2rem 0 0; }

.odr-re__runrow { display: flex; flex-wrap: wrap; align-items: center; gap: var(--sp-2);
  margin: var(--sp-3) 0; }
.odr-re__runnote { font-size: var(--fs-xs); color: var(--text-faint); flex: 1 1 14rem; }

.odr-re__score { display: grid; grid-template-columns: repeat(auto-fit, minmax(8.5rem, 1fr));
  gap: var(--sp-2); margin: var(--sp-3) 0 var(--sp-2); }
.odr-re__stat { background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); padding: var(--sp-2); display: grid; gap: 1px; }
.odr-re__stat--bad { border-color: var(--attack); }
.odr-re__statv { font-size: var(--fs-lg); font-weight: 650; font-variant-numeric: tabular-nums; }
.odr-re__statl { font-size: var(--fs-xs); text-transform: uppercase; letter-spacing: .06em;
  color: var(--text-faint); }
.odr-re__statn { font-size: var(--fs-xs); color: var(--text-muted); }
.odr-re__verdict { font-size: var(--fs-sm); font-weight: 550; margin: var(--sp-2) 0;
  padding: var(--sp-2) var(--sp-3); border-radius: var(--radius);
  background: var(--grant-soft); color: var(--text); border-left: 3px solid var(--grant); }
.odr-re__verdict--bad { background: var(--attack-soft); border-left-color: var(--attack); }

.odr-re__section { border-top: 1px solid var(--border); padding: var(--sp-2) 0; }
.odr-re__section > summary { font-weight: 600; cursor: pointer; }
.odr-re__none { font-size: var(--fs-xs); color: var(--text-faint); margin: .3rem 0; }
.odr-re__finding { border: 1px solid var(--border); border-left: 3px solid var(--border-strong);
  border-radius: var(--radius); background: var(--surface);
  padding: var(--sp-2); margin: var(--sp-2) 0; }
.odr-re__finding--bad { border-left-color: var(--attack); }
.odr-re__fhead { display: flex; flex-wrap: wrap; gap: var(--sp-2); align-items: baseline; }
.odr-re__signal { font-family: var(--font-mono); font-size: var(--fs-xs); font-weight: 650; }
.odr-re__badge, .odr-re__ep { font-size: var(--fs-xs); color: var(--text-faint); }
.odr-re__t { font-family: var(--font-mono); font-size: var(--fs-xs);
  font-variant-numeric: tabular-nums; color: var(--text-muted); }
.odr-re__flabel { font-size: var(--fs-sm); margin: .3rem 0 0; }
.odr-re__why { margin-top: .35rem; }
.odr-re__why > summary { font-size: var(--fs-xs); color: var(--text-faint); cursor: pointer; }
.odr-re__note { font-size: var(--fs-xs); color: var(--text-muted); margin: .3rem 0;
  padding-left: var(--sp-2); border-left: 2px solid var(--border); }
.odr-re__frame { display: flex; flex-wrap: wrap; gap: var(--sp-2); align-items: baseline;
  font-size: var(--fs-xs); padding: .15rem 0; border-top: 1px dotted var(--border); }
.odr-re__frameix { font-family: var(--font-mono); color: var(--text-faint); }
.odr-re__framesum { color: var(--text-muted); }
.odr-re__hex { font-family: var(--font-mono); color: var(--text); word-break: break-all; }
`;
  document.head.append(style);
}
