/*
 * inspector.js — the highest-value thing in the interface.
 *
 * Two rules, both from docs/UI.md, both structural rather than optional:
 *
 * 1. Selecting a field in the decode tree highlights exactly its bytes.
 * 2. Every frame is presented as a SPLIT between what an observer can read
 *    without a key and what they cannot. Not a toggle, not a tooltip: the two
 *    groups are always drawn, on every frame, in every security mode. On a
 *    cleartext frame the sealed group is drawn empty and says so, which is the
 *    Module 2 lesson. On an SCS_17 frame the command byte sits in the readable
 *    group, which is the Module 4 lesson, met three modules early by looking
 *    at it.
 *
 * Every value is selectable text, because people paste these into notes.
 */

import { el, clear, fmtT, DIR_LABEL, LINE_LABEL } from '../util.js';

let selectedFieldId = null;

export function renderInspector(host, { frame, onFieldOpen }) {
  clear(host);
  selectedFieldId = null;

  if (!frame) {
    host.append(el('p', { class: 'inspector__empty' },
      'Select a frame in the traffic list. Its bytes appear on the left and its decode tree on the right; selecting a field highlights the bytes it names. Every value here is selectable text.'));
    return;
  }

  host.append(el('div', { class: 'inspector__meta' },
    el('span', { class: 't' }, `t = ${fmtT(frame.tUs)} s`),
    el('span', { class: 'lbl' }, frame.label),
    el('span', {}, `${LINE_LABEL[frame.line] || frame.line} · ${DIR_LABEL[frame.dir] || frame.dir}`),
    el('span', {}, `${frame.bytes.length} bytes`),
    frame.secure.active ? el('span', { class: 'badge-sec' }, frame.secure.encrypted ? '◆ ' : '◇ ', frame.secure.scs) : el('span', { class: 'badge-sec', style: 'border-color:var(--border-strong);color:var(--text-muted)' }, '○ no security block'),
    frame.origin === 'attacker' ? el('span', { class: 'band band--bronze' }, '⚑ attacker-originated') : null,
  ));

  const split = el('div', { class: 'inspector__split' });
  const bytesPane = el('div', { class: 'inspector__bytes' });
  const treePane = el('div', { class: 'inspector__tree' });
  split.append(bytesPane, treePane);
  host.append(split);

  // ---- byte / bit view ------------------------------------------------
  const flat = flatten(frame.fields, 0);
  const opaqueRanges = flat.filter((f) => f.visibility === 'opaque' && f.abs !== null)
    .map((f) => [f.abs, f.abs + f.length]);

  if (frame.view === 'bits') {
    bytesPane.append(el('h3', { style: 'font-size:var(--fs-sm);margin-bottom:.4rem' }, `${frame.bits.length} bits, as they crossed the wire`));
    const dump = el('div', { class: 'bitdump', id: 'bitdump' });
    frame.bits.forEach((b, i) => {
      dump.append(el('span', { class: `bit bit--${b}`, dataset: { bit: String(i) } }, String(b)));
    });
    bytesPane.append(dump);
    bytesPane.append(el('p', { class: 'bytes-legend' },
      'Idle high, one pulse per bit. There is no cryptography in this encoding to attack.'));
  } else {
    const dump = el('div', { class: 'hexdump', id: 'hexdump' });
    frame.bytes.forEach((b, i) => {
      const sealed = opaqueRanges.some(([a, z]) => i >= a && i < z);
      dump.append(el('span', {
        class: 'hexbyte' + (sealed ? ' hexbyte--opaque' : ''),
        dataset: { byte: String(i) },
        title: sealed ? `byte ${i} — ciphertext` : `byte ${i}`,
      }, b.toString(16).toUpperCase().padStart(2, '0')));
    });
    bytesPane.append(dump);
    bytesPane.append(el('p', { class: 'bytes-legend' },
      el('span', { class: 'swatch swatch--opaque' }), 'hatched = sealed under S-ENC. An observer without the session key holds these bytes and cannot read them. Everything unhatched is readable by anyone on the wire.'));
  }

  if (frame.note) {
    bytesPane.append(el('p', { class: 'fieldnote', style: 'margin-left:0' }, frame.note));
  }

  // ---- the split ------------------------------------------------------
  const clearFields = frame.fields.filter((f) => f.visibility !== 'opaque');
  const sealedFields = frame.fields.filter((f) => f.visibility === 'opaque');

  const readable = group('clear', '👁', 'Readable without a key',
    frame.secure.encrypted
      ? 'Everything an attacker on the wire gets for free, even with Secure Channel running.'
      : 'On this frame, that is all of it.');
  readable.body.append(tree(clearFields, 0, frame, onFieldOpen));
  treePane.append(readable.box);

  const sealed = group('sealed', '🔒', 'Requires the session key',
    frame.secure.encrypted
      ? `Sealed under S-ENC. ${frame.secure.keyHeld ? 'This bench holds the key, so the recovered plaintext is shown beneath the ciphertext — marked, so you never mistake it for something an observer had.' : 'This bench does not hold the key.'}`
      : 'Nothing on this frame is concealed.');
  if (sealedFields.length) {
    sealed.body.append(tree(sealedFields, 0, frame, onFieldOpen));
    for (const f of sealedFields) {
      if (f.sealed) sealed.body.append(plaintextBlock(f, frame, onFieldOpen));
    }
  } else {
    sealed.body.append(el('p', { style: 'padding:0 var(--sp-3);color:var(--text-muted);font-size:var(--fs-sm);margin:.3rem 0' },
      frame.secure.active
        ? 'This security block authenticates without encrypting. The MAC is real; nothing is hidden.'
        : 'No security block. Every byte of this frame — the card number included — is readable by anyone who can hear the link.'));
  }
  treePane.append(sealed.box);
}

function group(kind, glyph, title, note) {
  const body = el('div', { class: 'obs__body' });
  const box = el('section', { class: `obs obs--${kind}`, 'aria-label': title },
    el('div', { class: 'obs__hd' },
      el('span', { class: 'obs__glyph', 'aria-hidden': 'true' }, glyph),
      el('span', {}, title),
      el('span', { class: 'obs__note' }, note)),
    body);
  return { box, body };
}

function plaintextBlock(field, frame, onFieldOpen) {
  const wrap = el('div', { style: 'padding:0 var(--sp-3) var(--sp-2)' });
  wrap.append(el('p', { style: 'font-size:var(--fs-xs);color:var(--text-muted);margin:.4rem 0 .2rem' },
    el('span', { class: 'sealed-tag', style: 'margin-left:0' }, 'KEY HELD'),
    ' plaintext recovered with the session key — not something an observer had:'));
  wrap.append(el('div', { class: 'hexdump', style: 'font-size:var(--fs-xs)' },
    ...field.sealed.bytes.split(' ').map((b) => el('span', { class: 'hexbyte' }, b))));
  if (field.sealed.fields.length) {
    wrap.append(tree(field.sealed.fields.map((f) => ({ ...f, sealedPlaintext: true })), null, frame, onFieldOpen));
  }
  return wrap;
}

function tree(fields, parentAbs, frame, onFieldOpen) {
  const ul = el('ul', { class: 'tree', role: 'tree' });
  for (const f of fields) {
    const abs = resolveAbs(f, parentAbs);
    const li = el('li', { role: 'none' });
    const hasMore = (f.children && f.children.length) || f.note;
    const row = el('button', {
      class: 'fieldrow' + (f.visibility === 'opaque' ? ' fieldrow--opaque' : ''),
      role: 'treeitem',
      'aria-selected': 'false',
      'aria-expanded': hasMore ? 'false' : null,
      dataset: { fieldId: f.id },
    },
      el('span', { class: 'fieldrow__name' },
        el('span', { class: 'twisty' }, hasMore ? '▸' : ''),
        f.name,
        f.sealedPlaintext ? el('span', { class: 'sealed-tag' }, 'key held') : null),
      el('span', { class: 'fieldrow__val' }, f.value),
      el('span', { class: 'fieldrow__meaning' }, f.meaning || ''));

    const sub = el('div', { hidden: true });
    if (f.note) sub.append(el('p', { class: 'fieldnote' }, f.note));
    if (f.children && f.children.length) sub.append(tree(f.children, abs, frame, onFieldOpen));

    row.addEventListener('click', () => {
      const expand = sub.hidden;
      if (hasMore) {
        sub.hidden = !expand;
        row.setAttribute('aria-expanded', String(expand));
        row.querySelector('.twisty').textContent = expand ? '▾' : '▸';
      }
      selectField(row, f, abs, frame);
      if (onFieldOpen) onFieldOpen(f.id, frame);
    });

    li.append(row, sub);
    ul.append(li);
  }
  return ul;
}

function resolveAbs(f, parentAbs) {
  if (typeof f.offset === 'number') return f.offset;
  if (typeof f.offsetInPayload === 'number' && parentAbs !== null && f.offsetInPayload >= 0) return parentAbs + f.offsetInPayload;
  return null;
}

function flatten(fields, parentAbs, out = []) {
  for (const f of fields) {
    const abs = resolveAbs(f, parentAbs);
    out.push({ ...f, abs, length: f.length || 0 });
    if (f.children) flatten(f.children, abs, out);
  }
  return out;
}

function selectField(row, field, abs, frame) {
  for (const r of document.querySelectorAll('.fieldrow[aria-selected="true"]')) r.setAttribute('aria-selected', 'false');
  row.setAttribute('aria-selected', 'true');
  selectedFieldId = field.id;

  for (const b of document.querySelectorAll('.hexbyte--hi')) b.classList.remove('hexbyte--hi');
  for (const b of document.querySelectorAll('.bit--hi')) b.classList.remove('bit--hi');

  if (frame.view === 'bits' && typeof field.bitOffset === 'number') {
    for (let i = field.bitOffset; i < field.bitOffset + field.bitLength; i++) {
      const n = document.querySelector(`.bit[data-bit="${i}"]`);
      if (n) n.classList.add('bit--hi');
    }
    return;
  }
  if (abs === null || abs === undefined) return;
  const len = field.length || 0;
  for (let i = abs; i < abs + len; i++) {
    const n = document.querySelector(`.hexbyte[data-byte="${i}"]`);
    if (n) n.classList.add('hexbyte--hi');
  }
}
