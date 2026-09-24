/*
 * engine-mock.js — the REFERENCE IMPLEMENTATION of the engine contract.
 *
 * The site ships with engine-wasm.js — crates/odr-wasm, the real engine —
 * imported by js/app.js. This file is kept, deliberately, for two reasons:
 *
 *   1. It is the readable statement of what ../ENGINE-API.md means. A shape
 *      that is hard to produce here is a shape the contract should not ask for.
 *   2. It lets the site be worked on with no Rust toolchain and no site/pkg
 *      build: swap the one import in js/app.js and the interface runs.
 *
 *        import { createEngine } from './engine-mock.js';
 *
 * It implements ENGINE_API_VERSION 4. What it does NOT implement is the v2
 * submission API (§9) — the mock approximates those predicates by watching
 * which field you opened in the decode tree, which is the thing the real
 * engine could not do and the reason that API exists. The site checks for each
 * of those calls before making it, so both engines run.
 *
 * It DOES implement v4's rule editor (§13): ruleCatalog(), setRules() and
 * detection(). Module 5 asks a learner to build a detection rule set, and a
 * reference implementation that could only offer a menu would be describing a
 * different contract. The day and the findings below are hand-written; the
 * mechanism — composition selects rules, rules produce findings, findings are
 * scored against a key containing benign events — is the real one, so a set
 * that alerts on everything scores badly here too.
 *
 * If you change a shape here, change it in ../ENGINE-API.md first.
 *
 * The bytes below are built the way the real crates build them — real
 * CRC-16/AUG-CCITT, real control bytes, real security block layout — so the
 * inspector is telling the truth even while the engine is a mock. Ciphertext,
 * cryptograms and MACs are seeded pseudo-random filler: they are the right
 * length and the right shape, and they are not the output of AES.
 */

export const ENGINE_KIND = 'mock';
export const ENGINE_API_VERSION = 4;

/* ------------------------------------------------------------------ *
 * Bytes
 * ------------------------------------------------------------------ */

const SOM = 0x53;
const MARK = 0xff;

/** CRC-16/AUG-CCITT: poly 0x1021, init 0x1D0F. Check value 0xE5CC. */
export function crc16Aug(bytes) {
  let crc = 0x1d0f;
  for (const b of bytes) {
    crc ^= (b & 0xff) << 8;
    for (let i = 0; i < 8; i++) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc & 0xffff;
}

export function hex(b, width = 2) {
  return b.toString(16).toUpperCase().padStart(width, '0');
}

/** Deterministic PRNG. No wall clock, no Math.random anywhere in the engine. */
function rng(seed) {
  let s = seed >>> 0 || 0x9e3779b9;
  return function next() {
    s ^= s << 13; s >>>= 0;
    s ^= s >> 17;
    s ^= s << 5; s >>>= 0;
    return s >>> 0;
  };
}
function randomBytes(next, n) {
  const out = [];
  for (let i = 0; i < n; i++) out.push(next() & 0xff);
  return out;
}

/* ------------------------------------------------------------------ *
 * Frame builder
 *
 * Builds the byte array and the decode tree together, so an offset in the
 * tree can never drift away from the byte it names.
 * ------------------------------------------------------------------ */

class FrameBuilder {
  constructor() {
    this.bytes = [];
    this.fields = [];
  }
  push(name, values, opts = {}) {
    const offset = this.bytes.length;
    const arr = Array.isArray(values) ? values : [values];
    for (const v of arr) this.bytes.push(v & 0xff);
    const field = {
      id: opts.id || name.toLowerCase().replace(/[^a-z0-9]+/g, '_') + '_' + offset,
      name,
      offset,
      length: arr.length,
      value: opts.value !== undefined ? opts.value : arr.map((v) => hex(v)).join(' '),
      meaning: opts.meaning || '',
      note: opts.note || '',
      visibility: opts.visibility || 'clear',
      children: opts.children || [],
    };
    this.fields.push(field);
    return field;
  }
  get length() {
    return this.bytes.length;
  }
}

const COMMAND_NAMES = {
  0x60: 'POLL', 0x61: 'ID', 0x62: 'CAP', 0x64: 'LSTAT', 0x65: 'ISTAT',
  0x66: 'OSTAT', 0x67: 'RSTAT', 0x68: 'OUT', 0x69: 'LED', 0x6a: 'BUZ',
  0x6b: 'TEXT', 0x6e: 'COMSET', 0x75: 'KEYSET', 0x76: 'CHLNG', 0x77: 'SCRYPT',
};
const REPLY_NAMES = {
  0x40: 'ACK', 0x41: 'NAK', 0x45: 'PDID', 0x46: 'PDCAP', 0x48: 'LSTATR',
  0x49: 'ISTATR', 0x4a: 'OSTATR', 0x4b: 'RSTATR', 0x50: 'RAW', 0x53: 'KEYPAD',
  0x54: 'COM', 0x76: 'CCRYPT', 0x78: 'RMAC_I', 0x79: 'BUSY',
};
const SCS_NAMES = {
  0x11: 'SCS_11', 0x12: 'SCS_12', 0x13: 'SCS_13', 0x14: 'SCS_14',
  0x15: 'SCS_15', 0x16: 'SCS_16', 0x17: 'SCS_17', 0x18: 'SCS_18',
};
const SCS_NOTES = {
  0x11: 'CHLNG — the ACU opens the handshake with RND.A.',
  0x12: 'CCRYPT — the PD answers with its UID, RND.B and the client cryptogram.',
  0x13: 'SCRYPT — the ACU proves it holds the key.',
  0x14: 'RMAC_I — the PD seeds the reply MAC chain. The session is now up.',
  0x15: 'MAC, no encryption. A null cipher: the payload is plaintext.',
  0x16: 'MAC, no encryption. A null cipher: the payload is plaintext.',
  0x17: 'MAC and AES-128-CBC encryption, ACU to PD.',
  0x18: 'MAC and AES-128-CBC encryption, PD to ACU.',
};

let frameCounter = 0;

/**
 * Assemble one OSDP frame.
 * scs: 0x11..0x18 or null. payload: on-the-wire bytes (ciphertext if encrypted).
 * plaintext: what the payload decodes to when the key is held, or null.
 */
function osdpFrame(opts) {
  const {
    tUs, dir, address = 0x02, seq = 0, code, payload = [], scs = null,
    keyType = null, mac = null, plaintext = null, kind, summary, note = '',
    payloadFields = null, plaintextFields = null, tapped = false, origin = 'bus',
    requiresTap = null,
  } = opts;

  const isReply = dir === 'pd_to_acu';
  const b = new FrameBuilder();

  b.push('Mark', MARK, {
    meaning: 'line idle byte',
    note: 'Not counted in the length and not covered by the CRC. It gives the receiving UART something to lock onto while the RS-485 driver enables.',
  });
  b.push('SOM', SOM, { meaning: 'start of message', note: 'Every OSDP frame begins 0x53.' });

  const addrByte = isReply ? address | 0x80 : address & 0x7f;
  b.push('Address', addrByte, {
    meaning: `PD ${address}${isReply ? ', reply (bit 7 set)' : ', command'}`,
    note: 'Bit 7 is the direction bit, which is why an analyser can label direction without knowing the wiring.',
  });

  const lenField = b.push('Length', [0, 0], { meaning: '(filled in below)', note: 'Total frame length LSB first, counting SOM through the CRC. The mark byte is not included.' });

  let ctrl = (seq & 0x03) | 0x04;
  if (scs !== null) ctrl |= 0x08;
  b.push('Control', ctrl, {
    meaning: `seq ${seq & 0x03}, CRC, ${scs !== null ? 'SCB present' : 'no SCB'}`,
    note: 'Bits 0-1 sequence, bit 2 CRC (not checksum), bit 3 security block present.',
    children: [
      { id: 'ctrl_seq', name: 'sequence', value: String(seq & 0x03), meaning: 'bits 0-1', note: 'Two bits. It wraps every four frames, which is why it is a liveness aid and not a replay defence.', visibility: 'clear' },
      { id: 'ctrl_crc', name: 'CRC in use', value: '1', meaning: 'bit 2', note: 'Set: the trailer is a 16-bit CRC rather than a one-byte checksum.', visibility: 'clear' },
      { id: 'ctrl_scb', name: 'security block', value: scs !== null ? '1' : '0', meaning: 'bit 3', note: 'Set when a security block follows the control byte.', visibility: 'clear' },
    ],
  });

  if (scs !== null) {
    const scbData = [];
    if (scs >= 0x11 && scs <= 0x13) scbData.push(keyType === 'scbk-d' ? 0x00 : 0x01);
    else if (scs === 0x14) scbData.push(0x01);
    const scbLen = 2 + scbData.length;
    const scbBytes = [scbLen, scs, ...scbData];
    const children = [
      { id: 'scb_len', name: 'scb length', value: hex(scbLen), meaning: `${scbLen} bytes`, note: 'Counts itself and the type byte.', visibility: 'clear' },
      { id: 'scb_type', name: 'scb type', value: hex(scs), meaning: SCS_NAMES[scs], note: SCS_NOTES[scs] || '', visibility: 'clear' },
    ];
    if (scbData.length) {
      children.push({
        id: 'scb_data', name: 'key type', value: hex(scbData[0]),
        meaning: scs === 0x14 ? 'ACU cryptogram verified' : (scbData[0] === 0x00 ? 'SCBK-D (default key)' : 'SCBK (site key)'),
        note: scs === 0x14 ? '' : 'Sent in the clear, before any encryption exists. A passive listener learns whether this site ever moved off the published default key by watching one handshake.',
        visibility: 'clear',
      });
    }
    b.push('Security block', scbBytes, {
      meaning: SCS_NAMES[scs],
      note: SCS_NOTES[scs] || '',
      children,
    });
  }

  const nameTable = isReply ? REPLY_NAMES : COMMAND_NAMES;
  b.push(isReply ? 'Reply code' : 'Command code', code, {
    id: 'code',
    meaning: nameTable[code] || 'unknown',
    note: scs === 0x17 || scs === 0x18
      ? 'The command byte sits OUTSIDE the encrypted payload. It is plaintext on every OSDP frame, in every security mode. Traffic analysis never needed a key.'
      : 'Identifies the command or reply. Always plaintext.',
    visibility: 'clear',
  });

  if (payload.length) {
    const encrypted = scs === 0x17 || scs === 0x18;
    const fld = b.push('Payload', payload, {
      id: 'payload',
      value: payload.map((v) => hex(v)).join(' '),
      meaning: encrypted ? `${payload.length} bytes, AES-128-CBC` : `${payload.length} bytes`,
      note: encrypted
        ? 'Sealed under S-ENC. Without the session key this is the only part of the frame an observer cannot read.'
        : '',
      visibility: encrypted ? 'opaque' : 'clear',
      children: encrypted ? [] : (payloadFields || []),
    });
    if (encrypted && plaintext) {
      fld.sealed = {
        length: plaintext.length,
        bytes: plaintext.map((v) => hex(v)).join(' '),
        fields: plaintextFields || [],
      };
    }
  }

  if (mac) {
    b.push('MAC', mac, {
      id: 'mac',
      meaning: `${mac.length * 8}-bit truncated MAC`,
      note: 'AES-128-CBC-MAC truncated to its first four bytes. Four bytes is 2^32 — see drill 4.2 for what that is worth.',
      visibility: 'clear',
    });
  }

  // Length covers SOM..CRC inclusive; +2 for the CRC about to be appended.
  const total = b.length - 1 + 2;
  b.bytes[lenField.offset] = total & 0xff;
  b.bytes[lenField.offset + 1] = (total >> 8) & 0xff;
  lenField.value = `${hex(total & 0xff)} ${hex((total >> 8) & 0xff)}`;
  lenField.meaning = `${total} bytes`;

  const crc = crc16Aug(b.bytes.slice(1));
  b.push('CRC', [crc & 0xff, (crc >> 8) & 0xff], {
    id: 'crc',
    meaning: `0x${hex(crc, 4)}, valid`,
    note: 'CRC-16/AUG-CCITT over SOM onwards. An integrity check against noise, not against an attacker: anyone rewriting a frame recomputes it.',
  });

  const label = nameTable[code] || `0x${hex(code)}`;
  return {
    id: `f${++frameCounter}`,
    tUs,
    line: 'rs485',
    lane: 'bus',
    dir,
    view: 'hex',
    address,
    seq: seq & 0x03,
    code,
    label,
    kind: kind || label.toLowerCase(),
    summary: summary || label,
    note,
    tapped,
    origin,
    requiresTap,
    secure: scs === null
      ? { active: false, scs: null, encrypted: false, macBits: 0 }
      : { active: true, scs: SCS_NAMES[scs], scsByte: scs, encrypted: scs === 0x17 || scs === 0x18, macBits: mac ? mac.length * 8 : 0, keyHeld: !!plaintext },
    bytes: b.bytes,
    fields: b.fields,
  };
}

/* ---- Wiegand / RF bit-level frames ------------------------------- */

function wiegand26(facility, cardNumber) {
  const bits = [];
  const payload = [];
  for (let i = 7; i >= 0; i--) payload.push((facility >> i) & 1);
  for (let i = 15; i >= 0; i--) payload.push((cardNumber >> i) & 1);
  const even = payload.slice(0, 12).reduce((a, b) => a + b, 0) % 2;
  const odd = payload.slice(12).reduce((a, b) => a + b, 0) % 2;
  bits.push(even, ...payload, odd === 0 ? 1 : 0);
  return bits;
}

function bitFrame(opts) {
  const { tUs, line, bits, label, summary, kind, fields, note = '', dir = 'wire', tapped = false, origin = 'wire', requiresTap = null } = opts;
  return {
    id: `f${++frameCounter}`,
    tUs,
    line,
    lane: line === 'rf' ? 'rf' : 'wire',
    dir,
    view: 'bits',
    label,
    kind,
    summary,
    note,
    tapped,
    origin,
    requiresTap,
    secure: { active: false, scs: null, encrypted: false, macBits: 0 },
    bits,
    bytes: packBits(bits),
    fields,
  };
}

function packBits(bits) {
  const out = [];
  for (let i = 0; i < bits.length; i += 8) {
    let v = 0;
    for (let j = 0; j < 8; j++) v = (v << 1) | (bits[i + j] || 0);
    out.push(v);
  }
  return out;
}

function wiegandFields(bits, facility, cardNumber, opts = {}) {
  const fc = bits.slice(1, 9).join('');
  const cn = bits.slice(9, 25).join('');
  return [
    { id: 'w_pe', name: 'Even parity', bitOffset: 0, bitLength: 1, value: String(bits[0]), meaning: 'over bits 1-12', note: 'One bit of parity over the first half. It catches a single flipped bit on a noisy wire. It is not a signature and it authenticates nobody.', visibility: 'clear' },
    { id: 'w_fc', name: 'Facility code', bitOffset: 1, bitLength: 8, value: fc, meaning: `${facility} (0x${hex(facility)})`, note: 'Eight bits. Shared by every badge in the building, which is why it is the field a brute-force sweep holds constant.', visibility: 'clear' },
    { id: 'w_cn', name: 'Card number', bitOffset: 9, bitLength: 16, value: cn, meaning: `${cardNumber}`, note: opts.substituted ? 'Rewritten in flight by the inline tap. The reader never emitted this number.' : 'Sixteen bits. 65,536 possibilities, sent in the clear, with nothing to defeat.', visibility: 'clear' },
    { id: 'w_po', name: 'Odd parity', bitOffset: 25, bitLength: 1, value: String(bits[25]), meaning: 'over bits 14-25', note: 'Recomputed by anyone who edits the number. Parity is not integrity.', visibility: 'clear' },
  ];
}

/* ------------------------------------------------------------------ *
 * Scenario construction
 * ------------------------------------------------------------------ */

const POLL_PERIOD_US = 50_000;   // 20 polls a second. Honest, and it looks it.
const CARD = { facility: 42, number: 24601 };

function cardReadPayload(facility, number) {
  const bits = wiegand26(facility, number);
  const packed = packBits(bits);
  return {
    bits,
    bytes: [0x00, 0x01, 0x1a, 0x00, ...packed],
    fields(prefix, opts = {}) {
      return [
        { id: prefix + '_reader', name: 'reader', offsetInPayload: 0, length: 1, value: '00', meaning: 'reader 0', note: '', visibility: opts.visibility || 'clear' },
        { id: prefix + '_fmt', name: 'format', offsetInPayload: 1, length: 1, value: '01', meaning: 'raw bit array', note: 'The PD is not interpreting the credential. It is forwarding the bits it saw.', visibility: opts.visibility || 'clear' },
        { id: prefix + '_len', name: 'bit count', offsetInPayload: 2, length: 2, value: '1A 00', meaning: '26 bits', note: '', visibility: opts.visibility || 'clear' },
        { id: prefix + '_bits', name: 'card bits', offsetInPayload: 4, length: packed.length, value: packed.map((v) => hex(v)).join(' '), meaning: `FC ${facility}, card ${number}`, note: 'The same 26 bits Module 1 watched cross a Wiegand wire. The credential did not get stronger when the bus did.', visibility: opts.visibility || 'clear' },
      ];
    },
  };
}

function pdcapPayload(withCrypto) {
  const entries = [
    [0x01, 0x01, 0x01], // contact status monitoring
    [0x02, 0x01, 0x01], // output control
    [0x04, 0x01, 0x01], // LED control
    [0x05, 0x01, 0x01], // audible output
    [0x07, 0x01, 0x01], // text output
  ];
  if (withCrypto) entries.push([0x09, 0x01, 0x01]);
  entries.push([0x0a, 0x04, 0x00]);
  const bytes = entries.flat();
  const fields = [];
  let off = 0;
  for (const e of entries) {
    const isCrypto = e[0] === 0x09;
    fields.push({
      id: 'cap_' + hex(e[0]),
      name: `function 0x${hex(e[0])}`,
      offsetInPayload: off,
      length: 3,
      value: e.map((v) => hex(v)).join(' '),
      meaning: isCrypto ? 'communication security: AES-128' : `capability, compliance ${e[1]}`,
      note: isCrypto ? 'This entry is the whole downgrade attack. Delete it in flight and the controller concludes the reader cannot do crypto — and then talks to it in the clear, believing that is the reader\'s fault.' : '',
      visibility: 'clear',
    });
    off += 3;
  }
  if (!withCrypto) {
    fields.push({
      id: 'cap_missing',
      name: 'function 0x09',
      offsetInPayload: -1,
      length: 0,
      value: 'absent',
      meaning: 'communication security: NOT REPORTED',
      note: 'The reader does support AES-128. This reply was edited on the wire by the inline tap. The controller cannot tell the difference, because nothing in OSDP authenticates a capability report.',
      visibility: 'clear',
    });
  }
  return { bytes, fields };
}

/**
 * Every scenario is one deterministic run of the bench. It produces frames,
 * state events and timeline markers, and nothing in it depends on wall clock.
 */
function buildScenario(id, cfg) {
  const next = rng(cfg.seed);
  const frames = [];
  const events = [];
  const markers = [];
  const duration = cfg.durationUs;

  const mark = (tUs, label, kind, requiresTap = null, unlessTap = null) => markers.push({ tUs, label, kind, requiresTap, unlessTap });
  const ev = (tUs, patch, label, requiresTap = null, unlessTap = null) => events.push({ tUs, patch, label, requiresTap, unlessTap });

  const badgeTimes = cfg.badgeTimes || [];
  const tapInline = !!cfg.inlineTap;

  // ---- RF + Wiegand side ------------------------------------------
  if (cfg.wire === 'wiegand') {
    let seqT = 0;
    for (const badge of badgeTimes) {
      const t = badge.tUs;
      const num = badge.number ?? CARD.number;
      const fc = badge.facility ?? CARD.facility;
      frames.push(bitFrame({
        tUs: t,
        line: 'rf',
        bits: em4100Bits(fc, num),
        label: 'RF',
        kind: 'rf_present',
        summary: `card presented — EM4100, FC ${fc} / ${num}`,
        dir: 'card_to_reader',
        origin: badge.cloned ? 'attacker' : 'card',
        note: badge.cloned ? 'A writable T5577 tag carrying a number copied from someone else\'s badge. The reader cannot tell.' : 'A 125 kHz tag with no processor, no key and no challenge. It shouts its number at anything that energises it.',
        fields: em4100Fields(fc, num),
      }));
      mark(t, badge.cloned ? 'cloned tag presented' : 'card presented', 'card');

      const emitted = wiegand26(fc, num);
      frames.push(bitFrame({
        tUs: t + 120_000,
        line: 'wiegand',
        bits: emitted,
        label: 'D0/D1',
        kind: 'wiegand',
        summary: `26-bit pulse train — FC ${fc} / ${num}`,
        origin: badge.injected ? 'attacker' : 'reader',
        requiresTap: badge.injected ? 'any' : null,
        note: badge.injected
          ? 'These pulses were driven onto the wire by the tap. No card was presented to the reader.'
          : 'Twenty-six pulses, 50 µs wide, 2 ms apart, idle high. There is no cryptography here to attack.',
        fields: wiegandFields(emitted, fc, num),
      }));

      let arriveFc = fc, arriveNum = num;
      if (tapInline && badge.substitute) {
        arriveFc = badge.substitute.facility;
        arriveNum = badge.substitute.number;
        const rewritten = wiegand26(arriveFc, arriveNum);
        frames.push(bitFrame({
          tUs: t + 160_000,
          line: 'wiegand',
          bits: rewritten,
          label: 'D0/D1',
          kind: 'wiegand_substituted',
          requiresTap: 'inline',
          summary: `26-bit pulse train — FC ${arriveFc} / ${arriveNum} (substituted)`,
          origin: 'attacker',
          tapped: true,
          note: 'The inline tap consumed the reader\'s frame and emitted its own. The reader\'s output is unchanged; the panel never saw it.',
          fields: wiegandFields(rewritten, arriveFc, arriveNum, { substituted: true }),
        }));
        mark(t + 160_000, 'credential substituted', 'attack', 'inline');
      }

      const granted = badge.granted !== false;
      // An attacker-produced outcome only happens when the learner has actually
      // placed a tap that could produce it. Where a tap would have SUBSTITUTED a
      // credential, the un-tapped bench still grants on the original one.
      const req = badge.injected ? 'any' : (badge.substitute ? 'inline' : null);
      const emitGrant = (fc, num, requires, unless) => {
        ev(t + 200_000, { lastCredential: `${fc}/${num}`, decision: granted ? 'granted' : 'denied' }, granted ? 'grant' : 'deny', requires, unless);
        if (granted) {
          ev(t + 220_000, { door: 'open', strike: 'energised' }, 'strike fires', requires, unless);
          ev(t + 5_220_000, { door: 'closed', strike: 'idle' }, 'strike releases', requires, unless);
          mark(t + 220_000, 'STRIKE FIRES — door opens', 'grant', requires, unless);
        } else {
          mark(t + 200_000, 'access denied', 'deny', requires, unless);
        }
      };
      emitGrant(arriveFc, arriveNum, req, null);
      if (badge.substitute) emitGrant(fc, num, null, 'inline');
      seqT++;
    }
  }

  // ---- OSDP bus ----------------------------------------------------
  if (cfg.wire === 'osdp') {
    let seq = 1;
    let scActive = false;
    let scs = { cmd: null, reply: null };
    const secureFrom = cfg.secureChannel ? (cfg.handshakeAtUs ?? 0) + 600_000 : Infinity;
    const nullCipher = cfg.nullCipher;

    if (cfg.secureChannel) {
      const h = cfg.handshakeAtUs ?? 200_000;
      const keyType = cfg.keyType || 'scbk-d';
      frames.push(osdpFrame({ tUs: h, dir: 'acu_to_pd', seq: 0, code: 0x76, scs: 0x11, keyType, payload: randomBytes(next, 8), kind: 'chlng', summary: 'CHLNG — RND.A', note: 'The ACU opens the handshake. Eight bytes of controller nonce, in the clear.' }));
      frames.push(osdpFrame({ tUs: h + 40_000, dir: 'pd_to_acu', seq: 0, code: 0x76, scs: 0x12, keyType, payload: randomBytes(next, 32), kind: 'ccrypt', summary: 'CCRYPT — cUID, RND.B, client cryptogram', note: 'cUID (8) ‖ RND.B (8) ‖ client cryptogram (16). Forty-eight bits of PD nonce is all the entropy the session key ever gets.' }));
      frames.push(osdpFrame({ tUs: h + 90_000, dir: 'acu_to_pd', seq: 0, code: 0x77, scs: 0x13, keyType, payload: randomBytes(next, 16), kind: 'scrypt', summary: 'SCRYPT — server cryptogram' }));
      frames.push(osdpFrame({ tUs: h + 130_000, dir: 'pd_to_acu', seq: 0, code: 0x78, scs: 0x14, payload: randomBytes(next, 16), kind: 'rmac_i', summary: 'RMAC_I — MAC chain seeded' }));
      mark(h, 'secure channel handshake', 'handshake');
      ev(h + 130_000, { secureChannel: 'established', scs: nullCipher ? 'SCS_15/16' : 'SCS_17/18', key: keyType === 'scbk-d' ? 'SCBK-D' : 'SCBK' }, 'secure channel up');
      scActive = true;
      scs = nullCipher ? { cmd: 0x15, reply: 0x16 } : { cmd: 0x17, reply: 0x18 };
    }

    if (cfg.downgrade) {
      const d = cfg.downgradeAtUs;
      frames.push(osdpFrame({ tUs: d, dir: 'acu_to_pd', seq: 1, code: 0x62, payload: [0x00], kind: 'cap', summary: 'CAP — what can you do?' }));
      const real = pdcapPayload(true);
      frames.push(osdpFrame({ tUs: d + 30_000, dir: 'pd_to_acu', seq: 1, code: 0x46, payload: real.bytes, payloadFields: real.fields, kind: 'pdcap', summary: 'PDCAP — as the reader sent it', note: 'What the reader actually replied. The tap sees this and does not forward it.' }));
      const edited = pdcapPayload(false);
      frames.push(osdpFrame({ tUs: d + 45_000, dir: 'pd_to_acu', seq: 1, code: 0x46, payload: edited.bytes, payloadFields: edited.fields, kind: 'pdcap_downgraded', tapped: true, origin: 'attacker', requiresTap: 'inline', summary: 'PDCAP — as the controller received it', note: 'The 0x09 communication-security entry is gone. The controller now believes it is talking to a reader that cannot do AES.' }));
      mark(d + 45_000, 'PDCAP rewritten — downgrade', 'attack', 'inline');
      ev(d + 60_000, { secureChannel: 'downgraded', scs: 'none', key: 'none' }, 'downgraded to cleartext', 'inline');
      scActive = false;
      scs = { cmd: null, reply: null };
    }

    let t = cfg.pollStartUs ?? 0;
    const badges = [...badgeTimes].sort((a, b) => a.tUs - b.tUs);
    let bi = 0;
    while (t < duration) {
      const secure = scActive && t >= secureFrom && !(cfg.downgrade && t >= cfg.downgradeAtUs + 60_000);
      const useScs = secure ? scs : { cmd: null, reply: null };
      const mac = secure ? randomBytes(next, 4) : null;

      const pollPayload = secure && !nullCipher ? randomBytes(next, 16) : [];
      frames.push(osdpFrame({
        tUs: t, dir: 'acu_to_pd', seq: seq & 3, code: 0x60, scs: useScs.cmd,
        payload: pollPayload, plaintext: secure && !nullCipher ? [] : null,
        mac: mac ? mac.slice() : null, kind: 'poll', summary: 'POLL',
        note: 'The heartbeat. Twenty of these a second, forever, whether or not anything is happening. This density is the whole of drill 4.1.',
      }));

      const badge = badges[bi];
      const isBadge = badge && t >= badge.tUs && t < badge.tUs + POLL_PERIOD_US;

      if (isBadge) {
        const fc = badge.facility ?? CARD.facility;
        const num = badge.number ?? CARD.number;
        const cr = cardReadPayload(fc, num);
        if (secure && !nullCipher) {
          frames.push(osdpFrame({
            tUs: t + 8_000, dir: 'pd_to_acu', seq: seq & 3, code: 0x50, scs: useScs.reply,
            payload: randomBytes(next, 16), plaintext: cr.bytes,
            plaintextFields: cr.fields('cr', {}), mac: randomBytes(next, 4),
            kind: 'raw', summary: 'RAW — card read (sealed)',
            note: 'You can see that a card was read. You cannot see whose. The reply code told you the first half for free.',
          }));
        } else {
          frames.push(osdpFrame({
            tUs: t + 8_000, dir: 'pd_to_acu', seq: seq & 3, code: 0x50, scs: useScs.reply,
            payload: cr.bytes, payloadFields: cr.fields('cr'), mac: mac ? randomBytes(next, 4) : null,
            kind: 'raw', summary: `RAW — card read, FC ${fc} / ${num}`,
            note: secure && nullCipher
              ? 'SCS_15/16 authenticate without encrypting. The MAC is real; the card number is in plain sight beside it.'
              : 'The credential, in the clear, on a bus sold as the secure replacement for Wiegand. No key was needed to read this.',
          }));
        }
        mark(t, badge.cloned ? 'cloned tag read' : 'badge-in', 'card');

        const granted = badge.granted !== false;
        seq++;
        frames.push(osdpFrame({
          tUs: t + 20_000, dir: 'acu_to_pd', seq: seq & 3, code: 0x68,
          scs: useScs.cmd, payload: secure && !nullCipher ? randomBytes(next, 16) : [0x00, 0x01, 0x05, 0x00],
          plaintext: secure && !nullCipher ? [0x00, 0x01, 0x05, 0x00] : null,
          mac: secure ? randomBytes(next, 4) : null,
          kind: 'out', summary: granted ? 'OUT — energise strike' : 'LED — deny',
          note: 'The frame that opens the door.',
        }));
        frames.push(osdpFrame({ tUs: t + 28_000, dir: 'pd_to_acu', seq: seq & 3, code: 0x40, scs: useScs.reply, payload: secure && !nullCipher ? randomBytes(next, 16) : [], mac: secure ? randomBytes(next, 4) : null, kind: 'ack', summary: 'ACK' }));

        if (granted) {
          ev(t + 30_000, { lastCredential: `${fc}/${num}`, decision: 'granted' }, 'grant');
          ev(t + 40_000, { door: 'open', strike: 'energised' }, 'strike fires');
          ev(t + 5_040_000, { door: 'closed', strike: 'idle' }, 'strike releases');
          mark(t + 40_000, 'STRIKE FIRES — door opens', 'grant');
        } else {
          ev(t + 30_000, { lastCredential: `${fc}/${num}`, decision: 'denied' }, 'deny');
          mark(t + 30_000, 'access denied', 'deny');
        }
        bi++;
      } else if (cfg.injectAtUs && Math.abs(t - cfg.injectAtUs) < POLL_PERIOD_US / 2) {
        frames.push(osdpFrame({
          tUs: t + 12_000, dir: 'acu_to_pd', seq: (seq + 1) & 3, code: 0x68,
          payload: [0x00, 0x01, 0x05, 0x00], kind: 'out_injected', origin: 'attacker', tapped: true, requiresTap: 'write',
          summary: 'OUT — energise strike (injected)',
          note: 'Sent by the attacker actor, not the controller. Nothing in an unsecured OSDP frame says who wrote it.',
        }));
        frames.push(osdpFrame({ tUs: t + 20_000, dir: 'pd_to_acu', seq: (seq + 1) & 3, code: 0x40, kind: 'ack', summary: 'ACK — to the attacker', requiresTap: 'write' }));
        mark(t + 12_000, 'attacker injected OUT', 'attack', 'write');
        ev(t + 24_000, { door: 'open', strike: 'energised', decision: 'granted', lastCredential: 'none — injected' }, 'strike fires (injected)', 'write');
        ev(t + 5_024_000, { door: 'closed', strike: 'idle' }, 'strike releases', 'write');
        // no tap, no injection: the bus just keeps polling.
      } else {
        frames.push(osdpFrame({
          tUs: t + 8_000, dir: 'pd_to_acu', seq: seq & 3, code: 0x40, scs: useScs.reply,
          payload: secure && !nullCipher ? randomBytes(next, 16) : [], plaintext: secure && !nullCipher ? [] : null,
          mac: secure ? randomBytes(next, 4) : null, kind: 'ack', summary: 'ACK — nothing to report',
        }));
      }

      seq++;
      t += POLL_PERIOD_US;
    }
  }

  frames.sort((a, b) => a.tUs - b.tUs);
  events.sort((a, b) => a.tUs - b.tUs);
  markers.sort((a, b) => a.tUs - b.tUs);
  return { id, durationUs: duration, frames, events, markers, cfg };
}

function em4100Bits(facility, number) {
  // 64-bit EM4100: 9 header ones, 10 nibbles with row parity, 4 column parity, stop 0.
  const bits = [1, 1, 1, 1, 1, 1, 1, 1, 1];
  const data = [(facility >> 4) & 0xf, facility & 0xf, (number >> 12) & 0xf, (number >> 8) & 0xf, (number >> 4) & 0xf, number & 0xf, 0, 0, 0, 0];
  const cols = [0, 0, 0, 0];
  for (const nib of data) {
    let p = 0;
    for (let i = 3; i >= 0; i--) {
      const bit = (nib >> i) & 1;
      bits.push(bit);
      p ^= bit;
      cols[3 - i] ^= bit;
    }
    bits.push(p);
  }
  bits.push(...cols, 0);
  return bits;
}

function em4100Fields(facility, number) {
  return [
    { id: 'em_hdr', name: 'Header', bitOffset: 0, bitLength: 9, value: '111111111', meaning: 'nine ones', note: 'The tag repeats this forever while it is in the field. There is no "start a session" and nothing to refuse.', visibility: 'clear' },
    { id: 'em_id', name: 'Tag ID', bitOffset: 9, bitLength: 50, value: `${hex(facility)} ${hex(number, 4)}`, meaning: `FC ${facility}, card ${number}`, note: 'Ten data nibbles with row parity. This number is the entire credential: no processor, no key, no challenge.', visibility: 'clear' },
    { id: 'em_col', name: 'Column parity', bitOffset: 59, bitLength: 4, value: '····', meaning: 'error detection', note: 'Detection, not protection.', visibility: 'clear' },
    { id: 'em_stop', name: 'Stop bit', bitOffset: 63, bitLength: 1, value: '0', meaning: 'end of word', note: '', visibility: 'clear' },
  ];
}

/* ------------------------------------------------------------------ *
 * Scenario catalogue
 * ------------------------------------------------------------------ */

const SCENARIOS = {
  'wiegand-badge-in': () => buildScenario('wiegand-badge-in', {
    seed: 0x0d00, wire: 'wiegand', durationUs: 20_000_000,
    badgeTimes: [{ tUs: 3_000_000 }, { tUs: 12_400_000, facility: 42, number: 24601 }],
  }),
  'wiegand-clone': () => buildScenario('wiegand-clone', {
    seed: 0x0d01, wire: 'wiegand', durationUs: 20_000_000,
    badgeTimes: [{ tUs: 3_000_000 }, { tUs: 11_000_000, cloned: true }],
  }),
  'wiegand-implant': () => buildScenario('wiegand-implant', {
    seed: 0x0d02, wire: 'wiegand', durationUs: 20_000_000, inlineTap: true,
    badgeTimes: [{ tUs: 4_000_000 }, { tUs: 12_000_000, substitute: { facility: 42, number: 1 } }],
  }),
  'wiegand-replay': () => buildScenario('wiegand-replay', {
    seed: 0x0d03, wire: 'wiegand', durationUs: 20_000_000,
    badgeTimes: [{ tUs: 3_000_000 }, { tUs: 13_500_000, injected: true }],
  }),
  'osdp-clear': () => buildScenario('osdp-clear', {
    seed: 0x0d10, wire: 'osdp', durationUs: 20_000_000,
    badgeTimes: [{ tUs: 8_200_000 }, { tUs: 16_600_000, facility: 42, number: 1337, granted: false }],
  }),
  'osdp-inject': () => buildScenario('osdp-inject', {
    seed: 0x0d11, wire: 'osdp', durationUs: 20_000_000,
    badgeTimes: [{ tUs: 5_000_000 }], injectAtUs: 14_000_000,
  }),
  'osdp-secure': () => buildScenario('osdp-secure', {
    seed: 0x0d20, wire: 'osdp', durationUs: 20_000_000, secureChannel: true,
    keyType: 'scbk-d', handshakeAtUs: 200_000,
    badgeTimes: [{ tUs: 9_000_000 }, { tUs: 15_200_000 }],
  }),
  'osdp-null-cipher': () => buildScenario('osdp-null-cipher', {
    seed: 0x0d21, wire: 'osdp', durationUs: 20_000_000, secureChannel: true,
    nullCipher: true, keyType: 'scbk', handshakeAtUs: 200_000,
    badgeTimes: [{ tUs: 7_600_000 }, { tUs: 15_000_000 }],
  }),
  'osdp-downgrade': () => buildScenario('osdp-downgrade', {
    seed: 0x0d22, wire: 'osdp', durationUs: 24_000_000, secureChannel: true,
    keyType: 'scbk', handshakeAtUs: 200_000, downgrade: true, downgradeAtUs: 9_000_000,
    badgeTimes: [{ tUs: 5_000_000 }, { tUs: 17_000_000 }],
  }),
  'osdp-secure-day': () => buildScenario('osdp-secure-day', {
    seed: 0x0d30, wire: 'osdp', durationUs: 40_000_000, secureChannel: true,
    keyType: 'scbk', handshakeAtUs: 200_000,
    badgeTimes: [
      { tUs: 4_100_000 }, { tUs: 6_300_000, number: 10231 }, { tUs: 9_800_000, number: 3391 },
      { tUs: 18_400_000, number: 24601 }, { tUs: 27_100_000, number: 10231 },
      { tUs: 33_500_000, number: 8812 }, { tUs: 36_900_000, number: 3391 },
    ],
  }),
};

/* ------------------------------------------------------------------ *
 * Curriculum — the drill catalogue, as docs/CURRICULUM.md defines it.
 * ------------------------------------------------------------------ */

function d(id, title, band, opts) {
  return Object.assign({
    id, title, band, simulated: true, hints: [], bronzeSteps: [],
    scenario: 'osdp-clear', predicate: { kind: 'reach', event: 'grant' },
  }, opts);
}

const MODULES = [
  {
    id: 'm0', number: 0, title: 'The credential',
    blurb: 'Before the wire, the card. The reader was never the weak part, and a learner who starts at Wiegand has skipped the cheapest attack in the building.',
    drills: [
      d('0.1', 'What a prox card is', 'bronze', {
        scenario: 'wiegand-badge-in',
        summary: 'A 125 kHz EM4100 tag: no processor, no key, no challenge. It shouts its number at anything that energises it, forever, to anyone.',
        objective: 'Read the tag ID off the modulated carrier and match the engine\'s value.',
        flagText: 'The learner reads a tag ID off the carrier and it matches the engine\'s value.',
        predicate: { kind: 'inspect', frameKind: 'rf_present', fieldId: 'em_id' },
        bronzeSteps: ['Press Run and let the card reach the reader.', 'Click the RF row in the traffic list — it is the first one.', 'In the decode tree, open Tag ID. That number is the whole credential.'],
        hints: ['The RF frame is on the rf lane of the timeline, at the first marker.', 'EM4100 sends nine header ones, then ten data nibbles. The tag ID is the nibbles.'],
      }),
      d('0.2', 'Cloning 125 kHz', 'bronze', {
        scenario: 'wiegand-clone',
        summary: 'Copy the number onto a writable tag. There is nothing to defeat — the format has no concept of authentication.',
        objective: 'Present a cloned tag and have the controller grant, where the original was never presented.',
        flagText: 'A cloned tag presents to the reader and the controller grants, where the original tag was never presented.',
        predicate: { kind: 'reach', event: 'grant', after: 10_000_000 },
        bronzeSteps: ['Run to the first badge-in and note the number.', 'Run on. The second presentation is a T5577 tag carrying that same number.', 'Watch the door. The controller cannot tell the two apart, because there is nothing to tell apart.'],
        hints: ['Nothing needs configuring. That is the lesson.'],
      }),
      d('0.3', 'HID Prox and the format problem', 'silver', {
        scenario: 'wiegand-badge-in',
        summary: 'H10301 over the air. The same facility-code-and-card-number payload you meet again on the wire in Module 1 — the credential and the wire protocol carry identical bits with identical absence of protection.',
        objective: 'Extract facility code and card number from the RF layer, then predict the Wiegand bit pattern the reader will emit before it emits it.',
        flagText: 'Learner predicts the exact Wiegand bit pattern from the RF payload.',
        predicate: { kind: 'inspect', frameKind: 'wiegand', fieldId: 'w_fc' },
        hints: ['Compare the RF frame and the D0/D1 frame side by side. The bits are the same bits.'],
      }),
      d('0.4', '13.56 MHz: the upgrade that mostly was not', 'silver', {
        scenario: 'wiegand-badge-in',
        summary: 'MIFARE Classic, its sector keys, and Crypto1 — a cipher broken in 2008 and still on badges today. What a nested attack recovers, and how fast.',
        objective: 'Recover all sector keys from observed reader traffic alone, then read the credential block.',
        flagText: 'Attacker recovers all sector keys from observed traffic, then reads the credential block.',
        predicate: { kind: 'attacker', has: 'keys' },
        hints: ['The attacker panel runs the nested attack. You supply nothing but the capture.'],
      }),
      d('0.5', 'The ones that hold up', 'bronze', {
        scenario: 'wiegand-badge-in',
        summary: 'DESIGNED CONTRAST: DESFire EV2 and Seos do real mutual authentication with real keys. Present the same attacks; watch them fail.',
        objective: 'Run 0.2 and 0.4\'s attacks against a DESFire card and record why each one stops. This drill passes on correct diagnosis, not on a successful attack.',
        flagText: 'Both attacks fail and the learner\'s diagnosis of why is correct.',
        predicate: { kind: 'diagnose' },
        bronzeSteps: ['Open the card panel and switch the credential to DESFire EV2.', 'Run the clone attack. Read the failure reason the engine reports.', 'Run the key-recovery attack. Read that failure reason too.'],
      }),
      d('0.6', 'The attacks that skip all of this', 'reference', {
        simulated: false,
        scenario: 'wiegand-badge-in',
        summary: 'Request-to-exit sensors triggered from outside, door position switches, crash bars, under-door tools, and the plain fact that many doors are opened by defeating the mechanics rather than the electronics.',
        objective: 'Reference section. Nothing here is simulated, and it says so.',
        flagText: 'No flag. This section exists so the course does not leave you with a badly calibrated sense of where the risk lives.',
        predicate: { kind: 'none' },
      }),
    ],
  },
  {
    id: 'm1', number: 1, title: 'The wire (Wiegand)',
    blurb: 'Two data lines, idle high, no crypto anywhere in the specification.',
    drills: [
      d('1.1', 'What a badge actually says', 'bronze', {
        scenario: 'wiegand-badge-in',
        summary: 'Present a card at the reader, watch 26 pulses cross the wire, decode them by hand with the decoder open beside you.',
        objective: 'Submit the facility code and card number the engine transmitted.',
        flagText: 'Learner-submitted facility code and card number match what the engine transmitted.',
        predicate: { kind: 'inspect', frameKind: 'wiegand', fieldId: 'w_cn' },
        bronzeSteps: ['Press Run.', 'Select the D0/D1 row in the traffic list.', 'Open Facility code, then Card number, in the decode tree. The bits highlight as you go.'],
        hints: ['Bit 0 is even parity. Bits 1-8 are the facility code. Bits 9-24 are the card number.'],
      }),
      d('1.2', 'Parity is not integrity', 'bronze', {
        scenario: 'wiegand-implant',
        summary: 'Flip a bit in the card number, fix the parity bits, watch the panel accept a different badge.',
        objective: 'Get a frame to the controller that parses cleanly, has valid parity, and carries a card number no credential ever presented.',
        flagText: 'A frame reaches the controller that parses cleanly, has valid parity, and carries a card number never presented to the reader.',
        predicate: { kind: 'frame', frameKind: 'wiegand_substituted' },
        bronzeSteps: ['The tap is already inline on the reader→controller link.', 'Open the tap panel and set Rewrite card number.', 'Run. Compare the two D0/D1 frames — both have valid parity.'],
      }),
      d('1.3', 'Replay', 'bronze', {
        scenario: 'wiegand-replay',
        summary: 'Sniff one badge-in, unplug the card, re-emit the captured bits.',
        objective: 'Make the controller grant access at a time when no credential was presented to the reader.',
        flagText: 'The controller grants access at a time when no credential was presented to the reader.',
        predicate: { kind: 'reach', event: 'grant', after: 10_000_000 },
        bronzeSteps: ['Place a tap on the reader→controller link (click the link, choose Sniff).', 'Run to the first badge-in. The tap captures it.', 'Run on. At t=13.5 s the tap re-emits with no card anywhere near the reader.'],
        hints: ['The second grant has no RF frame before it. That absence is the finding.'],
      }),
      d('1.4', 'The implant', 'silver', {
        scenario: 'wiegand-implant',
        summary: 'Insert an inline device between reader and panel. Pass everything through untouched, then selectively rewrite one credential into another.',
        objective: 'Grant on a substituted credential while the reader\'s own output stays unchanged.',
        flagText: 'The tap is inline, the reader\'s credential was consumed, and the controller granted on a substituted one — with the reader\'s output unchanged.',
        predicate: { kind: 'all', of: [{ kind: 'tap', mode: 'inline', link: 'reader-controller' }, { kind: 'frame', frameKind: 'wiegand_substituted' }] },
        hints: ['A sniff tap will not do it. The link has to be cut — look at the topology while you switch the mode.'],
      }),
      d('1.5', 'What brute force actually costs', 'silver', {
        scenario: 'wiegand-replay',
        summary: 'Sweep a facility code at real wire timing. Watch the clock.',
        objective: 'Not a flag — a number. Read the wall-clock cost of the full 26-bit space at your chosen timing, and compare it to 1.3.',
        flagText: 'No flag. The drill ends by showing the wall-clock cost of the full 26-bit space at the timing you chose.',
        predicate: { kind: 'task', taskId: 'wiegand-sweep' },
        hints: ['The bar in the drill panel is the real sweep. It is not going to finish while you are here. That is the point.'],
      }),
      d('1.6', 'Clock-and-data', 'silver', {
        scenario: 'wiegand-replay',
        summary: 'The same exercise on ABA track 2. Different encoding, identical outcome.',
        objective: 'Replay successfully on a clock-and-data link.',
        flagText: 'Replay succeeds on a clock-and-data link.',
        predicate: { kind: 'reach', event: 'grant', after: 10_000_000 },
        hints: ['Switch the link encoding in the link panel first, then run the same replay.'],
      }),
    ],
  },
  {
    id: 'm2', number: 2, title: 'OSDP as it is usually deployed',
    blurb: 'The replacement for Wiegand, shipped with its one security feature switched off.',
    drills: [
      d('2.1', 'Reading the bus', 'bronze', {
        scenario: 'osdp-clear',
        summary: 'A controller polling a reader. Identify SOM, address, length, control byte, sequence number, command code, CRC. Find the card read.',
        objective: 'Label the byte offsets of a frame the engine generated.',
        flagText: 'Learner correctly labels the byte offsets of a generated frame.',
        predicate: { kind: 'inspect', frameKind: 'poll', fieldId: 'code' },
        bronzeSteps: ['Press Run for a second, then Pause. Look at how many frames that was.', 'Select any POLL row.', 'Walk the decode tree top to bottom. Each field highlights its own bytes.'],
        hints: ['The control byte is one byte doing three jobs: sequence, CRC flag, security-block flag.'],
      }),
      d('2.2', 'It is still in the clear', 'bronze', {
        scenario: 'osdp-clear',
        summary: 'No Secure Channel configured. Sniff a badge-in.',
        objective: 'Extract a card number matching the presented credential from passive observation only — zero frames injected.',
        flagText: 'The attacker actor extracted a card number matching the credential, from passive observation only.',
        predicate: { kind: 'inspect', frameKind: 'raw', fieldId: 'cr_bits' },
        bronzeSteps: ['Check the bench state strip: Secure Channel is off, and you can see that it is off.', 'Run to t=8.2 s.', 'Select the RAW row. The card bits are right there in the payload.'],
      }),
      d('2.3', 'Injection on an unsecured bus', 'bronze', {
        scenario: 'osdp-inject',
        summary: 'Nothing authenticates the controller. Send your own commands.',
        objective: 'Get the PD to ACK a command that came from the attacker.',
        flagText: 'The PD ACKs a command originated by the attacker actor.',
        predicate: { kind: 'frame', frameKind: 'out_injected' },
        bronzeSteps: ['Place a tap on the reader↔controller bus and set it to Inject.', 'Run past t=14 s.', 'The PD ACKs. It has no way to know the frame was not the controller\'s.'],
      }),
      d('2.4', 'Sequence numbers and BUSY', 'silver', {
        scenario: 'osdp-clear',
        summary: 'What the protocol does defend against — desynchronised sequence numbers, retries, the BUSY reply — and why none of it is security.',
        objective: 'Recover a desynchronised link without resetting the simulation.',
        flagText: 'The learner recovers a desynchronised link without resetting the simulation.',
        predicate: { kind: 'inspect', frameKind: 'poll', fieldId: 'ctrl_seq' },
        hints: ['Two bits of sequence. It wraps every four frames. Ask yourself what that can possibly stop.'],
      }),
    ],
  },
  {
    id: 'm3', number: 3, title: 'Secure Channel',
    blurb: 'The handshake, the keys, and the five ways the key gets out anyway.',
    drills: [
      d('3.1', 'The handshake, step by step', 'bronze', {
        scenario: 'osdp-secure',
        summary: 'CHLNG, CCRYPT, SCRYPT, RMAC_I. Watch the keys derive. Every intermediate value visible.',
        objective: 'Predict the client cryptogram before the engine transmits it, given the key and both nonces.',
        flagText: 'The learner predicts the client cryptogram before the engine transmits it.',
        predicate: { kind: 'inspect', frameKind: 'ccrypt', fieldId: 'payload' },
        bronzeSteps: ['Step to t=0.2 s with the step control.', 'Select each of the four handshake frames in turn: CHLNG, CCRYPT, SCRYPT, RMAC_I.', 'The security block type byte names each stage. Read it in the decode tree.'],
      }),
      d('3.2', 'The default key', 'bronze', {
        scenario: 'osdp-secure',
        summary: 'A PD commissioned with SCBK-D. Recognise it from the security block byte, then decrypt everything.',
        objective: 'Hold the session keys and decrypt a card read, given only bus traffic.',
        flagText: 'The attacker holds the session keys and has decrypted a card read, given only the bus traffic.',
        predicate: { kind: 'inspect', frameKind: 'chlng', fieldId: 'scb_data' },
        bronzeSteps: ['Select the CHLNG frame.', 'Open the security block. The key-type byte reads 00.', '00 is SCBK-D, the published default. It is sent before any encryption exists, so you learned it for free.'],
      }),
      d('3.3', 'Weak keys', 'silver', {
        scenario: 'osdp-secure',
        summary: 'A site key that is not SCBK-D but is still from the sample-code family. Recover it from a captured handshake.',
        objective: 'Recover the PD\'s configured SCBK from capture alone.',
        flagText: 'Attacker-recovered SCBK equals the PD\'s configured SCBK, recovered from capture alone.',
        predicate: { kind: 'attacker', has: 'keys' },
        hints: ['The sample-code family is about 768 patterns: repeated bytes, ascending runs, descending runs. That is not a key space.'],
      }),
      d('3.4', 'Install mode', 'silver', {
        scenario: 'osdp-secure',
        summary: 'A controller left in install mode. Ask it for the key. It tells you.',
        objective: 'Hold the SCBK, having sent nothing but legitimate protocol requests.',
        flagText: 'Attacker holds the SCBK and the only frames it sent were legitimate protocol requests.',
        predicate: { kind: 'config', group: 'controller', field: 'acuInstallMode', value: true },
        hints: ['Install mode is in the controller panel. Turn it on and watch what becomes askable.'],
      }),
      d('3.5', 'Keyset capture', 'silver', {
        scenario: 'osdp-secure',
        summary: 'Be on the bus during commissioning. There is no key exchange to attack because there is no key exchange.',
        objective: 'Capture a CMD_KEYSET payload and decrypt subsequent traffic.',
        flagText: 'Attacker captured a CMD_KEYSET payload and can decrypt subsequent traffic.',
        predicate: { kind: 'tap', mode: 'sniff', link: 'reader-controller' },
        hints: ['The key is sent to the reader over the link it is meant to protect, in the clear, once, at commissioning.'],
      }),
      d('3.6', 'Downgrade', 'gold', {
        scenario: 'osdp-downgrade',
        summary: 'Inline. Rewrite the PDCAP reply so the reader claims it cannot do crypto. The controller believes it.',
        objective: 'Reach a steady state carrying card reads with no security block, where both endpoints were configured to require Secure Channel.',
        flagText: 'The link reaches a steady state carrying card reads with no security block, where both endpoints required Secure Channel.',
        predicate: { kind: 'all', of: [{ kind: 'tap', mode: 'inline', link: 'reader-controller' }, { kind: 'frame', frameKind: 'pdcap_downgraded' }] },
      }),
    ],
  },
  {
    id: 'm4', number: 4, title: 'The weaknesses nobody mentions',
    blurb: 'Not the five headline attacks. The ones that survive doing everything right.',
    drills: [
      d('4.1', 'Traffic analysis through encryption', 'silver', {
        scenario: 'osdp-secure-day',
        summary: 'The command byte is plaintext even inside Secure Channel. You cannot read the card number. You can read the building\'s schedule.',
        objective: 'Report the times of every badge-in over a simulated day, correct to the engine\'s log, without ever holding a key.',
        flagText: 'The learner reports the times of every badge-in over a simulated day, correct to the engine\'s log, holding no key.',
        note: 'This mock hands you 40 seconds of bus carrying seven badge-ins. The real engine generates a full simulated day; the technique and the answer are read exactly the same way.',
        predicate: { kind: 'inspect', frameKind: 'raw', fieldId: 'code' },
        hints: ['Do not fight the ciphertext. Filter the traffic list to reply code 0x50 and read the timestamps.', 'The collapse-idle-polling control makes the shape obvious — but notice what you gave up to see it.'],
      }),
      d('4.2', 'Truncated MACs', 'gold', {
        scenario: 'osdp-secure',
        summary: '32 bits of MAC. Compute what that is worth.',
        objective: 'Produce a frame the PD accepts whose MAC was not derived from the session key.',
        flagText: 'The learner produces a frame the PD accepts whose MAC was not derived from the session key.',
        predicate: { kind: 'task', taskId: 'mac-forge' },
        note: 'The engine runs this with a shortened MAC so it completes in seconds. Alongside it, the genuine 32-bit computation starts and keeps running. It will still be running when you close the tab.',
      }),
      d('4.3', 'IV reuse', 'gold', {
        scenario: 'osdp-secure',
        summary: 'IVs derive from the previous MAC. Find the collision, recover plaintext.',
        objective: 'Recover a plaintext payload from two frames sharing an IV.',
        flagText: 'Attacker recovers a plaintext payload from two frames sharing an IV.',
        predicate: { kind: 'attacker', has: 'plaintext' },
      }),
      d('4.4', 'The null ciphers', 'silver', {
        scenario: 'osdp-null-cipher',
        summary: 'SCS_15 and SCS_16 authenticate without encrypting. Some deployments use them believing otherwise.',
        objective: 'Read a card number from a MACed-but-unencrypted link.',
        flagText: 'Attacker reads a card number from a MACed-but-unencrypted link.',
        predicate: { kind: 'inspect', frameKind: 'raw', fieldId: 'cr_bits' },
        hints: ['Check the bench state strip. It says SCS_15/16. The MAC is real; the encryption is absent.'],
      }),
    ],
  },
  {
    id: 'm5', number: 5, title: 'The other chair',
    blurb: 'Every module above, replayed from a monitoring position. Same traffic, odr-detect running, and the question is what a defender could have concluded and when.',
    drills: [
      d('5.1', 'What a passive monitor can see', 'silver', {
        scenario: 'osdp-secure',
        summary: 'Which of the four attacks in module 3 are visible to a passive monitor at all?',
        objective: 'Classify each module 3 attack as visible or invisible to a passive monitor, and say what the observable is.',
        flagText: 'Scored on true positives and false positives against a generated day of traffic.',
        predicate: { kind: 'ruleset', need: 'complete' },
      }),
      d('5.2', 'A rule that catches the downgrade', 'gold', {
        scenario: 'osdp-downgrade',
        summary: 'Build a detection rule that catches the downgrade and does not fire on a genuine legacy reader being added to the bus.',
        objective: 'Write a rule with a true positive on the downgrade and no false positive on the legacy reader.',
        flagText: 'The rule set is scored on true positives and false positives.',
        predicate: { kind: 'ruleset', need: 'downgrade' },
        hints: ['A reader that never could do crypto has always said so. A downgraded one said otherwise thirty seconds ago.'],
      }),
      d('5.3', 'Install mode in a log', 'silver', {
        scenario: 'osdp-secure',
        summary: 'What does install mode look like in a log, and why is it usually indistinguishable from a real commissioning?',
        objective: 'Identify the frames, and say honestly what separates the attack from a technician doing their job.',
        flagText: 'Scored on true positives and false positives.',
        predicate: { kind: 'ruleset', need: 'keyset' },
      }),
    ],
  },
];

const DRILL_INDEX = new Map();
for (const m of MODULES) for (const dr of m.drills) DRILL_INDEX.set(dr.id, Object.assign({ moduleId: m.id, moduleTitle: m.title, moduleNumber: m.number }, dr));

/* ------------------------------------------------------------------ *
 * Module 5 — the rule catalogue, a canned day, and a scorer
 *
 * ENGINE-API.md §13. Module 5's drills ask a learner to BUILD a detection
 * rule set rather than pick one, so the contract carries three calls:
 * ruleCatalog(), setRules() and detection().
 *
 * What is canned here is the DAY and the findings each rule would produce on
 * it — hand-written, and honest about being hand-written. What is not canned
 * is the mechanism: a composition selects rules and sets their parameters, the
 * rules produce findings, and the findings are scored against an answer key
 * that includes benign events. A set that alerts on everything scores badly
 * here for the same reason it does in odr-detect — because the key contains
 * traffic that is supposed to look like an attack and is not.
 *
 * The real engine derives every one of these findings by running detectors
 * over bytes a simulated bus produced. See ENGINE-API.md §12.
 * ------------------------------------------------------------------ */

const SIGNAL_TEXT = {
  cleartext_bus: 'this address is being talked to with no encryption and no authentication',
  sensitive_command_in_clear: 'a command that opens a door or moves a peripheral crossed the bus unprotected',
  default_key_in_use: 'the secure channel is keyed with the published default key',
  null_cipher: 'secure channel is established and the payloads are not encrypted',
  keyset_observed: 'a secure channel base key was pushed to a peripheral',
  capability_downgrade: 'a peripheral stopped claiming AES-128 support that it previously claimed',
  secure_channel_lost: 'an address that ran Secure Channel is now in the clear without re-handshaking',
  device_identity_changed: 'a different device is answering at this address',
  sequence_anomaly: 'a frame’s sequence number does not follow the cycle',
  cadence_violation: 'a command arrived before the previous one was answered',
  unsolicited_reply: 'a reply arrived that no command asked for',
  duplicate_address: 'two devices answered to the same address',
  replayed_frame: 'a byte-identical frame carrying a payload was sent twice',
  replayed_credential: 'the same credential appeared twice, faster than a person could present it',
  unauthenticated_wire: 'this is a two-wire link, so anything driven onto it will be believed',
  malformed_credential: 'bits on the wire fit no known card format with valid parity',
  traffic_pattern_exposed: 'the building’s badge-in schedule is readable from the traffic',
};

const sig = (id) => ({ id, describes: SIGNAL_TEXT[id] || '' });

/** The selectable rules. Mirrors odr_detect::catalog::RULES. */
const RULE_CATALOGUE = [
  {
    id: 'posture', label: 'Posture — unsecured traffic, per address', inStandard: true,
    catches: 'a run of frames for one address carrying no security block: that peripheral’s traffic is readable and forgeable, and the door command on it is copyable.',
    falsePositives: 'nothing benign, but it is loud by design — it reports what a link is configured to be. Drop the frame threshold to 1 or 2 and every properly secured link reports too, because a handshake’s own first frames are unsecured.',
    signals: ['cleartext_bus', 'sensitive_command_in_clear'].map(sig),
    params: [
      { id: 'min_frames', label: 'Frames before a run is called', type: 'count', min: 1, max: 512, default: 8, help: 'A handshake begins in the clear, and so does the ID/CAP exchange before one. Below about eight this rule starts reporting every secured link on the bus.' },
      { id: 'gap_us', label: 'Silence that ends a run', type: 'duration', unit: 'us', min: 100000, max: 600000000, default: 30000000, help: 'A link that went quiet is not a link that went insecure.' },
      { id: 'max_evidence', label: 'Frames cited per finding', type: 'count', min: 1, max: 64, default: 6, help: 'A four-hour cleartext run should cite the first, the last and enough in between to show it was continuous.' },
    ],
  },
  {
    id: 'keys', label: 'Keys — the default key, and the null ciphers', inStandard: true,
    catches: 'SCBK-D named in the clear in the handshake’s key-type byte, and SCS_15/16 frames carrying a payload: authenticated, not encrypted.',
    falsePositives: 'an ordinary encrypted bus is full of SCS_15 frames, because an empty payload has nothing to encrypt — the rule ignores those, and a version that did not would fire on every healthy secured link.',
    signals: ['default_key_in_use', 'null_cipher'].map(sig),
    params: [
      { id: 'trust_capability_claim', label: 'Believe a capability reply that admits to SCBK-D', type: 'toggle', min: 0, max: 1, default: 1, help: 'On: report the default key as soon as a REPLY_PDCAP admits to it. Off: wait for a handshake to use it.' },
    ],
  },
  {
    id: 'keyset', label: 'Keyset — a base key pushed to a peripheral', inStandard: true,
    catches: 'CMD_KEYSET on the bus, and whether the key was recoverable from the capture. Curriculum 3.4 and 3.5 from the other chair.',
    falsePositives: 'every commissioning, on purpose. The frame is unmistakable and its authorisation is in no frame, so the finding is ambiguous and the scorer counts it in neither precision nor recall. Drill 5.3’s whole answer.',
    signals: ['keyset_observed'].map(sig),
    params: [
      { id: 'show_recovered_key', label: 'Print the recovered key in the evidence note', type: 'toggle', min: 0, max: 1, default: 1, help: 'Seeing the key written out beside the frame it came from is the lesson of curriculum 3.5. The key material is simulated.' },
    ],
  },
  {
    id: 'downgrade', label: 'Downgrade — a peripheral that stopped claiming AES-128', inStandard: true,
    catches: 'an address that used to claim AES-128 and no longer does, and an address that ran Secure Channel and is now in the clear without re-handshaking. The rule drill 5.2 is about.',
    falsePositives: 'with the identity check on: nothing in the day. With it off: every reader swap in the building. A reader that has never claimed AES-128 is never reported either way, which is why a legacy reader being added is not a false positive here.',
    signals: ['capability_downgrade', 'secure_channel_lost', 'device_identity_changed'].map(sig),
    params: [
      { id: 'require_same_identity', label: 'Require REPLY_PDID to be unchanged', type: 'toggle', min: 0, max: 1, default: 1, help: 'On: a capability drop at an address whose reported identity also changed is a reader replacement. Off: it is reported as a downgrade — which catches an attacker who rewrote REPLY_PDID too, and alerts on every genuine reader swap. REPLY_PDID is as unauthenticated as REPLY_PDCAP, so this buys quiet, not security.' },
      { id: 'resync_grace_us', label: 'Grace for a reader coming back', type: 'duration', unit: 'us', min: 0, max: 120000000, default: 5000000, help: 'A reader power-cycling produces a short unsecured burst before the channel returns. Shorter than the real recovery and this rule calls a reboot an attack.' },
      { id: 'min_unsecured_run', label: 'Unsecured frames before the channel is called lost', type: 'count', min: 1, max: 256, default: 4, help: 'How many frames with no security block, at an address known to have run one, before it counts as lost rather than as a gap.' },
    ],
  },
  {
    id: 'injection', label: 'Injection — the conversation broken', inStandard: true,
    catches: 'the two-bit sequence cycle, the command-then-reply cadence, a reply nothing asked for, and one poll drawing two different answers from one address.',
    falsePositives: 'a retransmission, a sequence reset and a peripheral that has gone offline all look like this. A well-formed frame sent in the gap between polls is deliberately not reported at all.',
    signals: ['sequence_anomaly', 'cadence_violation', 'unsolicited_reply', 'duplicate_address'].map(sig),
    params: [
      { id: 'min_command_gap_us', label: 'Two commands closer than this are not a retry', type: 'duration', unit: 'us', min: 0, max: 60000000, default: 20000, help: 'Twenty milliseconds is an order of magnitude below any realistic reply timeout. Raise it past the timeout and every retry becomes an alert.' },
      { id: 'gap_us', label: 'Silence that resets continuity', type: 'duration', unit: 'us', min: 100000, max: 600000000, default: 30000000, help: 'A monitor that was not listening has no standing to say the next sequence number is wrong.' },
      { id: 'max_per_kind', label: 'Findings per kind', type: 'count', min: 1, max: 256, default: 8, help: 'A thoroughly broken link should report a problem, not ten thousand of them.' },
    ],
  },
  {
    id: 'replay', label: 'Replay — a frame or a credential seen twice', inStandard: true,
    catches: 'a reply byte-identical to an earlier one that no outstanding command asked for, and the same credential twice inside the time a person needs to present a badge twice.',
    falsePositives: 'a person badging twice. The sequence number is two bits, so two genuine reads of the same card seconds apart are byte-for-byte identical, CRC included. Raise the human interval and an honest double badge-in becomes an alert.',
    signals: ['replayed_frame', 'replayed_credential'].map(sig),
    params: [
      { id: 'frame_window_us', label: 'How far back to look for an identical frame', type: 'duration', unit: 'us', min: 1000, max: 600000000, default: 30000000, help: 'Longer sees more replays and more coincidences.' },
      { id: 'credential_window_us', label: 'How far back to look for the same credential', type: 'duration', unit: 'us', min: 1000, max: 600000000, default: 30000000, help: 'The same as above, for the card rather than the bytes.' },
      { id: 'human_min_us', label: 'Fastest a person can present a badge twice', type: 'duration', unit: 'us', min: 0, max: 60000000, default: 800000, help: '800 ms, and it is a claim about hands rather than about protocols. Set it above a few seconds and honest double badge-ins are reported as attacks.' },
      { id: 'max_per_kind', label: 'Findings per kind', type: 'count', min: 1, max: 256, default: 8, help: 'A cap, so one broken link does not fill the console.' },
    ],
  },
  {
    id: 'wire', label: 'Wire — a two-wire link, and bits that fit no format', inStandard: true,
    catches: 'the existence of a D0/D1 or clock-and-data pair, which has no authentication to check, and credential bits that fit no known format with valid parity.',
    falsePositives: 'none worth the name. What it cannot do is more interesting: it cannot tell a replayed badge from a re-badged one, and it cannot tell which card format a frame is, because the wire does not say.',
    signals: ['unauthenticated_wire', 'malformed_credential'].map(sig),
    params: [
      { id: 'gap_us', label: 'Silence that starts a new run', type: 'duration', unit: 'us', min: 100000, max: 600000000, default: 30000000, help: 'One posture finding per stretch of wire traffic.' },
      { id: 'max_malformed', label: 'Malformed-credential findings', type: 'count', min: 1, max: 256, default: 8, help: 'A cap. A reader emitting garbage emits a lot of it.' },
    ],
  },
  {
    id: 'traffic', label: 'Traffic analysis — the schedule, through the encryption', inStandard: true,
    catches: 'the times of every badge-in, readable with no key, because the command and reply id byte is plaintext inside Secure Channel. Curriculum 4.1’s answer.',
    falsePositives: 'it fires on healthy buses on purpose — that is the finding. Turning on Secure Channel fixes the card numbers and does not fix this.',
    signals: ['traffic_pattern_exposed'].map(sig),
    params: [
      { id: 'min_events', label: 'Presentations before a schedule is a pattern', type: 'count', min: 1, max: 512, default: 3, help: 'One badge-in is not a pattern. Three is a shift.' },
      { id: 'max_listed', label: 'Times listed in the note', type: 'count', min: 1, max: 256, default: 12, help: 'How many presentation times to write out in the evidence.' },
    ],
  },
];

const RULE_BY_ID = new Map(RULE_CATALOGUE.map((r) => [r.id, r]));

const RULE_PRESETS = [
  { id: 'empty', label: 'Nothing at all — the honest floor', help: 'No rules. It catches nothing and it cries wolf about nothing, which is the floor every other score should be read against.' },
  { id: 'standard', label: 'The standard set — the worked answer', help: 'All eight rules at their default tuning. Read its score with suspicion: the answer key and these detectors were written by the same hand.' },
  { id: 'strict', label: 'Strict downgrade — catches more, cries wolf', help: 'Posture, keys, keyset and the downgrade rule with its identity check turned off. It catches the attacker who rewrote REPLY_PDID as well, and it alerts on every genuine reader swap.' },
];

const S = 1_000_000;

/** The day the rule set is scored against. Times are the episode spans. */
const MOCK_EPISODES = [
  { id: 'secure_baseline', startUs: 0, endUs: 30 * S, describes: 'a healthy bus under a site key; establishes what address 0x01 normally claims' },
  { id: 'reader_power_cycle', startUs: 90 * S, endUs: 120 * S, describes: 'benign: the reader reboots and the link resynchronises, which looks like a sequence attack and like a lost secure channel' },
  { id: 'legacy_reader_added', startUs: 180 * S, endUs: 210 * S, describes: 'benign: a genuinely legacy reader joins the bus at a new address and cannot do crypto, which looks exactly like a downgrade to a naive rule' },
  { id: 'commissioning', startUs: 270 * S, endUs: 300 * S, describes: 'ambiguous: an installer pushes a site key, which is byte-for-byte what an attacker in install mode would do' },
  { id: 'reader_replaced', startUs: 360 * S, endUs: 390 * S, describes: 'benign: a reader is swapped for a legacy model at the same address, dropping the AES claim without anybody attacking anything' },
  { id: 'cleartext_bus', startUs: 450 * S, endUs: 480 * S, describes: 'a bus with no Secure Channel at all, containing a person badging twice' },
  { id: 'downgrade', startUs: 540 * S, endUs: 570 * S, describes: 'attack: an inline implant rewrites the capability reply so the controller talks in the clear to a reader that can do better' },
  { id: 'bus_replay', startUs: 630 * S, endUs: 660 * S, describes: 'attack: a captured card read is put back on the bus verbatim' },
  { id: 'wiegand_door', startUs: 720 * S, endUs: 750 * S, describes: 'a two-wire door: one replayed credential among genuine ones, on a link with no authentication to check' },
];

/** The answer key. Built from the scenario script, never from the findings. */
const MOCK_EXPECTED = [
  { signal: 'traffic_pattern_exposed', tUs: 12 * S, windowUs: 60 * S, verdict: 'weakness', label: 'the badge-in schedule is readable from the traffic although the payloads are encrypted' },
  { signal: 'cleartext_bus', tUs: 181 * S, windowUs: 30 * S, verdict: 'weakness', label: 'the legacy reader at 0x02 is talked to in the clear, on a bus that is otherwise secured' },
  { signal: 'default_key_in_use', tUs: 271 * S, windowUs: 30 * S, verdict: 'weakness', label: 'the reader arrived on SCBK-D, so the channel that carried the site key was keyed with a published key' },
  { signal: 'keyset_observed', tUs: 278 * S, windowUs: 30 * S, verdict: 'ambiguous', label: 'a CMD_KEYSET pushed the site key; the wire cannot say whether it was authorised' },
  { signal: 'device_identity_changed', tUs: 364 * S, windowUs: 30 * S, verdict: 'ambiguous', label: 'REPLY_PDID at 0x04 reports a different device; the wire cannot say whether the swap was authorised' },
  { signal: 'cleartext_bus', tUs: 451 * S, windowUs: 30 * S, verdict: 'weakness', label: 'no Secure Channel at all on the bus at 0x05' },
  { signal: 'sensitive_command_in_clear', tUs: 452 * S, windowUs: 30 * S, verdict: 'weakness', label: 'the CMD_OUT that opens the door crosses the bus unprotected and can simply be copied' },
  { signal: 'capability_downgrade', tUs: 544 * S, windowUs: 30 * S, verdict: 'attack', label: 'the reader at 0x01 stopped claiming AES-128 it has claimed all day, with the same reported identity' },
  { signal: 'secure_channel_lost', tUs: 545 * S, windowUs: 30 * S, verdict: 'attack', label: 'an address that has run Secure Channel is now carrying card reads in the clear' },
  { signal: 'duplicate_address', tUs: 640 * S, windowUs: 30 * S, verdict: 'attack', label: 'the played-back frame is a second answer to a poll the real reader had already answered' },
  { signal: 'replayed_frame', tUs: 634 * S, windowUs: 30 * S, verdict: 'attack', label: 'a byte-identical card-read frame appeared again, with a conversation in between' },
  { signal: 'unauthenticated_wire', tUs: 720 * S, windowUs: 30 * S, verdict: 'weakness', label: 'a D0/D1 pair: nothing on it is authenticated, so anything driven onto it is believed' },
];

/** The things in the day that look like attacks and are not. */
const MOCK_BENIGN = [
  { tUs: 90 * S, durationUs: 30 * S, label: 'the reader at 0x01 power-cycled and the link resynchronised', looksLike: 'secure_channel_lost' },
  { tUs: 180 * S, durationUs: 30 * S, label: 'a genuinely legacy reader was added at 0x02: it has never claimed AES-128, so it has not been downgraded', looksLike: 'capability_downgrade' },
  { tUs: 270 * S, durationUs: 30 * S, label: 'an installer commissioned the door at 0x03', looksLike: 'keyset_observed' },
  { tUs: 360 * S, durationUs: 30 * S, label: 'a reader was replaced with a legacy model at the same address: the AES-128 claim disappears without anybody attacking anything', looksLike: 'capability_downgrade' },
  { tUs: 460 * S, durationUs: 10 * S, label: 'a person badged twice on the cleartext bus, four seconds apart', looksLike: 'replayed_credential' },
];

/** Cite a frame, the way the inspector renders one. */
function citeFrame(index, tUs, bytes, summary) {
  return {
    index, tUs, summary,
    bytes: bytes.slice(),
    hex: bytes.map((x) => hex(x)).join(' '),
  };
}

const PDCAP_LEGACY = [0x53, 0x01, 0x0e, 0x00, 0x04, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00];
const PDCAP_AES = [0x53, 0x01, 0x0e, 0x00, 0x04, 0x46, 0x09, 0x01, 0x01, 0x00, 0x00];
const RAW_READ = [0x53, 0x01, 0x10, 0x00, 0x06, 0x50, 0x00, 0x01, 0x1a, 0x00, 0x15, 0x60, 0x19];
const CMD_OUT = [0x53, 0x05, 0x0a, 0x00, 0x04, 0x68, 0x00, 0x01, 0x14, 0x00];
const KEYSET = [0x53, 0x03, 0x18, 0x00, 0x06, 0x75, 0x01, 0x10, 0x30, 0x31, 0x32, 0x33];

/**
 * What each rule concludes about this day, and under what tuning.
 *
 * `when` is the whole point: a parameter that is offered and changes nothing is
 * worse than a parameter that is not offered.
 */
const MOCK_FINDINGS = [
  // posture
  { rule: 'posture', signal: 'cleartext_bus', tUs: 182 * S, severity: 'high', confidence: 'certain',
    note: 'address 0x02: 41 consecutive frames over 8.2 s carried no security block, so nothing on this link is encrypted or authenticated. 2 of them report a credential, in the clear. Nothing here is an attack; this is what the link is configured to be.',
    frames: [citeFrame(812, 181 * S, PDCAP_LEGACY, 'PD->ACU REPLY_PDCAP (no AES-128 claimed)'), citeFrame(840, 182 * S, RAW_READ, 'PD->ACU REPLY_RAW 26 bits, in the clear')] },
  { rule: 'posture', signal: 'cleartext_bus', tUs: 452 * S, severity: 'high', confidence: 'certain',
    note: 'address 0x05: 118 consecutive frames over 27.4 s carried no security block. 4 of them report a credential, in the clear.',
    frames: [citeFrame(2110, 451 * S, RAW_READ, 'PD->ACU REPLY_RAW 26 bits, in the clear')] },
  { rule: 'posture', signal: 'sensitive_command_in_clear', tUs: 455 * S, severity: 'critical', confidence: 'certain',
    note: 'address 0x05: CMD_OUT — the command that fires the strike — crossed the bus with no security block. Anything on the pair can copy it.',
    frames: [citeFrame(2160, 455 * S, CMD_OUT, 'ACU->PD CMD_OUT, no security block')] },
  { rule: 'posture', signal: 'cleartext_bus', tUs: 2 * S, severity: 'high', confidence: 'certain',
    when: (p) => p.min_frames <= 3,
    note: 'address 0x01: 3 consecutive frames with no security block. These are the ID/CAP exchange and the first handshake frame of a perfectly healthy secured link — which is what a threshold this low reports.',
    frames: [citeFrame(4, 1 * S, PDCAP_AES, 'PD->ACU REPLY_PDCAP claiming AES-128')] },
  { rule: 'posture', signal: 'cleartext_bus', tUs: 92 * S, severity: 'high', confidence: 'certain',
    when: (p) => p.min_frames <= 3,
    note: 'address 0x01: 3 consecutive frames with no security block, during the reader’s reboot. The channel comes back four frames later.',
    frames: [citeFrame(410, 92 * S, PDCAP_AES, 'PD->ACU REPLY_PDCAP claiming AES-128')] },

  // keys
  { rule: 'keys', signal: 'default_key_in_use', tUs: 272 * S, severity: 'critical', confidence: 'certain',
    note: 'address 0x03: the handshake’s security block names key type 0x00, which is SCBK-D — the published default. Everything derived from it is derivable by anyone with the capture.',
    frames: [citeFrame(1250, 272 * S, [0x53, 0x03, 0x1a, 0x00, 0x0e, 0x02, 0x11, 0x00, 0x76], 'ACU->PD osdp_CHLNG, SCS_11, key type SCBK-D')] },

  // keyset
  { rule: 'keyset', signal: 'keyset_observed', tUs: 278 * S, severity: 'critical', confidence: 'ambiguous',
    note: 'address 0x03: a CMD_KEYSET crossed the bus inside a MAC-only security block (SCS_15), which authenticates and does not encrypt, so the key crossed as plaintext. Whether this was an installer commissioning a door or an attacker in install mode is not in any frame — OSDP has no notion of who a controller is, and the only thing separating the two is whether an installer was booked.',
    frames: [citeFrame(1288, 278 * S, KEYSET, 'ACU->PD CMD_KEYSET, SCS_15, 16-byte key in the clear')] },

  // downgrade
  { rule: 'downgrade', signal: 'capability_downgrade', tUs: 545 * S, severity: 'critical', confidence: 'probable',
    note: 'address 0x01: this capability reply does not claim AES-128, and the reply at 1.004 s from the same address did. Secure Channel has been observed established at this address, so the capability was not merely claimed — it was used. REPLY_PDID has reported the same vendor, model and serial throughout, so a reader replacement does not explain it. The capability exchange is unauthenticated and happens before any key material exists, which is why this is probable rather than certain: nothing on the wire proves the earlier reply was not the forged one.',
    frames: [citeFrame(4, 1 * S, PDCAP_AES, 'PD->ACU REPLY_PDCAP claiming AES-128'), citeFrame(2530, 545 * S, PDCAP_LEGACY, 'PD->ACU REPLY_PDCAP, AES-128 claim absent')] },
  { rule: 'downgrade', signal: 'secure_channel_lost', tUs: 550 * S, severity: 'high', confidence: 'probable',
    when: (p) => p.min_unsecured_run <= 6,
    note: 'address 0x01: 9 consecutive frames with no security block, spanning 4.8 s, at an address where Secure Channel has been observed established. No handshake frame appears in the run, so this is not a resynchronisation. The run includes a credential report in the clear.',
    frames: [citeFrame(2560, 548 * S, RAW_READ, 'PD->ACU REPLY_RAW 26 bits, in the clear'), citeFrame(2590, 550 * S, CMD_OUT, 'ACU->PD CMD_OUT, no security block')] },
  { rule: 'downgrade', signal: 'device_identity_changed', tUs: 364 * S, severity: 'info', confidence: 'certain',
    note: 'address 0x04: REPLY_PDID now reports vendor [00, 06, 8e] model 2 serial [11, 27, 00, 3a], which is not the device that was answering here before. Usually a reader was replaced. REPLY_PDID is unauthenticated, so an attacker already rewriting the capability reply can rewrite this one too — a changed identity is a reason to stop calling a capability drop an attack, not evidence that it was not one.',
    frames: [citeFrame(1700, 364 * S, [0x53, 0x04, 0x14, 0x00, 0x04, 0x45, 0x00, 0x06, 0x8e, 0x02], 'PD->ACU REPLY_PDID, new vendor and serial')] },
  { rule: 'downgrade', signal: 'capability_downgrade', tUs: 366 * S, severity: 'high', confidence: 'probable',
    when: (p) => p.require_same_identity === 0,
    note: 'address 0x04: this capability reply does not claim AES-128, and an earlier reply from the same address did. The identity check is OFF, so the fact that REPLY_PDID also changed was not allowed to explain it.',
    frames: [citeFrame(1702, 366 * S, PDCAP_LEGACY, 'PD->ACU REPLY_PDCAP, AES-128 claim absent')] },
  { rule: 'downgrade', signal: 'secure_channel_lost', tUs: 372 * S, severity: 'high', confidence: 'probable',
    when: (p) => p.require_same_identity === 0,
    note: 'address 0x04: 11 unsecured frames at an address that has run Secure Channel. With the identity check off, the swap does not reset the premise, so the replacement reader’s ordinary traffic is read as a channel that was lost.',
    frames: [citeFrame(1740, 372 * S, RAW_READ, 'PD->ACU REPLY_RAW 26 bits, in the clear')] },
  { rule: 'downgrade', signal: 'secure_channel_lost', tUs: 95 * S, severity: 'high', confidence: 'probable',
    when: (p) => p.resync_grace_us < 4_000_000,
    note: 'address 0x01: 5 unsecured frames spanning 3.9 s at an address that has run Secure Channel. A reader power-cycling recovers well inside 5 s; with the grace set below that, this reboot is reported as a lost channel.',
    frames: [citeFrame(412, 95 * S, PDCAP_AES, 'PD->ACU REPLY_PDCAP claiming AES-128 (the reader is coming back)')] },

  // injection
  { rule: 'injection', signal: 'duplicate_address', tUs: 640 * S, severity: 'high', confidence: 'probable',
    note: 'address 0x09: one poll drew two different replies. Either two devices are configured to the same address or something is answering for one that is not it.',
    frames: [citeFrame(3010, 640 * S, RAW_READ, 'PD->ACU REPLY_RAW (the real reader)'), citeFrame(3011, 640 * S, RAW_READ, 'PD->ACU REPLY_RAW (a second answer to the same poll)')] },
  { rule: 'injection', signal: 'sequence_anomaly', tUs: 96 * S, severity: 'medium', confidence: 'probable',
    when: (p) => p.gap_us > 60_000_000,
    note: 'address 0x01: the sequence number restarted at 0 rather than following the 1,2,3 cycle. With the continuity memory set this long, the silence while the reader rebooted was not allowed to reset it — so a power cycle reads as a sequence attack.',
    frames: [citeFrame(420, 96 * S, [0x53, 0x01, 0x08, 0x00, 0x00, 0x60], 'ACU->PD POLL, sequence 0')] },
  { rule: 'injection', signal: 'cadence_violation', tUs: 20 * S, severity: 'medium', confidence: 'probable',
    when: (p) => p.min_command_gap_us > 5_000_000,
    note: 'address 0x01: a second command arrived 50 ms after the first with no reply between them. At this threshold, the controller’s ordinary polling cadence is being read as an injection.',
    frames: [citeFrame(300, 20 * S, [0x53, 0x01, 0x08, 0x00, 0x02, 0x60], 'ACU->PD POLL')] },

  // replay
  { rule: 'replay', signal: 'replayed_frame', tUs: 641 * S, severity: 'high', confidence: 'probable',
    note: 'address 0x09: a byte-identical card-read frame appeared again seven seconds later, and nothing asked for it — the poll it should be answering had already been answered. Two genuine reads of the same card can be byte-identical, because the sequence number is only two bits; what makes this a replay is the conversation, not the bytes.',
    frames: [citeFrame(2980, 634 * S, RAW_READ, 'PD->ACU REPLY_RAW 26 bits'), citeFrame(3011, 641 * S, RAW_READ, 'PD->ACU REPLY_RAW 26 bits, identical, unsolicited')] },
  { rule: 'replay', signal: 'replayed_credential', tUs: 462 * S, severity: 'high', confidence: 'possible',
    when: (p) => p.human_min_us >= 4_000_000,
    note: 'address 0x05: the same credential appeared twice, four seconds apart. That is well inside the interval this rule has been told a person cannot manage — which is a claim about hands, not about protocols. A turnstile, a mantrap and a loading dock all behave differently.',
    frames: [citeFrame(2200, 458 * S, RAW_READ, 'PD->ACU REPLY_RAW 26 bits'), citeFrame(2240, 462 * S, RAW_READ, 'PD->ACU REPLY_RAW 26 bits, same credential')] },

  // wire
  { rule: 'wire', signal: 'unauthenticated_wire', tUs: 722 * S, severity: 'high', confidence: 'certain',
    note: 'a D0/D1 pair carrying 4 credential presentations. There is no authentication of any kind on this link — no sequence number, no CRC and no conversation — so anything driven onto it is believed. A replayed badge and a re-badged badge are the same bits.',
    frames: [citeFrame(3400, 722 * S, [0x1a, 0x00, 0x15, 0x60], 'wire 26 bits, H10301 facility 42 card 24601')] },

  // traffic
  { rule: 'traffic', signal: 'traffic_pattern_exposed', tUs: 25 * S, severity: 'medium', confidence: 'certain',
    when: (p) => p.min_events <= 12,
    note: '14 credential presentations over 12 minutes, 9 of them with encrypted payloads. The card numbers in those are not readable. The times are, because the reply id byte sits outside the encrypted payload: REPLY_RAW is 0x50 on the wire whether or not what follows it is ciphertext. Secure Channel bought confidentiality of the credential and nothing at all of the schedule.',
    frames: [citeFrame(120, 8 * S, RAW_READ, 'PD->ACU REPLY_RAW, SCS_18 (payload sealed, id byte in the clear)')] },
];

/** A rule at its defaults. */
function defaultParams(rule) {
  const out = {};
  for (const p of rule.params) out[p.id] = p.default;
  return out;
}

/** Parse a preset name or a composition. Mirrors RuleSetSpec::parse. */
function parseRuleSet(text) {
  const trimmed = String(text == null ? '' : text).trim();
  if (trimmed === 'empty') return { name: 'nothing at all', rules: [] };
  if (trimmed === 'standard') {
    return {
      name: 'standard',
      rules: RULE_CATALOGUE.map((r) => ({ id: r.id, params: defaultParams(r) })),
    };
  }
  if (trimmed === 'strict') {
    const rules = ['posture', 'keys', 'keyset', 'downgrade']
      .map((id) => ({ id, params: defaultParams(RULE_BY_ID.get(id)) }));
    rules[3].params.require_same_identity = 0;
    return { name: 'strict downgrade', rules };
  }
  const spec = { name: 'composed', rules: [] };
  if (!trimmed) return spec;
  for (const entry of trimmed.split(';')) {
    const part = entry.trim();
    if (!part) continue;
    const colon = part.indexOf(':');
    const ruleId = (colon < 0 ? part : part.slice(0, colon)).trim();
    const rule = RULE_BY_ID.get(ruleId);
    if (!rule) throw new Error(`no rule called "${ruleId}"`);
    if (spec.rules.some((r) => r.id === ruleId)) continue;
    const params = defaultParams(rule);
    if (colon >= 0) {
      for (const assignment of part.slice(colon + 1).split(',')) {
        const a = assignment.trim();
        if (!a) continue;
        const eq = a.indexOf('=');
        if (eq < 0) throw new Error(`"${a}" is not a parameter assignment; write name=value`);
        const paramId = a.slice(0, eq).trim();
        const p = rule.params.find((x) => x.id === paramId);
        if (!p) throw new Error(`rule "${ruleId}" has no parameter "${paramId}"`);
        const raw = a.slice(eq + 1).trim();
        if (!/^\d+$/.test(raw)) throw new Error(`${ruleId}.${paramId} was given "${raw}", which is not a whole number`);
        const value = Number(raw);
        if (value < p.min || value > p.max) throw new Error(`${ruleId}.${paramId} accepts ${p.min}..=${p.max}, not ${value}`);
        params[paramId] = value;
      }
    }
    spec.rules.push({ id: ruleId, params });
  }
  spec.rules.sort((a, b) => RULE_CATALOGUE.findIndex((r) => r.id === a.id) - RULE_CATALOGUE.findIndex((r) => r.id === b.id));
  const preset = matchingPreset(spec);
  if (preset) spec.name = preset === 'empty' ? 'nothing at all' : (preset === 'strict' ? 'strict downgrade' : 'standard');
  return spec;
}

/** One line of text, defaults omitted. Mirrors RuleSetSpec::encode. */
function encodeRuleSet(spec) {
  return spec.rules.map((r) => {
    const rule = RULE_BY_ID.get(r.id);
    const changed = rule.params
      .filter((p) => r.params[p.id] !== p.default)
      .map((p) => `${p.id}=${r.params[p.id]}`);
    return changed.length ? `${r.id}:${changed.join(',')}` : r.id;
  }).join(';');
}

function sameRuleSet(a, b) {
  if (a.rules.length !== b.rules.length) return false;
  return a.rules.every((r, i) => {
    const o = b.rules[i];
    return r.id === o.id && Object.keys(r.params).every((k) => r.params[k] === o.params[k]);
  });
}

function matchingPreset(spec) {
  for (const p of RULE_PRESETS) {
    const preset = p.id === 'empty' ? { rules: [] }
      : p.id === 'standard' ? parseRuleSet('standard')
        : parseRuleSet('strict');
    if (sameRuleSet(spec, preset)) return p.id;
  }
  return null;
}

function episodeAt(tUs) {
  const e = MOCK_EPISODES.find((x) => tUs >= x.startUs && tUs <= x.endUs);
  return e ? { id: e.id, describes: e.describes } : null;
}

/** Run the composed set over the canned day. */
function runRuleSet(spec) {
  const out = [];
  for (const chosen of spec.rules) {
    for (const f of MOCK_FINDINGS) {
      if (f.rule !== chosen.id) continue;
      if (f.when && !f.when(chosen.params)) continue;
      out.push({
        signal: f.signal, describes: SIGNAL_TEXT[f.signal] || '',
        tUs: f.tUs, severity: f.severity, confidence: f.confidence,
        note: f.note, frames: f.frames, frameCount: f.frames.length,
        episode: episodeAt(f.tUs),
      });
    }
  }
  // The canonical order odr-detect's Report::new imposes.
  out.sort((a, b) => a.tUs - b.tUs || a.signal.localeCompare(b.signal));
  return out;
}

/** Score a report against the key. Mirrors AnswerKey::score. */
function scoreRuleSet(spec) {
  const findings = runRuleSet(spec);
  const used = findings.map(() => false);
  const caught = [];
  const ambiguousHits = [];
  const missed = [];

  for (const e of MOCK_EXPECTED) {
    const i = findings.findIndex((f, idx) => !used[idx]
      && f.signal === e.signal && f.tUs >= e.tUs && f.tUs <= e.tUs + e.windowUs);
    if (i < 0) {
      if (e.verdict !== 'ambiguous') missed.push({ signal: e.signal, describes: SIGNAL_TEXT[e.signal], label: e.label, verdict: e.verdict, tUs: e.tUs, episode: episodeAt(e.tUs) });
      continue;
    }
    used[i] = true;
    const hit = Object.assign({}, findings[i], {
      label: e.label, verdict: e.verdict, expectedUs: e.tUs,
      latencyUs: Math.max(0, findings[i].tUs - e.tUs),
    });
    if (e.verdict === 'ambiguous') ambiguousHits.push(hit); else caught.push(hit);
  }

  const falsePositives = findings
    .filter((_, i) => !used[i])
    .map((f) => {
      const b = MOCK_BENIGN.find((x) => f.tUs >= x.tUs && f.tUs <= x.tUs + x.durationUs);
      return Object.assign({}, f, { benign: b ? b.label : null });
    });

  const scored = caught.length + falsePositives.length;
  const total = caught.length + missed.length;
  const latencies = caught.map((h) => h.latencyUs);
  return {
    ran: true,
    ruleSet: selectionOf(spec),
    evidenceChecks: true,
    score: {
      findings: findings.length,
      truePositives: caught.length,
      falsePositives: falsePositives.length,
      falseNegatives: missed.length,
      ambiguous: ambiguousHits.length,
      precisionPct: scored === 0 ? 100 : Math.floor((caught.length * 100) / scored),
      recallPct: total === 0 ? 100 : Math.floor((caught.length * 100) / total),
      quietOnBenign: falsePositives.every((f) => f.benign === null),
      worstTimeToDetectUs: latencies.length ? Math.max(...latencies) : 0,
      meanTimeToDetectUs: latencies.length ? Math.floor(latencies.reduce((a, x) => a + x, 0) / latencies.length) : 0,
    },
    caught,
    ambiguousHits,
    missed,
    falsePositives,
    benign: MOCK_BENIGN.map((b) => Object.assign({}, b, { episode: episodeAt(b.tUs) })),
    episodes: MOCK_EPISODES.map((e) => ({ id: e.id, describes: e.describes, startUs: e.startUs, endUs: e.endUs })),
    listCap: 60,
    error: null,
    summary: '',
  };
}

function selectionOf(spec) {
  const signals = [];
  for (const r of spec.rules) {
    for (const s of RULE_BY_ID.get(r.id).signals) {
      if (!signals.some((x) => x.id === s.id)) signals.push(s);
    }
  }
  return {
    text: encodeRuleSet(spec),
    name: spec.name,
    preset: matchingPreset(spec),
    ruleCount: spec.rules.length,
    signals,
  };
}

/** Did this signal fire inside this episode? */
function firedDuring(detection, signal, episodeId) {
  const ep = MOCK_EPISODES.find((e) => e.id === episodeId);
  if (!ep) return false;
  const all = detection.caught.concat(detection.ambiguousHits, detection.falsePositives);
  return all.some((f) => f.signal === signal && f.tUs >= ep.startUs && f.tUs <= ep.endUs);
}

/* ------------------------------------------------------------------ *
 * Bench configuration
 * ------------------------------------------------------------------ */

/*
 * The bench options, as ENGINE-API.md v3 describes them.
 *
 * The ids and the legal values are the same ones odr-scenario's option list
 * uses, because this file is the readable statement of what that contract
 * means. `fixed` marks the two kinds of field that are not controls: a value
 * read off the bench that was built, and a setting this bench genuinely cannot
 * express — which is still SHOWN, because docs/UI.md's rule is collapse, never
 * remove.
 */

const FORMAT_CHOICES = [
  ['h10301', 'H10301 — 26-bit, 8-bit facility code'],
  ['h10306', 'H10306 — 34-bit, 16-bit facility code'],
  ['c1k35s', 'Corporate 1000 — 35-bit, interleaved parity'],
  ['h10304', 'H10304 — 37-bit with a facility code'],
  ['h10302', 'H10302 — 37-bit, no facility code'],
];

const NO_CRYPTO_HERE =
  'There is no Secure Channel on a Wiegand or clock-and-data pair. Neither protocol has any '
  + 'cryptography in its specification — that absence is the whole of Module 1, and there is '
  + 'nothing here to turn on.';
const NO_BUS_HERE =
  'A Wiegand pair is not a bus: nothing polls it, and its rate is the reader\'s own pulse timing '
  + 'rather than a line rate.';
const NOT_A_PAIR =
  'This bench is an RS-485 multidrop bus. The Wiegand and clock-and-data pairs are Module 1\'s '
  + 'benches — swapping one for the other is not a setting, it is a different door.';
const READ_OFF_THE_BENCH =
  'Read off the bench that was built. This is what the simulation did, not a control.';

function defaultConfig() {
  return {
    card: {
      id: 'card', title: 'Credential', node: 'card',
      fields: [
        { id: 'type', label: 'Type', type: 'select', value: 'em4100', fixed: true, fixedReason: READ_OFF_THE_BENCH, options: [['em4100', 'EM4100 125 kHz'], ['h10301', 'HID Prox H10301'], ['mifare', 'MIFARE Classic 1K'], ['desfire', 'DESFire EV2']], help: 'What the tag is. The first three have no meaningful authentication.' },
        { id: 'values', label: 'Facility code / card number', type: 'select', value: 'generated from the session seed', fixed: true, fixedReason: 'Deliberately not printed here. Drill 1.1\'s flag is to submit what the engine transmitted, and a panel that showed it would make that a lookup.', help: '' },
        { id: 'format', label: 'Credential format', type: 'select', value: 'h10301', options: FORMAT_CHOICES, help: 'Which bit layout the reader emits and the panel is configured to believe. Nothing on the wire says which one it is.' },
      ],
      summary: (v) => `${({ em4100: 'EM4100', h10301: 'HID Prox', mifare: 'MIFARE Classic', desfire: 'DESFire EV2' })[v.type]} — provisioned from the session seed`,
    },
    reader: {
      id: 'reader', title: 'Reader (PD)', node: 'reader',
      fields: [
        { id: 'address', label: 'PD address', type: 'number', value: 2, min: 0, max: 126, fixed: true, fixedReason: READ_OFF_THE_BENCH, help: 'Bit 7 of the address byte carries direction, so an address is seven bits.' },
        { id: 'pdClaimsAes', label: 'Reader claims AES-128', type: 'boolean', value: true, help: 'Function code 0x09 in the PDCAP reply. This is the entry the downgrade attack deletes in flight; clearing it here is the same bench without the attacker.' },
        { id: 'pdInstallMode', label: 'Reader install mode', type: 'boolean', value: false, help: 'An uncommissioned reader takes a key from anything that establishes a channel under the default key.' },
      ],
      summary: (v) => `PD ${v.address}, AES-128 ${v.pdClaimsAes ? 'supported' : 'NOT supported'}`,
    },
    link: {
      id: 'link', title: 'Link', node: 'link',
      fields: [
        { id: 'linkType', label: 'Wire protocol', type: 'select', value: 'osdp', options: [['wiegand', 'Wiegand D0/D1'], ['clockdata', 'Clock-and-data (ABA track 2)']], help: 'Two legacy pairs, the same absence of cryptography. Clock-and-data is ABA track 2, which is a magstripe encoding on a door.' },
        { id: 'baud', label: 'Line rate', type: 'select', value: '9600', options: [['9600', '9600 baud'], ['19200', '19200 baud'], ['38400', '38400 baud'], ['115200', '115200 baud']], help: 'What the bus clocks at. It is what makes an online MAC forgery cost what drill 4.2 says it costs.' },
        { id: 'pollMs', label: 'Poll interval', type: 'number', value: 50, min: 10, max: 2000, unit: 'ms', help: 'How long the controller waits between polls. Real installations poll hard, and the amount of idle traffic is exactly what makes traffic analysis work.' },
      ],
      summary: (v) => `${({ wiegand: 'Wiegand D0/D1', clockdata: 'Clock-and-data (ABA track 2)', osdp: 'OSDP over RS-485' })[v.linkType]}${v.linkType === 'osdp' ? `, ${v.baud} baud, ${Math.round(1000 / v.pollMs)} polls/s` : ''}`,
    },
    security: {
      id: 'security', title: 'Secure Channel', node: 'controller', critical: true,
      fields: [
        { id: 'secureChannel', label: 'Secure Channel', type: 'select', value: 'off', options: [['off', 'Off — everything in the clear'], ['if-available', 'If available — the reader decides'], ['required', 'Required']], help: 'Off is how OSDP ships and how most of it is deployed. "If available" lets the reader\'s own capability reply decide, which is what the downgrade attack rewrites. "Required" still means "required of readers that say they can".' },
        { id: 'key', label: 'Base key', type: 'select', value: 'scbk-d', options: [['scbk-d', 'SCBK-D — the published default'], ['weak', 'Weak — from the sample-code family'], ['site', 'Site key — not in any published list']], help: 'SCBK-D is printed in the specification, so everybody has it. A weak key is from the published sample-code family and can be swept for. A site key is neither, so it has to be asked for or captured.' },
        { id: 'nullCipher', label: 'Null cipher (SCS_15/16)', type: 'boolean', value: false, help: 'Authenticate without encrypting. A real, specified mode, and some deployments run it believing "secure channel is on" hides the card number.' },
        { id: 'macBytes', label: 'MAC bytes', type: 'number', value: 4, min: 1, max: 4, unit: 'bytes', help: 'OSDP truncates to four and offers no way to change it, so four is the only honest value. Shorter is a rig, and drill 4.2 says so out loud.' },
      ],
      summary: (v) => v.secureChannel !== 'off'
        ? `on, ${({ 'scbk-d': 'SCBK-D (the published default)', weak: 'a key from the published sample family', site: 'site key' })[v.key]}, ${v.nullCipher ? 'SCS_15/16 (null cipher — MAC only)' : 'SCS_17/18'}, ${v.macBytes * 8}-bit MAC`
        : 'OFF — everything on this bus is in the clear',
    },
    controller: {
      id: 'controller', title: 'Controller (ACU)', node: 'controller',
      fields: [
        { id: 'trustPdcap', label: 'Trust the capability reply', type: 'boolean', value: true, help: 'Nothing authenticates a capability report. With this on the controller decides from it whether to run a handshake at all — which is the whole of the downgrade attack. Turning it off is the defence.' },
        { id: 'acuInstallMode', label: 'Controller install mode', type: 'boolean', value: false, help: 'A controller in install mode hands the site key to anything that turns up claiming the default. Installers leave it on.' },
        { id: 'strikeMs', label: 'Strike time', type: 'number', value: 3000, min: 200, max: 30000, unit: 'ms', help: 'How long the door stays unlocked after a grant.' },
      ],
      summary: (v) => `${v.secureChannel === 'required' ? 'requires Secure Channel' : (v.secureChannel === 'if-available' ? 'Secure Channel if available' : 'accepts cleartext')}${v.acuInstallMode ? ' · INSTALL MODE ON' : ''} · strike ${(v.strikeMs / 1000).toFixed(1)} s`,
    },
    attacker: {
      id: 'attacker', title: 'Attacker position', node: 'tap',
      fields: [
        { id: 'runner', label: 'What the bench ran', type: 'select', value: 'baseline', fixed: true, fixedReason: READ_OFF_THE_BENCH, help: 'The taps decide this.' },
        { id: 'captured', label: 'Frames held', type: 'number', value: 0, fixed: true, fixedReason: READ_OFF_THE_BENCH, help: 'Frames the attacker kept, payloads and all — readable or not.' },
      ],
      summary: (v) => (v.captured ? `capturing · ${v.captured} frame(s) held` : 'nothing clipped on — the bench runs untouched'),
    },
  };
}

/*
 * Which options a bench accepts, and what to say about the ones it cannot.
 *
 * The real engine keeps this in odr-scenario, per scenario. The mock keys it on
 * the one thing its canned scenarios differ by: whether the wire is a bus.
 */
function unsupportedHere(onABus, fieldId) {
  const osdpOnly = ['secureChannel', 'key', 'nullCipher', 'macBytes', 'trustPdcap', 'acuInstallMode', 'pdInstallMode', 'pdClaimsAes'];
  if (!onABus && osdpOnly.includes(fieldId)) return NO_CRYPTO_HERE;
  if (!onABus && ['baud', 'pollMs'].includes(fieldId)) return NO_BUS_HERE;
  if (onABus && fieldId === 'linkType') return NOT_A_PAIR;
  return null;
}

/*
 * What a setting costs the drill that is loaded.
 *
 * A sentence, not a refusal: docs/UI.md records the owner's feedback as prefer
 * warning over blocking, so the bench still builds and the interface says what
 * stopped working.
 */
function drillWarning(drillId, fieldId, values) {
  if (!drillId) return null;
  const m = String(drillId);
  if (m.startsWith('2.') && fieldId === 'secureChannel' && values.secureChannel !== 'off') {
    return 'Module 2 is about a bus with nothing configured on it. With Secure Channel on, the card read is sealed and this drill\'s flag cannot be earned.';
  }
  if ((m.startsWith('3.') || m.startsWith('4.')) && fieldId === 'secureChannel' && values.secureChannel === 'off') {
    return 'This drill is about attacking a secure channel. With Secure Channel off there is no handshake to capture, and the flag cannot be earned.';
  }
  if (m === '3.2' && fieldId === 'key' && values.key !== 'scbk-d') {
    return 'Drill 3.2 is about recognising SCBK-D — the key printed in the manual. On any other key there is nothing published to recognise, and the flag cannot be earned.';
  }
  if (m === '3.3' && fieldId === 'key' && values.key !== 'weak') {
    return 'Drill 3.3 sweeps the published sample-key family. On a key that is not from that family there is nothing for the sweep to find, and the flag cannot be earned.';
  }
  if (m === '3.4' && fieldId === 'acuInstallMode' && !values.acuInstallMode) {
    return 'Drill 3.4 asks a controller in install mode for the key. With install mode off it will not answer, and the flag cannot be earned — which is the fix, and worth seeing.';
  }
  if (m === '3.6' && fieldId === 'trustPdcap' && !values.trustPdcap) {
    return 'This is the defence. With the capability reply distrusted the controller runs the handshake anyway, the downgrade is refused, and drill 3.6\'s flag cannot be earned — which is exactly what drill 5.2 asks you to detect.';
  }
  if (m === '4.2' && fieldId === 'macBytes' && values.macBytes >= 4) {
    return 'Four bytes is the honest width, and at four the forgery does not finish — that is drill 4.2\'s other half and the crawling bar says so. The flag needs the rigged bench.';
  }
  if (m === '4.4' && fieldId === 'nullCipher' && !values.nullCipher) {
    return 'Drill 4.4 reads a payload off a MACed-but-unencrypted link. With encryption on there is nothing in the clear to read.';
  }
  return null;
}

const TOPOLOGY_NODES = [
  { id: 'card', label: 'Card', sub: 'credential', configGroup: 'card' },
  { id: 'reader', label: 'Reader', sub: 'PD', configGroup: 'reader' },
  { id: 'controller', label: 'Controller', sub: 'ACU', configGroup: 'controller' },
  { id: 'door', label: 'Door', sub: 'strike', configGroup: 'controller' },
];
const TOPOLOGY_LINKS = [
  { id: 'card-reader', from: 'card', to: 'reader', label: 'rf', tappable: true, configGroup: 'card' },
  { id: 'reader-controller', from: 'reader', to: 'controller', label: 'wire', tappable: true, configGroup: 'link' },
  { id: 'controller-door', from: 'controller', to: 'door', label: 'strike', tappable: false, configGroup: 'controller' },
];

/* ------------------------------------------------------------------ *
 * The engine object
 * ------------------------------------------------------------------ */

class MockEngine {
  constructor() {
    this.version = 0;
    this.config = defaultConfig();
    this.changed = new Set();
    this._drill = null;
    this.taps = [];
    this.observed = new Set();     // learner actions the engine has been told about
    this.tasks = [];
    this.session = null;
    this._scenario = null;
    this._frameIndex = new Map();
    this._tapSeq = 0;
    // Module 5's answer: the rule set the learner composed, which the engine
    // RUNS rather than compares. The floor is nothing at all.
    this._rules = parseRuleSet('empty');
    this._ruleError = null;
    this.loadDrill('1.1', 'bronze');
  }

  _bump() { this.version++; }

  /* ---- catalogue ---- */
  catalog() {
    return {
      modules: MODULES.map((m) => ({
        id: m.id, number: m.number, title: m.title, blurb: m.blurb,
        drills: m.drills.map((dr) => ({
          id: dr.id, title: dr.title, band: dr.band, simulated: dr.simulated,
          summary: dr.summary, moduleId: m.id,
        })),
      })),
      drillCount: DRILL_INDEX.size,
    };
  }

  getDrill(id) {
    const dr = DRILL_INDEX.get(id);
    if (!dr) return null;
    return {
      id: dr.id, title: dr.title, band: dr.band, simulated: dr.simulated,
      moduleId: dr.moduleId, moduleTitle: dr.moduleTitle, moduleNumber: dr.moduleNumber,
      summary: dr.summary, objective: dr.objective, flagText: dr.flagText,
      note: dr.note || '', scenario: dr.scenario,
      guidance: {
        bronze: dr.bronzeSteps || [],
        silver: [],
        gold: [],
      },
      hints: dr.hints || [],
    };
  }

  /* ---- session ---- */
  loadDrill(drillId, band) {
    const dr = DRILL_INDEX.get(drillId);
    if (!dr) throw new Error(`unknown drill ${drillId}`);
    this._loadScenario(dr.scenario);
    const chosen = band || (dr.band === 'reference' ? 'bronze' : dr.band);
    this.session = {
      drillId, band: chosen,
      scenarioId: dr.scenario, sandbox: false,
      title: `${dr.id} ${dr.title}`,
      durationUs: this._scenario.durationUs,
      seed: 0x0d0000 + Number(dr.id.replace('.', '')),
    };
    if (band) this.session.band = band;
    this.observed.clear();
    this.taps = [];
    this._rules = parseRuleSet('empty');
    this._ruleError = null;
    this._applyScenarioDefaults(dr);
    this.tasks = [];
    if (dr.predicate.kind === 'task') this._startTask(dr.predicate.taskId);
    this._bump();
    return this.session;
  }

  loadSandbox(scenarioId) {
    this._loadScenario(scenarioId || 'osdp-clear');
    this.session = {
      drillId: null, band: 'silver', scenarioId: this._scenario.id, sandbox: true,
      title: 'Free play', durationUs: this._scenario.durationUs, seed: 0x0d0000,
    };
    this.observed.clear();
    this.tasks = [];
    this._bump();
    return this.session;
  }

  _loadScenario(id) {
    const make = SCENARIOS[id] || SCENARIOS['osdp-clear'];
    this._scenario = make();
    this._frameIndex = new Map();
    for (const f of this._scenario.frames) this._frameIndex.set(f.id, f);
  }

  /**
   * Does the bench currently carry a tap capable of producing this event?
   * 'any'    — any tap at all on the reader↔controller link
   * 'write'  — a tap that can put frames on the link (inject or inline)
   * 'inline' — a tap that has cut the link
   * `unless` inverts: the event only happens when NO such tap is present.
   */
  _tapAllows(requires, unless) {
    const has = (kind) => this.taps.some((t) => {
      if (t.linkId !== 'reader-controller') return false;
      if (kind === 'any') return true;
      if (kind === 'write') return t.mode === 'inject' || t.mode === 'inline';
      return t.mode === kind;
    });
    if (unless && has(unless)) return false;
    if (!requires) return true;
    return has(requires);
  }

  _activeFrames() {
    return this._scenario.frames.filter((f) => this._tapAllows(f.requiresTap, null));
  }
  _activeEvents() {
    return this._scenario.events.filter((e) => this._tapAllows(e.requiresTap, e.unlessTap));
  }
  _activeMarkers() {
    return this._scenario.markers.filter((m) => this._tapAllows(m.requiresTap, m.unlessTap));
  }

  _applyScenarioDefaults(dr) {
    this._drill = dr;
    const c = this._scenario.cfg;
    const set = (g, f, v) => { const fld = this.config[g].fields.find((x) => x.id === f); if (fld) fld.value = v; };
    set('link', 'linkType', c.wire === 'osdp' ? 'osdp' : 'wiegand');
    set('security', 'secureChannel', c.secureChannel ? 'required' : 'off');
    set('security', 'nullCipher', !!c.nullCipher);
    set('security', 'key', c.keyType === 'scbk' ? 'weak' : 'scbk-d');
    set('card', 'type', c.wire === 'osdp' ? 'h10301' : 'em4100');
    // A bench the learner has not touched, which is what loading one means.
    this.changed.clear();

    // docs/UI.md: "Bronze pre-places the taps and says which control to touch."
    // Only Bronze. At Silver and Gold, placing the tap is the learner's job,
    // and the bench must not quietly do it for them.
    this.taps = [];
    if (this.session.band !== 'bronze') return;
    const mode = this._tapNeededBy(dr);
    if (mode) this.taps.push({ id: `tap${++this._tapSeq}`, linkId: 'reader-controller', mode, prePlaced: true });
  }

  /** The weakest tap that lets this drill's flag become reachable. */
  _tapNeededBy(dr) {
    const fromPredicate = (p) => {
      if (!p) return null;
      if (p.kind === 'tap') return p.mode;
      // A Module 5 drill is scored from a capture, so the weakest tap that
      // makes it reachable is a passive probe on the bus.
      if (p.kind === 'ruleset') return 'sniff';
      if (p.kind === 'all') return p.of.map(fromPredicate).find(Boolean) || null;
      return null;
    };
    const explicit = fromPredicate(dr.predicate);
    if (explicit) return explicit;
    const need = this._scenario.frames.reduce((acc, f) => {
      if (!f.requiresTap) return acc;
      if (f.requiresTap === 'inline') return 'inline';
      if (f.requiresTap === 'write' && acc !== 'inline') return 'write';
      return acc || 'any';
    }, null);
    return { inline: 'inline', write: 'inject', any: 'sniff' }[need] || null;
  }

  setBand(band) {
    if (this.session) { this.session.band = band; this._bump(); }
    return this.session;
  }

  /* ---- configuration ---- */
  _values() {
    const v = {};
    for (const g of Object.values(this.config)) for (const f of g.fields) v[f.id] = f.value;
    return v;
  }

  _cfg(groupId, fieldId) {
    const f = this.config[groupId].fields.find((x) => x.id === fieldId);
    return f ? f.value : undefined;
  }

  _onABus() {
    return this._scenario ? this._scenario.cfg.wire === 'osdp' : true;
  }

  configGroups() {
    const all = this._values();
    const onABus = this._onABus();
    const drillId = this.session ? this.session.drillId : null;
    return Object.values(this.config).map((g) => ({
      id: g.id,
      title: g.title,
      node: g.node,
      critical: !!g.critical,
      summary: g.summary(all),
      alert: g.id === 'security'
        ? (onABus && all.secureChannel === 'off')
        : (g.id === 'controller' ? !!all.acuInstallMode : false),
      fields: g.fields.map((f) => {
        const cannot = f.fixed ? f.fixedReason : unsupportedHere(onABus, f.id);
        return {
          ...f,
          fixed: !!cannot,
          fixedReason: cannot || undefined,
          changed: this.changed.has(f.id),
          warning: cannot ? undefined : (drillWarning(drillId, f.id, all) || undefined),
        };
      }),
    }));
  }

  setConfig(groupId, fieldId, value) {
    const g = this.config[groupId];
    if (!g) return { ok: false, error: `there is no ${groupId} group` };
    const f = g.fields.find((x) => x.id === fieldId);
    if (!f) return { ok: false, error: `there is no bench option called ${fieldId}` };
    // Refusal is for the impossible only. A setting that would break the loaded
    // drill is applied, and comes back carrying a warning.
    const cannot = f.fixed ? f.fixedReason : unsupportedHere(this._onABus(), fieldId);
    if (cannot) return { ok: false, error: cannot, groups: this.configGroups() };
    if (f.type === 'number') {
      const n = Number(value);
      if (!Number.isFinite(n)) return { ok: false, error: `${value} is not a whole number`, groups: this.configGroups() };
      if (n < f.min || n > f.max) {
        return { ok: false, error: `${n} ${f.unit || ''} is outside this option's range of ${f.min} to ${f.max}`.replace('  ', ' '), groups: this.configGroups() };
      }
      f.value = n;
    } else if (f.type === 'boolean') {
      f.value = value === true || value === 'true' || value === 'yes' || value === 'on' || value === '1';
    } else {
      if (f.options && !f.options.some(([v]) => v === value)) {
        return { ok: false, error: `"${value}" is not one of this option's values: ${f.options.map(([v]) => v).join(', ')}`, groups: this.configGroups() };
      }
      f.value = value;
    }
    this.changed.add(fieldId);
    this._bump();
    return { ok: true, groups: this.configGroups() };
  }

  /** Put every option back to the bench's own setting. */
  resetConfig() {
    this.changed.clear();
    this.config = defaultConfig();
    if (this._drill) this._applyScenarioDefaults(this._drill);
    this._bump();
    return { ok: true, groups: this.configGroups() };
  }

  /* ---- topology ---- */
  topology() {
    const st = this.stateAt(this._lastQueryT || 0);
    return {
      nodes: TOPOLOGY_NODES.map((n) => ({ ...n, state: n.id === 'door' ? st.door : 'idle' })),
      links: TOPOLOGY_LINKS.map((l) => ({
        ...l,
        protocol: l.id === 'reader-controller' ? this._cfg('link', 'linkType') : (l.id === 'card-reader' ? 'rf' : 'relay'),
        cut: this.taps.some((t) => t.linkId === l.id && t.mode === 'inline'),
      })),
      taps: this.taps.map((t) => ({ ...t })),
    };
  }

  addTap({ linkId, mode }) {
    const link = TOPOLOGY_LINKS.find((l) => l.id === linkId);
    if (!link || !link.tappable) return { ok: false, error: 'that link cannot be tapped' };
    const existing = this.taps.find((t) => t.linkId === linkId);
    if (existing) { existing.mode = mode; this._bump(); return { ok: true, tap: { ...existing } }; }
    const tap = { id: `tap${++this._tapSeq}`, linkId, mode, prePlaced: false };
    this.taps.push(tap);
    this._bump();
    return { ok: true, tap: { ...tap } };
  }

  setTapMode(tapId, mode) {
    const t = this.taps.find((x) => x.id === tapId);
    if (!t) return { ok: false };
    t.mode = mode; this._bump();
    return { ok: true, tap: { ...t } };
  }

  removeTap(tapId) {
    this.taps = this.taps.filter((t) => t.id !== tapId);
    this._bump();
    return { ok: true };
  }

  /* ---- time ---- */
  duration() { return this._scenario.durationUs; }

  nextEventUs(tUs) {
    for (const f of this._activeFrames()) if (f.tUs > tUs) return f.tUs;
    return this._scenario.durationUs;
  }
  prevEventUs(tUs) {
    let best = 0;
    for (const f of this._activeFrames()) { if (f.tUs < tUs) best = f.tUs; else break; }
    return best;
  }

  stateAt(tUs) {
    this._lastQueryT = tUs;
    const st = {
      tUs, door: 'closed', strike: 'idle', decision: 'none', lastCredential: null,
      secureChannel: this._cfg('security', 'secureChannel') !== 'off' ? 'configured' : 'off',
      scs: null, key: null,
    };
    for (const e of this._activeEvents()) {
      if (e.tUs > tUs) break;
      Object.assign(st, e.patch);
    }
    st.attacker = {
      taps: this.taps.length,
      inline: this.taps.some((t) => t.mode === 'inline'),
      holdsKeys: this._keyHeld() && this.taps.length > 0,
      captured: this.taps.length > 0 ? this._activeFrames().filter((f) => f.tUs <= tUs).length : 0,
    };
    return st;
  }

  markers() { return this._activeMarkers().map((m) => ({ ...m })); }

  /* ---- traffic ---- */
  frames({ fromUs = 0, toUs = Infinity, collapseIdle = false, filter = null, limit = 4000 } = {}) {
    let out = this._activeFrames().filter((f) => f.tUs >= fromUs && f.tUs <= toUs);
    if (filter) {
      const q = filter.toLowerCase();
      out = out.filter((f) => f.label.toLowerCase().includes(q) || f.summary.toLowerCase().includes(q) || f.kind.includes(q));
    }
    let collapsed = null;
    if (collapseIdle) {
      const kept = [];
      const spans = [];
      let run = [];
      const flush = () => {
        if (run.length >= 4) {
          spans.push({ fromUs: run[0].tUs, toUs: run[run.length - 1].tUs, count: run.length });
          kept.push({
            id: `collapse-${run[0].id}`, collapsed: true, tUs: run[0].tUs, toUs: run[run.length - 1].tUs,
            count: run.length, lane: 'bus', line: 'rs485', dir: 'acu_to_pd', label: '⋯',
            summary: `${run.length} idle POLL/ACK frames hidden`, kind: 'collapsed',
          });
        } else kept.push(...run);
        run = [];
      };
      for (const f of out) {
        if (f.kind === 'poll' || f.kind === 'ack') run.push(f);
        else { flush(); kept.push(f); }
      }
      flush();
      const hidden = spans.reduce((a, s) => a + s.count, 0);
      collapsed = { hiddenFrames: hidden, spans };
      out = kept;
    }
    const total = out.length;
    if (out.length > limit) out = out.slice(out.length - limit);
    return {
      total,
      truncated: total > limit,
      collapsed,
      rows: out.map((f) => f.collapsed ? f : {
        id: f.id, tUs: f.tUs, line: f.line, lane: f.lane, dir: f.dir, label: f.label,
        kind: f.kind, summary: f.summary, secure: f.secure, origin: f.origin, tapped: f.tapped,
        length: f.bytes.length,
      }),
    };
  }

  frame(id) {
    const f = this._frameIndex.get(id);
    if (!f) return null;
    this.observed.add(`frame:${f.kind}`);
    this._bump();
    const keyHeld = this._keyHeld();
    return {
      id: f.id, tUs: f.tUs, line: f.line, lane: f.lane, dir: f.dir, view: f.view,
      label: f.label, kind: f.kind, summary: f.summary, note: f.note,
      origin: f.origin, tapped: f.tapped, secure: { ...f.secure, keyHeld: f.secure.encrypted ? keyHeld : true },
      bytes: f.bytes.slice(),
      bits: f.bits ? f.bits.slice() : null,
      fields: f.fields,
    };
  }

  _keyHeld() {
    const key = this._cfg('security', 'key');
    return key === 'scbk-d' || key === 'weak';
  }

  /** The learner did something the flag predicate may care about. */
  observe(action) {
    if (!action) return;
    if (action.type === 'field_opened') this.observed.add(`field:${action.fieldId}`);
    if (action.type === 'frame_selected') this.observed.add(`frame:${action.frameKind}`);
    if (action.type === 'diagnosis') this.observed.add('diagnosis');
    if (action.type === 'cursor') this.observed.add(`t:${Math.floor(action.tUs / 1_000_000)}`);
    this._bump();
  }

  /* ---- timeline ---- */
  timeline({ fromUs = 0, toUs = null, bins = 480, collapseIdle = false } = {}) {
    const hi = toUs === null ? this._scenario.durationUs : toUs;
    const span = Math.max(1, hi - fromUs);
    const lanes = [
      { id: 'rf', label: 'RF', type: 'density', bins: new Array(bins).fill(0) },
      { id: 'wire', label: 'Wire', type: 'density', bins: new Array(bins).fill(0) },
      { id: 'bus', label: 'Bus', type: 'density', bins: new Array(bins).fill(0) },
    ];
    const byId = Object.fromEntries(lanes.map((l) => [l.id, l]));
    const frames = this.frames({ fromUs, toUs: hi, collapseIdle }).rows;
    for (const f of frames) {
      const lane = byId[f.lane];
      if (!lane) continue;
      const i = Math.min(bins - 1, Math.floor(((f.tUs - fromUs) / span) * bins));
      lane.bins[i] += f.collapsed ? 1 : 1;
    }
    const doorSegments = [];
    let cur = { from: fromUs, state: 'closed' };
    for (const e of this._activeEvents()) {
      if (e.patch.door && e.tUs >= fromUs && e.tUs <= hi) {
        doorSegments.push({ fromUs: cur.from, toUs: e.tUs, state: cur.state });
        cur = { from: e.tUs, state: e.patch.door };
      }
    }
    doorSegments.push({ fromUs: cur.from, toUs: hi, state: cur.state });
    lanes.push({ id: 'door', label: 'Door', type: 'state', segments: doorSegments });
    return {
      fromUs, toUs: hi, bins, lanes,
      markers: this._activeMarkers().filter((m) => m.tUs >= fromUs && m.tUs <= hi),
      collapsed: collapseIdle ? this.frames({ fromUs, toUs: hi, collapseIdle }).collapsed : null,
      honest: !collapseIdle,
    };
  }

  /* ---- flags ---- */
  flag() {
    const s = this.session;
    if (!s || !s.drillId) return { drillId: null, earned: false, predicate: '', evidence: [] };
    const dr = DRILL_INDEX.get(s.drillId);
    const res = this._evaluate(dr.predicate);
    return {
      drillId: s.drillId,
      predicate: dr.flagText,
      earned: res.ok,
      simulated: dr.simulated,
      evidence: res.evidence,
      outstanding: res.outstanding,
    };
  }

  _evaluate(p) {
    const t = this._lastQueryT || 0;
    switch (p.kind) {
      case 'none':
        return { ok: false, evidence: ['This section is reference material. There is no flag and nothing is simulated.'], outstanding: [] };
      case 'all': {
        const parts = p.of.map((q) => this._evaluate(q));
        return {
          ok: parts.every((x) => x.ok),
          evidence: parts.flatMap((x) => x.evidence),
          outstanding: parts.flatMap((x) => x.outstanding),
        };
      }
      case 'reach': {
        const after = p.after || 0;
        const hit = this._activeEvents().find((e) => e.patch.decision === 'granted' && e.tUs >= after && e.tUs <= t);
        return hit
          ? { ok: true, evidence: [`Controller granted at t=${(hit.tUs / 1e6).toFixed(3)} s on credential ${hit.patch.lastCredential}.`], outstanding: [] }
          : { ok: false, evidence: [], outstanding: [`Run the bench past the grant${after ? ` at t≈${(after / 1e6).toFixed(1)} s` : ''}.`] };
      }
      case 'frame': {
        const f = this._activeFrames().find((x) => x.kind === p.frameKind && x.tUs <= t);
        return f
          ? { ok: true, evidence: [`Frame ${f.id} (${f.summary}) crossed the link at t=${(f.tUs / 1e6).toFixed(3)} s.`], outstanding: [] }
          : { ok: false, evidence: [], outstanding: ['The frame the predicate names has not been produced yet.'] };
      }
      case 'inspect': {
        const seenFrame = this.observed.has(`frame:${p.frameKind}`);
        const seenField = this.observed.has(`field:${p.fieldId}`);
        const out = [];
        if (!seenFrame) out.push(`Select a ${p.frameKind.toUpperCase()} frame in the traffic list.`);
        if (!seenField) out.push('Open the field the objective names in the decode tree.');
        return {
          ok: seenFrame && seenField,
          evidence: seenFrame && seenField ? ['The engine saw you read the value off the frame it generated.'] : [],
          outstanding: out,
        };
      }
      case 'tap': {
        const tap = this.taps.find((x) => x.linkId === p.link && x.mode === p.mode);
        return tap
          ? { ok: true, evidence: [`${p.mode === 'inline' ? 'An' : 'A'} ${p.mode} tap is on the ${p.link.replace('-', ' → ')} link.`], outstanding: [] }
          : { ok: false, evidence: [], outstanding: [`Place a ${p.mode} tap on the ${p.link.replace('-', ' → ')} link.`] };
      }
      case 'config': {
        const g = this.config[p.group];
        const f = g && g.fields.find((x) => x.id === p.field);
        return f && f.value === p.value
          ? { ok: true, evidence: [`${g.title}: ${f.label} is ${f.value}.`], outstanding: [] }
          : { ok: false, evidence: [], outstanding: [`Set ${p.field} in the ${p.group} panel.`] };
      }
      case 'attacker': {
        const st = this.stateAt(t);
        return st.attacker.holdsKeys
          ? { ok: true, evidence: ['The attacker actor holds the session keys, derived from captured traffic alone.'], outstanding: [] }
          : { ok: false, evidence: [], outstanding: ['The attacker does not hold a key yet. Place a tap and capture a handshake.'] };
      }
      case 'task': {
        const task = this.tasks.find((x) => x.id === p.taskId);
        return task && task.shortDone
          ? { ok: true, evidence: [task.evidence], outstanding: [] }
          : { ok: false, evidence: [], outstanding: ['Start the attack from the drill panel.'] };
      }
      case 'ruleset':
        return this._evaluateRuleSet(p.need);
      case 'diagnose':
        return this.observed.has('diagnosis')
          ? { ok: true, evidence: ['Diagnosis recorded and scored against the engine\'s own account of why each attack stopped.'], outstanding: [] }
          : { ok: false, evidence: [], outstanding: ['Record your diagnosis in the drill panel.'] };
      default:
        return { ok: false, evidence: [], outstanding: [] };
    }
  }

  /* ---- §13 Module 5: the rule editor ---- */

  /** The parts a rule set is built from, and what is selected right now. */
  ruleCatalog() {
    const chosen = new Map(this._rules.rules.map((r) => [r.id, r.params]));
    return {
      rules: RULE_CATALOGUE.map((r) => ({
        id: r.id, label: r.label, catches: r.catches,
        falsePositives: r.falsePositives, inStandard: r.inStandard,
        selected: chosen.has(r.id),
        signals: r.signals.map((x) => ({ ...x })),
        params: r.params.map((p) => {
          const value = chosen.has(r.id) ? chosen.get(r.id)[p.id] : p.default;
          return {
            id: p.id, label: p.label, help: p.help, type: p.type,
            min: p.min, max: p.max, default: p.default,
            value, changed: value !== p.default,
            ...(p.unit ? { unit: p.unit } : {}),
          };
        }),
      })),
      presets: RULE_PRESETS.map((p) => ({
        ...p, text: encodeRuleSet(parseRuleSet(p.id)),
      })),
      selection: selectionOf(this._rules),
    };
  }

  /**
   * Compose the rule set and run it.
   *
   * A refusal changes nothing and comes back in words: a learner whose rule was
   * silently dropped would be scored on a set they did not build.
   */
  setRules(text) {
    try {
      this._rules = parseRuleSet(text);
      this._ruleError = null;
      this._bump();
      return { ok: true, error: null, selection: selectionOf(this._rules) };
    } catch (e) {
      this._ruleError = String(e.message || e);
      this._bump();
      return { ok: false, error: this._ruleError, selection: selectionOf(this._rules) };
    }
  }

  /** The score, with its reasoning. `null` outside Module 5. */
  detection() {
    const s = this.session;
    if (!s || !s.drillId || !s.drillId.startsWith('5.')) return null;
    const probeOnLink = this.taps.some((t) => t.linkId === 'reader-controller');
    // A probe that is not clipped on sees nothing, so a rule set has nothing
    // to run against: the honest floor, not the learner's set.
    const spec = probeOnLink ? this._rules : parseRuleSet('empty');
    const d = scoreRuleSet(spec);
    d.ran = probeOnLink && spec.rules.length > 0;
    d.probeOnLink = probeOnLink;
    d.error = this._ruleError;
    d.summary = `${d.score.findings} findings; ${d.score.truePositives} true positive(s), `
      + `${d.score.falsePositives} false positive(s), ${d.score.falseNegatives} missed, `
      + `${d.score.ambiguous} ambiguous; precision ${d.score.precisionPct}%, recall ${d.score.recallPct}%`;
    return d;
  }

  /** Module 5's three flag predicates, over the scored rule set. */
  _evaluateRuleSet(need) {
    const d = this.detection();
    if (!d || !d.probeOnLink) {
      return { ok: false, evidence: [], outstanding: ['Clip a passive probe on the reader → controller link; a monitor that is not there sees nothing.'] };
    }
    if (!d.ran) {
      return { ok: false, evidence: [], outstanding: ['Build a rule set in the rule builder and run it against the generated day.'] };
    }
    const evidence = [d.summary];
    const outstanding = [];
    if (need === 'complete') {
      if (d.missed.length) outstanding.push(`${d.missed.length} attack(s) in the key were missed: ${d.missed.map((m) => m.label).join(', ')}`);
      if (!d.score.quietOnBenign) outstanding.push(`${d.falsePositives.filter((f) => f.benign).length} false positive(s) on benign traffic`);
    }
    if (need === 'downgrade') {
      if (!firedDuring(d, 'capability_downgrade', 'downgrade')) {
        outstanding.push('No capability downgrade was reported during the downgrade episode: a rule needs a prior claim from the same address to compare against.');
      }
      for (const benign of ['legacy_reader_added', 'reader_replaced']) {
        if (firedDuring(d, 'capability_downgrade', benign)) {
          outstanding.push(`A downgrade was reported during the ${benign} episode, which is benign.`);
        }
      }
      if (!d.score.quietOnBenign) outstanding.push('Something on the benign traffic was called an attack.');
    }
    if (need === 'keyset') {
      if (!firedDuring(d, 'keyset_observed', 'commissioning')) {
        outstanding.push('No keyset was reported during the commissioning episode.');
      } else if (!d.ambiguousHits.some((h) => h.signal === 'keyset_observed')) {
        outstanding.push('The keyset was reported with a confidence the link does not permit; nothing in any frame says whether it was authorised.');
      } else {
        evidence.push('The keyset was reported as undecidable, and the scorer counted it as ambiguous — excluded from both precision and recall, which is exactly the position a defender is in.');
      }
    }
    return { ok: outstanding.length === 0, evidence, outstanding };
  }

  /* ---- long-running tasks (drills 1.5 and 4.2) ---- */
  _startTask(id) {
    if (id === 'mac-forge') {
      this.tasks.push({
        id, label: '32-bit MAC forgery — the real one',
        shortLabel: 'shortened MAC (12 bits) — for the drill',
        shortDone: false, progress: 0, rate: 16,
        total: 2 ** 32, done: 0,
        note: 'A MAC forgery is an online attack: every candidate has to be sent to the PD and answered. At 9600 baud that is about sixteen attempts a second, so 2^32 takes what it takes. The drill runs a shortened MAC so it finishes in seconds. This bar is the real one, and it does not stop when you leave.',
        evidence: 'The PD accepted a frame whose MAC was not derived from the session key (shortened-MAC run).',
      });
    }
    if (id === 'wiegand-sweep') {
      this.tasks.push({
        id, label: 'Full 26-bit sweep at wire timing',
        shortLabel: 'single facility code — for the drill',
        shortDone: false, progress: 0, rate: 18.5,
        total: 2 ** 26, done: 0,
        note: 'At 26 bits and real Wiegand timing, one credential every 54 ms. The projected date below is arithmetic, not drama.',
        evidence: 'Sweep of one facility code completed; the full-space cost is reported rather than simulated.',
      });
    }
  }

  startTask(id) {
    const t = this.tasks.find((x) => x.id === id);
    if (t) { t.shortDone = true; this._bump(); }
    return t ? { ok: true } : { ok: false };
  }

  taskStates(elapsedMs) {
    return this.tasks.map((t) => {
      const done = Math.min(t.total, t.rate * (elapsedMs / 1000));
      const remainingSec = (t.total - done) / t.rate;
      return {
        id: t.id, label: t.label, shortLabel: t.shortLabel, shortDone: t.shortDone,
        note: t.note, done, total: t.total,
        fraction: done / t.total,
        remainingSeconds: remainingSec,
        projected: projectedDate(remainingSec),
      };
    });
  }
}

/**
 * Rendered in full, deliberately. The decision in docs/UI.md is that the real
 * attack runs on a bar that never finishes and states when it would — because
 * a learner who has watched "MAC forged" appear in four seconds has had an
 * experience that overwrites whatever the text said.
 */
function projectedDate(remainingSeconds) {
  const years = remainingSeconds / (365.2425 * 24 * 3600);
  const duration = years >= 1
    ? `${years.toFixed(1)} years`
    : `${(remainingSeconds / 86400).toFixed(1)} days`;
  let when;
  if (years < 8000) {
    when = new Date(Date.now() + remainingSeconds * 1000)
      .toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
  } else {
    when = `the year ${Math.round(new Date().getFullYear() + years).toLocaleString('en-GB')} CE`;
  }
  return `${duration} — ${when}`;
}

/* ------------------------------------------------------------------ *
 * Entry point. engine-wasm.js must export a function of this shape.
 * ------------------------------------------------------------------ */

export async function createEngine(/* options */) {
  return new MockEngine();
}
