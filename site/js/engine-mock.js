/*
 * engine-mock.js — a stand-in for crates/odr-wasm.
 *
 * This file is the ONLY place the front end knows anything about protocol
 * bytes, drills or simulation state. Everything the interface draws comes
 * through the object returned by createEngine(). When the WebAssembly build is
 * ready, ship an engine-wasm.js exposing the same named export and change the
 * one import in js/app.js. Nothing else moves.
 *
 * The contract this file implements is written down in ../ENGINE-API.md.
 * If you change a shape here, change it there first.
 *
 * The bytes below are built the way the real crates build them — real
 * CRC-16/AUG-CCITT, real control bytes, real security block layout — so the
 * inspector is telling the truth even while the engine is a mock. Ciphertext,
 * cryptograms and MACs are seeded pseudo-random filler: they are the right
 * length and the right shape, and they are not the output of AES.
 */

export const ENGINE_KIND = 'mock';
export const ENGINE_API_VERSION = 1;

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
        predicate: { kind: 'config', group: 'controller', field: 'installMode', value: true },
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
        predicate: { kind: 'diagnose' },
      }),
      d('5.2', 'A rule that catches the downgrade', 'gold', {
        scenario: 'osdp-downgrade',
        summary: 'Build a detection rule that catches the downgrade and does not fire on a genuine legacy reader being added to the bus.',
        objective: 'Write a rule with a true positive on the downgrade and no false positive on the legacy reader.',
        flagText: 'The rule set is scored on true positives and false positives.',
        predicate: { kind: 'frame', frameKind: 'pdcap_downgraded' },
        hints: ['A reader that never could do crypto has always said so. A downgraded one said otherwise thirty seconds ago.'],
      }),
      d('5.3', 'Install mode in a log', 'silver', {
        scenario: 'osdp-secure',
        summary: 'What does install mode look like in a log, and why is it usually indistinguishable from a real commissioning?',
        objective: 'Identify the frames, and say honestly what separates the attack from a technician doing their job.',
        flagText: 'Scored on true positives and false positives.',
        predicate: { kind: 'diagnose' },
      }),
    ],
  },
];

const DRILL_INDEX = new Map();
for (const m of MODULES) for (const dr of m.drills) DRILL_INDEX.set(dr.id, Object.assign({ moduleId: m.id, moduleTitle: m.title, moduleNumber: m.number }, dr));

/* ------------------------------------------------------------------ *
 * Bench configuration
 * ------------------------------------------------------------------ */

function defaultConfig() {
  return {
    card: {
      id: 'card', title: 'Credential', node: 'card',
      fields: [
        { id: 'type', label: 'Type', type: 'select', value: 'em4100', options: [['em4100', 'EM4100 125 kHz'], ['h10301', 'HID Prox H10301'], ['mifare', 'MIFARE Classic 1K'], ['desfire', 'DESFire EV2']], help: 'What the tag is. The first three have no meaningful authentication.' },
        { id: 'facility', label: 'Facility code', type: 'number', value: 42, min: 0, max: 255, help: 'Shared across the site.' },
        { id: 'number', label: 'Card number', type: 'number', value: 24601, min: 0, max: 65535, help: '' },
      ],
      summary: (v) => `${({ em4100: 'EM4100', h10301: 'HID Prox', mifare: 'MIFARE Classic', desfire: 'DESFire EV2' })[v.type]}, FC ${v.facility} / ${v.number}`,
    },
    reader: {
      id: 'reader', title: 'Reader (PD)', node: 'reader',
      fields: [
        { id: 'address', label: 'PD address', type: 'number', value: 2, min: 0, max: 126, help: 'Bit 7 of the address byte carries direction, so an address is seven bits.' },
        { id: 'supportsCrypto', label: 'Supports AES-128', type: 'boolean', value: true, help: 'Reported in the PDCAP reply, function code 0x09. This is the field the downgrade attack deletes.' },
        { id: 'tamper', label: 'Tamper switch', type: 'boolean', value: true, help: '' },
      ],
      summary: (v) => `PD ${v.address}, AES-128 ${v.supportsCrypto ? 'supported' : 'NOT supported'}`,
    },
    link: {
      id: 'link', title: 'Link', node: 'link',
      fields: [
        { id: 'protocol', label: 'Protocol', type: 'select', value: 'osdp', options: [['wiegand', 'Wiegand D0/D1'], ['clockdata', 'Clock-and-data (ABA)'], ['osdp', 'OSDP over RS-485']], help: '' },
        { id: 'baud', label: 'Baud', type: 'select', value: '9600', options: [['9600', '9600'], ['19200', '19200'], ['38400', '38400'], ['115200', '115200']], help: '' },
        { id: 'pollRate', label: 'Poll rate', type: 'select', value: '20', options: [['5', '5 / s'], ['20', '20 / s'], ['50', '50 / s']], help: 'Real installations poll hard. The timeline shows it honestly.' },
      ],
      summary: (v) => `${({ wiegand: 'Wiegand', clockdata: 'Clock-and-data', osdp: 'OSDP RS-485' })[v.protocol]}, ${v.baud} baud, ${v.pollRate} polls/s`,
    },
    security: {
      id: 'security', title: 'Secure Channel', node: 'controller', critical: true,
      fields: [
        { id: 'enabled', label: 'Secure Channel', type: 'boolean', value: false, help: 'OSDP ships with this off. Most deployments leave it off.' },
        { id: 'key', label: 'Base key', type: 'select', value: 'scbk-d', options: [['scbk-d', 'SCBK-D (published default)'], ['weak', 'Site key, sample-code family'], ['strong', 'Site key, properly random']], help: 'SCBK-D is in the specification. Everybody has it.' },
        { id: 'mode', label: 'Cipher mode', type: 'select', value: 'scs17', options: [['scs15', 'SCS_15/16 — MAC only, no encryption'], ['scs17', 'SCS_17/18 — MAC and AES-128-CBC']], help: 'SCS_15/16 are null ciphers. They authenticate and do not conceal.' },
        { id: 'macBits', label: 'MAC length', type: 'select', value: '32', options: [['32', '32 bits (the specification)'], ['128', '128 bits (not legal OSDP)']], help: 'The specification truncates to four bytes.' },
      ],
      summary: (v) => v.enabled
        ? `on, ${({ 'scbk-d': 'SCBK-D', weak: 'weak site key', strong: 'site key' })[v.key]}, ${v.mode === 'scs15' ? 'SCS_15/16 (no encryption)' : 'SCS_17/18'}, ${v.macBits}-bit MAC`
        : 'OFF — everything on this bus is in the clear',
    },
    controller: {
      id: 'controller', title: 'Controller (ACU)', node: 'controller',
      fields: [
        { id: 'requireSecure', label: 'Require Secure Channel', type: 'boolean', value: false, help: 'If set, the controller refuses to run a PD that reports no crypto support — unless something rewrites that report.' },
        { id: 'installMode', label: 'Install mode', type: 'boolean', value: false, critical: true, help: 'A controller in install mode hands out the SCBK on request. Installers leave it on.' },
        { id: 'strikeMs', label: 'Strike time', type: 'number', value: 5000, min: 500, max: 30000, help: 'How long the door stays unlocked after a grant.' },
      ],
      summary: (v) => `${v.requireSecure ? 'requires Secure Channel' : 'accepts cleartext'}${v.installMode ? ' · INSTALL MODE ON' : ''} · strike ${(v.strikeMs / 1000).toFixed(1)} s`,
    },
    attacker: {
      id: 'attacker', title: 'Attacker position', node: 'tap',
      fields: [
        { id: 'capture', label: 'Capture to buffer', type: 'boolean', value: true, help: '' },
        { id: 'rewriteCard', label: 'Rewrite card number', type: 'boolean', value: false, help: 'Inline taps only. Substitutes the credential in flight.' },
        { id: 'rewriteTo', label: 'Substitute number', type: 'number', value: 1, min: 0, max: 65535, help: '' },
      ],
      summary: (v) => `${v.capture ? 'capturing' : 'not capturing'}${v.rewriteCard ? ` · rewriting card number to ${v.rewriteTo}` : ''}`,
    },
  };
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
    this.taps = [];
    this.observed = new Set();     // learner actions the engine has been told about
    this.tasks = [];
    this.session = null;
    this._scenario = null;
    this._frameIndex = new Map();
    this._tapSeq = 0;
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
    const c = this._scenario.cfg;
    const set = (g, f, v) => { const fld = this.config[g].fields.find((x) => x.id === f); if (fld) fld.value = v; };
    set('link', 'protocol', c.wire === 'osdp' ? 'osdp' : 'wiegand');
    set('security', 'enabled', !!c.secureChannel);
    set('security', 'mode', c.nullCipher ? 'scs15' : 'scs17');
    set('security', 'key', c.keyType === 'scbk-d' ? 'scbk-d' : (c.keyType === 'scbk' ? 'weak' : 'scbk-d'));
    set('controller', 'requireSecure', !!c.secureChannel);
    set('card', 'type', c.wire === 'osdp' ? 'h10301' : 'em4100');

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
  configGroups() {
    return Object.values(this.config).map((g) => {
      const values = {};
      for (const f of g.fields) values[f.id] = f.value;
      return {
        id: g.id, title: g.title, node: g.node, critical: !!g.critical,
        summary: g.summary(values),
        alert: g.id === 'security' ? !values.enabled : (g.id === 'controller' ? !!values.installMode : false),
        fields: g.fields.map((f) => ({ ...f })),
      };
    });
  }

  setConfig(groupId, fieldId, value) {
    const g = this.config[groupId];
    if (!g) return { ok: false, error: 'no such group' };
    const f = g.fields.find((x) => x.id === fieldId);
    if (!f) return { ok: false, error: 'no such field' };
    f.value = f.type === 'number' ? Number(value) : value;
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
        protocol: l.id === 'reader-controller' ? this.config.link.fields[0].value : (l.id === 'card-reader' ? 'rf' : 'relay'),
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
      secureChannel: this.config.security.fields[0].value ? 'configured' : 'off',
      scs: null, key: null,
    };
    for (const e of this._activeEvents()) {
      if (e.tUs > tUs) break;
      Object.assign(st, e.patch);
    }
    st.attacker = {
      taps: this.taps.length,
      inline: this.taps.some((t) => t.mode === 'inline'),
      holdsKeys: this.config.security.fields[1].value === 'scbk-d' && this.taps.length > 0,
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
    const key = this.config.security.fields[1].value;
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
      case 'diagnose':
        return this.observed.has('diagnosis')
          ? { ok: true, evidence: ['Diagnosis recorded and scored against the engine\'s own account of why each attack stopped.'], outstanding: [] }
          : { ok: false, evidence: [], outstanding: ['Record your diagnosis in the drill panel.'] };
      default:
        return { ok: false, evidence: [], outstanding: [] };
    }
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
