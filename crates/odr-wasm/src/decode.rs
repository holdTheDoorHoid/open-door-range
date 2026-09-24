//! **The decode tree, and the readable/sealed split.**
//!
//! `docs/UI.md` calls the inspector the single highest-value thing in the
//! interface, and `site/ENGINE-API.md` §6 makes its split structural: every
//! frame is drawn as two labelled groups, *readable without a key* and
//! *requires the session key*, on every frame in every security mode.
//!
//! **The split is decided here, not by the site.** A field carries
//! `visibility: "opaque"` when, and only when, it is the payload of a frame the
//! security block says is encrypted. Everything else is `"clear"` — the
//! address, the length, the control byte, the security block, the MAC, and
//! *the command or reply code*, which is plaintext in every OSDP security mode
//! and is the reason traffic analysis works on an encrypted bus. If this file
//! ever marked the code byte opaque, the interface would be lying.
//!
//! Offsets mirror [`odr_osdp::Frame::encode`] exactly, and `crate::tests`
//! re-derives them from the encoder for every frame of every scenario. A tree
//! whose offsets had drifted from the bytes would highlight the wrong thing,
//! which is worse than not highlighting at all.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use odr_osdp::payload::{Capability, Ccrypt, KeysetCommand, PdCapabilities, RawCardRead};
use odr_osdp::{Frame, ScsType};
use odr_wiegand::{BitVec, CardFormat};

use crate::json::{self, Json};

/// Where a field sits, in the addressing modes `site/ENGINE-API.md` §6 allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum At {
    /// An absolute byte offset into the frame, with a length.
    Bytes(usize, usize),
    /// A byte offset relative to the parent field.
    InPayload(usize, usize),
    /// Conspicuously absent: rendered as `value: 'absent'`.
    Absent,
    /// A bit offset into the bit view, with a bit length.
    Bits(usize, usize),
    /// No position at all.
    Nowhere,
}

/// The recovered plaintext of an encrypted payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Sealed {
    /// The plaintext bytes.
    pub bytes: Vec<u8>,
    /// Its decode tree, addressed relative to the plaintext.
    pub fields: Vec<Field>,
}

/// One node of the decode tree.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// Stable id. Drill predicates and the site's field-open reports name these.
    pub id: String,
    /// The label.
    pub name: String,
    /// The value, verbatim and selectable.
    pub value: String,
    /// What it means in one phrase.
    pub meaning: String,
    /// The teaching sentence, or empty.
    pub note: String,
    /// `"clear"` or `"opaque"`.
    pub visibility: &'static str,
    /// Where it sits.
    pub at: At,
    /// Nested decode.
    pub children: Vec<Field>,
    /// The recovered plaintext, when the bench holds the key.
    pub sealed: Option<Sealed>,
}

impl Field {
    /// A clear field at an absolute offset.
    pub fn at(id: &str, name: &str, at: At, value: impl Into<String>) -> Field {
        Field {
            id: id.to_string(),
            name: name.to_string(),
            value: value.into(),
            meaning: String::new(),
            note: String::new(),
            visibility: "clear",
            at,
            children: Vec::new(),
            sealed: None,
        }
    }

    /// Set the meaning.
    pub fn means(mut self, meaning: impl Into<String>) -> Field {
        self.meaning = meaning.into();
        self
    }

    /// Set the teaching note.
    pub fn note(mut self, note: impl Into<String>) -> Field {
        self.note = note.into();
        self
    }

    /// Mark it as needing the session key.
    pub fn opaque(mut self) -> Field {
        self.visibility = "opaque";
        self
    }

    /// Give it children.
    pub fn kids(mut self, children: Vec<Field>) -> Field {
        self.children = children;
        self
    }

    /// Attach recovered plaintext.
    pub fn with_sealed(mut self, sealed: Option<Sealed>) -> Field {
        self.sealed = sealed;
        self
    }

    /// Render for `site/ENGINE-API.md` §6.
    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("id", json::s(self.id.clone()))
            .set("name", json::s(self.name.clone()))
            .set(
                "value",
                json::s(if matches!(self.at, At::Absent) {
                    String::from("absent")
                } else {
                    self.value.clone()
                }),
            )
            .set("meaning", json::s(self.meaning.clone()))
            .set("note", json::s(self.note.clone()))
            .set("visibility", json::s(self.visibility));
        match self.at {
            At::Bytes(off, len) => {
                o.set("offset", json::nz(off)).set("length", json::nz(len));
            }
            At::InPayload(off, len) => {
                o.set("offsetInPayload", json::nz(off))
                    .set("length", json::nz(len));
            }
            At::Absent => {
                o.set("offsetInPayload", json::n(-1.0f64))
                    .set("length", json::nz(0));
            }
            At::Bits(off, len) => {
                o.set("bitOffset", json::nz(off))
                    .set("bitLength", json::nz(len));
            }
            At::Nowhere => {}
        }
        if !self.children.is_empty() {
            o.set(
                "children",
                Json::Arr(self.children.iter().map(Field::to_json).collect()),
            );
        }
        if let Some(sealed) = &self.sealed {
            let mut sj = Json::obj();
            sj.set("length", json::nz(sealed.bytes.len()))
                .set("bytes", json::s(hex_spaced(&sealed.bytes)))
                .set(
                    "fields",
                    Json::Arr(sealed.fields.iter().map(Field::to_json).collect()),
                );
            o.set("sealed", sj);
        }
        o
    }
}

/// `"53 02 0E"`.
pub fn hex_spaced(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&hex_byte(*b));
    }
    s
}

/// `"0E"`.
pub fn hex_byte(b: u8) -> String {
    const D: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(2);
    s.push(D[usize::from(b >> 4)] as char);
    s.push(D[usize::from(b & 0x0F)] as char);
    s
}

/// The name a command or reply code goes by.
pub fn code_name(frame: &Frame) -> String {
    if frame.is_reply {
        frame.reply_code().map_or_else(
            || format!("0x{}", hex_byte(frame.id)),
            |r| r.name().to_string(),
        )
    } else {
        frame.command_code().map_or_else(
            || format!("0x{}", hex_byte(frame.id)),
            |c| c.name().to_string(),
        )
    }
}

/// `"SCS_17"`.
pub fn scs_name(scs: ScsType) -> String {
    format!("SCS_{}", hex_byte(scs.to_u8()))
}

fn scs_note(scs: ScsType) -> &'static str {
    match scs {
        ScsType::Chlng => "CHLNG — the ACU opens the handshake with RND.A.",
        ScsType::Ccrypt => "CCRYPT — the PD answers with its UID, RND.B and the client cryptogram.",
        ScsType::Scrypt => "SCRYPT — the ACU proves it holds the key.",
        ScsType::RmacI => "RMAC_I — the PD seeds the reply MAC chain. The session is now up.",
        ScsType::CmdMacOnly | ScsType::ReplyMacOnly => {
            "MAC, no encryption. A null cipher: the payload is plaintext beside a real MAC."
        }
        ScsType::CmdEncrypted => "MAC and AES-128-CBC encryption, ACU to PD.",
        ScsType::ReplyEncrypted => "MAC and AES-128-CBC encryption, PD to ACU.",
    }
}

// ---------------------------------------------------------------------------
// OSDP
// ---------------------------------------------------------------------------

/// **The decode tree of one OSDP frame**, in wire order, with offsets that
/// mirror [`Frame::encode`].
///
/// `plaintext` is the recovered payload when the bench holds the session key,
/// and `None` otherwise — which is the normal case, and the point of drill 4.1.
pub fn osdp_fields(frame: &Frame, plaintext: Option<&[u8]>) -> Vec<Field> {
    let wire = frame.encode();
    let mut out = Vec::new();
    let mut at = 0usize;

    if frame.mark {
        out.push(
            Field::at("mark", "Mark", At::Bytes(at, 1), hex_byte(0xFF))
                .means("line idle byte")
                .note(
                    "Not counted in the length and not covered by the CRC. It gives the receiving \
                     UART something to lock onto while the RS-485 driver enables.",
                ),
        );
        at += 1;
    }

    out.push(
        Field::at(
            "som",
            "SOM",
            At::Bytes(at, 1),
            hex_byte(wire.get(at).copied().unwrap_or(0x53)),
        )
        .means("start of message")
        .note("Every OSDP frame begins 0x53."),
    );
    at += 1;

    let addr_byte = wire.get(at).copied().unwrap_or(frame.address);
    out.push(
        Field::at("address", "Address", At::Bytes(at, 1), hex_byte(addr_byte))
            .means(format!(
                "PD {}{}",
                frame.address & 0x7F,
                if frame.is_reply {
                    ", reply (bit 7 set)"
                } else {
                    ", command"
                }
            ))
            .note(
                "Bit 7 is the direction bit, which is why an analyser can label direction without \
                 knowing the wiring.",
            ),
    );
    at += 1;

    let declared = frame.declared_len();
    out.push(
        Field::at(
            "length",
            "Length",
            At::Bytes(at, 2),
            hex_spaced(&wire[at.min(wire.len())..(at + 2).min(wire.len())]),
        )
        .means(format!("{declared} bytes"))
        .note(
            "Total frame length LSB first, counting SOM through the trailer. The mark byte is not \
             included.",
        ),
    );
    at += 2;

    let ctrl = frame.control_byte();
    out.push(
        Field::at("control", "Control", At::Bytes(at, 1), hex_byte(ctrl))
            .means(format!(
                "seq {}, {}, {}",
                frame.sequence & 0x03,
                if frame.use_crc { "CRC" } else { "checksum" },
                if frame.security.is_some() {
                    "SCB present"
                } else {
                    "no SCB"
                }
            ))
            .note("Bits 0-1 sequence, bit 2 CRC (not checksum), bit 3 security block present.")
            .kids(alloc::vec![
                Field::at(
                    "ctrl_seq",
                    "sequence",
                    At::Nowhere,
                    (frame.sequence & 0x03).to_string()
                )
                .means("bits 0-1")
                .note(
                    "Two bits. It wraps every four frames, which is why it is a liveness aid and \
                     not a replay defence."
                ),
                Field::at(
                    "ctrl_crc",
                    "CRC in use",
                    At::Nowhere,
                    u8::from(frame.use_crc).to_string()
                )
                .means("bit 2")
                .note("Set: the trailer is a 16-bit CRC rather than a one-byte checksum."),
                Field::at(
                    "ctrl_scb",
                    "security block",
                    At::Nowhere,
                    u8::from(frame.security.is_some()).to_string()
                )
                .means("bit 3")
                .note("Set when a security block follows the control byte."),
            ]),
    );
    at += 1;

    if let Some(sb) = &frame.security {
        let n = sb.encoded_len();
        let encoded = sb.encode();
        let mut kids = alloc::vec![
            Field::at("scb_len", "scb length", At::Nowhere, hex_byte(n as u8))
                .means(format!("{n} bytes"))
                .note("Counts itself and the type byte."),
            Field::at("scb_type", "scb type", At::Nowhere, hex_byte(sb.raw_type))
                .means(
                    sb.scs_type
                        .map_or_else(|| String::from("unknown"), scs_name)
                )
                .note(sb.scs_type.map_or("", scs_note)),
        ];
        if let Some(first) = sb.data.first() {
            let is_rmac = sb.scs_type == Some(ScsType::RmacI);
            kids.push(
                Field::at("scb_data", "key type", At::Nowhere, hex_byte(*first))
                    .means(if is_rmac {
                        String::from("ACU cryptogram verified")
                    } else if *first == 0x00 {
                        String::from("SCBK-D (the published default key)")
                    } else {
                        String::from("SCBK (site key)")
                    })
                    .note(if is_rmac {
                        ""
                    } else {
                        "Sent in the clear, before any encryption exists. A passive listener \
                         learns whether this site ever moved off the published default key by \
                         watching one handshake."
                    }),
            );
        }
        out.push(
            Field::at(
                "security_block",
                "Security block",
                At::Bytes(at, n),
                hex_spaced(&encoded),
            )
            .means(
                sb.scs_type
                    .map_or_else(|| String::from("unrecognised block"), scs_name),
            )
            .note(sb.scs_type.map_or("", scs_note))
            .kids(kids),
        );
        at += n;
    }

    let encrypted = frame.is_encrypted();
    out.push(
        Field::at(
            "code",
            if frame.is_reply {
                "Reply code"
            } else {
                "Command code"
            },
            At::Bytes(at, 1),
            hex_byte(frame.id),
        )
        .means(code_name(frame))
        .note(if encrypted {
            "The command byte sits OUTSIDE the encrypted payload. It is plaintext on every OSDP \
             frame, in every security mode. Traffic analysis never needed a key."
        } else {
            "Identifies the command or reply. Always plaintext."
        }),
    );
    at += 1;

    if !frame.payload.is_empty() {
        let len = frame.payload.len();
        let field = Field::at(
            "payload",
            "Payload",
            At::Bytes(at, len),
            hex_spaced(&frame.payload),
        )
        .means(if encrypted {
            format!("{len} bytes, AES-128-CBC")
        } else {
            format!("{len} bytes")
        })
        .note(if encrypted {
            "Sealed under S-ENC. Without the session key this is the only part of the frame an \
             observer cannot read."
        } else {
            ""
        });
        let field = if encrypted {
            let sealed = plaintext.map(|p| Sealed {
                bytes: p.to_vec(),
                fields: payload_fields(frame, p, "pt"),
            });
            field.opaque().with_sealed(sealed)
        } else {
            field.kids(payload_fields(frame, &frame.payload, "pl"))
        };
        out.push(field);
        at += len;
    }

    if frame.security.as_ref().is_some_and(|s| s.has_mac()) {
        let mac = frame.mac.unwrap_or([0u8; 4]);
        out.push(
            Field::at("mac", "MAC", At::Bytes(at, 4), hex_spaced(&mac))
                .means("32-bit truncated MAC")
                .note(
                    "AES-128-CBC-MAC truncated to its first four bytes. Four bytes is 2^32 — see \
                     drill 4.2 for what that is worth.",
                ),
        );
        at += 4;
    }

    let trailer = frame.trailer_len();
    let tail = &wire[at.min(wire.len())..(at + trailer).min(wire.len())];
    out.push(
        Field::at(
            "crc",
            if frame.use_crc { "CRC" } else { "Checksum" },
            At::Bytes(at, trailer),
            hex_spaced(tail),
        )
        .means(if frame.use_crc {
            let v = u16::from(tail.first().copied().unwrap_or(0))
                | (u16::from(tail.get(1).copied().unwrap_or(0)) << 8);
            format!("0x{}{}, valid", hex_byte((v >> 8) as u8), hex_byte(v as u8))
        } else {
            String::from("one-byte checksum, valid")
        })
        .note(
            "CRC-16/AUG-CCITT over SOM onwards. An integrity check against noise, not against an \
             attacker: anyone rewriting a frame recomputes it.",
        ),
    );

    out
}

/// The decode of a payload, addressed relative to the payload itself.
fn payload_fields(frame: &Frame, payload: &[u8], prefix: &str) -> Vec<Field> {
    use odr_osdp::codes::{Command, Reply};

    if frame.is_reply {
        match frame.reply_code() {
            Some(Reply::Raw) => return card_read_fields(payload, prefix),
            Some(Reply::PdCap) => return pdcap_fields(payload, prefix),
            Some(Reply::Ccrypt) => return ccrypt_fields(payload, prefix),
            Some(Reply::RmacI) => {
                return alloc::vec![Field::at(
                    &format!("{prefix}_rmac"),
                    "initial R-MAC",
                    At::InPayload(0, payload.len().min(16)),
                    hex_spaced(&payload[..payload.len().min(16)])
                )
                .means("seeds the reply MAC chain")
                .note(
                    "Both ends compute this from the server cryptogram. The chain it seeds is what \
                     makes each frame's IV depend on the last one — which is drill 4.3."
                )]
            }
            _ => {}
        }
    } else {
        match frame.command_code() {
            Some(Command::Chlng) => {
                return alloc::vec![Field::at(
                    &format!("{prefix}_rnda"),
                    "RND.A",
                    At::InPayload(0, payload.len().min(8)),
                    hex_spaced(&payload[..payload.len().min(8)])
                )
                .means("the ACU's nonce, 8 bytes")
                .note(
                    "Only the first six bytes reach the session keys. Forty-eight bits of the \
                     controller's nonce is all the entropy a session ever gets."
                )]
            }
            Some(Command::Scrypt) => {
                return alloc::vec![Field::at(
                    &format!("{prefix}_server"),
                    "server cryptogram",
                    At::InPayload(0, payload.len().min(16)),
                    hex_spaced(&payload[..payload.len().min(16)])
                )
                .means("the ACU proves it holds the key")
                .note(
                    "In the clear. It proves possession of the SCBK to anyone already holding it."
                )]
            }
            Some(Command::Keyset) => return keyset_fields(payload, prefix),
            Some(Command::Out) => return output_fields(payload, prefix),
            _ => {}
        }
    }
    Vec::new()
}

fn card_read_fields(payload: &[u8], prefix: &str) -> Vec<Field> {
    let Ok(read) = RawCardRead::decode(payload) else {
        return Vec::new();
    };
    let head = RawCardRead::HEADER_LEN;
    let bits = payload.len().saturating_sub(head);
    let decoded = odr_wiegand::decode(
        CardFormat::H10301,
        &unpack_bits(&read.data, usize::from(read.bit_count)),
    )
    .ok()
    .and_then(|d| match (d.facility_code, d.card_number) {
        (Some(f), Some(c)) => Some(format!("FC {f}, card {c}")),
        _ => None,
    });
    alloc::vec![
        Field::at(
            &format!("{prefix}_reader"),
            "reader",
            At::InPayload(0, 1),
            hex_byte(read.reader)
        )
        .means(format!("reader {}", read.reader)),
        Field::at(
            &format!("{prefix}_fmt"),
            "format",
            At::InPayload(1, 1),
            hex_byte(read.format_code)
        )
        .means(if read.format_code == 0 {
            "raw bit array"
        } else {
            "PD-applied format"
        })
        .note("The PD is not interpreting the credential. It is forwarding the bits it saw."),
        Field::at(
            &format!("{prefix}_len"),
            "bit count",
            At::InPayload(2, 2),
            hex_spaced(&payload[2..4.min(payload.len())])
        )
        .means(format!("{} bits", read.bit_count)),
        Field::at(
            &format!("{prefix}_bits"),
            "card bits",
            At::InPayload(head, bits),
            hex_spaced(&read.data)
        )
        .means(decoded.unwrap_or_else(|| format!("{} raw bits", read.bit_count)))
        .note(
            "The same bits Module 1 watched cross a Wiegand wire. The credential did not get \
             stronger when the bus did."
        ),
    ]
}

/// The inverse of `odr_bus::capture::pack_bits`: MSB-first, `n` bits.
pub fn unpack_bits(bytes: &[u8], n: usize) -> BitVec {
    let mut bits = Vec::with_capacity(n);
    for i in 0..n {
        bits.push(bytes.get(i / 8).is_some_and(|b| b & (0x80 >> (i % 8)) != 0));
    }
    BitVec::from_bools(&bits)
}

fn pdcap_fields(payload: &[u8], prefix: &str) -> Vec<Field> {
    let Ok(caps) = PdCapabilities::decode(payload) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, entry) in caps.entries.iter().enumerate() {
        let off = i * Capability::LEN;
        let crypto = entry.function_code == 0x09;
        out.push(
            Field::at(
                &format!("{prefix}_cap_{}", hex_byte(entry.function_code)),
                &format!("function 0x{}", hex_byte(entry.function_code)),
                At::InPayload(off, Capability::LEN),
                hex_spaced(&payload[off..(off + Capability::LEN).min(payload.len())]),
            )
            .means(if crypto {
                format!(
                    "communication security: AES-128 {}, default key {}",
                    if entry.compliance & 1 == 1 {
                        "yes"
                    } else {
                        "no"
                    },
                    if entry.count & 1 == 1 {
                        "in use"
                    } else {
                        "not in use"
                    }
                )
            } else {
                format!(
                    "{}, compliance {}",
                    capability_name(entry.function_code),
                    entry.compliance
                )
            })
            .note(if crypto {
                "This entry is the whole downgrade attack. Delete it in flight and the controller \
                 concludes the reader cannot do crypto — and then talks to it in the clear, \
                 believing that is the reader's fault."
            } else {
                ""
            }),
        );
    }
    if !caps.entries.iter().any(|e| e.function_code == 0x09) {
        out.push(
            Field::at(
                &format!("{prefix}_cap_missing"),
                "function 0x09",
                At::Absent,
                "absent",
            )
            .means("communication security: NOT REPORTED")
            .note(
                "No communication-security entry. A controller that trusts this reply concludes \
                 the reader cannot do AES and talks to it in the clear. Nothing in OSDP \
                 authenticates a capability report.",
            ),
        );
    }
    out
}

fn ccrypt_fields(payload: &[u8], prefix: &str) -> Vec<Field> {
    if Ccrypt::decode(payload).is_err() {
        return Vec::new();
    }
    alloc::vec![
        Field::at(
            &format!("{prefix}_cuid"),
            "cUID",
            At::InPayload(0, 8),
            hex_spaced(&payload[0..8])
        )
        .means("the PD's identifier"),
        Field::at(
            &format!("{prefix}_rndb"),
            "RND.B",
            At::InPayload(8, 8),
            hex_spaced(&payload[8..16])
        )
        .means("the PD's nonce")
        .note("Contributes nothing to the session keys. Sixty-four bits of theatre."),
        Field::at(
            &format!("{prefix}_ccrypt"),
            "client cryptogram",
            At::InPayload(16, 16),
            hex_spaced(&payload[16..32])
        )
        .means("AES-ECB(S-ENC, RND.A ‖ RND.B)")
        .note(
            "Anyone holding the base key can recompute this from the two nonces, which is how a \
             candidate key is tested in four AES operations — drills 3.2 and 3.3."
        ),
    ]
}

fn keyset_fields(payload: &[u8], prefix: &str) -> Vec<Field> {
    let Ok(cmd) = KeysetCommand::decode(payload) else {
        return Vec::new();
    };
    alloc::vec![
        Field::at(
            &format!("{prefix}_keytype"),
            "key type",
            At::InPayload(0, 1),
            hex_byte(cmd.key_type)
        )
        .means("SCBK"),
        Field::at(
            &format!("{prefix}_keylen"),
            "key length",
            At::InPayload(1, 1),
            hex_byte(cmd.key.len() as u8)
        )
        .means(format!("{} bytes", cmd.key.len())),
        Field::at(
            &format!("{prefix}_key"),
            "the site key",
            At::InPayload(2, cmd.key.len()),
            hex_spaced(&cmd.key)
        )
        .means("SCBK, being installed")
        .note(
            "The site key crossing the link it exists to protect. OSDP has no key exchange, so \
             commissioning pushes the key over the bus — inside a channel keyed with the published \
             default, which anyone can read. That is drill 3.5 in one frame."
        ),
    ]
}

fn output_fields(payload: &[u8], prefix: &str) -> Vec<Field> {
    if payload.len() < 4 {
        return Vec::new();
    }
    alloc::vec![
        Field::at(
            &format!("{prefix}_out_num"),
            "output number",
            At::InPayload(0, 1),
            hex_byte(payload[0])
        )
        .means(format!("output {}", payload[0])),
        Field::at(
            &format!("{prefix}_out_ctl"),
            "control code",
            At::InPayload(1, 1),
            hex_byte(payload[1])
        )
        .means("permanent state, immediate")
        .note("The frame that opens the door."),
        Field::at(
            &format!("{prefix}_out_time"),
            "timer",
            At::InPayload(2, 2),
            hex_spaced(&payload[2..4])
        )
        .means(format!(
            "{} × 100 ms",
            u16::from(payload[2]) | (u16::from(payload[3]) << 8)
        )),
    ]
}

fn capability_name(code: u8) -> &'static str {
    match code {
        0x01 => "contact status monitoring",
        0x02 => "output control",
        0x03 => "card data format",
        0x04 => "reader LED control",
        0x05 => "reader audible output",
        0x06 => "reader text output",
        0x07 => "time keeping",
        0x08 => "check character support",
        0x09 => "communication security",
        0x0A => "receive buffer size",
        0x0B => "largest combined message",
        _ => "capability",
    }
}

// ---------------------------------------------------------------------------
// Bit-level lines: RF and the two-wire protocols
// ---------------------------------------------------------------------------

/// The decode of a 26-bit Wiegand frame, addressed in bits because bytes are a
/// lie on this line.
pub fn wiegand_fields(bits: &BitVec, substituted: bool) -> Vec<Field> {
    let n = bits.len();
    let decoded = odr_wiegand::decode(CardFormat::H10301, bits).ok();
    let bit_str = |from: usize, len: usize| -> String {
        (from..(from + len).min(n))
            .map(|i| {
                if bits.get(i).unwrap_or(false) {
                    '1'
                } else {
                    '0'
                }
            })
            .collect()
    };
    if n != 26 {
        return alloc::vec![Field::at(
            "w_raw",
            "bit stream",
            At::Bits(0, n),
            bit_str(0, n)
        )
        .means(format!("{n} bits"))
        .note("Not a 26-bit H10301 frame. The format is a configuration at the panel, never something the wire declares.")];
    }
    let fc = decoded.as_ref().and_then(|d| d.facility_code);
    let cn = decoded.as_ref().and_then(|d| d.card_number);
    alloc::vec![
        Field::at("w_pe", "Even parity", At::Bits(0, 1), bit_str(0, 1))
            .means("over bits 1-12")
            .note(
                "One bit of parity over the first half. It catches a single flipped bit on a noisy \
                 wire. It is not a signature and it authenticates nobody."
            ),
        Field::at("w_fc", "Facility code", At::Bits(1, 8), bit_str(1, 8))
            .means(fc.map_or_else(
                || String::from("unreadable"),
                |v| format!("{v} (0x{})", hex_byte(v as u8))
            ))
            .note(
                "Eight bits. Shared by every badge in the building, which is why it is the field a \
                 brute-force sweep holds constant."
            ),
        Field::at("w_cn", "Card number", At::Bits(9, 16), bit_str(9, 16))
            .means(cn.map_or_else(|| String::from("unreadable"), |v| format!("{v}")))
            .note(if substituted {
                "Rewritten in flight by the inline tap. The reader never emitted this number."
            } else {
                "Sixteen bits, sent in the clear, with nothing to defeat."
            }),
        Field::at("w_po", "Odd parity", At::Bits(25, 1), bit_str(25, 1))
            .means("over bits 13-24")
            .note("Recomputed by anyone who edits the number. Parity is not integrity."),
    ]
}

/// The decode of whatever a 125 kHz tag put into the reader's field.
pub fn rf_fields(bits: &BitVec, label: &str) -> Vec<Field> {
    let n = bits.len();
    let bit_str = |from: usize, len: usize| -> String {
        (from..(from + len).min(n))
            .map(|i| {
                if bits.get(i).unwrap_or(false) {
                    '1'
                } else {
                    '0'
                }
            })
            .collect()
    };
    if n == 64 {
        // EM4100: nine header ones, ten nibbles with row parity, four column
        // parity bits, one stop bit.
        return alloc::vec![
            Field::at("em_hdr", "Header", At::Bits(0, 9), bit_str(0, 9))
                .means("nine ones")
                .note(
                    "The tag repeats this forever while it is in the field. There is no \"start a \
                     session\" and nothing to refuse."
                ),
            Field::at("em_id", "Tag ID", At::Bits(9, 50), bit_str(9, 50))
                .means(label.to_string())
                .note(
                    "Ten data nibbles with row parity. This number is the entire credential: no \
                     processor, no key, no challenge."
                ),
            Field::at("em_col", "Column parity", At::Bits(59, 4), bit_str(59, 4))
                .means("error detection")
                .note("Detection, not protection."),
            Field::at("em_stop", "Stop bit", At::Bits(63, 1), bit_str(63, 1)).means("end of word"),
        ];
    }
    alloc::vec![Field::at("rf_bits", "Tag ID", At::Bits(0, n), bit_str(0, n))
        .means(label.to_string())
        .note(
            "The bits the tag emitted into the reader's field. On a 125 kHz prox card they are the \
             whole credential."
        )]
}
