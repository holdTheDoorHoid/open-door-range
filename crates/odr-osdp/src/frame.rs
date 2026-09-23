//! Frame encoding, parsing and stream resynchronisation.
//!
//! # The wire format
//!
//! ```text
//!  [FF]   optional "mark" byte, a line-idle filler. NOT counted by the
//!         length field and NOT covered by the trailer.
//!   53    SOM, start of message. Always 0x53.
//!  addr   PD address 0x00..0x7E, or 0x7F for the configuration/broadcast
//!         address. Bit 7 set means "this is a reply from the PD".
//!  len_l  ) total frame length, little-endian, counting SOM through the
//!  len_h  ) trailer inclusive, but EXCLUDING the mark byte.
//!  ctrl   bit 0-1  sequence number, 0..3
//!         bit 2    1 = two-byte CRC trailer, 0 = one-byte checksum
//!         bit 3    1 = a security block follows
//!         bit 4-7  reserved
//! [scb]   security block, if ctrl bit 3: scb_len, scb_type, then
//!         scb_len - 2 more bytes.
//!   id    command code (ACU → PD) or reply code (PD → ACU).
//! [data]  payload. Encrypted only under SCS_17 / SCS_18.
//! [mac]   4 bytes, only under SCS_15..SCS_18.
//! trail   CRC-16 little-endian, or one checksum byte.
//! ```
//!
//! # The id byte is plaintext, always
//!
//! Look at where `id` sits: *before* the encrypted region, not inside it. Even
//! at the strongest security level OSDP offers (SCS_17/SCS_18, MAC plus
//! encryption), the command and reply codes travel in the clear. This is
//! deliberate in the specification — it lets a bus analyser and a
//! non-participating device follow the conversation — and it is load-bearing
//! for the traffic-analysis lesson.
//!
//! The practical consequence: on a fully encrypted OSDP bus, an eavesdropper
//! still sees `POLL, ACK, POLL, ACK, POLL, RAW, ACK, OSTAT, ACK` and knows a
//! card was presented and a door opened, at what time, at which address. The
//! card number is protected. The fact that a human walked through that door at
//! 06:12 is not. [`Frame::parse`] reads `id` from an SCS_18 frame with no key
//! at all — there is a test for exactly that.
//!
//! # Parsing is tolerant by policy
//!
//! Every function in this module returns a structured error rather than
//! panicking, and [`Scanner`] can start mid-stream, skip garbage, and resume
//! after a corrupt frame. An offline analyser handed a noisy logic-analyser
//! capture must degrade gracefully, not stop at the first bad byte.

use crate::codes::{Command, Reply};
use crate::crc::{checksum, crc16};
use crate::security::{ScsType, SecurityBlock};
use alloc::vec::Vec;
use core::fmt;

/// Start of message. Every OSDP frame begins with this byte.
pub const SOM: u8 = 0x53;

/// The optional "mark" byte that may precede SOM.
///
/// On a half-duplex RS-485 bus the driver takes time to enable; a mark byte
/// gives the receiver's UART something to lock onto that is not part of the
/// frame. It is not counted in the length and not covered by the trailer.
pub const MARK: u8 = 0xFF;

/// The OSDP configuration / broadcast address.
///
/// A PD fresh out of the box answers here. It is also how `CMD_COMSET`
/// reaches a device whose address you do not yet know.
pub const CONFIGURATION_ADDRESS: u8 = 0x7F;

/// Shortest possible frame: header (5) + id (1) + one-byte checksum (1).
pub const MIN_FRAME_LEN: usize = 7;

/// Largest length value we will believe from a `len` field.
///
/// OSDP's own maximum is negotiated with `CMD_ACURXSIZE` and is at most 1440
/// bytes in practice. We cap a little above that so a corrupted length field
/// cannot make a parser try to buffer 64 KiB.
pub const MAX_FRAME_LEN: usize = 1600;

/// Everything that can go wrong reading a frame.
///
/// Distinguishing [`ParseError::Truncated`] from the rest matters: truncation
/// means "come back with more bytes", everything else means "this is not a
/// frame, resynchronise".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// The buffer does not begin with SOM (or MARK then SOM).
    NoStartOfMessage,
    /// Not enough bytes yet. `needed` is the total the frame claims to be.
    Truncated {
        /// Bytes the frame says it needs, counted from SOM.
        needed: usize,
        /// Bytes actually available from SOM onward.
        available: usize,
    },
    /// The length field is impossible: below [`MIN_FRAME_LEN`] or above
    /// [`MAX_FRAME_LEN`].
    BadLength {
        /// The value read from the length field.
        declared: u16,
    },
    /// The security block's own length field does not fit inside the frame, or
    /// is smaller than the two bytes it must contain.
    BadSecurityBlockLength {
        /// The value read from `scb_len`.
        declared: u8,
    },
    /// The frame is long enough for its header but leaves no room for the id
    /// byte, or for the MAC its security block requires.
    NoRoomForBody,
    /// CRC mismatch. The frame was structurally fine and the bytes are corrupt
    /// (or were tampered with — the CRC is not a security control).
    BadCrc {
        /// What the trailer should have been.
        expected: u16,
        /// What the trailer actually was.
        found: u16,
    },
    /// One-byte checksum mismatch.
    BadChecksum {
        /// What the trailer should have been.
        expected: u8,
        /// What the trailer actually was.
        found: u8,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::NoStartOfMessage => write!(f, "no SOM (0x53) at the start of the buffer"),
            ParseError::Truncated { needed, available } => write!(
                f,
                "truncated frame: needs {needed} bytes, only {available} available"
            ),
            ParseError::BadLength { declared } => {
                write!(f, "implausible length field {declared} (0x{declared:04x})")
            }
            ParseError::BadSecurityBlockLength { declared } => {
                write!(f, "bad security block length {declared}")
            }
            ParseError::NoRoomForBody => {
                write!(f, "frame length leaves no room for the id byte or MAC")
            }
            ParseError::BadCrc { expected, found } => {
                write!(f, "CRC mismatch: expected 0x{expected:04x}, found 0x{found:04x}")
            }
            ParseError::BadChecksum { expected, found } => {
                write!(f, "checksum mismatch: expected 0x{expected:02x}, found 0x{found:02x}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

impl ParseError {
    /// True if the only problem is that more bytes are needed.
    ///
    /// A streaming caller should keep the tail and wait; an offline analyser
    /// should report a truncated capture.
    pub fn is_truncation(&self) -> bool {
        matches!(self, ParseError::Truncated { .. })
    }
}

/// Which way a frame is travelling.
///
/// Encoded as bit 7 of the address byte, which is why an analyser can label
/// direction without knowing anything about the bus wiring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Controller (ACU) to peripheral device (PD): a command.
    AcuToPd,
    /// Peripheral device to controller: a reply.
    PdToAcu,
}

/// A decoded OSDP frame.
///
/// `payload` is always the bytes **as they appeared on the wire**. Under
/// SCS_17/SCS_18 that is ciphertext; use [`crate::channel::SecureChannel`] to
/// get plaintext. This split is deliberate: an analyser without the key must
/// still be able to hold, display and re-serialise a frame it cannot read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Whether a `0xFF` mark byte preceded SOM. Preserved so a capture can be
    /// re-serialised byte-identically.
    pub mark: bool,
    /// PD address, 0..=0x7F. Bit 7 is *not* stored here; see [`Frame::is_reply`].
    pub address: u8,
    /// True if this frame came from the PD (address bit 7 was set).
    pub is_reply: bool,
    /// Sequence number, 0..=3.
    ///
    /// Two bits. Sequence 0 is special: it means "I have just reset, accept me
    /// without checking". A replay attacker only has to wrap four frames to get
    /// back to a number the peer will accept, which is why sequence numbers do
    /// not meaningfully stop replay on their own.
    pub sequence: u8,
    /// True if the trailer is a CRC-16; false for the one-byte checksum.
    pub use_crc: bool,
    /// The security block, if control bit 3 was set.
    pub security: Option<SecurityBlock>,
    /// Command code (`!is_reply`) or reply code (`is_reply`). Raw, because an
    /// analyser must be able to show a code it does not recognise.
    pub id: u8,
    /// Payload bytes exactly as they appeared on the wire.
    pub payload: Vec<u8>,
    /// The four-byte truncated MAC, present only under SCS_15..SCS_18.
    pub mac: Option<[u8; 4]>,
}

impl Frame {
    /// Build a bare command frame: CRC trailer, no security block, no mark.
    pub fn command(address: u8, sequence: u8, command: Command, payload: Vec<u8>) -> Self {
        Self {
            mark: false,
            address: address & 0x7F,
            is_reply: false,
            sequence: sequence & 0x03,
            use_crc: true,
            security: None,
            id: command.to_u8(),
            payload,
            mac: None,
        }
    }

    /// Build a bare reply frame: CRC trailer, no security block, no mark.
    pub fn reply(address: u8, sequence: u8, reply: Reply, payload: Vec<u8>) -> Self {
        Self {
            mark: false,
            address: address & 0x7F,
            is_reply: true,
            sequence: sequence & 0x03,
            use_crc: true,
            security: None,
            id: reply.to_u8(),
            payload,
            mac: None,
        }
    }

    /// Direction of travel, from the address bit 7.
    pub fn direction(&self) -> Direction {
        if self.is_reply {
            Direction::PdToAcu
        } else {
            Direction::AcuToPd
        }
    }

    /// Interpret [`Frame::id`] as a command code. `None` for replies and for
    /// codes this crate does not know.
    pub fn command_code(&self) -> Option<Command> {
        if self.is_reply {
            None
        } else {
            Command::from_u8(self.id)
        }
    }

    /// Interpret [`Frame::id`] as a reply code. `None` for commands and for
    /// codes this crate does not know.
    pub fn reply_code(&self) -> Option<Reply> {
        if self.is_reply {
            Reply::from_u8(self.id)
        } else {
            None
        }
    }

    /// Is this frame addressed to every PD on the bus?
    pub fn is_broadcast(&self) -> bool {
        self.address == CONFIGURATION_ADDRESS
    }

    /// The security block type, if any.
    pub fn scs_type(&self) -> Option<ScsType> {
        self.security.as_ref().and_then(|s| s.scs_type)
    }

    /// True if the payload of this frame is ciphertext.
    ///
    /// Note that this is `false` for SCS_15/SCS_16 — those carry a MAC and a
    /// perfectly readable payload.
    pub fn is_encrypted(&self) -> bool {
        self.security.as_ref().is_some_and(|s| s.is_encrypted())
    }

    /// Number of trailer bytes: 2 for CRC, 1 for checksum.
    pub fn trailer_len(&self) -> usize {
        if self.use_crc {
            2
        } else {
            1
        }
    }

    fn mac_len(&self) -> usize {
        if self.security.as_ref().is_some_and(|s| s.has_mac()) {
            4
        } else {
            0
        }
    }

    /// Total encoded length **as the length field reports it**: SOM through
    /// trailer, excluding any mark byte.
    pub fn declared_len(&self) -> usize {
        5 // SOM, addr, len_lsb, len_msb, ctrl
            + self.security.as_ref().map_or(0, |s| s.encoded_len())
            + 1 // id
            + self.payload.len()
            + self.mac_len()
            + self.trailer_len()
    }

    /// Total bytes this frame occupies on the wire, mark byte included.
    pub fn wire_len(&self) -> usize {
        self.declared_len() + usize::from(self.mark)
    }

    /// The control byte.
    pub fn control_byte(&self) -> u8 {
        let mut c = self.sequence & 0x03;
        if self.use_crc {
            c |= 0x04;
        }
        if self.security.is_some() {
            c |= 0x08;
        }
        c
    }

    /// The bytes a MAC is computed over: SOM through the end of the (possibly
    /// encrypted) payload, with the length field already set to the final
    /// value.
    ///
    /// The mark byte, the MAC field itself and the trailer are excluded. Call
    /// this, MAC the result, then set [`Frame::mac`] before encoding.
    pub fn bytes_for_mac(&self) -> Vec<u8> {
        let declared = self.declared_len();
        let mut out = Vec::with_capacity(declared);
        out.push(SOM);
        out.push(self.address & 0x7F | if self.is_reply { 0x80 } else { 0x00 });
        out.push((declared & 0xFF) as u8);
        out.push(((declared >> 8) & 0xFF) as u8);
        out.push(self.control_byte());
        if let Some(sb) = &self.security {
            out.extend_from_slice(&sb.encode());
        }
        out.push(self.id);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Serialise the frame to wire bytes, computing the trailer.
    ///
    /// If the security block requires a MAC but [`Frame::mac`] is `None`, four
    /// zero bytes are written in its place — the frame will be structurally
    /// valid and cryptographically wrong. The secure-channel code always fills
    /// it in; this behaviour exists so a frame composer can show a
    /// work-in-progress frame instead of refusing.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        if self.mark {
            out.push(MARK);
        }
        let body_start = out.len();
        out.extend_from_slice(&self.bytes_for_mac());
        if self.mac_len() == 4 {
            out.extend_from_slice(&self.mac.unwrap_or([0u8; 4]));
        }
        let body = &out[body_start..];
        if self.use_crc {
            let c = crc16(body);
            out.push((c & 0xFF) as u8);
            out.push(((c >> 8) & 0xFF) as u8);
        } else {
            let c = checksum(body);
            out.push(c);
        }
        out
    }

    /// Parse one frame from the start of `data`.
    ///
    /// A leading [`MARK`] byte is consumed if present. On success, returns the
    /// frame and how many bytes of `data` it consumed (mark included), so a
    /// caller can advance.
    ///
    /// This never panics and never indexes out of bounds regardless of what is
    /// in `data`.
    pub fn parse(data: &[u8]) -> Result<(Frame, usize), ParseError> {
        let mut cursor = 0usize;
        let mark = match (data.first(), data.get(1)) {
            (Some(&MARK), Some(&SOM)) => {
                cursor = 1;
                true
            }
            (Some(&MARK), None) => {
                return Err(ParseError::Truncated {
                    needed: MIN_FRAME_LEN,
                    available: 0,
                })
            }
            (Some(&SOM), _) => false,
            _ => return Err(ParseError::NoStartOfMessage),
        };

        let body = &data[cursor..];
        if body.first() != Some(&SOM) {
            return Err(ParseError::NoStartOfMessage);
        }
        if body.len() < 5 {
            return Err(ParseError::Truncated {
                needed: MIN_FRAME_LEN,
                available: body.len(),
            });
        }

        let addr_byte = body[1];
        let declared = u16::from(body[2]) | (u16::from(body[3]) << 8);
        let declared_usize = declared as usize;
        if !(MIN_FRAME_LEN..=MAX_FRAME_LEN).contains(&declared_usize) {
            return Err(ParseError::BadLength { declared });
        }
        if body.len() < declared_usize {
            return Err(ParseError::Truncated {
                needed: declared_usize,
                available: body.len(),
            });
        }
        let frame_bytes = &body[..declared_usize];

        let control = frame_bytes[4];
        let sequence = control & 0x03;
        let use_crc = control & 0x04 != 0;
        let has_scb = control & 0x08 != 0;
        let trailer_len = if use_crc { 2 } else { 1 };

        // Verify the trailer before trusting anything inside the frame.
        let (covered, trailer) = frame_bytes.split_at(declared_usize - trailer_len);
        if use_crc {
            let found = u16::from(trailer[0]) | (u16::from(trailer[1]) << 8);
            let expected = crc16(covered);
            if found != expected {
                return Err(ParseError::BadCrc { expected, found });
            }
        } else {
            let found = trailer[0];
            let expected = checksum(covered);
            if found != expected {
                return Err(ParseError::BadChecksum { expected, found });
            }
        }

        let mut pos = 5usize;
        let security = if has_scb {
            if pos + 2 > covered.len() {
                return Err(ParseError::BadSecurityBlockLength { declared: 0 });
            }
            let scb_len = frame_bytes[pos];
            if scb_len < 2 || pos + usize::from(scb_len) > covered.len() {
                return Err(ParseError::BadSecurityBlockLength { declared: scb_len });
            }
            let raw_type = frame_bytes[pos + 1];
            let data = frame_bytes[pos + 2..pos + usize::from(scb_len)].to_vec();
            pos += usize::from(scb_len);
            Some(SecurityBlock {
                scs_type: ScsType::from_u8(raw_type),
                raw_type,
                data,
            })
        } else {
            None
        };

        if pos >= covered.len() {
            return Err(ParseError::NoRoomForBody);
        }
        let id = frame_bytes[pos];
        pos += 1;

        let mac_len = if security.as_ref().is_some_and(|s| s.has_mac()) {
            4
        } else {
            0
        };
        if covered.len() < pos + mac_len {
            return Err(ParseError::NoRoomForBody);
        }
        let payload_end = covered.len() - mac_len;
        let payload = frame_bytes[pos..payload_end].to_vec();
        let mac = if mac_len == 4 {
            let mut m = [0u8; 4];
            m.copy_from_slice(&frame_bytes[payload_end..payload_end + 4]);
            Some(m)
        } else {
            None
        };

        let frame = Frame {
            mark,
            address: addr_byte & 0x7F,
            is_reply: addr_byte & 0x80 != 0,
            sequence,
            use_crc,
            security,
            id,
            payload,
            mac,
        };
        Ok((frame, cursor + declared_usize))
    }
}

/// What a [`Scanner`] found at one position in a byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanEvent {
    /// Bytes skipped before the next plausible start-of-frame. On a real
    /// capture this is line noise, the tail of a frame you started reading
    /// mid-way through, or another protocol on the same wire.
    Garbage {
        /// Offset into the original buffer.
        offset: usize,
        /// How many bytes were skipped.
        len: usize,
    },
    /// A frame that parsed and passed its trailer check.
    Frame {
        /// Offset into the original buffer, pointing at the mark byte if there
        /// was one, otherwise at SOM.
        offset: usize,
        /// Bytes consumed.
        len: usize,
        /// The decoded frame.
        frame: alloc::boxed::Box<Frame>,
    },
    /// Something that started with SOM but is not a valid frame. The scanner
    /// resynchronises by advancing one byte and hunting for the next SOM.
    Malformed {
        /// Offset of the SOM that failed to parse.
        offset: usize,
        /// Why it failed.
        error: ParseError,
    },
    /// The buffer ended in the middle of something that looked like a frame.
    ///
    /// In streaming mode ([`Scanner::new`]) iteration stops here and the caller
    /// should retain [`Scanner::remaining`] and append more bytes. In offline
    /// mode ([`Scanner::offline`]) the scanner treats it as another false start
    /// and keeps hunting.
    Incomplete {
        /// Offset of the partial frame.
        offset: usize,
        /// Always a [`ParseError::Truncated`].
        error: ParseError,
    },
}

/// A tolerant, resynchronising frame scanner.
///
/// Built for the two jobs DESIGN.md gives this crate: feeding the simulator,
/// and reading a real capture that may start mid-frame and may contain errors.
///
/// Pick the constructor that matches the job:
///
/// * [`Scanner::new`] — **streaming**. Stops at the first truncation, because
///   the rest of that frame is probably still in flight. Keep
///   [`Scanner::remaining`] and prepend it to the next chunk.
/// * [`Scanner::offline`] — **whole capture**. Never stops early. A truncated
///   frame is reported and then treated as one more false start, so a single
///   `0x53` in the middle of a payload with a large-looking length field cannot
///   swallow the rest of the file.
///
/// ```
/// use odr_osdp::frame::{Frame, Scanner, ScanEvent};
/// use odr_osdp::codes::Command;
///
/// let mut stream = vec![0xDE, 0xAD];                       // junk
/// stream.extend(Frame::command(1, 0, Command::Poll, vec![]).encode());
/// let events: Vec<_> = Scanner::new(&stream).collect();
/// assert!(matches!(events[0], ScanEvent::Garbage { len: 2, .. }));
/// assert!(matches!(events[1], ScanEvent::Frame { .. }));
/// ```
#[derive(Debug, Clone)]
pub struct Scanner<'a> {
    data: &'a [u8],
    pos: usize,
    done: bool,
    stop_on_truncation: bool,
}

impl<'a> Scanner<'a> {
    /// Start a **streaming** scan: iteration stops at the first truncated
    /// frame, and [`Scanner::remaining`] hands back the partial tail.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            done: false,
            stop_on_truncation: true,
        }
    }

    /// Start an **offline** scan over a complete capture: a truncation is
    /// reported as [`ScanEvent::Incomplete`] and then resynchronised past, so
    /// the scan always reaches the end of the buffer.
    ///
    /// Use this for a file. A payload byte that happens to be `0x53` followed
    /// by bytes that read as a 1200-byte length would otherwise end the scan.
    pub fn offline(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            done: false,
            stop_on_truncation: false,
        }
    }

    /// The bytes not yet consumed.
    ///
    /// After iteration stops on [`ScanEvent::Incomplete`], this is the partial
    /// frame; prepend it to the next chunk of a live stream.
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos.min(self.data.len())..]
    }

    /// Byte offset the scanner has reached.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Index of the next byte at or after `from` that could begin a frame.
    fn next_start(&self, from: usize) -> Option<usize> {
        (from..self.data.len()).find(|&i| {
            self.data[i] == SOM || (self.data[i] == MARK && self.data.get(i + 1) == Some(&SOM))
        })
    }
}

impl Iterator for Scanner<'_> {
    type Item = ScanEvent;

    fn next(&mut self) -> Option<ScanEvent> {
        if self.done || self.pos >= self.data.len() {
            return None;
        }
        let start = match self.next_start(self.pos) {
            Some(s) => s,
            None => {
                let ev = ScanEvent::Garbage {
                    offset: self.pos,
                    len: self.data.len() - self.pos,
                };
                self.pos = self.data.len();
                return Some(ev);
            }
        };
        if start > self.pos {
            let ev = ScanEvent::Garbage {
                offset: self.pos,
                len: start - self.pos,
            };
            self.pos = start;
            return Some(ev);
        }

        match Frame::parse(&self.data[start..]) {
            Ok((frame, used)) => {
                self.pos = start + used;
                Some(ScanEvent::Frame {
                    offset: start,
                    len: used,
                    frame: alloc::boxed::Box::new(frame),
                })
            }
            Err(e) if e.is_truncation() => {
                if self.stop_on_truncation {
                    self.done = true;
                } else {
                    // Offline: this may simply be a 0x53 inside a payload whose
                    // following bytes read as a large length. Step over it.
                    self.pos = start + 1;
                }
                Some(ScanEvent::Incomplete {
                    offset: start,
                    error: e,
                })
            }
            Err(e) => {
                // Resynchronise: this SOM was a false positive (a 0x53 inside a
                // payload, say). Step over it and hunt for the next one.
                self.pos = start + 1;
                Some(ScanEvent::Malformed {
                    offset: start,
                    error: e,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codes::{Command, Reply};
    use crate::security::{KeyType, ScsType};
    use alloc::vec;

    fn roundtrip(f: &Frame) -> Frame {
        let bytes = f.encode();
        let (parsed, used) = Frame::parse(&bytes).expect("parses");
        assert_eq!(used, bytes.len(), "consumed the whole buffer");
        assert_eq!(&parsed.encode(), &bytes, "re-encodes byte-identically");
        parsed
    }

    #[test]
    fn poll_frame_has_the_expected_shape() {
        let f = Frame::command(0x01, 0, Command::Poll, vec![]);
        let bytes = f.encode();
        // SOM, addr, len_lsb, len_msb, ctrl, id, crc_lo, crc_hi
        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes[0], 0x53);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[2], 0x08);
        assert_eq!(bytes[3], 0x00);
        assert_eq!(bytes[4], 0x04); // seq 0, CRC on, no SCB
        assert_eq!(bytes[5], Command::Poll.to_u8());
        assert_eq!(f.declared_len(), 8);
    }

    #[test]
    fn reply_sets_address_bit_7() {
        let f = Frame::reply(0x05, 2, Reply::Ack, vec![]);
        let bytes = f.encode();
        assert_eq!(bytes[1], 0x85);
        let parsed = roundtrip(&f);
        assert!(parsed.is_reply);
        assert_eq!(parsed.address, 0x05);
        assert_eq!(parsed.direction(), Direction::PdToAcu);
        assert_eq!(parsed.reply_code(), Some(Reply::Ack));
        assert_eq!(parsed.command_code(), None);
    }

    #[test]
    fn mark_byte_is_preserved() {
        let mut f = Frame::command(0x02, 1, Command::Id, vec![0x00]);
        f.mark = true;
        let bytes = f.encode();
        assert_eq!(bytes[0], MARK);
        assert_eq!(bytes[1], SOM);
        let parsed = roundtrip(&f);
        assert!(parsed.mark);
        // The mark is NOT counted by the length field.
        assert_eq!(parsed.declared_len(), bytes.len() - 1);
        assert_eq!(parsed.wire_len(), bytes.len());
    }

    #[test]
    fn checksum_variant_round_trips() {
        let mut f = Frame::command(0x03, 3, Command::Lstat, vec![]);
        f.use_crc = false;
        let bytes = f.encode();
        assert_eq!(bytes[4] & 0x04, 0, "CRC bit clear");
        assert_eq!(f.trailer_len(), 1);
        let parsed = roundtrip(&f);
        assert!(!parsed.use_crc);
        assert_eq!(parsed.sequence, 3);
    }

    #[test]
    fn sequence_number_is_two_bits() {
        for seq in 0u8..4 {
            let f = Frame::command(1, seq, Command::Poll, vec![]);
            assert_eq!(roundtrip(&f).sequence, seq);
        }
        // Anything above 3 is masked; there are only two bits on the wire.
        assert_eq!(Frame::command(1, 7, Command::Poll, vec![]).sequence, 3);
    }

    #[test]
    fn security_block_round_trips() {
        let mut f = Frame::command(1, 0, Command::Chlng, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        f.security = Some(SecurityBlock::handshake(ScsType::Chlng, KeyType::Default));
        let parsed = roundtrip(&f);
        assert_eq!(parsed.scs_type(), Some(ScsType::Chlng));
        assert_eq!(
            parsed.security.as_ref().unwrap().key_type(),
            Some(KeyType::Default)
        );
        assert_eq!(parsed.payload, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(parsed.mac, None);
    }

    #[test]
    fn mac_field_is_split_off_the_payload() {
        let mut f = Frame::command(1, 1, Command::Poll, vec![0xAA; 16]);
        f.security = Some(SecurityBlock::new(ScsType::CmdEncrypted));
        f.mac = Some([0xDE, 0xAD, 0xBE, 0xEF]);
        let parsed = roundtrip(&f);
        assert_eq!(parsed.payload, vec![0xAA; 16]);
        assert_eq!(parsed.mac, Some([0xDE, 0xAD, 0xBE, 0xEF]));
        assert!(parsed.is_encrypted());
    }

    /// The traffic-analysis lesson, as a test: the id byte is readable without
    /// any key at all, even at the strongest security level.
    #[test]
    fn command_id_is_plaintext_inside_a_secure_channel() {
        let mut f = Frame::command(0x0A, 2, Command::Out, vec![0x99; 16]);
        f.security = Some(SecurityBlock::new(ScsType::CmdEncrypted));
        f.mac = Some([1, 2, 3, 4]);
        let bytes = f.encode();

        // Parse with no key material whatsoever.
        let (parsed, _) = Frame::parse(&bytes).unwrap();
        assert_eq!(parsed.command_code(), Some(Command::Out));
        assert_eq!(parsed.address, 0x0A);
        assert!(parsed.is_encrypted());

        // And the same for a reply.
        let mut r = Frame::reply(0x0A, 2, Reply::Raw, vec![0x77; 32]);
        r.security = Some(SecurityBlock::new(ScsType::ReplyEncrypted));
        r.mac = Some([5, 6, 7, 8]);
        let (parsed, _) = Frame::parse(&r.encode()).unwrap();
        assert_eq!(
            parsed.reply_code(),
            Some(Reply::Raw),
            "an eavesdropper sees a card was read, without the key"
        );
    }

    #[test]
    fn bad_crc_is_reported_not_panicked() {
        let mut bytes = Frame::command(1, 0, Command::Poll, vec![]).encode();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        match Frame::parse(&bytes) {
            Err(ParseError::BadCrc { .. }) => {}
            other => panic!("expected BadCrc, got {other:?}"),
        }
    }

    #[test]
    fn bad_checksum_is_reported() {
        let mut f = Frame::command(1, 0, Command::Poll, vec![]);
        f.use_crc = false;
        let mut bytes = f.encode();
        let last = bytes.len() - 1;
        bytes[last] = bytes[last].wrapping_add(1);
        match Frame::parse(&bytes) {
            Err(ParseError::BadChecksum { .. }) => {}
            other => panic!("expected BadChecksum, got {other:?}"),
        }
    }

    #[test]
    fn truncation_is_distinguishable() {
        let bytes = Frame::command(1, 0, Command::Id, vec![0, 0, 0]).encode();
        for cut in 1..bytes.len() {
            let err = Frame::parse(&bytes[..cut]).unwrap_err();
            assert!(err.is_truncation(), "cut at {cut} gave {err:?}");
        }
    }

    #[test]
    fn implausible_length_is_rejected() {
        let mut bytes = Frame::command(1, 0, Command::Poll, vec![]).encode();
        bytes[2] = 0x02; // far below MIN_FRAME_LEN
        bytes[3] = 0x00;
        assert!(matches!(
            Frame::parse(&bytes),
            Err(ParseError::BadLength { declared: 2 })
        ));

        let mut bytes = Frame::command(1, 0, Command::Poll, vec![]).encode();
        bytes[2] = 0xFF;
        bytes[3] = 0xFF;
        assert!(matches!(Frame::parse(&bytes), Err(ParseError::BadLength { .. })));
    }

    #[test]
    fn no_som_is_rejected() {
        assert_eq!(
            Frame::parse(&[0x00, 0x01, 0x02]),
            Err(ParseError::NoStartOfMessage)
        );
        assert_eq!(Frame::parse(&[]), Err(ParseError::NoStartOfMessage));
    }

    #[test]
    fn bad_security_block_length_is_rejected() {
        let mut f = Frame::command(1, 0, Command::Chlng, vec![0; 8]);
        f.security = Some(SecurityBlock::handshake(ScsType::Chlng, KeyType::Default));
        let mut bytes = f.encode();
        bytes[5] = 0x01; // scb_len below the minimum of 2
        let body = bytes.len() - 2;
        let c = crc16(&bytes[..body]);
        bytes[body] = (c & 0xFF) as u8;
        bytes[body + 1] = (c >> 8) as u8;
        assert!(matches!(
            Frame::parse(&bytes),
            Err(ParseError::BadSecurityBlockLength { declared: 1 })
        ));
    }

    #[test]
    fn security_block_overrunning_the_frame_is_rejected() {
        let mut f = Frame::command(1, 0, Command::Chlng, vec![0; 8]);
        f.security = Some(SecurityBlock::handshake(ScsType::Chlng, KeyType::Default));
        let mut bytes = f.encode();
        bytes[5] = 0x7F; // scb_len larger than the whole frame
        let body = bytes.len() - 2;
        let c = crc16(&bytes[..body]);
        bytes[body] = (c & 0xFF) as u8;
        bytes[body + 1] = (c >> 8) as u8;
        assert!(matches!(
            Frame::parse(&bytes),
            Err(ParseError::BadSecurityBlockLength { declared: 0x7F })
        ));
    }

    #[test]
    fn frame_with_no_room_for_a_mac_is_rejected() {
        // Declare SCS_17 (which demands a 4-byte MAC) on a frame with a
        // zero-length payload and no MAC bytes.
        let mut bytes = alloc::vec![SOM, 0x01, 0x00, 0x00, 0x0C, 0x02, 0x17, 0x60];
        let len = bytes.len() + 2;
        bytes[2] = len as u8;
        let c = crc16(&bytes);
        bytes.push((c & 0xFF) as u8);
        bytes.push((c >> 8) as u8);
        assert!(matches!(Frame::parse(&bytes), Err(ParseError::NoRoomForBody)));
    }

    #[test]
    fn unknown_security_block_type_is_preserved_not_rejected() {
        let mut f = Frame::command(1, 0, Command::Poll, vec![]);
        f.security = Some(SecurityBlock {
            scs_type: None,
            raw_type: 0x99,
            data: vec![0x01],
        });
        let parsed = roundtrip(&f);
        assert_eq!(parsed.security.as_ref().unwrap().raw_type, 0x99);
        assert_eq!(parsed.scs_type(), None);
        assert!(!parsed.is_encrypted());
    }

    #[test]
    fn unknown_command_code_still_parses() {
        let mut f = Frame::command(1, 0, Command::Poll, vec![]);
        f.id = 0xEE;
        let parsed = roundtrip(&f);
        assert_eq!(parsed.id, 0xEE);
        assert_eq!(parsed.command_code(), None);
    }

    #[test]
    fn scanner_skips_garbage_and_finds_frames() {
        let mut stream = vec![0x11, 0x22, 0x33];
        let a = Frame::command(1, 0, Command::Poll, vec![]);
        let b = Frame::reply(1, 0, Reply::Ack, vec![]);
        stream.extend(a.encode());
        stream.extend(b.encode());
        stream.extend_from_slice(&[0x00, 0x00]);

        let events: Vec<ScanEvent> = Scanner::new(&stream).collect();
        let frames: Vec<&Frame> = events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Frame { frame, .. } => Some(&**frame),
                _ => None,
            })
            .collect();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].command_code(), Some(Command::Poll));
        assert_eq!(frames[1].reply_code(), Some(Reply::Ack));
        assert!(matches!(events[0], ScanEvent::Garbage { offset: 0, len: 3 }));
    }

    #[test]
    fn scanner_resynchronises_after_a_corrupt_frame() {
        let bad = {
            let mut b = Frame::command(1, 0, Command::Id, vec![0, 0, 0]).encode();
            let last = b.len() - 1;
            b[last] ^= 0x01;
            b
        };
        let good = Frame::reply(2, 1, Reply::Ack, vec![]).encode();
        let mut stream = bad;
        stream.extend(good);

        let events: Vec<ScanEvent> = Scanner::new(&stream).collect();
        assert!(events
            .iter()
            .any(|e| matches!(e, ScanEvent::Malformed { offset: 0, .. })));
        let found: Vec<&Frame> = events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Frame { frame, .. } => Some(&**frame),
                _ => None,
            })
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].reply_code(), Some(Reply::Ack));
        assert_eq!(found[0].address, 2);
    }

    #[test]
    fn scanner_starting_mid_frame_recovers() {
        let first = Frame::command(1, 0, Command::Text, vec![b'h', b'i', 0x53, 0x53]).encode();
        let second = Frame::reply(1, 0, Reply::Ack, vec![]).encode();
        let mut stream = first[5..].to_vec(); // chop the header off frame one
        stream.extend(second);

        let found: Vec<Frame> = Scanner::new(&stream)
            .filter_map(|e| match e {
                ScanEvent::Frame { frame, .. } => Some(*frame),
                _ => None,
            })
            .collect();
        assert_eq!(found.len(), 1, "only the intact second frame is recovered");
        assert_eq!(found[0].reply_code(), Some(Reply::Ack));
    }

    #[test]
    fn scanner_reports_a_truncated_tail_and_keeps_it() {
        let whole = Frame::command(1, 0, Command::Id, vec![0, 0, 0]).encode();
        let mut stream = Frame::reply(1, 0, Reply::Ack, vec![]).encode();
        let cut = whole.len() - 3;
        stream.extend_from_slice(&whole[..cut]);

        let mut scanner = Scanner::new(&stream);
        let events: Vec<ScanEvent> = scanner.by_ref().collect();
        assert!(matches!(
            events.last(),
            Some(ScanEvent::Incomplete { .. })
        ));
        // Feeding the retained tail plus the rest recovers the frame.
        let mut retry = scanner.remaining().to_vec();
        retry.extend_from_slice(&whole[cut..]);
        let (f, _) = Frame::parse(&retry).expect("completed frame parses");
        assert_eq!(f.command_code(), Some(Command::Id));
    }

    #[test]
    fn scanner_handles_pure_garbage_without_looping() {
        let stream = [0x00u8; 32];
        let events: Vec<ScanEvent> = Scanner::new(&stream).collect();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], ScanEvent::Garbage { offset: 0, len: 32 }));
    }

    #[test]
    fn scanner_on_empty_input_yields_nothing() {
        assert_eq!(Scanner::new(&[]).count(), 0);
    }

    /// Fuzz-flavoured: the parser must never panic, whatever it is fed.
    #[test]
    fn parser_survives_arbitrary_bytes() {
        let mut rng = crate::rng::SeededRng::new(0xC0FFEE);
        for _ in 0..4000 {
            let len = (rng.next_u8() % 64) as usize;
            let mut buf = alloc::vec![0u8; len];
            rng.fill(&mut buf);
            if len > 0 {
                buf[0] = SOM; // bias hard towards "looks like a frame"
            }
            let _ = Frame::parse(&buf);
            let _ = Scanner::new(&buf).count();
        }
    }

    #[test]
    fn broadcast_address_is_recognised() {
        let f = Frame::command(CONFIGURATION_ADDRESS, 0, Command::Comset, vec![1, 0, 0, 0, 0]);
        assert!(f.is_broadcast());
        assert!(!Frame::command(0x01, 0, Command::Poll, vec![]).is_broadcast());
    }
}
