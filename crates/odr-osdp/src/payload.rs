//! Typed encode/decode for the payloads that carry meaning.
//!
//! [`crate::frame::Frame`] deliberately treats a payload as bytes: an analyser
//! must be able to hold a frame it cannot interpret. This module is the layer
//! above, turning those bytes into structures for the ones that matter to the
//! range.
//!
//! Every `decode` is fallible and bounds-checked, and every type round-trips
//! through `encode`. Payloads not modelled here stay as opaque bytes; the
//! README lists which.
//!
//! # The one to read first
//!
//! [`PdCapabilities`]. The Mellon **downgrade** attack is nothing more than
//! deleting one three-byte entry from this reply as it passes an inline
//! implant. [`PdCapabilities::claims_aes128`] is the predicate that tells you
//! whether it has been done.

use crate::codes::Reply;
use alloc::vec::Vec;
use core::fmt;

/// Why a payload could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadError {
    /// The payload is shorter than this structure requires.
    TooShort {
        /// Minimum bytes needed.
        expected: usize,
        /// Bytes actually present.
        actual: usize,
    },
    /// The payload has a length that is structurally impossible, e.g. a PDCAP
    /// reply whose byte count is not a multiple of three.
    BadLength {
        /// Bytes actually present.
        actual: usize,
    },
    /// An internal length field disagrees with the payload size.
    InconsistentLength {
        /// What the internal field said.
        declared: usize,
        /// What was actually available.
        available: usize,
    },
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PayloadError::TooShort { expected, actual } => {
                write!(f, "payload too short: need {expected} bytes, have {actual}")
            }
            PayloadError::BadLength { actual } => {
                write!(f, "payload length {actual} is not valid for this message")
            }
            PayloadError::InconsistentLength {
                declared,
                available,
            } => write!(
                f,
                "internal length field says {declared} but {available} bytes are available"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PayloadError {}

fn need(data: &[u8], n: usize) -> Result<(), PayloadError> {
    if data.len() < n {
        Err(PayloadError::TooShort {
            expected: n,
            actual: data.len(),
        })
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// REPLY_PDID
// ---------------------------------------------------------------------------

/// `REPLY_PDID` (`0x45`) — the PD's identity, 12 bytes.
///
/// Layout, all multi-byte fields **little-endian**:
///
/// ```text
/// 0..3   vendor code (IEEE OUI)
/// 3      model number
/// 4      hardware version
/// 5..9   serial number
/// 9      firmware major
/// 10     firmware minor
/// 11     firmware build
/// ```
///
/// The serial number is the `cUID` a reader also uses in the secure channel
/// handshake, and it is sent in the clear here. Fingerprinting a fleet from a
/// capture is trivial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdId {
    /// IEEE OUI of the manufacturer, in wire order (little-endian).
    pub vendor_code: [u8; 3],
    /// Vendor-defined model number.
    pub model: u8,
    /// Vendor-defined hardware version.
    pub version: u8,
    /// Serial number, in wire order (little-endian).
    pub serial_number: [u8; 4],
    /// Firmware major version.
    pub firmware_major: u8,
    /// Firmware minor version.
    pub firmware_minor: u8,
    /// Firmware build number.
    pub firmware_build: u8,
}

impl PdId {
    /// Encoded size in bytes.
    pub const LEN: usize = 12;

    /// Decode a `REPLY_PDID` payload.
    pub fn decode(data: &[u8]) -> Result<Self, PayloadError> {
        need(data, Self::LEN)?;
        Ok(PdId {
            vendor_code: [data[0], data[1], data[2]],
            model: data[3],
            version: data[4],
            serial_number: [data[5], data[6], data[7], data[8]],
            firmware_major: data[9],
            firmware_minor: data[10],
            firmware_build: data[11],
        })
    }

    /// Encode to a `REPLY_PDID` payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.vendor_code);
        out.push(self.model);
        out.push(self.version);
        out.extend_from_slice(&self.serial_number);
        out.push(self.firmware_major);
        out.push(self.firmware_minor);
        out.push(self.firmware_build);
        out
    }

    /// The vendor code as a 24-bit number, interpreting the wire bytes as
    /// little-endian.
    ///
    /// **Medium confidence on endianness** — libosdp writes `BYTE_0, BYTE_1,
    /// BYTE_2` which is little-endian, but the field is conventionally printed
    /// as an OUI in big-endian order. Use [`PdId::vendor_code`] if the byte
    /// order matters to you.
    pub fn vendor_code_u32(&self) -> u32 {
        u32::from(self.vendor_code[0])
            | (u32::from(self.vendor_code[1]) << 8)
            | (u32::from(self.vendor_code[2]) << 16)
    }

    /// The serial number as a 32-bit little-endian number.
    pub fn serial_u32(&self) -> u32 {
        u32::from_le_bytes(self.serial_number)
    }
}

// ---------------------------------------------------------------------------
// REPLY_PDCAP
// ---------------------------------------------------------------------------

/// A PD capability function code, as carried in `REPLY_PDCAP`.
///
/// Values `0x01` through `0x10`, verified against `libosdp` and `jeff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum CapabilityFunction {
    /// `0x01` — contact (input) status monitoring.
    ContactStatusMonitoring = 0x01,
    /// `0x02` — output control.
    OutputControl = 0x02,
    /// `0x03` — card data format the reader emits.
    CardDataFormat = 0x03,
    /// `0x04` — reader LED control.
    ReaderLedControl = 0x04,
    /// `0x05` — reader audible (buzzer) output.
    ReaderAudibleOutput = 0x05,
    /// `0x06` — reader text output (display).
    ReaderTextOutput = 0x06,
    /// `0x07` — time keeping. Obsolete alongside `CMD_TDSET`.
    TimeKeeping = 0x07,
    /// `0x08` — check character support: does the PD do CRC-16 as well as the
    /// one-byte checksum?
    CheckCharacterSupport = 0x08,
    /// `0x09` — **communication security**. The entry the downgrade attack
    /// removes.
    ///
    /// Its two bytes are bit flags, not the usual compliance/count pair:
    /// compliance bit 0 = "AES-128 supported", count bit 0 = "the default key
    /// (SCBK-D) is in use". So a single `PDCAP` reply tells a passive listener
    /// both whether the reader *can* do crypto and whether anyone bothered to
    /// change the key.
    CommunicationSecurity = 0x09,
    /// `0x0A` — receive buffer size. The two bytes are a 16-bit little-endian
    /// size, not a compliance/count pair.
    ReceiveBufferSize = 0x0A,
    /// `0x0B` — largest combined message size. Also a 16-bit little-endian
    /// size.
    LargestCombinedMessageSize = 0x0B,
    /// `0x0C` — smart card support.
    SmartCardSupport = 0x0C,
    /// `0x0D` — number of readers attached to this PD.
    Readers = 0x0D,
    /// `0x0E` — biometrics.
    Biometrics = 0x0E,
    /// `0x0F` — secure PIN entry.
    SecurePinEntry = 0x0F,
    /// `0x10` — OSDP version the PD claims to implement.
    OsdpVersion = 0x10,
}

impl CapabilityFunction {
    /// All known capability function codes.
    pub const ALL: &'static [CapabilityFunction] = &[
        CapabilityFunction::ContactStatusMonitoring,
        CapabilityFunction::OutputControl,
        CapabilityFunction::CardDataFormat,
        CapabilityFunction::ReaderLedControl,
        CapabilityFunction::ReaderAudibleOutput,
        CapabilityFunction::ReaderTextOutput,
        CapabilityFunction::TimeKeeping,
        CapabilityFunction::CheckCharacterSupport,
        CapabilityFunction::CommunicationSecurity,
        CapabilityFunction::ReceiveBufferSize,
        CapabilityFunction::LargestCombinedMessageSize,
        CapabilityFunction::SmartCardSupport,
        CapabilityFunction::Readers,
        CapabilityFunction::Biometrics,
        CapabilityFunction::SecurePinEntry,
        CapabilityFunction::OsdpVersion,
    ];

    /// Parse a raw function code.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x01 => CapabilityFunction::ContactStatusMonitoring,
            0x02 => CapabilityFunction::OutputControl,
            0x03 => CapabilityFunction::CardDataFormat,
            0x04 => CapabilityFunction::ReaderLedControl,
            0x05 => CapabilityFunction::ReaderAudibleOutput,
            0x06 => CapabilityFunction::ReaderTextOutput,
            0x07 => CapabilityFunction::TimeKeeping,
            0x08 => CapabilityFunction::CheckCharacterSupport,
            0x09 => CapabilityFunction::CommunicationSecurity,
            0x0A => CapabilityFunction::ReceiveBufferSize,
            0x0B => CapabilityFunction::LargestCombinedMessageSize,
            0x0C => CapabilityFunction::SmartCardSupport,
            0x0D => CapabilityFunction::Readers,
            0x0E => CapabilityFunction::Biometrics,
            0x0F => CapabilityFunction::SecurePinEntry,
            0x10 => CapabilityFunction::OsdpVersion,
            _ => return None,
        })
    }

    /// The raw byte.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// One three-byte entry in a `REPLY_PDCAP` payload.
///
/// The interpretation of the second and third bytes depends on the function
/// code: usually "compliance level" and "number of items", but a 16-bit
/// little-endian size for [`CapabilityFunction::ReceiveBufferSize`] and
/// [`CapabilityFunction::LargestCombinedMessageSize`], and bit flags for
/// [`CapabilityFunction::CommunicationSecurity`]. The raw bytes are always
/// preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    /// The raw function code byte, preserved even when unrecognised.
    pub function_code: u8,
    /// Second byte. "Compliance level" in the common case.
    pub compliance: u8,
    /// Third byte. "Number of items" in the common case.
    pub count: u8,
}

impl Capability {
    /// Encoded size of one entry.
    pub const LEN: usize = 3;

    /// Build an entry from a known function code.
    pub fn new(function: CapabilityFunction, compliance: u8, count: u8) -> Self {
        Self {
            function_code: function.to_u8(),
            compliance,
            count,
        }
    }

    /// The function code as a known enum, if recognised.
    pub fn function(&self) -> Option<CapabilityFunction> {
        CapabilityFunction::from_u8(self.function_code)
    }

    /// Interpret the two data bytes as a 16-bit little-endian size. Meaningful
    /// only for the buffer-size capabilities.
    pub fn as_u16(&self) -> u16 {
        u16::from(self.compliance) | (u16::from(self.count) << 8)
    }
}

/// `REPLY_PDCAP` (`0x46`) — what the PD says it can do.
///
/// A sequence of three-byte [`Capability`] entries and nothing else, so the
/// payload length must be a multiple of three.
///
/// # The downgrade attack, concretely
///
/// A controller in "secure channel if supported" mode asks `CMD_CAP`, reads the
/// reply, and looks for [`CapabilityFunction::CommunicationSecurity`] with the
/// AES-128 bit set. An inline implant between reader and controller deletes
/// that one entry, fixes the frame length and CRC — neither of which is
/// authenticated at this point in the conversation, because secure channel has
/// not been established yet — and the controller concludes the reader is a
/// legacy device. Every subsequent card read crosses the wire in the clear.
///
/// The attack works because capability negotiation happens *before* the
/// authentication that would protect it. There is no version of OSDP in which
/// this exchange is authenticated.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PdCapabilities {
    /// The entries, in wire order.
    pub entries: Vec<Capability>,
}

impl PdCapabilities {
    /// Decode a `REPLY_PDCAP` payload.
    pub fn decode(data: &[u8]) -> Result<Self, PayloadError> {
        if !data.len().is_multiple_of(Capability::LEN) {
            return Err(PayloadError::BadLength { actual: data.len() });
        }
        let entries = data
            .as_chunks::<{ Capability::LEN }>()
            .0
            .iter()
            .map(|c| Capability {
                function_code: c[0],
                compliance: c[1],
                count: c[2],
            })
            .collect();
        Ok(PdCapabilities { entries })
    }

    /// Encode to a `REPLY_PDCAP` payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.entries.len() * Capability::LEN);
        for e in &self.entries {
            out.push(e.function_code);
            out.push(e.compliance);
            out.push(e.count);
        }
        out
    }

    /// Find the entry for a given function code.
    pub fn get(&self, function: CapabilityFunction) -> Option<&Capability> {
        self.entries
            .iter()
            .find(|e| e.function_code == function.to_u8())
    }

    /// Does this PD claim AES-128 secure channel support?
    ///
    /// Bit 0 of the compliance byte of the
    /// [`CapabilityFunction::CommunicationSecurity`] entry. A missing entry
    /// means "no" — which is exactly the state a downgrade attack manufactures.
    pub fn claims_aes128(&self) -> bool {
        self.get(CapabilityFunction::CommunicationSecurity)
            .is_some_and(|c| c.compliance & 0x01 != 0)
    }

    /// Does this PD say it is still using the default key, SCBK-D?
    ///
    /// Bit 0 of the count byte of the communication-security entry. A reader
    /// that answers "yes" here is telling every listener on the bus that its
    /// key is the published one.
    pub fn uses_default_key(&self) -> bool {
        self.get(CapabilityFunction::CommunicationSecurity)
            .is_some_and(|c| c.count & 0x01 != 0)
    }

    /// Remove the communication-security entry, returning whether one was
    /// removed.
    ///
    /// This is the downgrade attack as a single method call. It lives here, in
    /// the protocol crate, so that `odr-attack` performs a real edit to a real
    /// structure rather than describing one — the rule in DESIGN.md that drills
    /// run attacks instead of narrating them.
    pub fn strip_security_capability(&mut self) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|e| e.function_code != CapabilityFunction::CommunicationSecurity.to_u8());
        self.entries.len() != before
    }
}

// ---------------------------------------------------------------------------
// REPLY_RAW
// ---------------------------------------------------------------------------

/// `REPLY_RAW` (`0x50`) — a credential was presented.
///
/// ```text
/// 0      reader number
/// 1      format code
/// 2..4   bit count, little-endian
/// 4..    card bits, MSB-first, left-aligned in the byte array
/// ```
///
/// The bit count is in **bits**, and the data is padded to whole bytes, so a
/// 26-bit Wiegand read arrives as four bytes with six bits of padding at the
/// end. Feed [`RawCardRead::bits`] to `odr-wiegand` to get facility code and
/// card number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCardRead {
    /// Which reader on this PD saw the card. Usually 0.
    pub reader: u8,
    /// Format code. `0x00` means "raw/unspecified", `0x01` means the PD
    /// applied a known format. Most readers send `0x00` and let the controller
    /// decode.
    pub format_code: u8,
    /// Number of meaningful bits in [`RawCardRead::data`].
    pub bit_count: u16,
    /// The card bits, MSB-first, zero-padded to a byte boundary.
    pub data: Vec<u8>,
}

impl RawCardRead {
    /// Size of the fixed header before the card bits.
    pub const HEADER_LEN: usize = 4;

    /// Decode a `REPLY_RAW` payload.
    ///
    /// Tolerant about the bit count: if it implies more bytes than are present,
    /// the error says so rather than truncating silently, because a card read
    /// that is quietly short is a security-relevant bug.
    pub fn decode(data: &[u8]) -> Result<Self, PayloadError> {
        need(data, Self::HEADER_LEN)?;
        let bit_count = u16::from(data[2]) | (u16::from(data[3]) << 8);
        let needed_bytes = usize::from(bit_count).div_ceil(8);
        let body = &data[Self::HEADER_LEN..];
        if body.len() < needed_bytes {
            return Err(PayloadError::InconsistentLength {
                declared: needed_bytes,
                available: body.len(),
            });
        }
        Ok(RawCardRead {
            reader: data[0],
            format_code: data[1],
            bit_count,
            data: body.to_vec(),
        })
    }

    /// Encode to a `REPLY_RAW` payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.data.len());
        out.push(self.reader);
        out.push(self.format_code);
        out.push((self.bit_count & 0xFF) as u8);
        out.push((self.bit_count >> 8) as u8);
        out.extend_from_slice(&self.data);
        out
    }

    /// The meaningful bits, most significant first, as booleans.
    ///
    /// Length is exactly [`RawCardRead::bit_count`]; padding is dropped.
    pub fn bits(&self) -> Vec<bool> {
        (0..usize::from(self.bit_count))
            .map(|i| {
                self.data
                    .get(i / 8)
                    .is_some_and(|b| b & (0x80 >> (i % 8)) != 0)
            })
            .collect()
    }

    /// Build a `RawCardRead` from a bit sequence, MSB-first.
    pub fn from_bits(reader: u8, format_code: u8, bits: &[bool]) -> Self {
        let mut data = alloc::vec![0u8; bits.len().div_ceil(8)];
        for (i, &bit) in bits.iter().enumerate() {
            if bit {
                data[i / 8] |= 0x80 >> (i % 8);
            }
        }
        RawCardRead {
            reader,
            format_code,
            bit_count: bits.len() as u16,
            data,
        }
    }
}

// ---------------------------------------------------------------------------
// REPLY_KEYPAD
// ---------------------------------------------------------------------------

/// `REPLY_KEYPAD` (`0x53`) — digits typed on the reader's keypad.
///
/// ```text
/// 0      reader number
/// 1      digit count
/// 2..    the digits, one ASCII byte each
/// ```
///
/// On an unencrypted or SCS_15/16 bus this is somebody's PIN, in ASCII, one
/// keystroke per frame if the reader reports as you type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeypadData {
    /// Which reader the keys were pressed on.
    pub reader: u8,
    /// The key codes, normally ASCII digits plus `*` (`0x7F`) and `#`
    /// (`0x0D`).
    pub digits: Vec<u8>,
}

impl KeypadData {
    /// Decode a `REPLY_KEYPAD` payload.
    pub fn decode(data: &[u8]) -> Result<Self, PayloadError> {
        need(data, 2)?;
        let count = usize::from(data[1]);
        let body = &data[2..];
        if body.len() < count {
            return Err(PayloadError::InconsistentLength {
                declared: count,
                available: body.len(),
            });
        }
        Ok(KeypadData {
            reader: data[0],
            digits: body[..count].to_vec(),
        })
    }

    /// Encode to a `REPLY_KEYPAD` payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.digits.len());
        out.push(self.reader);
        out.push(self.digits.len() as u8);
        out.extend_from_slice(&self.digits);
        out
    }
}

// ---------------------------------------------------------------------------
// Status replies
// ---------------------------------------------------------------------------

/// `REPLY_LSTATR` (`0x48`) — local status: tamper and power.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalStatus {
    /// Non-zero if the PD's tamper switch is active.
    pub tamper: u8,
    /// Non-zero if the PD has lost primary power.
    pub power: u8,
}

impl LocalStatus {
    /// Encoded size.
    pub const LEN: usize = 2;

    /// Decode a `REPLY_LSTATR` payload.
    pub fn decode(data: &[u8]) -> Result<Self, PayloadError> {
        need(data, Self::LEN)?;
        Ok(LocalStatus {
            tamper: data[0],
            power: data[1],
        })
    }

    /// Encode to a `REPLY_LSTATR` payload.
    pub fn encode(&self) -> Vec<u8> {
        alloc::vec![self.tamper, self.power]
    }

    /// Is the PD reporting a tamper?
    pub fn is_tampered(&self) -> bool {
        self.tamper != 0
    }
}

/// A status reply that is simply one byte per item: `ISTATR`, `OSTATR`,
/// `RSTATR`.
///
/// These three share a shape, so they share a type. Which one you have is a
/// property of the frame's reply code, not of the payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StatusList {
    /// One byte per input, output or reader, in index order.
    pub states: Vec<u8>,
}

impl StatusList {
    /// Decode any of `REPLY_ISTATR`, `REPLY_OSTATR`, `REPLY_RSTATR`. Cannot
    /// fail: a zero-length list is legal, meaning "I have none of these".
    pub fn decode(data: &[u8]) -> Self {
        StatusList {
            states: data.to_vec(),
        }
    }

    /// Encode to the payload bytes.
    pub fn encode(&self) -> Vec<u8> {
        self.states.clone()
    }

    /// State of one item, or `None` if the index is past the end.
    pub fn get(&self, index: usize) -> Option<u8> {
        self.states.get(index).copied()
    }

    /// Is the item at `index` active (non-zero)?
    pub fn is_active(&self, index: usize) -> bool {
        self.get(index).is_some_and(|s| s != 0)
    }
}

// ---------------------------------------------------------------------------
// Output / LED / buzzer / text
// ---------------------------------------------------------------------------

/// `CMD_OUT` (`0x68`) — drive an output relay. **This is the door.**
///
/// ```text
/// 0      output number
/// 1      control code
/// 2..4   timer in units of 100 ms, little-endian
/// ```
///
/// On an unencrypted bus, forging this frame is the entire attack: no
/// credential, no cloning, no key. An implant on the reader side of a legacy
/// bus simply says "output 0, on, for 5 seconds".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputCommand {
    /// Which output to drive, zero-indexed.
    pub output: u8,
    /// Control code. `0x00` permanent off, `0x01` permanent on,
    /// `0x02` permanent off with timer, `0x03` permanent on with timer,
    /// `0x04` temporary off, `0x05` temporary on. **Medium confidence** on the
    /// exact meaning of codes above `0x01`; the values are what implementations
    /// use.
    pub control_code: u8,
    /// Timer, in units of 100 ms.
    pub timer_100ms: u16,
}

impl OutputCommand {
    /// Encoded size.
    pub const LEN: usize = 4;

    /// Decode a `CMD_OUT` payload.
    pub fn decode(data: &[u8]) -> Result<Self, PayloadError> {
        need(data, Self::LEN)?;
        Ok(OutputCommand {
            output: data[0],
            control_code: data[1],
            timer_100ms: u16::from(data[2]) | (u16::from(data[3]) << 8),
        })
    }

    /// Encode to a `CMD_OUT` payload.
    pub fn encode(&self) -> Vec<u8> {
        alloc::vec![
            self.output,
            self.control_code,
            (self.timer_100ms & 0xFF) as u8,
            (self.timer_100ms >> 8) as u8,
        ]
    }
}

/// Reader LED colours.
///
/// `0` through `3` (off, red, green, amber) are original OSDP and universally
/// supported. `4` through `7` were added later and **medium confidence**: they
/// are consistent across the implementations checked but not verified against
/// the normative text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LedColor {
    /// `0x00` — off / black.
    Off = 0x00,
    /// `0x01` — red.
    Red = 0x01,
    /// `0x02` — green.
    Green = 0x02,
    /// `0x03` — amber.
    Amber = 0x03,
    /// `0x04` — blue.
    Blue = 0x04,
    /// `0x05` — magenta.
    Magenta = 0x05,
    /// `0x06` — cyan.
    Cyan = 0x06,
    /// `0x07` — white.
    White = 0x07,
}

impl LedColor {
    /// Parse a raw colour byte.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x00 => LedColor::Off,
            0x01 => LedColor::Red,
            0x02 => LedColor::Green,
            0x03 => LedColor::Amber,
            0x04 => LedColor::Blue,
            0x05 => LedColor::Magenta,
            0x06 => LedColor::Cyan,
            0x07 => LedColor::White,
            _ => return None,
        })
    }

    /// The raw byte.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// `CMD_LED` (`0x69`) — control one reader LED, 14 bytes.
///
/// The command carries two independent settings: a *temporary* one that runs
/// for a timer and then expires, and a *permanent* one the LED falls back to.
/// That is why there are so many fields.
///
/// ```text
/// 0   reader        7   temp timer LSB
/// 1   led number    8   temp timer MSB
/// 2   temp control  9   perm control
/// 3   temp on time  10  perm on time
/// 4   temp off time 11  perm off time
/// 5   temp on color 12  perm on color
/// 6   temp off color 13 perm off color
/// ```
///
/// On/off times are in units of 100 ms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedCommand {
    /// Which reader.
    pub reader: u8,
    /// Which LED on that reader.
    pub led: u8,
    /// Temporary control code: `0` no change, `1` cancel the temporary
    /// setting, `2` set it.
    pub temp_control: u8,
    /// Temporary on duration, units of 100 ms.
    pub temp_on_time: u8,
    /// Temporary off duration, units of 100 ms.
    pub temp_off_time: u8,
    /// Colour during the temporary "on" phase.
    pub temp_on_color: u8,
    /// Colour during the temporary "off" phase.
    pub temp_off_color: u8,
    /// How long the temporary setting lasts, units of 100 ms.
    pub temp_timer_100ms: u16,
    /// Permanent control code: `0` no change, `1` set.
    pub perm_control: u8,
    /// Permanent on duration, units of 100 ms.
    pub perm_on_time: u8,
    /// Permanent off duration, units of 100 ms.
    pub perm_off_time: u8,
    /// Colour during the permanent "on" phase.
    pub perm_on_color: u8,
    /// Colour during the permanent "off" phase.
    pub perm_off_color: u8,
}

impl LedCommand {
    /// Encoded size.
    pub const LEN: usize = 14;

    /// Decode a `CMD_LED` payload.
    pub fn decode(data: &[u8]) -> Result<Self, PayloadError> {
        need(data, Self::LEN)?;
        Ok(LedCommand {
            reader: data[0],
            led: data[1],
            temp_control: data[2],
            temp_on_time: data[3],
            temp_off_time: data[4],
            temp_on_color: data[5],
            temp_off_color: data[6],
            temp_timer_100ms: u16::from(data[7]) | (u16::from(data[8]) << 8),
            perm_control: data[9],
            perm_on_time: data[10],
            perm_off_time: data[11],
            perm_on_color: data[12],
            perm_off_color: data[13],
        })
    }

    /// Encode to a `CMD_LED` payload.
    pub fn encode(&self) -> Vec<u8> {
        alloc::vec![
            self.reader,
            self.led,
            self.temp_control,
            self.temp_on_time,
            self.temp_off_time,
            self.temp_on_color,
            self.temp_off_color,
            (self.temp_timer_100ms & 0xFF) as u8,
            (self.temp_timer_100ms >> 8) as u8,
            self.perm_control,
            self.perm_on_time,
            self.perm_off_time,
            self.perm_on_color,
            self.perm_off_color,
        ]
    }
}

/// `CMD_BUZ` (`0x6A`) — the reader beeper, 5 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuzzerCommand {
    /// Which reader.
    pub reader: u8,
    /// Tone code. `0` off, `1` default tone, `2` alternate tone.
    pub tone: u8,
    /// On duration, units of 100 ms.
    pub on_time: u8,
    /// Off duration, units of 100 ms.
    pub off_time: u8,
    /// How many times to repeat. `0` means "forever".
    pub count: u8,
}

impl BuzzerCommand {
    /// Encoded size.
    pub const LEN: usize = 5;

    /// Decode a `CMD_BUZ` payload.
    pub fn decode(data: &[u8]) -> Result<Self, PayloadError> {
        need(data, Self::LEN)?;
        Ok(BuzzerCommand {
            reader: data[0],
            tone: data[1],
            on_time: data[2],
            off_time: data[3],
            count: data[4],
        })
    }

    /// Encode to a `CMD_BUZ` payload.
    pub fn encode(&self) -> Vec<u8> {
        alloc::vec![
            self.reader,
            self.tone,
            self.on_time,
            self.off_time,
            self.count
        ]
    }
}

/// `CMD_TEXT` (`0x6B`) — write to the reader's display.
///
/// ```text
/// 0      reader
/// 1      control code (1 permanent, 2 temporary with wrap, 3 temporary no wrap)
/// 2      temporary display time, seconds
/// 3      row offset, 1-based
/// 4      column offset, 1-based
/// 5      text length
/// 6..    the text, ASCII
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextCommand {
    /// Which reader.
    pub reader: u8,
    /// Control code. **Medium confidence** on the exact code meanings.
    pub control_code: u8,
    /// How long a temporary message stays up, in seconds.
    pub temp_time_s: u8,
    /// Row offset, 1-based.
    pub offset_row: u8,
    /// Column offset, 1-based.
    pub offset_col: u8,
    /// The text itself.
    pub text: Vec<u8>,
}

impl TextCommand {
    /// Size of the fixed header before the text.
    pub const HEADER_LEN: usize = 6;

    /// Decode a `CMD_TEXT` payload.
    pub fn decode(data: &[u8]) -> Result<Self, PayloadError> {
        need(data, Self::HEADER_LEN)?;
        let len = usize::from(data[5]);
        let body = &data[Self::HEADER_LEN..];
        if body.len() < len {
            return Err(PayloadError::InconsistentLength {
                declared: len,
                available: body.len(),
            });
        }
        Ok(TextCommand {
            reader: data[0],
            control_code: data[1],
            temp_time_s: data[2],
            offset_row: data[3],
            offset_col: data[4],
            text: body[..len].to_vec(),
        })
    }

    /// Encode to a `CMD_TEXT` payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.text.len());
        out.push(self.reader);
        out.push(self.control_code);
        out.push(self.temp_time_s);
        out.push(self.offset_row);
        out.push(self.offset_col);
        out.push(self.text.len() as u8);
        out.extend_from_slice(&self.text);
        out
    }
}

// ---------------------------------------------------------------------------
// COMSET and KEYSET
// ---------------------------------------------------------------------------

/// `CMD_COMSET` (`0x6E`) and `REPLY_COM` (`0x54`) — address and baud rate.
///
/// ```text
/// 0      new PD address
/// 1..5   new baud rate, little-endian u32
/// ```
///
/// Almost always sent to the configuration address `0x7F`, before any secure
/// channel exists, because a PD with no address cannot have a session. An
/// attacker who can inject one frame during commissioning can park a reader at
/// an address the controller is not polling, or at a baud rate it is not
/// listening at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComsetCommand {
    /// The address the PD should adopt.
    pub address: u8,
    /// The baud rate the PD should adopt, e.g. 9600, 19200, 38400, 115200.
    pub baud_rate: u32,
}

impl ComsetCommand {
    /// Encoded size.
    pub const LEN: usize = 5;

    /// Decode a `CMD_COMSET` or `REPLY_COM` payload.
    pub fn decode(data: &[u8]) -> Result<Self, PayloadError> {
        need(data, Self::LEN)?;
        Ok(ComsetCommand {
            address: data[0],
            baud_rate: u32::from_le_bytes([data[1], data[2], data[3], data[4]]),
        })
    }

    /// Encode to a `CMD_COMSET` or `REPLY_COM` payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.push(self.address);
        out.extend_from_slice(&self.baud_rate.to_le_bytes());
        out
    }
}

/// `CMD_KEYSET` (`0x75`) — install a Secure Channel Base Key.
///
/// ```text
/// 0      key type: 0x01 = SCBK
/// 1      key length in bytes: 0x10 for AES-128
/// 2..    the key
/// ```
///
/// # Attack 5 of five, in one struct
///
/// OSDP has no key agreement — no Diffie-Hellman, no certificate, nothing. The
/// site key is *pushed* to the PD in this frame. The specification says to do
/// it inside an already-established secure channel, which is fine on the second
/// key change and impossible on the first, because there is no key yet to
/// establish that channel with. The realistic deployment path is: PD arrives on
/// SCBK-D, installer commissions it, `CMD_KEYSET` crosses the bus protected by
/// a key that is printed in the standard.
///
/// A logger left inside a door frame during the installer's visit walks away
/// with the key for every door on the site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysetCommand {
    /// Key type. `0x01` is SCBK; no other value is in common use.
    pub key_type: u8,
    /// The key bytes. 16 for AES-128.
    pub key: Vec<u8>,
}

impl KeysetCommand {
    /// Key type byte for a Secure Channel Base Key.
    pub const KEY_TYPE_SCBK: u8 = 0x01;

    /// Build a `CMD_KEYSET` for an AES-128 SCBK.
    pub fn scbk(key: [u8; 16]) -> Self {
        KeysetCommand {
            key_type: Self::KEY_TYPE_SCBK,
            key: key.to_vec(),
        }
    }

    /// Decode a `CMD_KEYSET` payload.
    pub fn decode(data: &[u8]) -> Result<Self, PayloadError> {
        need(data, 2)?;
        let len = usize::from(data[1]);
        let body = &data[2..];
        if body.len() < len {
            return Err(PayloadError::InconsistentLength {
                declared: len,
                available: body.len(),
            });
        }
        Ok(KeysetCommand {
            key_type: data[0],
            key: body[..len].to_vec(),
        })
    }

    /// Encode to a `CMD_KEYSET` payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.key.len());
        out.push(self.key_type);
        out.push(self.key.len() as u8);
        out.extend_from_slice(&self.key);
        out
    }

    /// The key as a 16-byte array, if it is the right length.
    ///
    /// Useful for handing straight to [`crate::weak_keys::classify`] after
    /// sniffing a commissioning session.
    pub fn as_aes128(&self) -> Option<[u8; 16]> {
        let mut out = [0u8; 16];
        if self.key.len() == 16 {
            out.copy_from_slice(&self.key);
            Some(out)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// NAK
// ---------------------------------------------------------------------------

/// `REPLY_NAK` error codes, `0x00` through `0x09`.
///
/// Verified three ways (libosdp, jeff, go-osdp) and consistent across all
/// three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NakError {
    /// `0x00` — no error. Rare on the wire; a PD with nothing wrong sends
    /// `ACK`.
    None = 0x00,
    /// `0x01` — bad checksum or CRC.
    MessageCheck = 0x01,
    /// `0x02` — command length error.
    CommandLength = 0x02,
    /// `0x03` — unknown command code; the PD does not implement it.
    UnknownCommand = 0x03,
    /// `0x04` — sequence number error.
    ///
    /// With only two bits of sequence number, this is also what a PD says when
    /// a replayed frame arrives at the wrong point in the cycle — and what it
    /// stops saying after four frames, when the counter wraps back round.
    SequenceNumber = 0x04,
    /// `0x05` — secure channel is not supported by this PD.
    ///
    /// The honest version of what a downgrade attack fakes.
    SecureChannelUnsupported = 0x05,
    /// `0x06` — unsupported security block, or security conditions not met.
    SecurityConditionsNotMet = 0x06,
    /// `0x07` — biometric type not supported.
    BioTypeUnsupported = 0x07,
    /// `0x08` — biometric format not supported.
    BioFormatUnsupported = 0x08,
    /// `0x09` — unable to process the command record.
    UnableToProcess = 0x09,
}

impl NakError {
    /// All known NAK codes.
    pub const ALL: &'static [NakError] = &[
        NakError::None,
        NakError::MessageCheck,
        NakError::CommandLength,
        NakError::UnknownCommand,
        NakError::SequenceNumber,
        NakError::SecureChannelUnsupported,
        NakError::SecurityConditionsNotMet,
        NakError::BioTypeUnsupported,
        NakError::BioFormatUnsupported,
        NakError::UnableToProcess,
    ];

    /// Parse a raw NAK code.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x00 => NakError::None,
            0x01 => NakError::MessageCheck,
            0x02 => NakError::CommandLength,
            0x03 => NakError::UnknownCommand,
            0x04 => NakError::SequenceNumber,
            0x05 => NakError::SecureChannelUnsupported,
            0x06 => NakError::SecurityConditionsNotMet,
            0x07 => NakError::BioTypeUnsupported,
            0x08 => NakError::BioFormatUnsupported,
            0x09 => NakError::UnableToProcess,
            _ => return None,
        })
    }

    /// The raw byte.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// A short human-readable description.
    pub fn describe(self) -> &'static str {
        match self {
            NakError::None => "no error",
            NakError::MessageCheck => "bad checksum or CRC",
            NakError::CommandLength => "command length error",
            NakError::UnknownCommand => "unknown command code",
            NakError::SequenceNumber => "sequence number error",
            NakError::SecureChannelUnsupported => "secure channel not supported",
            NakError::SecurityConditionsNotMet => "security conditions not met",
            NakError::BioTypeUnsupported => "biometric type not supported",
            NakError::BioFormatUnsupported => "biometric format not supported",
            NakError::UnableToProcess => "unable to process command record",
        }
    }
}

/// `REPLY_NAK` (`0x41`) — the PD rejected the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nak {
    /// The raw error byte, preserved even when unrecognised.
    pub error_code: u8,
    /// Optional extra data. Its meaning depends on the error code; most PDs
    /// send none.
    pub data: Vec<u8>,
}

impl Nak {
    /// Build a NAK with no extra data.
    pub fn new(error: NakError) -> Self {
        Nak {
            error_code: error.to_u8(),
            data: Vec::new(),
        }
    }

    /// Decode a `REPLY_NAK` payload.
    pub fn decode(data: &[u8]) -> Result<Self, PayloadError> {
        need(data, 1)?;
        Ok(Nak {
            error_code: data[0],
            data: data[1..].to_vec(),
        })
    }

    /// Encode to a `REPLY_NAK` payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.data.len());
        out.push(self.error_code);
        out.extend_from_slice(&self.data);
        out
    }

    /// The error code as a known enum, if recognised.
    pub fn error(&self) -> Option<NakError> {
        NakError::from_u8(self.error_code)
    }
}

// ---------------------------------------------------------------------------
// Secure channel payloads
// ---------------------------------------------------------------------------

/// `REPLY_CCRYPT` (`0x76`) — the PD's half of the handshake, 32 bytes.
///
/// ```text
/// 0..8    cUID — the PD's unique identifier
/// 8..16   RND.B — the PD's nonce
/// 16..32  the client cryptogram
/// ```
///
/// All 32 bytes travel in the clear, before any session key exists. An
/// eavesdropper who has, or guesses, the SCBK can derive every session key from
/// this frame plus the `CMD_CHLNG` that preceded it, with no interaction. That
/// is the whole of Mellon attack 4: capture one handshake, try 768 keys
/// offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ccrypt {
    /// The PD's unique identifier.
    pub cuid: [u8; 8],
    /// The PD's nonce, RND.B.
    pub rnd_b: [u8; 8],
    /// The client cryptogram, `AES-ECB(S-ENC, RND.A ‖ RND.B)`.
    pub client_cryptogram: [u8; 16],
}

impl Ccrypt {
    /// Encoded size.
    pub const LEN: usize = 32;

    /// Decode a `REPLY_CCRYPT` payload.
    pub fn decode(data: &[u8]) -> Result<Self, PayloadError> {
        need(data, Self::LEN)?;
        let mut cuid = [0u8; 8];
        let mut rnd_b = [0u8; 8];
        let mut client_cryptogram = [0u8; 16];
        cuid.copy_from_slice(&data[0..8]);
        rnd_b.copy_from_slice(&data[8..16]);
        client_cryptogram.copy_from_slice(&data[16..32]);
        Ok(Ccrypt {
            cuid,
            rnd_b,
            client_cryptogram,
        })
    }

    /// Encode to a `REPLY_CCRYPT` payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.cuid);
        out.extend_from_slice(&self.rnd_b);
        out.extend_from_slice(&self.client_cryptogram);
        out
    }
}

/// Look up the typed decoder appropriate to a reply code, as a hint for a
/// display layer.
///
/// Returns a short label for what the payload of this reply means; `None` when
/// this crate models it only as opaque bytes.
pub fn reply_payload_kind(reply: Reply) -> Option<&'static str> {
    Some(match reply {
        Reply::PdId => "PdId",
        Reply::PdCap => "PdCapabilities",
        Reply::Raw => "RawCardRead",
        Reply::Keypad => "KeypadData",
        Reply::LStatR => "LocalStatus",
        Reply::IStatR | Reply::OStatR | Reply::RStatR => "StatusList",
        Reply::Com => "ComsetCommand",
        Reply::Nak => "Nak",
        Reply::Ccrypt => "Ccrypt",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn pdid_round_trips() {
        let id = PdId {
            vendor_code: [0x00, 0x06, 0x8E],
            model: 0x01,
            version: 0x02,
            serial_number: [0xDE, 0xAD, 0xBE, 0xEF],
            firmware_major: 2,
            firmware_minor: 2,
            firmware_build: 2,
        };
        let bytes = id.encode();
        assert_eq!(bytes.len(), PdId::LEN);
        assert_eq!(PdId::decode(&bytes).unwrap(), id);
        assert_eq!(id.serial_u32(), 0xEFBE_ADDE);
        assert!(matches!(
            PdId::decode(&bytes[..11]),
            Err(PayloadError::TooShort {
                expected: 12,
                actual: 11
            })
        ));
    }

    #[test]
    fn pdcap_round_trips() {
        let caps = PdCapabilities {
            entries: vec![
                Capability::new(CapabilityFunction::ContactStatusMonitoring, 1, 4),
                Capability::new(CapabilityFunction::OutputControl, 1, 2),
                Capability::new(CapabilityFunction::CommunicationSecurity, 0x01, 0x01),
            ],
        };
        let bytes = caps.encode();
        assert_eq!(bytes.len(), 9);
        assert_eq!(PdCapabilities::decode(&bytes).unwrap(), caps);
    }

    #[test]
    fn pdcap_rejects_a_ragged_payload() {
        assert!(matches!(
            PdCapabilities::decode(&[1, 2, 3, 4]),
            Err(PayloadError::BadLength { actual: 4 })
        ));
        assert_eq!(PdCapabilities::decode(&[]).unwrap().entries.len(), 0);
    }

    /// The downgrade attack, executed rather than described.
    #[test]
    fn stripping_the_security_capability_downgrades_the_reader() {
        let mut caps = PdCapabilities {
            entries: vec![
                Capability::new(CapabilityFunction::ContactStatusMonitoring, 1, 4),
                Capability::new(CapabilityFunction::CommunicationSecurity, 0x01, 0x00),
                Capability::new(CapabilityFunction::Readers, 1, 1),
            ],
        };
        assert!(caps.claims_aes128());
        assert!(!caps.uses_default_key());

        assert!(caps.strip_security_capability());
        assert!(
            !caps.claims_aes128(),
            "after the edit the reader looks like a legacy device"
        );
        assert_eq!(caps.entries.len(), 2, "the other capabilities survive");
        // The edited reply is a perfectly well-formed PDCAP.
        let bytes = caps.encode();
        assert_eq!(PdCapabilities::decode(&bytes).unwrap(), caps);
        // Stripping again is a no-op.
        assert!(!caps.strip_security_capability());
    }

    #[test]
    fn pdcap_reports_the_default_key_flag() {
        let caps = PdCapabilities {
            entries: vec![Capability::new(
                CapabilityFunction::CommunicationSecurity,
                0x01,
                0x01,
            )],
        };
        assert!(caps.claims_aes128());
        assert!(caps.uses_default_key());
    }

    #[test]
    fn capability_function_codes_round_trip() {
        for &f in CapabilityFunction::ALL {
            assert_eq!(CapabilityFunction::from_u8(f.to_u8()), Some(f));
        }
        assert_eq!(CapabilityFunction::from_u8(0x00), None);
        assert_eq!(CapabilityFunction::from_u8(0x11), None);
    }

    #[test]
    fn capability_two_byte_sizes() {
        let c = Capability {
            function_code: CapabilityFunction::ReceiveBufferSize.to_u8(),
            compliance: 0x80,
            count: 0x02,
        };
        assert_eq!(c.as_u16(), 640);
    }

    #[test]
    fn raw_card_read_round_trips() {
        let r = RawCardRead {
            reader: 0,
            format_code: 0,
            bit_count: 26,
            data: vec![0b1010_1010, 0b0101_0101, 0b1100_1100, 0b1100_0000],
        };
        let bytes = r.encode();
        assert_eq!(bytes.len(), 8);
        assert_eq!(RawCardRead::decode(&bytes).unwrap(), r);
        assert_eq!(r.bits().len(), 26);
        assert!(r.bits()[0]);
        assert!(!r.bits()[1]);
    }

    #[test]
    fn raw_card_read_bits_round_trip() {
        let bits: Vec<bool> = (0..37).map(|i| i % 3 == 0).collect();
        let r = RawCardRead::from_bits(0, 0, &bits);
        assert_eq!(r.bit_count, 37);
        assert_eq!(r.data.len(), 5);
        assert_eq!(r.bits(), bits);
        assert_eq!(RawCardRead::decode(&r.encode()).unwrap(), r);
    }

    #[test]
    fn raw_card_read_rejects_a_short_body() {
        // Claims 64 bits but supplies one byte.
        let bad = [0x00, 0x00, 0x40, 0x00, 0xAA];
        assert!(matches!(
            RawCardRead::decode(&bad),
            Err(PayloadError::InconsistentLength { .. })
        ));
        assert!(matches!(
            RawCardRead::decode(&[0, 0, 0]),
            Err(PayloadError::TooShort { .. })
        ));
    }

    #[test]
    fn keypad_round_trips() {
        let k = KeypadData {
            reader: 0,
            digits: vec![b'1', b'2', b'3', b'4'],
        };
        let bytes = k.encode();
        assert_eq!(bytes, vec![0x00, 0x04, b'1', b'2', b'3', b'4']);
        assert_eq!(KeypadData::decode(&bytes).unwrap(), k);
        assert!(matches!(
            KeypadData::decode(&[0x00, 0x09, b'1']),
            Err(PayloadError::InconsistentLength { .. })
        ));
    }

    #[test]
    fn local_status_round_trips() {
        let s = LocalStatus {
            tamper: 1,
            power: 0,
        };
        assert_eq!(LocalStatus::decode(&s.encode()).unwrap(), s);
        assert!(s.is_tampered());
        assert!(matches!(
            LocalStatus::decode(&[0]),
            Err(PayloadError::TooShort { .. })
        ));
    }

    #[test]
    fn status_list_round_trips() {
        let s = StatusList {
            states: vec![0, 1, 0, 1],
        };
        assert_eq!(StatusList::decode(&s.encode()), s);
        assert!(s.is_active(1));
        assert!(!s.is_active(0));
        assert_eq!(s.get(9), None);
        assert!(!s.is_active(9));
        assert_eq!(StatusList::decode(&[]).states.len(), 0);
    }

    #[test]
    fn output_command_round_trips() {
        let o = OutputCommand {
            output: 0,
            control_code: 1,
            timer_100ms: 50,
        };
        let bytes = o.encode();
        assert_eq!(bytes, vec![0x00, 0x01, 0x32, 0x00]);
        assert_eq!(OutputCommand::decode(&bytes).unwrap(), o);
    }

    #[test]
    fn led_command_round_trips() {
        let l = LedCommand {
            reader: 0,
            led: 0,
            temp_control: 2,
            temp_on_time: 5,
            temp_off_time: 5,
            temp_on_color: LedColor::Green.to_u8(),
            temp_off_color: LedColor::Off.to_u8(),
            temp_timer_100ms: 30,
            perm_control: 1,
            perm_on_time: 0,
            perm_off_time: 0,
            perm_on_color: LedColor::Red.to_u8(),
            perm_off_color: LedColor::Off.to_u8(),
        };
        let bytes = l.encode();
        assert_eq!(bytes.len(), LedCommand::LEN);
        assert_eq!(LedCommand::decode(&bytes).unwrap(), l);
    }

    #[test]
    fn led_colors_round_trip() {
        for v in 0u8..=7 {
            assert_eq!(LedColor::from_u8(v).map(|c| c.to_u8()), Some(v));
        }
        assert_eq!(LedColor::from_u8(8), None);
    }

    #[test]
    fn buzzer_command_round_trips() {
        let b = BuzzerCommand {
            reader: 0,
            tone: 1,
            on_time: 2,
            off_time: 2,
            count: 3,
        };
        assert_eq!(BuzzerCommand::decode(&b.encode()).unwrap(), b);
        assert!(matches!(
            BuzzerCommand::decode(&[0; 4]),
            Err(PayloadError::TooShort { .. })
        ));
    }

    #[test]
    fn text_command_round_trips() {
        let t = TextCommand {
            reader: 0,
            control_code: 1,
            temp_time_s: 0,
            offset_row: 1,
            offset_col: 1,
            text: b"PRESENT CARD".to_vec(),
        };
        let bytes = t.encode();
        assert_eq!(bytes[5], 12);
        assert_eq!(TextCommand::decode(&bytes).unwrap(), t);
        assert!(matches!(
            TextCommand::decode(&[0, 1, 0, 1, 1, 99, b'x']),
            Err(PayloadError::InconsistentLength { .. })
        ));
    }

    #[test]
    fn comset_round_trips() {
        let c = ComsetCommand {
            address: 0x05,
            baud_rate: 115_200,
        };
        let bytes = c.encode();
        assert_eq!(bytes, vec![0x05, 0x00, 0xC2, 0x01, 0x00]);
        assert_eq!(ComsetCommand::decode(&bytes).unwrap(), c);
    }

    #[test]
    fn keyset_round_trips_and_exposes_the_key() {
        let key = crate::weak_keys::SCBK_D;
        let k = KeysetCommand::scbk(key);
        let bytes = k.encode();
        assert_eq!(bytes.len(), 18, "libosdp's CMD_KEYSET_DATA_LEN");
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 0x10);
        assert_eq!(KeysetCommand::decode(&bytes).unwrap(), k);

        // A sniffer that captured this frame gets the key straight out.
        let sniffed = KeysetCommand::decode(&bytes).unwrap().as_aes128().unwrap();
        assert_eq!(sniffed, key);
        assert!(crate::weak_keys::is_weak(&sniffed));
    }

    #[test]
    fn keyset_rejects_a_short_body() {
        assert!(matches!(
            KeysetCommand::decode(&[0x01, 0x10, 0x00]),
            Err(PayloadError::InconsistentLength { .. })
        ));
        assert_eq!(KeysetCommand::decode(&[0x01, 0x00]).unwrap().key.len(), 0);
    }

    #[test]
    fn nak_round_trips() {
        for &e in NakError::ALL {
            let n = Nak::new(e);
            let bytes = n.encode();
            let back = Nak::decode(&bytes).unwrap();
            assert_eq!(back, n);
            assert_eq!(back.error(), Some(e));
            assert!(!e.describe().is_empty());
        }
        let n = Nak::decode(&[0xFE, 0x01, 0x02]).unwrap();
        assert_eq!(n.error(), None, "unknown codes survive");
        assert_eq!(n.data, vec![0x01, 0x02]);
        assert!(matches!(
            Nak::decode(&[]),
            Err(PayloadError::TooShort { .. })
        ));
    }

    #[test]
    fn ccrypt_round_trips() {
        let c = Ccrypt {
            cuid: [1, 2, 3, 4, 5, 6, 7, 8],
            rnd_b: [9, 10, 11, 12, 13, 14, 15, 16],
            client_cryptogram: [0xAA; 16],
        };
        let bytes = c.encode();
        assert_eq!(bytes.len(), 32, "libosdp's REPLY_CCRYPT_DATA_LEN");
        assert_eq!(Ccrypt::decode(&bytes).unwrap(), c);
        assert!(matches!(
            Ccrypt::decode(&bytes[..31]),
            Err(PayloadError::TooShort { .. })
        ));
    }

    #[test]
    fn payload_kind_hints_cover_the_modelled_replies() {
        assert_eq!(reply_payload_kind(Reply::PdCap), Some("PdCapabilities"));
        assert_eq!(reply_payload_kind(Reply::Raw), Some("RawCardRead"));
        assert_eq!(reply_payload_kind(Reply::Ack), None);
    }

    /// No decoder may panic on a truncated or oversized buffer.
    #[test]
    fn decoders_never_panic_on_arbitrary_input() {
        let mut rng = crate::rng::SeededRng::new(0xBADC0DE);
        for _ in 0..2000 {
            let len = (rng.next_u8() % 48) as usize;
            let mut buf = vec![0u8; len];
            rng.fill(&mut buf);
            let _ = PdId::decode(&buf);
            let _ = PdCapabilities::decode(&buf);
            let _ = RawCardRead::decode(&buf);
            let _ = KeypadData::decode(&buf);
            let _ = LocalStatus::decode(&buf);
            let _ = StatusList::decode(&buf);
            let _ = OutputCommand::decode(&buf);
            let _ = LedCommand::decode(&buf);
            let _ = BuzzerCommand::decode(&buf);
            let _ = TextCommand::decode(&buf);
            let _ = ComsetCommand::decode(&buf);
            let _ = KeysetCommand::decode(&buf);
            let _ = Nak::decode(&buf);
            let _ = Ccrypt::decode(&buf);
        }
    }
}
