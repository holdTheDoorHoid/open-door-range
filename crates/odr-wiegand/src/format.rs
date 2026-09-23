//! Card data formats: what the bits on the wire *mean*.
//!
//! A Wiegand frame is a bare run of bits with no header, no length field, and
//! no format identifier. The reader sends N bits; the panel is *configured* to
//! believe those N bits are some particular format and slices them accordingly.
//! Nothing on the wire says which. That is why [`infer_formats`] returns a list
//! rather than an answer, and it is also why the "format" of a captured
//! credential is frequently a guess that happens to be right.
//!
//! # The formats implemented here
//!
//! | Format | Bits | Facility / site code | Card number | Parity bits |
//! |---|---|---|---|---|
//! | [`CardFormat::H10301`] | 26 | 8 bits (0–255) | 16 bits (0–65 535) | 2 |
//! | [`CardFormat::H10306`] | 34 | 16 bits | 16 bits | 2 |
//! | [`CardFormat::Corporate1000`] | 35 | 12 bits (company code) | 20 bits | 3 |
//! | [`CardFormat::H10304`] | 37 | 16 bits | 19 bits | 2 |
//! | [`CardFormat::H10302`] | 37 | none | 35 bits | 2 |
//! | [`CardFormat::Raw`] | any | none | all of them | 0 |
//!
//! # Bit layouts
//!
//! Positions are zero-based and count from the first bit on the wire. `P`
//! marks a parity bit, `F` a facility/company code bit, `C` a card number bit.
//!
//! ```text
//! H10301 (26):  P FFFFFFFF CCCCCCCCCCCCCCCC P
//!               0 1......8 9.............24 25
//!   bit 0  = even parity over bits 1..=12   (the FC and the top 4 card bits)
//!   bit 25 = odd  parity over bits 13..=24  (the bottom 12 card bits)
//!
//! H10306 (34):  P FFFFFFFFFFFFFFFF CCCCCCCCCCCCCCCC P
//!               0 1.............16 17...........32 33
//!   bit 0  = even parity over bits 1..=16
//!   bit 33 = odd  parity over bits 17..=32
//!
//! Corporate 1000 (35):
//!               P P FFFFFFFFFFFF CCCCCCCCCCCCCCCCCCCC P
//!               0 1 2.........13 14................33 34
//!   bit 1  = even parity over bits 2..=33 skipping every position p where
//!            p % 3 == 1        (22 bits: 2,3, 5,6, 8,9, ...)
//!   bit 34 = odd  parity over bits 1..=32 skipping every p where p % 3 == 0
//!            (22 bits: 1,2, 4,5, 7,8, ...)
//!   bit 0  = odd  parity over bits 1..=34 — every other bit in the frame,
//!            including the two parity bits above, so it must be applied last.
//!
//! H10304 (37):  P FFFFFFFFFFFFFFFF CCCCCCCCCCCCCCCCCCC P
//!               0 1.............16 17...............35 36
//!   bit 0  = even parity over bits 1..=18
//!   bit 36 = odd  parity over bits 18..=35   (note the overlap at bit 18)
//!
//! H10302 (37):  P CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC P
//!               0 1.................................35 36
//!   same two parity rules as H10304.
//! ```
//!
//! The overlap at bit 18 in the 37-bit formats is not a typo — both windows are
//! 18 bits wide and they share that bit. It is a genuine quirk of the format.

use crate::bits::{BitError, BitVec};
use crate::parity::{Coverage, Parity, ParityReport, ParityRule};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

/// A card data format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CardFormat {
    /// HID H10301, the 26-bit standard format. By far the most common, and
    /// the one whose entire key space is 8 + 16 = 24 bits.
    H10301,
    /// HID H10306, 34-bit: 16-bit facility code, 16-bit card number.
    H10306,
    /// HID Corporate 1000, 35-bit: 12-bit company code, 20-bit card number,
    /// three parity bits with interleaved coverage.
    Corporate1000,
    /// HID H10304, 37-bit with a facility code.
    H10304,
    /// HID H10302, 37-bit with no facility code — the whole 35-bit body is one
    /// card number.
    H10302,
    /// Passthrough for a frame of arbitrary width whose format is unknown.
    ///
    /// No parity is claimed and no fields are sliced; the whole frame is the
    /// "card number". This is what a sniffer produces before anyone has decided
    /// what they are looking at, and it is a perfectly good thing to replay.
    Raw {
        /// Frame width in bits.
        bit_len: usize,
    },
}

/// Every named format, in ascending bit-length order.
///
/// [`CardFormat::Raw`] is not in this list because it is not a guess — it is
/// the fallback when no guess fits.
pub const KNOWN_FORMATS: &[CardFormat] = &[
    CardFormat::H10301,
    CardFormat::H10306,
    CardFormat::Corporate1000,
    CardFormat::H10304,
    CardFormat::H10302,
];

/// Where a field sits: `(start, len)` in bit positions.
type Field = (usize, usize);

impl CardFormat {
    /// Frame width in bits.
    pub fn bit_len(self) -> usize {
        match self {
            CardFormat::H10301 => 26,
            CardFormat::H10306 => 34,
            CardFormat::Corporate1000 => 35,
            CardFormat::H10304 | CardFormat::H10302 => 37,
            CardFormat::Raw { bit_len } => bit_len,
        }
    }

    /// Short name, as card tools normally print it.
    pub fn name(self) -> &'static str {
        match self {
            CardFormat::H10301 => "H10301",
            CardFormat::H10306 => "H10306",
            CardFormat::Corporate1000 => "C1k35s",
            CardFormat::H10304 => "H10304",
            CardFormat::H10302 => "H10302",
            CardFormat::Raw { .. } => "raw",
        }
    }

    /// One-line description suitable for a UI.
    pub fn description(self) -> &'static str {
        match self {
            CardFormat::H10301 => "HID 26-bit standard (8-bit facility code, 16-bit card number)",
            CardFormat::H10306 => "HID 34-bit (16-bit facility code, 16-bit card number)",
            CardFormat::Corporate1000 => {
                "HID Corporate 1000 35-bit (12-bit company code, 20-bit card number)"
            }
            CardFormat::H10304 => "HID 37-bit with facility code (16-bit FC, 19-bit card number)",
            CardFormat::H10302 => "HID 37-bit without facility code (35-bit card number)",
            CardFormat::Raw { .. } => "unknown / raw bit stream",
        }
    }

    /// Facility-code field position, if the format has one.
    pub fn facility_field(self) -> Option<Field> {
        match self {
            CardFormat::H10301 => Some((1, 8)),
            CardFormat::H10306 => Some((1, 16)),
            CardFormat::Corporate1000 => Some((2, 12)),
            CardFormat::H10304 => Some((1, 16)),
            CardFormat::H10302 | CardFormat::Raw { .. } => None,
        }
    }

    /// Card-number field position.
    pub fn card_field(self) -> Field {
        match self {
            CardFormat::H10301 => (9, 16),
            CardFormat::H10306 => (17, 16),
            CardFormat::Corporate1000 => (14, 20),
            CardFormat::H10304 => (17, 19),
            CardFormat::H10302 => (1, 35),
            CardFormat::Raw { bit_len } => (0, bit_len),
        }
    }

    /// True when the format carries a facility / site / company code.
    pub fn has_facility_code(self) -> bool {
        self.facility_field().is_some()
    }

    /// Largest facility code the format can express.
    pub fn max_facility_code(self) -> Option<u64> {
        self.facility_field().map(|(_, len)| max_for_width(len))
    }

    /// Largest card number the format can express.
    ///
    /// For a [`CardFormat::Raw`] wider than 64 bits this saturates at
    /// `u64::MAX`; see [`Decoded::card_number`] for how that case is reported.
    pub fn max_card_number(self) -> u64 {
        max_for_width(self.card_field().1)
    }

    /// Size of the format's credential space — every facility code times every
    /// card number.
    ///
    /// Saturates rather than overflowing. For H10301 this is 16 777 216, which
    /// is the number the brute-force drill exists to make visceral.
    pub fn credential_space(self) -> u128 {
        let fc = self
            .facility_field()
            .map_or(1u128, |(_, len)| 1u128 << len.min(127));
        let cn = 1u128 << self.card_field().1.min(127);
        fc.saturating_mul(cn)
    }

    /// The parity rules, **in the order they must be applied**.
    ///
    /// Order matters for Corporate 1000, whose outermost parity bit covers the
    /// other two parity bits. Encoding walks this list front to back.
    pub fn parity_rules(self) -> Vec<ParityRule> {
        match self {
            CardFormat::H10301 => vec![
                ParityRule {
                    bit: 0,
                    parity: Parity::Even,
                    coverage: Coverage::Range { start: 1, len: 12 },
                    label: "leading parity",
                },
                ParityRule {
                    bit: 25,
                    parity: Parity::Odd,
                    coverage: Coverage::Range { start: 13, len: 12 },
                    label: "trailing parity",
                },
            ],
            CardFormat::H10306 => vec![
                ParityRule {
                    bit: 0,
                    parity: Parity::Even,
                    coverage: Coverage::Range { start: 1, len: 16 },
                    label: "leading parity",
                },
                ParityRule {
                    bit: 33,
                    parity: Parity::Odd,
                    coverage: Coverage::Range { start: 17, len: 16 },
                    label: "trailing parity",
                },
            ],
            CardFormat::Corporate1000 => vec![
                ParityRule {
                    bit: 1,
                    parity: Parity::Even,
                    coverage: Coverage::comb(2, 33, 3, 1),
                    label: "inner even parity",
                },
                ParityRule {
                    bit: 34,
                    parity: Parity::Odd,
                    coverage: Coverage::comb(1, 32, 3, 0),
                    label: "trailing parity",
                },
                ParityRule {
                    bit: 0,
                    parity: Parity::Odd,
                    coverage: Coverage::Range { start: 1, len: 34 },
                    label: "whole-frame parity",
                },
            ],
            CardFormat::H10304 | CardFormat::H10302 => vec![
                ParityRule {
                    bit: 0,
                    parity: Parity::Even,
                    coverage: Coverage::Range { start: 1, len: 18 },
                    label: "leading parity",
                },
                ParityRule {
                    bit: 36,
                    parity: Parity::Odd,
                    coverage: Coverage::Range { start: 18, len: 18 },
                    label: "trailing parity",
                },
            ],
            CardFormat::Raw { .. } => Vec::new(),
        }
    }
}

fn max_for_width(len: usize) -> u64 {
    if len >= 64 {
        u64::MAX
    } else {
        (1u64 << len) - 1
    }
}

impl fmt::Display for CardFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CardFormat::Raw { bit_len } => write!(f, "raw/{bit_len}"),
            other => write!(f, "{}", other.name()),
        }
    }
}

/// A credential as a person would describe it: a format, a facility code and a
/// card number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Credential {
    /// Which format to render it in.
    pub format: CardFormat,
    /// Facility / site / company code. Must be `Some` exactly when the format
    /// has such a field.
    pub facility_code: Option<u64>,
    /// Card number.
    pub card_number: u64,
}

impl Credential {
    /// A credential in a format that has a facility code.
    pub fn new(format: CardFormat, facility_code: u64, card_number: u64) -> Credential {
        Credential {
            format,
            facility_code: Some(facility_code),
            card_number,
        }
    }

    /// A credential in a format that has no facility code.
    pub fn without_facility(format: CardFormat, card_number: u64) -> Credential {
        Credential {
            format,
            facility_code: None,
            card_number,
        }
    }

    /// Render to bits. See [`encode`].
    pub fn encode(&self) -> Result<BitVec, FormatError> {
        encode(self)
    }
}

impl fmt::Display for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.facility_code {
            Some(fc) => write!(f, "{} fc={} cn={}", self.format, fc, self.card_number),
            None => write!(f, "{} cn={}", self.format, self.card_number),
        }
    }
}

/// What a decoder found in a frame.
///
/// Note what is *not* here: a success/failure verdict on parity. Parity lives
/// in [`Decoded::parity`] as a separate report, so a caller can act on
/// "decoded fine, parity bad" — the case that matters on a real wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    /// The format this was decoded *as*. Not a claim about the card.
    pub format: CardFormat,
    /// The frame, kept verbatim so it can be replayed without re-encoding.
    pub bits: BitVec,
    /// Facility code, when the format has one.
    pub facility_code: Option<u64>,
    /// Card number. `None` only for a [`CardFormat::Raw`] wider than 64 bits,
    /// where no integer can hold it — the bits are still in
    /// [`Decoded::bits`].
    pub card_number: Option<u64>,
    /// Per-rule parity results.
    pub parity: ParityReport,
}

impl Decoded {
    /// True when every parity rule passed.
    pub fn parity_valid(&self) -> bool {
        self.parity.is_valid()
    }

    /// Rebuild a [`Credential`], when the card number fits in a `u64`.
    pub fn credential(&self) -> Option<Credential> {
        Some(Credential {
            format: self.format,
            facility_code: self.facility_code,
            card_number: self.card_number?,
        })
    }
}

impl fmt::Display for Decoded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format)?;
        if let Some(fc) = self.facility_code {
            write!(f, " fc={fc}")?;
        }
        match self.card_number {
            Some(cn) => write!(f, " cn={cn}")?,
            None => write!(f, " cn=<{} bits>", self.bits.len())?,
        }
        if self.parity.is_empty() {
            write!(f, " (no parity defined)")
        } else if self.parity.is_valid() {
            write!(f, " parity=ok")
        } else {
            write!(f, " parity=FAILED")
        }
    }
}

/// Why a credential could not be encoded, or a frame could not be sliced.
///
/// Every variant here is about a mismatch between a format and the data offered
/// to it. Bad *parity* is never an error — it is a result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatError {
    /// The frame is not the width this format expects.
    LengthMismatch {
        /// Format that was asked for.
        format: CardFormat,
        /// Width the format requires.
        expected: usize,
        /// Width actually offered.
        found: usize,
    },
    /// A field value is larger than its field.
    FieldTooLarge {
        /// `"facility code"` or `"card number"`.
        field: &'static str,
        /// The offending value.
        value: u64,
        /// The largest value that fits.
        max: u64,
    },
    /// The format has a facility code but the credential did not supply one.
    MissingFacilityCode {
        /// The format in question.
        format: CardFormat,
    },
    /// The credential supplied a facility code but the format has no field for
    /// it — almost always a sign the wrong format was selected.
    UnexpectedFacilityCode {
        /// The format in question.
        format: CardFormat,
    },
    /// A raw frame wider than 64 bits was asked for as an integer.
    TooWideForU64 {
        /// The frame width.
        bit_len: usize,
    },
    /// A lower-level bit error leaked through. Should not happen for input
    /// that passed the checks above; kept so nothing has to panic.
    Bits(BitError),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::LengthMismatch {
                format,
                expected,
                found,
            } => {
                write!(f, "{format} needs {expected} bits, got {found}")
            }
            FormatError::FieldTooLarge { field, value, max } => {
                write!(f, "{field} {value} exceeds the maximum of {max}")
            }
            FormatError::MissingFacilityCode { format } => {
                write!(f, "{format} requires a facility code")
            }
            FormatError::UnexpectedFacilityCode { format } => {
                write!(f, "{format} has no facility code field")
            }
            FormatError::TooWideForU64 { bit_len } => {
                write!(f, "a {bit_len}-bit frame does not fit in a u64")
            }
            FormatError::Bits(e) => write!(f, "{e}"),
        }
    }
}

impl From<BitError> for FormatError {
    fn from(e: BitError) -> Self {
        FormatError::Bits(e)
    }
}

/// Encode a credential to bits, with correct parity.
///
/// ```
/// use odr_wiegand::{CardFormat, Credential, encode};
///
/// let bits = encode(&Credential::new(CardFormat::H10301, 0, 0)).unwrap();
/// // An all-zero 26-bit card is not all zeros on the wire: the trailing odd
/// // parity bit over twelve zeros must be a one.
/// assert_eq!(bits.to_bin_string(), "00000000000000000000000001");
/// ```
///
/// # Errors
/// [`FormatError`] when a field does not fit, or the credential and format
/// disagree about whether there is a facility code.
pub fn encode(cred: &Credential) -> Result<BitVec, FormatError> {
    let format = cred.format;
    let mut bits = BitVec::zeros(format.bit_len());

    match (format.facility_field(), cred.facility_code) {
        (Some((start, len)), Some(fc)) => {
            let max = max_for_width(len);
            if fc > max {
                return Err(FormatError::FieldTooLarge {
                    field: "facility code",
                    value: fc,
                    max,
                });
            }
            bits.set_field(start, len, fc)?;
        }
        (Some(_), None) => return Err(FormatError::MissingFacilityCode { format }),
        (None, Some(_)) => return Err(FormatError::UnexpectedFacilityCode { format }),
        (None, None) => {}
    }

    let (cstart, clen) = format.card_field();
    if clen > 64 {
        return Err(FormatError::TooWideForU64 { bit_len: clen });
    }
    let cmax = max_for_width(clen);
    if cred.card_number > cmax {
        return Err(FormatError::FieldTooLarge {
            field: "card number",
            value: cred.card_number,
            max: cmax,
        });
    }
    bits.set_field(cstart, clen, cred.card_number)?;

    for rule in format.parity_rules() {
        // Every rule is in range because the frame was sized from the format.
        rule.apply(&mut bits);
    }
    Ok(bits)
}

/// Slice a frame according to `format` and check its parity.
///
/// This succeeds whenever the frame is the right width. **Bad parity is
/// reported, not raised** — see [`Decoded::parity`].
///
/// ```
/// use odr_wiegand::{decode, BitVec, CardFormat};
///
/// let bits = BitVec::from_bin_str("1 01111011 0001000111010111 0").unwrap();
/// let d = decode(CardFormat::H10301, &bits).unwrap();
/// assert_eq!(d.facility_code, Some(123));
/// assert_eq!(d.card_number, Some(4567));
/// assert!(d.parity_valid());
/// ```
///
/// # Errors
/// [`FormatError::LengthMismatch`] if the frame is the wrong width.
pub fn decode(format: CardFormat, bits: &BitVec) -> Result<Decoded, FormatError> {
    if bits.len() != format.bit_len() {
        return Err(FormatError::LengthMismatch {
            format,
            expected: format.bit_len(),
            found: bits.len(),
        });
    }

    let facility_code = format
        .facility_field()
        .and_then(|(start, len)| bits.extract_u64(start, len));
    let (cstart, clen) = format.card_field();
    let card_number = bits.extract_u64(cstart, clen);
    let parity = ParityReport::evaluate(&format.parity_rules(), bits);

    Ok(Decoded {
        format,
        bits: bits.clone(),
        facility_code,
        card_number,
        parity,
    })
}

/// Decode a frame as an unknown raw stream of whatever width it happens to be.
///
/// Never fails. This is the honest reading of anything a sniffer captures
/// before a format has been chosen.
pub fn decode_raw(bits: &BitVec) -> Decoded {
    let format = CardFormat::Raw {
        bit_len: bits.len(),
    };
    Decoded {
        format,
        bits: bits.clone(),
        facility_code: None,
        card_number: bits.extract_u64(0, bits.len()),
        parity: ParityReport::default(),
    }
}

/// One plausible reading of a captured frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatCandidate {
    /// The decode under this format.
    pub decoded: Decoded,
    /// Whether the format's parity rules all hold. This is the *only* evidence
    /// the wire offers for picking between formats of the same width, and it is
    /// weak evidence: an attacker recomputes parity, and two formats of the
    /// same width can both pass.
    pub parity_valid: bool,
}

/// List every format that could plausibly explain a captured frame.
///
/// Candidates are returned **in confidence order**: named formats whose parity
/// checks out, then named formats whose parity does not, then the raw
/// passthrough, which always fits. Ambiguity is the normal case and is not an
/// error — a 37-bit frame is genuinely both an H10304 and an H10302 until
/// somebody looks at the panel's configuration.
///
/// ```
/// use odr_wiegand::{infer_formats, CardFormat, Credential, encode};
///
/// let bits = encode(&Credential::new(CardFormat::H10304, 7, 99)).unwrap();
/// let candidates = infer_formats(&bits);
/// // Both 37-bit formats parse, both with valid parity: the parity rules are
/// // identical, only the field split differs.
/// assert!(candidates.len() >= 3); // H10304, H10302, raw
/// assert!(candidates[0].parity_valid);
/// ```
pub fn infer_formats(bits: &BitVec) -> Vec<FormatCandidate> {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();

    for format in KNOWN_FORMATS {
        if format.bit_len() != bits.len() {
            continue;
        }
        if let Ok(decoded) = decode(*format, bits) {
            let parity_valid = decoded.parity_valid();
            let candidate = FormatCandidate {
                decoded,
                parity_valid,
            };
            if parity_valid {
                valid.push(candidate);
            } else {
                invalid.push(candidate);
            }
        }
    }

    let mut out = valid;
    out.append(&mut invalid);
    out.push(FormatCandidate {
        decoded: decode_raw(bits),
        parity_valid: true,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h10301_known_vector() {
        // Facility code 123 (0111_1011), card number 4567 (0x11D7).
        let bits = encode(&Credential::new(CardFormat::H10301, 123, 4567)).unwrap();
        assert_eq!(bits.len(), 26);
        assert_eq!(bits.to_bin_string(), "10111101100010001110101110");
        //                                P FFFFFFFF CCCCCCCCCCCCCCCC P
        assert_eq!(bits.get(0), Some(true), "leading even parity over 7 ones");
        assert_eq!(bits.get(25), Some(false), "trailing odd parity over 7 ones");

        let d = decode(CardFormat::H10301, &bits).unwrap();
        assert_eq!(d.facility_code, Some(123));
        assert_eq!(d.card_number, Some(4567));
        assert!(d.parity_valid());
    }

    #[test]
    fn h10301_all_zero_card_still_has_a_one_bit() {
        let bits = encode(&Credential::new(CardFormat::H10301, 0, 0)).unwrap();
        assert_eq!(bits.to_bin_string(), "00000000000000000000000001");
    }

    #[test]
    fn parity_failure_is_reported_not_fatal() {
        let mut bits = encode(&Credential::new(CardFormat::H10301, 123, 4567)).unwrap();
        bits.set(25, true).unwrap(); // flip the trailing parity bit
        let d = decode(CardFormat::H10301, &bits).unwrap();
        assert_eq!(d.facility_code, Some(123), "fields still parse");
        assert_eq!(d.card_number, Some(4567));
        assert!(!d.parity_valid());
        let failures: Vec<_> = d.parity.failures().collect();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].bit, 25);
    }

    #[test]
    fn round_trip_every_format() {
        let cases = [
            Credential::new(CardFormat::H10301, 200, 60000),
            Credential::new(CardFormat::H10306, 40000, 60000),
            Credential::new(CardFormat::Corporate1000, 4000, 1_000_000),
            Credential::new(CardFormat::H10304, 40000, 500_000),
            Credential::without_facility(CardFormat::H10302, 30_000_000_000),
            Credential::without_facility(CardFormat::Raw { bit_len: 48 }, 0xDEAD_BEEF_1234),
        ];
        for cred in cases {
            let bits = encode(&cred).unwrap();
            assert_eq!(bits.len(), cred.format.bit_len(), "{cred}");
            let d = decode(cred.format, &bits).unwrap();
            assert_eq!(d.facility_code, cred.facility_code, "{cred}");
            assert_eq!(d.card_number, Some(cred.card_number), "{cred}");
            assert!(d.parity_valid(), "{cred}");
        }
    }

    #[test]
    fn field_limits_are_enforced() {
        let e = encode(&Credential::new(CardFormat::H10301, 256, 0)).unwrap_err();
        assert!(matches!(
            e,
            FormatError::FieldTooLarge {
                field: "facility code",
                ..
            }
        ));
        let e = encode(&Credential::new(CardFormat::H10301, 0, 65536)).unwrap_err();
        assert!(matches!(
            e,
            FormatError::FieldTooLarge {
                field: "card number",
                ..
            }
        ));
    }

    #[test]
    fn facility_code_presence_must_match_the_format() {
        let e = encode(&Credential::without_facility(CardFormat::H10301, 1)).unwrap_err();
        assert!(matches!(e, FormatError::MissingFacilityCode { .. }));
        let e = encode(&Credential::new(CardFormat::H10302, 1, 1)).unwrap_err();
        assert!(matches!(e, FormatError::UnexpectedFacilityCode { .. }));
    }

    #[test]
    fn wrong_length_is_an_error() {
        let bits = BitVec::zeros(25);
        let e = decode(CardFormat::H10301, &bits).unwrap_err();
        assert_eq!(
            e,
            FormatError::LengthMismatch {
                format: CardFormat::H10301,
                expected: 26,
                found: 25
            }
        );
    }

    #[test]
    fn corporate_1000_parity_bits_land_where_the_spec_says() {
        let rules = CardFormat::Corporate1000.parity_rules();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].bit, 1);
        assert_eq!(rules[0].coverage.count(), 22);
        assert_eq!(rules[1].bit, 34);
        assert_eq!(rules[1].coverage.count(), 22);
        assert_eq!(rules[2].bit, 0);
        assert_eq!(rules[2].coverage.count(), 34);
    }

    #[test]
    fn credential_space_of_26_bit_is_sixteen_million() {
        assert_eq!(CardFormat::H10301.credential_space(), 16_777_216);
    }

    #[test]
    fn raw_wider_than_64_bits_keeps_the_bits() {
        let bits = BitVec::zeros(96);
        let d = decode_raw(&bits);
        assert_eq!(d.card_number, None);
        assert_eq!(d.bits.len(), 96);
        assert!(d.credential().is_none());
    }
}
