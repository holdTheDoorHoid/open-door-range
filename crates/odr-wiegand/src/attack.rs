//! Attack primitives.
//!
//! These belong here rather than in `odr-attack` because they are not really
//! attacks — they are the protocol's ordinary operations, used by someone other
//! than the reader. That is the whole finding. Replaying a Wiegand frame is
//! *encoding a frame*. Sweeping a facility code is *encoding frames in a loop*.
//! Swapping a credential inside a reader housing is *decoding then encoding*.
//! No cryptographic primitive is broken because there is none to break, and the
//! code in this module is correspondingly boring.
//!
//! `odr-attack` will wrap these in actors with state and narration. The bit and
//! timing mechanics live here, next to the protocol they operate on, so the
//! drill and the analyser cannot drift apart.

use crate::bits::BitVec;
use crate::format::{decode, decode_raw, encode, CardFormat, Credential, Decoded, FormatError};
use crate::wire::{encode_transitions, Transition, WiegandTiming, WireFrame};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::ops::RangeInclusive;

/// A frame captured off the wire, ready to be sent again.
///
/// There is nothing to store but the bits and the time they were seen. No
/// counter, no timestamp the panel checks, no nonce — so a capture stays valid
/// forever. A Wiegand credential captured in 2009 still opens the door in 2026
/// if the card is still enrolled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capture {
    /// Virtual microsecond at which the frame started.
    pub captured_at_us: u64,
    /// The bits exactly as observed.
    pub bits: BitVec,
}

impl Capture {
    /// Wrap a decoded wire frame.
    pub fn from_frame(frame: &WireFrame) -> Capture {
        Capture {
            captured_at_us: frame.start_us,
            bits: frame.bits.clone(),
        }
    }

    /// Wrap a bare bit vector.
    pub fn from_bits(bits: BitVec, captured_at_us: u64) -> Capture {
        Capture {
            captured_at_us,
            bits,
        }
    }

    /// Render the capture as edges to drive onto the wire at `at_us`.
    ///
    /// The timing need not match the timing it was captured with — a replay
    /// device sends the same bits at whatever rate it likes, and nothing
    /// downstream can tell.
    ///
    /// ```
    /// use odr_wiegand::{
    ///     encode, encode_transitions, decode_transitions, CardFormat, Capture,
    ///     Credential, WiegandTiming,
    /// };
    ///
    /// let timing = WiegandTiming::default();
    /// let original = encode(&Credential::new(CardFormat::H10301, 12, 3456)).unwrap();
    ///
    /// // Sniff it.
    /// let seen = decode_transitions(&encode_transitions(&original, &timing, 0), &timing);
    /// let capture = Capture::from_frame(&seen.frames[0]);
    ///
    /// // Send it again, two seconds later, from a faster transmitter.
    /// let replayed = capture.replay(2_000_000, &WiegandTiming::fast());
    /// let heard = decode_transitions(&replayed, &WiegandTiming::fast());
    /// assert_eq!(heard.frames[0].bits, original);
    /// ```
    pub fn replay(&self, at_us: u64, timing: &WiegandTiming) -> Vec<Transition> {
        encode_transitions(&self.bits, timing, at_us)
    }

    /// Best-effort interpretation of the captured bits.
    ///
    /// Returns the raw reading when no named format fits the width.
    pub fn interpret(&self) -> Decoded {
        crate::format::infer_formats(&self.bits)
            .into_iter()
            .next()
            .map_or_else(|| decode_raw(&self.bits), |c| c.decoded)
    }
}

/// An iterator over a block of credentials, for brute-force drills.
///
/// The card number varies fastest, which is what a real sweep does: a panel's
/// facility code is usually one value, so you fix it and walk the card numbers.
/// Nothing here rate-limits or backs off, because the wire has no mechanism to
/// ask it to.
///
/// ```
/// use odr_wiegand::{CardFormat, CredentialSweep};
///
/// let sweep = CredentialSweep::new(CardFormat::H10301, 12..=12, 1..=5).unwrap();
/// assert_eq!(sweep.credential_count(), 5);
/// let numbers: Vec<u64> = sweep.map(|c| c.card_number).collect();
/// assert_eq!(numbers, [1, 2, 3, 4, 5]);
/// ```
#[derive(Clone, Debug)]
pub struct CredentialSweep {
    format: CardFormat,
    fc_start: u64,
    fc_end: u64,
    cn_start: u64,
    cn_end: u64,
    fc: u64,
    cn: u64,
    exhausted: bool,
}

impl CredentialSweep {
    /// Sweep `facility_codes` × `card_numbers` in `format`.
    ///
    /// # Errors
    /// [`FormatError::FieldTooLarge`] if either range runs past what the format
    /// can express, [`FormatError::UnexpectedFacilityCode`] if the format has
    /// no facility code field (use [`CredentialSweep::without_facility`]).
    pub fn new(
        format: CardFormat,
        facility_codes: RangeInclusive<u64>,
        card_numbers: RangeInclusive<u64>,
    ) -> Result<Self, FormatError> {
        let Some(max_fc) = format.max_facility_code() else {
            return Err(FormatError::UnexpectedFacilityCode { format });
        };
        if *facility_codes.end() > max_fc {
            return Err(FormatError::FieldTooLarge {
                field: "facility code",
                value: *facility_codes.end(),
                max: max_fc,
            });
        }
        Self::build(format, Some(facility_codes), card_numbers)
    }

    /// Sweep card numbers only, for a format with no facility code.
    ///
    /// # Errors
    /// [`FormatError::MissingFacilityCode`] if the format does have one,
    /// [`FormatError::FieldTooLarge`] if the range does not fit.
    pub fn without_facility(
        format: CardFormat,
        card_numbers: RangeInclusive<u64>,
    ) -> Result<Self, FormatError> {
        if format.has_facility_code() {
            return Err(FormatError::MissingFacilityCode { format });
        }
        Self::build(format, None, card_numbers)
    }

    /// Every credential the format can express.
    ///
    /// For [`CardFormat::H10301`] that is 16 777 216 of them, which is the
    /// number the drill exists to put a wall-clock figure against.
    ///
    /// # Errors
    /// [`FormatError::TooWideForU64`] for a format whose space does not fit in
    /// 64-bit counters.
    pub fn exhaustive(format: CardFormat) -> Result<Self, FormatError> {
        if format.card_field().1 > 63 {
            return Err(FormatError::TooWideForU64 {
                bit_len: format.card_field().1,
            });
        }
        let cn = 0..=format.max_card_number();
        match format.max_facility_code() {
            Some(max_fc) => Self::build(format, Some(0..=max_fc), cn),
            None => Self::build(format, None, cn),
        }
    }

    fn build(
        format: CardFormat,
        facility_codes: Option<RangeInclusive<u64>>,
        card_numbers: RangeInclusive<u64>,
    ) -> Result<Self, FormatError> {
        let max_cn = format.max_card_number();
        if *card_numbers.end() > max_cn {
            return Err(FormatError::FieldTooLarge {
                field: "card number",
                value: *card_numbers.end(),
                max: max_cn,
            });
        }
        let (fc_start, fc_end) = facility_codes.map_or((0, 0), |r| (*r.start(), *r.end()));
        let (cn_start, cn_end) = (*card_numbers.start(), *card_numbers.end());
        let exhausted = fc_start > fc_end || cn_start > cn_end;
        Ok(CredentialSweep {
            format,
            fc_start,
            fc_end,
            cn_start,
            cn_end,
            fc: fc_start,
            cn: cn_start,
            exhausted,
        })
    }

    /// The format being swept.
    pub fn format(&self) -> CardFormat {
        self.format
    }

    /// How many credentials the sweep covers in total, regardless of how far it
    /// has already run. Saturates rather than overflowing.
    pub fn credential_count(&self) -> u128 {
        if self.fc_start > self.fc_end || self.cn_start > self.cn_end {
            return 0;
        }
        let fcs = if self.format.has_facility_code() {
            u128::from(self.fc_end - self.fc_start) + 1
        } else {
            1
        };
        let cns = u128::from(self.cn_end - self.cn_start) + 1;
        fcs.saturating_mul(cns)
    }

    /// What this sweep would cost on a real wire.
    ///
    /// `settle_us` is the quiet time left between frames so the panel treats
    /// them as separate presentations. Panels vary wildly; the inter-frame gap
    /// from the reader's timing is a reasonable floor and is what
    /// [`SweepCost::nominal`] uses.
    pub fn cost(&self, timing: &WiegandTiming, settle_us: u64) -> SweepCost {
        let bits = self.format.bit_len();
        let per = timing.frame_duration_us(bits).saturating_add(settle_us);
        SweepCost {
            credentials: self.credential_count(),
            bits_per_credential: bits,
            us_per_credential: per,
            total_us: self.credential_count().saturating_mul(u128::from(per)),
        }
    }
}

impl Iterator for CredentialSweep {
    type Item = Credential;

    fn next(&mut self) -> Option<Credential> {
        if self.exhausted {
            return None;
        }
        let cred = Credential {
            format: self.format,
            facility_code: if self.format.has_facility_code() {
                Some(self.fc)
            } else {
                None
            },
            card_number: self.cn,
        };

        if self.cn == self.cn_end {
            self.cn = self.cn_start;
            if !self.format.has_facility_code() || self.fc == self.fc_end {
                self.exhausted = true;
            } else {
                self.fc += 1;
            }
        } else {
            self.cn += 1;
        }
        Some(cred)
    }
}

/// What a sweep costs in wall-clock time.
///
/// The point of this type is one sentence in a drill: *"a 26-bit format has
/// 16 777 216 credentials, and at two milliseconds a bit that is a little over
/// eight days of continuous transmission — so brute force is real but it is not
/// a lunch break, which is why people attack the facility code instead."*
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SweepCost {
    /// How many credentials.
    pub credentials: u128,
    /// Frame width.
    pub bits_per_credential: usize,
    /// Frame time plus settle time for one credential.
    pub us_per_credential: u64,
    /// Total virtual microseconds.
    pub total_us: u128,
}

impl SweepCost {
    /// Cost with the nominal reader timing and a settle time of one
    /// inter-frame gap.
    pub fn nominal(sweep: &CredentialSweep) -> SweepCost {
        let timing = WiegandTiming::default();
        sweep.cost(&timing, timing.interframe_gap_us)
    }

    /// Total time in seconds.
    pub fn total_seconds(&self) -> f64 {
        self.total_us as f64 / 1_000_000.0
    }

    /// Total time in hours.
    pub fn total_hours(&self) -> f64 {
        self.total_seconds() / 3_600.0
    }

    /// Total time in days.
    pub fn total_days(&self) -> f64 {
        self.total_hours() / 24.0
    }

    /// A one-line summary for a UI or a drill transcript.
    pub fn describe(&self) -> String {
        let seconds = self.total_seconds();
        if seconds < 120.0 {
            format!(
                "{} credentials x {} us = {:.1} s",
                self.credentials, self.us_per_credential, seconds
            )
        } else if seconds < 7_200.0 {
            format!(
                "{} credentials x {} us = {:.1} minutes",
                self.credentials,
                self.us_per_credential,
                seconds / 60.0
            )
        } else if self.total_hours() < 48.0 {
            format!(
                "{} credentials x {} us = {:.1} hours",
                self.credentials,
                self.us_per_credential,
                self.total_hours()
            )
        } else {
            format!(
                "{} credentials x {} us = {:.1} days",
                self.credentials,
                self.us_per_credential,
                self.total_days()
            )
        }
    }
}

impl fmt::Display for SweepCost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

/// The outcome of an inline substitution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TamperResult {
    /// What the reader actually sent.
    pub observed: Decoded,
    /// What the panel will be told instead, with correct parity.
    pub emitted: BitVec,
    /// Whether the substituted frame is the same width as the original. When
    /// it is, nothing downstream of the implant can tell the difference —
    /// there is no field in the protocol that would differ.
    pub length_preserved: bool,
}

/// Decode a frame and emit a different credential in its place.
///
/// This is the inline-implant case: a small board cut into the reader's D0/D1
/// pair inside the housing, in the Tick / ESPKey family. It watches a badge go
/// past, then presents whatever credential it likes with valid parity. The
/// panel has no way to notice, because the only thing a panel checks is parity
/// and the implant computes it.
///
/// ```
/// use odr_wiegand::{encode, inline_tamper, CardFormat, Credential};
///
/// let victim = encode(&Credential::new(CardFormat::H10301, 12, 3456)).unwrap();
/// let boss = Credential::new(CardFormat::H10301, 1, 1);
/// let result = inline_tamper(&victim, &boss).unwrap();
///
/// assert!(result.length_preserved);
/// assert_eq!(result.observed.facility_code, Some(12));
/// // The emitted frame is a perfectly valid credential. Nothing downstream
/// // can tell it was not the card that was presented.
/// let seen = odr_wiegand::decode(CardFormat::H10301, &result.emitted).unwrap();
/// assert!(seen.parity_valid());
/// assert_eq!(seen.card_number, Some(1));
/// ```
///
/// # Errors
/// [`FormatError`] only if `replacement` cannot be encoded at all. A width
/// mismatch between the observed frame and the replacement is *not* an error —
/// it is reported in [`TamperResult::length_preserved`], because an implant is
/// free to send a different format and a panel configured for one format will
/// simply ignore or mis-parse the other, which is itself worth demonstrating.
pub fn inline_tamper(
    observed: &BitVec,
    replacement: &Credential,
) -> Result<TamperResult, FormatError> {
    let emitted = encode(replacement)?;
    let observed_decoded = crate::format::infer_formats(observed)
        .into_iter()
        .next()
        .map_or_else(|| decode_raw(observed), |c| c.decoded);
    Ok(TamperResult {
        length_preserved: emitted.len() == observed.len(),
        observed: observed_decoded,
        emitted,
    })
}

/// Re-encode an observed frame with one field changed, keeping the format.
///
/// A convenience over [`inline_tamper`] for the common drill: "same reader,
/// same format, different card number".
///
/// # Errors
/// [`FormatError::LengthMismatch`] if `observed` is not the right width for
/// `format`, or the usual field-size errors.
pub fn substitute_fields(
    observed: &BitVec,
    format: CardFormat,
    facility_code: Option<u64>,
    card_number: Option<u64>,
) -> Result<TamperResult, FormatError> {
    let decoded = decode(format, observed)?;
    let replacement = Credential {
        format,
        facility_code: facility_code.or(decoded.facility_code),
        card_number: card_number
            .or(decoded.card_number)
            .ok_or(FormatError::TooWideForU64 {
                bit_len: observed.len(),
            })?,
    };
    inline_tamper(observed, &replacement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::decode_transitions;

    #[test]
    fn replay_reproduces_the_frame_exactly() {
        let timing = WiegandTiming::default();
        let original = encode(&Credential::new(CardFormat::H10301, 77, 12345)).unwrap();
        let capture = Capture::from_bits(original.clone(), 0);
        let edges = capture.replay(1_000_000, &timing);
        let heard = decode_transitions(&edges, &timing);
        assert_eq!(heard.frames.len(), 1);
        assert_eq!(heard.frames[0].bits, original);
        assert_eq!(heard.frames[0].start_us, 1_000_000);
    }

    #[test]
    fn capture_interprets_itself() {
        let original = encode(&Credential::new(CardFormat::H10301, 77, 12345)).unwrap();
        let d = Capture::from_bits(original, 0).interpret();
        assert_eq!(d.format, CardFormat::H10301);
        assert_eq!(d.facility_code, Some(77));
    }

    #[test]
    fn sweep_covers_the_whole_block_card_number_fastest() {
        let sweep = CredentialSweep::new(CardFormat::H10301, 1..=2, 10..=12).unwrap();
        assert_eq!(sweep.credential_count(), 6);
        let got: Vec<(u64, u64)> = sweep
            .map(|c| (c.facility_code.unwrap(), c.card_number))
            .collect();
        assert_eq!(got, [(1, 10), (1, 11), (1, 12), (2, 10), (2, 11), (2, 12)]);
    }

    #[test]
    fn exhaustive_26_bit_sweep_is_sixteen_million() {
        let sweep = CredentialSweep::exhaustive(CardFormat::H10301).unwrap();
        assert_eq!(sweep.credential_count(), 16_777_216);
        let cost = SweepCost::nominal(&sweep);
        // 26 bits at 2 ms plus a 20 ms settle is 70.05 ms per credential.
        assert_eq!(cost.us_per_credential, 25 * 2_000 + 50 + 20_000);
        assert!(cost.total_days() > 10.0, "{}", cost.describe());
        assert!(cost.describe().ends_with("days"));
    }

    #[test]
    fn a_single_facility_code_sweep_is_much_cheaper() {
        let sweep = CredentialSweep::new(CardFormat::H10301, 42..=42, 0..=65_535).unwrap();
        assert_eq!(sweep.credential_count(), 65_536);
        let cost = SweepCost::nominal(&sweep);
        assert!(cost.total_hours() < 2.0, "{}", cost.describe());
    }

    #[test]
    fn sweeps_reject_values_the_format_cannot_hold() {
        assert!(matches!(
            CredentialSweep::new(CardFormat::H10301, 0..=300, 0..=1),
            Err(FormatError::FieldTooLarge {
                field: "facility code",
                ..
            })
        ));
        assert!(matches!(
            CredentialSweep::new(CardFormat::H10301, 0..=1, 0..=70_000),
            Err(FormatError::FieldTooLarge {
                field: "card number",
                ..
            })
        ));
        assert!(matches!(
            CredentialSweep::new(CardFormat::H10302, 0..=1, 0..=1),
            Err(FormatError::UnexpectedFacilityCode { .. })
        ));
    }

    #[test]
    fn sweep_without_facility_code() {
        let sweep = CredentialSweep::without_facility(CardFormat::H10302, 5..=7).unwrap();
        let got: Vec<Credential> = sweep.collect();
        assert_eq!(got.len(), 3);
        assert!(got.iter().all(|c| c.facility_code.is_none()));
    }

    #[test]
    fn empty_sweep_yields_nothing() {
        // An inverted range: start after end. Built from variables so it is
        // clearly deliberate rather than a typo.
        let (lo, hi) = (5u64, 4u64);
        let sweep = CredentialSweep::new(CardFormat::H10301, lo..=hi, 0..=10).unwrap();
        assert_eq!(sweep.credential_count(), 0);
        assert_eq!(sweep.count(), 0);
    }

    #[test]
    fn tamper_emits_a_valid_credential_of_the_same_width() {
        let victim = encode(&Credential::new(CardFormat::H10301, 12, 3456)).unwrap();
        let result = inline_tamper(&victim, &Credential::new(CardFormat::H10301, 1, 1)).unwrap();
        assert!(result.length_preserved);
        assert_eq!(result.emitted.len(), 26);
        let seen = decode(CardFormat::H10301, &result.emitted).unwrap();
        assert!(seen.parity_valid());
        assert_eq!(seen.facility_code, Some(1));
        assert_eq!(seen.card_number, Some(1));
    }

    #[test]
    fn tamper_across_formats_reports_the_length_change() {
        let victim = encode(&Credential::new(CardFormat::H10301, 12, 3456)).unwrap();
        let result = inline_tamper(&victim, &Credential::new(CardFormat::H10304, 1, 1)).unwrap();
        assert!(!result.length_preserved);
        assert_eq!(result.emitted.len(), 37);
    }

    #[test]
    fn substitute_one_field_and_keep_the_other() {
        let victim = encode(&Credential::new(CardFormat::H10301, 12, 3456)).unwrap();
        let result = substitute_fields(&victim, CardFormat::H10301, None, Some(1)).unwrap();
        let seen = decode(CardFormat::H10301, &result.emitted).unwrap();
        assert_eq!(seen.facility_code, Some(12), "facility code carried over");
        assert_eq!(seen.card_number, Some(1));
        assert!(seen.parity_valid());
    }
}
