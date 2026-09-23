//! The OSDP v2.2.2 command and reply code set.
//!
//! Every frame carries exactly one `id` byte. If the frame is travelling
//! ACU → PD it is a [`Command`]; PD → ACU it is a [`Reply`]. The two sets
//! overlap numerically — `0x76` is `CMD_CHLNG` in one direction and
//! `REPLY_CCRYPT` in the other — so direction (address bit 7) must be known
//! before a code can be named. That is why [`crate::frame::Frame`] stores the
//! raw byte and offers [`crate::frame::Frame::command_code`] and
//! [`crate::frame::Frame::reply_code`] separately.
//!
//! # Provenance
//!
//! The values here were cross-checked against three independent
//! implementations — `goToMain/libosdp` (C), `smartrent/jeff` (Elixir) and
//! `verkada/go-osdp` (Go). Where those sources disagreed, the disagreement is
//! recorded in the doc comment for the specific variant and in the crate
//! README. They were **not** checked against the paywalled normative text of
//! IEC 60839-11-5 / SIA OSDP v2.2.2.
//!
//! # Why the id byte matters more than it should
//!
//! These codes are never encrypted (see [`crate::frame`]). A passive listener
//! on a fully secured bus reads this enum off the wire directly. The sequence
//! `Poll, Ack, Poll, Ack, Raw, Ack, Out` is a person badging in and a door
//! unlocking, timestamped, and no key was required to see it.

/// Commands: frames sent by the ACU (controller) to a PD (reader).
///
/// Non-exhaustive in spirit but exhaustive as an enum: unknown bytes are not
/// representable here, and [`crate::frame::Frame`] keeps the raw byte so an
/// analyser can still display traffic this crate does not recognise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Command {
    /// `0x60` — the heartbeat. The ACU sends this many times a second to every
    /// address; the PD answers `ACK` if nothing has happened, or piggybacks an
    /// event reply like `RAW` or `KEYPAD` if something has.
    ///
    /// Because the PD cannot speak unprompted, the poll rate *is* the latency
    /// of the whole system, and the poll pattern is what makes traffic analysis
    /// so easy: the baseline is utterly regular, so any deviation is an event.
    Poll = 0x60,
    /// `0x61` — request the PD's identity. Answered with `PDID`.
    Id = 0x61,
    /// `0x62` — request the PD's capability report. Answered with `PDCAP`.
    ///
    /// This is the frame the Mellon **downgrade** attack rewrites: an inline
    /// implant edits the `PDCAP` reply so the reader appears not to support
    /// AES-128, and a controller configured to "use secure channel if
    /// available" politely stays in the clear.
    Cap = 0x62,
    /// `0x63` — diagnostic. Present only in `verkada/go-osdp`; absent from
    /// libosdp and jeff, and believed withdrawn from the specification.
    /// Included for capture-analysis completeness. **Low confidence.**
    Diag = 0x63,
    /// `0x64` — request local status (tamper, power). Answered with `LSTATR`.
    Lstat = 0x64,
    /// `0x65` — request input status. Answered with `ISTATR`.
    Istat = 0x65,
    /// `0x66` — request output status. Answered with `OSTATR`.
    Ostat = 0x66,
    /// `0x67` — request reader status. Answered with `RSTATR`.
    Rstat = 0x67,
    /// `0x68` — drive an output relay. This is the frame that opens the door.
    Out = 0x68,
    /// `0x69` — control a reader LED.
    Led = 0x69,
    /// `0x6A` — control the reader buzzer.
    Buz = 0x6A,
    /// `0x6B` — write text to the reader's display.
    Text = 0x6B,
    /// `0x6C` — set reader mode. Marked deprecated in libosdp and removed from
    /// the specification. **Low confidence**, kept for legacy captures.
    Rmode = 0x6C,
    /// `0x6D` — set time and date. Marked obsolete in libosdp. **Low
    /// confidence**, kept for legacy captures.
    Tdset = 0x6D,
    /// `0x6E` — change the PD's address and/or baud rate. Answered with `COM`.
    ///
    /// Usually sent to the configuration address `0x7F` during commissioning,
    /// unauthenticated, because the PD does not yet have an address to
    /// establish a secure channel on.
    Comset = 0x6E,
    /// `0x73` — request a biometric read. Answered with `BIOREADR`.
    Bioread = 0x73,
    /// `0x74` — request a biometric match against a supplied template.
    /// Answered with `BIOMATCHR`.
    Biomatch = 0x74,
    /// `0x75` — install a new Secure Channel Base Key.
    ///
    /// The Mellon **keyset capture** attack in one byte. OSDP has no key
    /// agreement: the SCBK is pushed to the PD in a `KEYSET` frame. If that
    /// frame is sent before a secure channel exists — which is exactly what
    /// happens when a PD is commissioned or factory-reset — the new site key
    /// crosses the bus in the clear. A sniffer left in a door frame during an
    /// installer's visit collects the key for the whole site.
    Keyset = 0x75,
    /// `0x76` — begin a secure channel: carries RND.A, the 8-byte ACU nonce.
    /// Answered with `REPLY_CCRYPT`. Note the numeric collision with
    /// [`Reply::Ccrypt`].
    Chlng = 0x76,
    /// `0x77` — carries the 16-byte server cryptogram. Answered with
    /// `REPLY_RMAC_I`.
    Scrypt = 0x77,
    /// `0x7B` — tell the PD how large a reply the ACU can receive. Also known
    /// as `CMD_MAXREPLY`.
    AcuRxSize = 0x7B,
    /// `0x7C` — file transfer. Answered with `FTSTAT`.
    FileTransfer = 0x7C,
    /// `0x80` — manufacturer-specific command. Answered with `MFGREP`,
    /// `MFGSTATR` or `MFGERRR`.
    ///
    /// The escape hatch. Whatever a vendor does here is outside the standard
    /// and outside anyone's threat model.
    Mfg = 0x80,
    /// `0xA1` — extended write, "transparent mode": a raw APDU pipe to a smart
    /// card in the reader's field. Answered with `XRD`.
    Xwr = 0xA1,
    /// `0xA2` — abort the current multi-part operation.
    ///
    /// **Contested value.** libosdp and jeff both say `0xA2`; the older
    /// `verkada/go-osdp` says `0x7A`. Two independent sources to one, and
    /// go-osdp lacks the entire `0xA1..0xA7` extended block, so `0xA2` is very
    /// likely right and `0x7A` a withdrawn assignment. Flagged in the README.
    Abort = 0xA2,
    /// `0xA3` — request PIV data from a smart card. Answered with `PIVDATAR`.
    PivData = 0xA3,
    /// `0xA4` — general authenticate (smart card). Answered with `GENAUTHR`.
    GenAuth = 0xA4,
    /// `0xA5` — challenge/response authenticate (smart card). Answered with
    /// `CRAUTHR`.
    CrAuth = 0xA5,
    /// `0xA7` — keep the smart-card session alive.
    KeepActive = 0xA7,
}

impl Command {
    /// Every command code this crate knows, in numeric order.
    pub const ALL: &'static [Command] = &[
        Command::Poll,
        Command::Id,
        Command::Cap,
        Command::Diag,
        Command::Lstat,
        Command::Istat,
        Command::Ostat,
        Command::Rstat,
        Command::Out,
        Command::Led,
        Command::Buz,
        Command::Text,
        Command::Rmode,
        Command::Tdset,
        Command::Comset,
        Command::Bioread,
        Command::Biomatch,
        Command::Keyset,
        Command::Chlng,
        Command::Scrypt,
        Command::AcuRxSize,
        Command::FileTransfer,
        Command::Mfg,
        Command::Xwr,
        Command::Abort,
        Command::PivData,
        Command::GenAuth,
        Command::CrAuth,
        Command::KeepActive,
    ];

    /// Parse a raw command byte. `None` if it is not a code this crate knows.
    pub fn from_u8(value: u8) -> Option<Command> {
        Some(match value {
            0x60 => Command::Poll,
            0x61 => Command::Id,
            0x62 => Command::Cap,
            0x63 => Command::Diag,
            0x64 => Command::Lstat,
            0x65 => Command::Istat,
            0x66 => Command::Ostat,
            0x67 => Command::Rstat,
            0x68 => Command::Out,
            0x69 => Command::Led,
            0x6A => Command::Buz,
            0x6B => Command::Text,
            0x6C => Command::Rmode,
            0x6D => Command::Tdset,
            0x6E => Command::Comset,
            0x73 => Command::Bioread,
            0x74 => Command::Biomatch,
            0x75 => Command::Keyset,
            0x76 => Command::Chlng,
            0x77 => Command::Scrypt,
            0x7B => Command::AcuRxSize,
            0x7C => Command::FileTransfer,
            0x80 => Command::Mfg,
            0xA1 => Command::Xwr,
            0xA2 => Command::Abort,
            0xA3 => Command::PivData,
            0xA4 => Command::GenAuth,
            0xA5 => Command::CrAuth,
            0xA7 => Command::KeepActive,
            _ => return None,
        })
    }

    /// The raw byte.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// The conventional short name, as it appears in the specification and in
    /// most analysers: `"osdp_POLL"` is normally written just `POLL`.
    pub fn name(self) -> &'static str {
        match self {
            Command::Poll => "POLL",
            Command::Id => "ID",
            Command::Cap => "CAP",
            Command::Diag => "DIAG",
            Command::Lstat => "LSTAT",
            Command::Istat => "ISTAT",
            Command::Ostat => "OSTAT",
            Command::Rstat => "RSTAT",
            Command::Out => "OUT",
            Command::Led => "LED",
            Command::Buz => "BUZ",
            Command::Text => "TEXT",
            Command::Rmode => "RMODE",
            Command::Tdset => "TDSET",
            Command::Comset => "COMSET",
            Command::Bioread => "BIOREAD",
            Command::Biomatch => "BIOMATCH",
            Command::Keyset => "KEYSET",
            Command::Chlng => "CHLNG",
            Command::Scrypt => "SCRYPT",
            Command::AcuRxSize => "ACURXSIZE",
            Command::FileTransfer => "FILETRANSFER",
            Command::Mfg => "MFG",
            Command::Xwr => "XWR",
            Command::Abort => "ABORT",
            Command::PivData => "PIVDATA",
            Command::GenAuth => "GENAUTH",
            Command::CrAuth => "CRAUTH",
            Command::KeepActive => "KEEPACTIVE",
        }
    }

    /// True for commands that are part of the secure channel handshake and are
    /// therefore expected to appear *outside* an established secure channel.
    pub fn is_secure_channel_handshake(self) -> bool {
        matches!(self, Command::Chlng | Command::Scrypt)
    }

    /// True for commands whose exposure in the clear is a finding in its own
    /// right.
    ///
    /// `KEYSET` leaks the site key. `COMSET` lets an attacker move a PD to a
    /// different address or baud rate. `OUT` opens the door. A detector can use
    /// this to flag "this frame should never have been unencrypted".
    pub fn is_sensitive(self) -> bool {
        matches!(self, Command::Keyset | Command::Comset | Command::Out)
    }
}

impl core::fmt::Display for Command {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Replies: frames sent by a PD back to the ACU.
///
/// A PD may only speak when polled, so every reply is an answer to some
/// command. `ACK` is the "nothing to report" answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Reply {
    /// `0x40` — command accepted, nothing further to say.
    Ack = 0x40,
    /// `0x41` — command rejected. Payload is a [`crate::payload::NakError`]
    /// code and optional extra data.
    Nak = 0x41,
    /// `0x45` — identity report. See [`crate::payload::PdId`].
    PdId = 0x45,
    /// `0x46` — capability report. See [`crate::payload::PdCapabilities`].
    ///
    /// The downgrade target. An attacker who can edit this frame in flight
    /// deletes the `CommunicationSecurity` entry (function code `0x09`) and the
    /// controller concludes the reader cannot do AES-128.
    PdCap = 0x46,
    /// `0x48` — local status: tamper and power.
    LStatR = 0x48,
    /// `0x49` — input status, one byte per input.
    IStatR = 0x49,
    /// `0x4A` — output status, one byte per output.
    OStatR = 0x4A,
    /// `0x4B` — reader tamper status, one byte per reader.
    RStatR = 0x4B,
    /// `0x50` — a card was read. See [`crate::payload::RawCardRead`].
    ///
    /// On an unencrypted bus this frame contains the credential's raw bits,
    /// which is all a cloner needs. On an SCS_15/SCS_16 bus it also contains
    /// the raw bits, because that mode authenticates without encrypting.
    Raw = 0x50,
    /// `0x51` — formatted card data. Deprecated in favour of `RAW`.
    Fmt = 0x51,
    /// `0x53` — keypad digits. See [`crate::payload::KeypadData`].
    ///
    /// Note the value collides with [`crate::frame::SOM`]. Nothing is wrong;
    /// it is just a good reminder that a naive "scan for 0x53" resynchroniser
    /// will find false starts inside real frames.
    Keypad = 0x53,
    /// `0x54` — communication configuration report, answering `COMSET`.
    Com = 0x54,
    /// `0x57` — biometric read result.
    BioReadR = 0x57,
    /// `0x58` — biometric match result.
    BioMatchR = 0x58,
    /// `0x76` — client cryptogram: cUID ‖ RND.B ‖ client cryptogram, 32 bytes.
    /// Numerically equal to [`Command::Chlng`]; direction disambiguates.
    Ccrypt = 0x76,
    /// `0x78` — the initial R-MAC, 16 bytes, seeding the MAC chain.
    RmacI = 0x78,
    /// `0x79` — "ask me again shortly". The PD is busy and has not processed
    /// the command.
    Busy = 0x79,
    /// `0x7A` — file transfer status.
    FtStat = 0x7A,
    /// `0x80` — PIV data response.
    PivDataR = 0x80,
    /// `0x81` — general authenticate response.
    GenAuthR = 0x81,
    /// `0x82` — challenge/response authenticate response.
    CrAuthR = 0x82,
    /// `0x83` — manufacturer-specific status response.
    MfgStatR = 0x83,
    /// `0x84` — manufacturer-specific error response.
    MfgErrR = 0x84,
    /// `0x90` — manufacturer-specific reply to `CMD_MFG`.
    MfgRep = 0x90,
    /// `0xB1` — extended read, the transparent-mode response to `XWR`.
    Xrd = 0xB1,
}

impl Reply {
    /// Every reply code this crate knows, in numeric order.
    pub const ALL: &'static [Reply] = &[
        Reply::Ack,
        Reply::Nak,
        Reply::PdId,
        Reply::PdCap,
        Reply::LStatR,
        Reply::IStatR,
        Reply::OStatR,
        Reply::RStatR,
        Reply::Raw,
        Reply::Fmt,
        Reply::Keypad,
        Reply::Com,
        Reply::BioReadR,
        Reply::BioMatchR,
        Reply::Ccrypt,
        Reply::RmacI,
        Reply::Busy,
        Reply::FtStat,
        Reply::PivDataR,
        Reply::GenAuthR,
        Reply::CrAuthR,
        Reply::MfgStatR,
        Reply::MfgErrR,
        Reply::MfgRep,
        Reply::Xrd,
    ];

    /// Parse a raw reply byte. `None` if it is not a code this crate knows.
    pub fn from_u8(value: u8) -> Option<Reply> {
        Some(match value {
            0x40 => Reply::Ack,
            0x41 => Reply::Nak,
            0x45 => Reply::PdId,
            0x46 => Reply::PdCap,
            0x48 => Reply::LStatR,
            0x49 => Reply::IStatR,
            0x4A => Reply::OStatR,
            0x4B => Reply::RStatR,
            0x50 => Reply::Raw,
            0x51 => Reply::Fmt,
            0x53 => Reply::Keypad,
            0x54 => Reply::Com,
            0x57 => Reply::BioReadR,
            0x58 => Reply::BioMatchR,
            0x76 => Reply::Ccrypt,
            0x78 => Reply::RmacI,
            0x79 => Reply::Busy,
            0x7A => Reply::FtStat,
            0x80 => Reply::PivDataR,
            0x81 => Reply::GenAuthR,
            0x82 => Reply::CrAuthR,
            0x83 => Reply::MfgStatR,
            0x84 => Reply::MfgErrR,
            0x90 => Reply::MfgRep,
            0xB1 => Reply::Xrd,
            _ => return None,
        })
    }

    /// The raw byte.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// The conventional short name.
    pub fn name(self) -> &'static str {
        match self {
            Reply::Ack => "ACK",
            Reply::Nak => "NAK",
            Reply::PdId => "PDID",
            Reply::PdCap => "PDCAP",
            Reply::LStatR => "LSTATR",
            Reply::IStatR => "ISTATR",
            Reply::OStatR => "OSTATR",
            Reply::RStatR => "RSTATR",
            Reply::Raw => "RAW",
            Reply::Fmt => "FMT",
            Reply::Keypad => "KEYPAD",
            Reply::Com => "COM",
            Reply::BioReadR => "BIOREADR",
            Reply::BioMatchR => "BIOMATCHR",
            Reply::Ccrypt => "CCRYPT",
            Reply::RmacI => "RMAC_I",
            Reply::Busy => "BUSY",
            Reply::FtStat => "FTSTAT",
            Reply::PivDataR => "PIVDATAR",
            Reply::GenAuthR => "GENAUTHR",
            Reply::CrAuthR => "CRAUTHR",
            Reply::MfgStatR => "MFGSTATR",
            Reply::MfgErrR => "MFGERRR",
            Reply::MfgRep => "MFGREP",
            Reply::Xrd => "XRD",
        }
    }

    /// True for replies that are part of the secure channel handshake.
    pub fn is_secure_channel_handshake(self) -> bool {
        matches!(self, Reply::Ccrypt | Reply::RmacI)
    }

    /// True if this reply reports a credential being presented.
    ///
    /// The traffic-analysis primitive: seeing one of these on an encrypted bus,
    /// without any key, tells you a person is at that door right now.
    pub fn is_credential_event(self) -> bool {
        matches!(
            self,
            Reply::Raw | Reply::Fmt | Reply::Keypad | Reply::BioReadR
        )
    }
}

impl core::fmt::Display for Reply {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    fn every_command_round_trips_through_its_byte() {
        for &c in Command::ALL {
            assert_eq!(Command::from_u8(c.to_u8()), Some(c), "{c}");
        }
    }

    #[test]
    fn every_reply_round_trips_through_its_byte() {
        for &r in Reply::ALL {
            assert_eq!(Reply::from_u8(r.to_u8()), Some(r), "{r}");
        }
    }

    #[test]
    fn command_bytes_are_unique() {
        let set: BTreeSet<u8> = Command::ALL.iter().map(|c| c.to_u8()).collect();
        assert_eq!(set.len(), Command::ALL.len());
    }

    #[test]
    fn reply_bytes_are_unique() {
        let set: BTreeSet<u8> = Reply::ALL.iter().map(|r| r.to_u8()).collect();
        assert_eq!(set.len(), Reply::ALL.len());
    }

    #[test]
    fn all_lists_are_sorted_by_value() {
        let mut prev = 0u8;
        for &c in Command::ALL {
            assert!(c.to_u8() > prev || prev == 0, "{c} out of order");
            prev = c.to_u8();
        }
        let mut prev = 0u8;
        for &r in Reply::ALL {
            assert!(r.to_u8() > prev || prev == 0, "{r} out of order");
            prev = r.to_u8();
        }
    }

    #[test]
    fn from_u8_rejects_unassigned_bytes() {
        // A scattering of values that are not in either set.
        for b in [0x00u8, 0x01, 0x42, 0x5F, 0x72, 0x7E, 0xFF] {
            assert_eq!(Command::from_u8(b), None, "command 0x{b:02x}");
        }
        for b in [0x00u8, 0x42, 0x44, 0x4F, 0x5A, 0x77, 0xFF] {
            assert_eq!(Reply::from_u8(b), None, "reply 0x{b:02x}");
        }
    }

    /// The command and reply namespaces are separate. `0x76` means two
    /// different things depending on direction, and that is correct.
    #[test]
    fn chlng_and_ccrypt_share_a_byte() {
        assert_eq!(Command::Chlng.to_u8(), 0x76);
        assert_eq!(Reply::Ccrypt.to_u8(), 0x76);
    }

    /// `REPLY_KEYPAD` is 0x53, the same byte as SOM.
    #[test]
    fn keypad_reply_collides_with_som() {
        assert_eq!(Reply::Keypad.to_u8(), crate::frame::SOM);
    }

    #[test]
    fn spot_check_verified_values() {
        assert_eq!(Command::Poll.to_u8(), 0x60);
        assert_eq!(Command::Keyset.to_u8(), 0x75);
        assert_eq!(Command::Scrypt.to_u8(), 0x77);
        assert_eq!(Command::AcuRxSize.to_u8(), 0x7B);
        assert_eq!(Command::Mfg.to_u8(), 0x80);
        assert_eq!(Command::Xwr.to_u8(), 0xA1);
        assert_eq!(Command::Abort.to_u8(), 0xA2);
        assert_eq!(Command::KeepActive.to_u8(), 0xA7);
        assert_eq!(Reply::Ack.to_u8(), 0x40);
        assert_eq!(Reply::Nak.to_u8(), 0x41);
        assert_eq!(Reply::PdCap.to_u8(), 0x46);
        assert_eq!(Reply::Raw.to_u8(), 0x50);
        assert_eq!(Reply::RmacI.to_u8(), 0x78);
        assert_eq!(Reply::Busy.to_u8(), 0x79);
        assert_eq!(Reply::MfgRep.to_u8(), 0x90);
        assert_eq!(Reply::Xrd.to_u8(), 0xB1);
    }

    #[test]
    fn names_are_non_empty_and_distinct() {
        let set: BTreeSet<&str> = Command::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(set.len(), Command::ALL.len());
        let set: BTreeSet<&str> = Reply::ALL.iter().map(|r| r.name()).collect();
        assert_eq!(set.len(), Reply::ALL.len());
    }

    #[test]
    fn classifiers_pick_the_right_members() {
        assert!(Command::Chlng.is_secure_channel_handshake());
        assert!(Command::Scrypt.is_secure_channel_handshake());
        assert!(!Command::Poll.is_secure_channel_handshake());
        assert!(Command::Keyset.is_sensitive());
        assert!(!Command::Poll.is_sensitive());
        assert!(Reply::Raw.is_credential_event());
        assert!(Reply::Keypad.is_credential_event());
        assert!(!Reply::Ack.is_credential_event());
        assert!(Reply::Ccrypt.is_secure_channel_handshake());
    }
}
