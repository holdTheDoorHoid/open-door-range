//! **Generating a day of traffic, and the answer key that goes with it.**
//!
//! Curriculum Module 5 scores a learner's rule set against "a generated day of
//! traffic containing both attacks and benign events". This module generates
//! it, by **running the engine** — every frame in the capture was produced by
//! `odr-bus` driving real reader and controller state machines, not by a
//! fixture writing plausible-looking bytes. A drill that scored a rule set
//! against hand-written traffic would be scoring it against this module's
//! imagination.
//!
//! # The two outputs are deliberately separate
//!
//! [`Day::capture`] is a string of newline-delimited JSON: exactly what a probe
//! in a riser would have recorded, and the only thing a detector is ever shown.
//! [`Day::key`] is the ground truth, and it comes from the **scenario script**
//! — what each episode was built to do — rather than from the engine's event
//! log. That matters: an answer key derived from what the detectors happened to
//! find would make any rule set score perfectly by construction.
//!
//! # Why a day is a sequence of episodes
//!
//! A world is assembled up front, so a single `World` cannot gain a peripheral
//! halfway through the afternoon or be put into install mode at four o'clock.
//! Each [`Episode`] is therefore its own world, and their captures are shifted
//! and concatenated with [`DayOptions::gap_us`] of silence between them. The
//! silence is not a fudge — it is a link going quiet while somebody works on
//! it, and every continuity rule in [`rules`](crate::rules) is written to reset
//! across one, precisely because a monitor that was not listening has no
//! standing to say what happened.
//!
//! # Addresses carry the story
//!
//! Each episode gets its own peripheral address, except where the story needs
//! history: the downgrade lands on address `0x01`, which earlier episodes have
//! already been seen claiming AES-128 and running Secure Channel. That is what
//! makes [`DowngradeDetector`](crate::rules::DowngradeDetector) able to call it
//! a downgrade rather than a reader, and it is the point of drill 5.2.
//!
//! # The benign half
//!
//! Six benign events are scattered through the day, five of them in episodes
//! that exist mainly to carry one: a legacy reader added to the bus, a reader
//! power-cycling and resyncing, a reader replaced with a different model at the
//! same address, an installer commissioning a door, and — twice, once on each
//! kind of link — a person badging twice. They are in the day because a scorer
//! with no benign traffic teaches a learner to alert on everything.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use odr_bus::capture::{export_from_tap, parse_ndjson, write_ndjson, CaptureOptions};
use odr_bus::{
    osdp_bench, wiegand_bench, AccessList, AcuConfig, BusDir, CaptureEvent, InjectingTap,
    InjectionPayload, InlineTap, LinkId, Micros, OsdpBenchSpec, PassiveTap, PdConfig, Presentation,
    Rs485Timing, ScRequirement, SourceId, TapId, World,
};
use odr_osdp::payload::PdId;
use odr_osdp::{Frame, PdCapabilities, Reply};
use odr_wiegand::{CardFormat, Credential};

use crate::error::{DetectError, Result};
use crate::finding::Signal;
use crate::score::{AnswerKey, BenignEvent, Expected, Verdict};

/// A site key that is not SCBK-D and is not in the published weak-key family.
///
/// Sixteen bytes with no repeated-byte, ascending or descending structure, so
/// `odr_osdp::weak_keys::classify` returns `None` for it — which is what makes
/// the weak-key findings in this day mean something when they do appear.
pub const SITE_KEY: [u8; 16] = [
    0x7C, 0x19, 0xA3, 0x40, 0xDE, 0x05, 0x91, 0x66, 0x2B, 0xF4, 0x88, 0x1D, 0x57, 0xC0, 0x3E, 0xA9,
];

/// One stretch of the generated day.
///
/// Each variant is a complete little story with a point, and the point is named
/// in [`Episode::describe`]. Additive: new episodes may appear, so match with a
/// `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Episode {
    /// A healthy bus: Secure Channel under a site key, three badge-ins.
    /// Benign, and the episode that gives address `0x01` its history.
    SecureBaseline,
    /// The reader at `0x01` power-cycles and the link resynchronises. Benign,
    /// and the case [`Signal::SequenceAnomaly`] and [`Signal::SecureChannelLost`]
    /// must not fire on.
    ReaderPowerCycle,
    /// A genuinely legacy reader is added at `0x02` beside the secure one at
    /// `0x01`. Benign, and the case drill 5.2 names explicitly.
    LegacyReaderAdded,
    /// An installer commissions a door at `0x03`: default key, `CMD_KEYSET`,
    /// re-handshake. Ambiguous by construction — drill 5.3.
    Commissioning,
    /// The reader at `0x04` is replaced with a different, legacy model.
    /// Benign, and the hardest false positive on the list.
    ReaderReplaced,
    /// An unsecured bus at `0x05`, with a person badging twice on it. A real
    /// weakness containing a benign event.
    CleartextBus,
    /// A bus at `0x06` running Secure Channel under SCBK-D.
    DefaultKey,
    /// A bus at `0x07` running the null ciphers: authenticated, not encrypted.
    NullCipher,
    /// **Attack.** An inline implant strips the capability reply at `0x01`, an
    /// address with history. Drill 3.6, seen from the other chair.
    Downgrade,
    /// **Attack.** A forged reply on an unsecured bus at `0x08`: two devices
    /// answering one address.
    ForgedReply,
    /// **Attack.** A card read captured and put back on an unsecured bus at
    /// `0x09`, byte for byte.
    BusReplay,
    /// A Wiegand door: three presentations and one replay, 300 ms behind the
    /// original. Weakness and attack together, on a link where almost nothing
    /// is detectable.
    WiegandDoor,
}

impl Episode {
    /// The default day, in order. The order matters: the downgrade needs the
    /// earlier episodes to have established what address `0x01` normally does.
    pub const DEFAULT_DAY: &'static [Episode] = &[
        Episode::SecureBaseline,
        Episode::ReaderPowerCycle,
        Episode::LegacyReaderAdded,
        Episode::Commissioning,
        Episode::ReaderReplaced,
        Episode::CleartextBus,
        Episode::DefaultKey,
        Episode::NullCipher,
        Episode::Downgrade,
        Episode::ForgedReply,
        Episode::BusReplay,
        Episode::WiegandDoor,
    ];

    /// A short name.
    pub fn name(self) -> &'static str {
        match self {
            Episode::SecureBaseline => "secure_baseline",
            Episode::ReaderPowerCycle => "reader_power_cycle",
            Episode::LegacyReaderAdded => "legacy_reader_added",
            Episode::Commissioning => "commissioning",
            Episode::ReaderReplaced => "reader_replaced",
            Episode::CleartextBus => "cleartext_bus",
            Episode::DefaultKey => "default_key",
            Episode::NullCipher => "null_cipher",
            Episode::Downgrade => "downgrade",
            Episode::ForgedReply => "forged_reply",
            Episode::BusReplay => "bus_replay",
            Episode::WiegandDoor => "wiegand_door",
        }
    }

    /// What it is and why it is in the day.
    pub fn describe(self) -> &'static str {
        match self {
            Episode::SecureBaseline => {
                "a healthy bus under a site key; establishes what address 0x01 normally claims"
            }
            Episode::ReaderPowerCycle => {
                "benign: the reader reboots and the link resynchronises, which looks like a \
                 sequence attack and like a lost secure channel"
            }
            Episode::LegacyReaderAdded => {
                "benign: a genuinely legacy reader joins the bus at a new address and cannot do \
                 crypto, which looks exactly like a downgrade to a naive rule"
            }
            Episode::Commissioning => {
                "ambiguous: an installer pushes a site key, which is byte-for-byte what an \
                 attacker in install mode would do"
            }
            Episode::ReaderReplaced => {
                "benign: a reader is swapped for a legacy model at the same address, dropping the \
                 AES claim without anybody attacking anything"
            }
            Episode::CleartextBus => {
                "a bus with no Secure Channel at all, containing a person badging twice"
            }
            Episode::DefaultKey => "Secure Channel keyed with the published default key",
            Episode::NullCipher => {
                "Secure Channel established with encryption off: SCS_15/16, authenticated and \
                 readable"
            }
            Episode::Downgrade => {
                "attack: an inline implant rewrites the capability reply so the controller talks \
                 in the clear to a reader that can do better"
            }
            Episode::ForgedReply => {
                "attack: an injector answers a poll that the real reader also answered"
            }
            Episode::BusReplay => "attack: a captured card read is put back on the bus verbatim",
            Episode::WiegandDoor => {
                "a two-wire door: one replayed credential among genuine ones, on a link with no \
                 authentication to check"
            }
        }
    }
}

/// How to build a day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DayOptions {
    /// Which episodes, in order.
    pub episodes: Vec<Episode>,
    /// How long the link is quiet between episodes.
    ///
    /// Comfortably longer than every continuity rule's reset threshold, because
    /// the episodes are separate worlds and pretending otherwise would have the
    /// detectors reasoning across a seam that does not exist on a real bus.
    pub gap_us: Micros,
}

impl Default for DayOptions {
    fn default() -> DayOptions {
        DayOptions {
            episodes: Episode::DEFAULT_DAY.to_vec(),
            gap_us: 60_000_000,
        }
    }
}

/// Where one episode sits in the finished day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpisodeSpan {
    /// Which episode.
    pub episode: Episode,
    /// When it starts in the day's timeline.
    pub start_us: Micros,
    /// How long it runs.
    pub duration_us: Micros,
    /// How many capture lines it contributed.
    pub events: usize,
}

/// **A generated day: one capture, one answer key, and the timeline that
/// relates them.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Day {
    capture: String,
    key: AnswerKey,
    timeline: Vec<EpisodeSpan>,
    seed: u64,
}

impl Day {
    /// The capture, in the format `DESIGN.md` §3 fixes. **This is the only
    /// thing a detector is shown.**
    pub fn capture(&self) -> &str {
        &self.capture
    }

    /// The ground truth. Hand this to [`AnswerKey::score`], never to a
    /// detector.
    pub fn key(&self) -> &AnswerKey {
        &self.key
    }

    /// Which episode ran when.
    pub fn timeline(&self) -> &[EpisodeSpan] {
        &self.timeline
    }

    /// The seed this day was generated from.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// A monitor over the capture — the same one a learner's rule set gets.
    pub fn monitor(&self) -> Result<crate::observe::Monitor> {
        crate::observe::Monitor::from_capture(&self.capture)
    }

    /// The timeline, one episode per line.
    pub fn explain(&self) -> String {
        let mut s = alloc::format!("day from seed {}\n", self.seed);
        for span in &self.timeline {
            s.push_str(&alloc::format!(
                "  {} at {} for {} ({} lines) — {}\n",
                span.episode.name(),
                crate::observe::fmt_us(span.start_us),
                crate::observe::fmt_us(span.duration_us),
                span.events,
                span.episode.describe()
            ));
        }
        s
    }
}

/// What one episode produced, before it is placed in the day.
struct Built {
    events: Vec<CaptureEvent>,
    expected: Vec<Expected>,
    benign: Vec<BenignEvent>,
    duration_us: Micros,
}

impl Built {
    fn new(events: Vec<CaptureEvent>, duration_us: Micros) -> Built {
        Built {
            events,
            expected: Vec::new(),
            benign: Vec::new(),
            duration_us,
        }
    }

    fn expect(self, signal: Signal, verdict: Verdict, label: &str) -> Built {
        self.expect_at(0, signal, verdict, label)
    }

    /// An expectation that only becomes true partway through the episode.
    ///
    /// The offset matters because it is the zero of the detection latency: a
    /// weakness that starts forty seconds in should not be scored as having
    /// been caught forty seconds late.
    fn expect_at(mut self, at_us: Micros, signal: Signal, verdict: Verdict, label: &str) -> Built {
        // A window running to the end of the episode is deliberate: the key
        // says "this is in here", not "this is at exactly this microsecond",
        // because the honest moment of detection depends on how much evidence
        // a rule waits for before it will commit.
        let window = self.duration_us.saturating_sub(at_us);
        self.expected.push(Expected::new(
            signal,
            at_us,
            window,
            verdict,
            String::from(label),
        ));
        self
    }

    fn benign_at(
        mut self,
        t_us: Micros,
        duration_us: Micros,
        label: &str,
        looks_like: Signal,
    ) -> Built {
        self.benign.push(BenignEvent::new(
            t_us,
            duration_us,
            String::from(label),
            Some(looks_like),
        ));
        self
    }
}

/// **Generate a day of mixed traffic and the answer key for it.**
///
/// Deterministic: the same seed and the same options produce a byte-identical
/// capture and an identical key, on every machine (`DESIGN.md` §3).
///
/// ```
/// use odr_detect::{generate_day, DayOptions, RuleSet};
///
/// let day = generate_day(0x0D00_5EED, &DayOptions::default()).unwrap();
/// let monitor = day.monitor().unwrap();
/// let report = RuleSet::standard().run(&monitor);
/// let score = day.key().score(&report);
///
/// // The rule set never saw the key, and the key never saw the capture.
/// assert!(score.true_positives().len() > 5);
/// assert!(score.is_quiet_on_benign());
/// ```
pub fn generate_day(seed: u64, options: &DayOptions) -> Result<Day> {
    if options.episodes.is_empty() {
        return Err(DetectError::Scenario(String::from(
            "a day needs at least one episode",
        )));
    }

    let mut events: Vec<CaptureEvent> = Vec::new();
    let mut key = AnswerKey::new();
    let mut timeline = Vec::new();
    let mut cursor: Micros = 0;

    for (i, episode) in options.episodes.iter().enumerate() {
        let built = build_episode(*episode, seed.wrapping_add(i as u64 * 0x9E37_79B9))?;
        let start = cursor;
        for mut e in built.events {
            e.t_us = e.t_us.saturating_add(start);
            events.push(e);
        }
        for mut e in built.expected {
            e.t_us = e.t_us.saturating_add(start);
            key.expect(e);
        }
        for mut b in built.benign {
            b.t_us = b.t_us.saturating_add(start);
            key.note_benign(b);
        }
        timeline.push(EpisodeSpan {
            episode: *episode,
            start_us: start,
            duration_us: built.duration_us,
            events: events.len(),
        });
        cursor = start
            .saturating_add(built.duration_us)
            .saturating_add(options.gap_us);
    }

    // `events` is per-episode line counts turned into a running total above;
    // fix it up to be the count this episode actually contributed.
    let mut previous = 0usize;
    for span in timeline.iter_mut() {
        let total = span.events;
        span.events = total - previous;
        previous = total;
    }

    key.sort();
    Ok(Day {
        capture: write_ndjson(&events),
        key,
        timeline,
        seed,
    })
}

// ---------------------------------------------------------------------------
// Shared machinery
// ---------------------------------------------------------------------------

/// A card that is on the door's list.
fn card(fc: u64, cn: u64) -> Credential {
    Credential::new(CardFormat::H10301, fc, cn)
}

/// Present a credential to a reader.
fn present(
    world: &mut World,
    reader: odr_bus::ReaderId,
    at_us: Micros,
    source: u32,
    cred: &Credential,
) -> Result<()> {
    let p = Presentation::from_credential(SourceId(source), cred)
        .map_err(|e| DetectError::Scenario(alloc::format!("credential does not encode: {e}")))?;
    world.present(reader, at_us, p)?;
    Ok(())
}

/// What one probe point recorded.
fn probe(world: &World, tap: TapId) -> Result<Vec<CaptureEvent>> {
    let text = export_from_tap(world.tap(tap)?, &CaptureOptions::default());
    Ok(parse_ndjson(&text)?)
}

/// An OSDP bench with a defender's monitor clipped to the controller end.
///
/// `inline` is added **first** so the monitor ends up on segment 0 — the
/// controller's side of the cut — which is where a defender's probe would be
/// and which is the only place from which an inline implant's rewrite is
/// visible at all.
struct Scene {
    world: World,
    link: LinkId,
    monitor: TapId,
    pds: Vec<odr_bus::ReaderId>,
}

fn osdp_scene(
    seed: u64,
    acu: AcuConfig,
    pds: Vec<PdConfig>,
    access: AccessList,
    inline: Option<InlineTap>,
) -> Result<Scene> {
    let bench = osdp_bench(
        seed,
        OsdpBenchSpec {
            acu,
            pds,
            timing: Rs485Timing::default(),
            access,
            start_polling_at_us: 0,
        },
    )?;
    let mut world = bench.world;
    if let Some(tap) = inline {
        world.add_tap(bench.link, Box::new(tap))?;
    }
    let monitor = world.add_tap(bench.link, Box::new(PassiveTap::new("defender's monitor")))?;
    Ok(Scene {
        world,
        link: bench.link,
        monitor,
        pds: bench.pds,
    })
}

/// A peripheral with AES-128 and a site key: the ordinary, healthy reader.
fn secure_pd(address: u8) -> PdConfig {
    PdConfig::at(address).with_site_key(SITE_KEY, ScRequirement::Required)
}

/// A controller that requires Secure Channel and believes capability replies,
/// which is the deployed default and the vulnerability (see `odr-bus`).
fn secure_acu(addresses: &[u8]) -> AcuConfig {
    AcuConfig::polling(addresses.iter().copied()).with_site_key(SITE_KEY, ScRequirement::Required)
}

// ---------------------------------------------------------------------------
// Episodes
// ---------------------------------------------------------------------------

fn build_episode(episode: Episode, seed: u64) -> Result<Built> {
    match episode {
        Episode::SecureBaseline => secure_baseline(seed),
        Episode::ReaderPowerCycle => reader_power_cycle(seed),
        Episode::LegacyReaderAdded => legacy_reader_added(seed),
        Episode::Commissioning => commissioning(seed),
        Episode::ReaderReplaced => reader_replaced(seed),
        Episode::CleartextBus => cleartext_bus(seed),
        Episode::DefaultKey => default_key(seed),
        Episode::NullCipher => null_cipher(seed),
        Episode::Downgrade => downgrade(seed),
        Episode::ForgedReply => forged_reply(seed),
        Episode::BusReplay => bus_replay(seed),
        Episode::WiegandDoor => wiegand_door(seed),
    }
}

/// A healthy secured bus with three badge-ins.
fn secure_baseline(seed: u64) -> Result<Built> {
    let cards = [card(42, 1001), card(42, 1002), card(42, 1003)];
    let mut access = AccessList::new();
    for c in &cards {
        access = access
            .with_credential(c)
            .map_err(|e| DetectError::Scenario(alloc::format!("access list: {e}")))?;
    }
    let mut scene = osdp_scene(
        seed,
        secure_acu(&[0x01]),
        alloc::vec![secure_pd(0x01)],
        access,
        None,
    )?;
    let pd = scene.pds[0];
    scene.world.run_until(2_000_000)?;
    for (i, c) in cards.iter().enumerate() {
        present(
            &mut scene.world,
            pd,
            3_000_000 + i as u64 * 3_000_000,
            i as u32,
            c,
        )?;
    }
    let duration = 14_000_000;
    scene.world.run_until(duration)?;

    Ok(Built::new(probe(&scene.world, scene.monitor)?, duration).expect(
        Signal::TrafficPatternExposed,
        Verdict::Weakness,
        "the badge-in schedule is readable from the traffic although the payloads are encrypted",
    ))
}

/// The reader reboots and the link comes back.
fn reader_power_cycle(seed: u64) -> Result<Built> {
    let c = card(42, 1001);
    let access = AccessList::new()
        .with_credential(&c)
        .map_err(|e| DetectError::Scenario(alloc::format!("access list: {e}")))?;
    let mut scene = osdp_scene(
        seed,
        secure_acu(&[0x01]),
        alloc::vec![secure_pd(0x01)],
        access,
        None,
    )?;
    let pd = scene.pds[0];
    scene.world.run_until(5_000_000)?;
    // The reader loses power: sequence, channel and last reply all go.
    scene.world.reader_mut(pd)?.reset_protocol();
    let duration = 20_000_000;
    scene.world.run_until(duration)?;

    Ok(Built::new(probe(&scene.world, scene.monitor)?, duration).benign_at(
        5_000_000,
        10_000_000,
        "the reader at 0x01 power-cycled: its sequence numbering restarts and its secure channel \
         has to be rebuilt",
        Signal::SequenceAnomaly,
    ))
}

/// A genuinely legacy reader joins the bus.
fn legacy_reader_added(seed: u64) -> Result<Built> {
    let mut legacy = PdConfig::at(0x02);
    legacy.capabilities = odr_bus::default_capabilities(false, false);
    legacy.sc = ScRequirement::Disabled;
    legacy.pd_id = PdId {
        vendor_code: [0x00, 0x4F, 0x44],
        model: 7,
        version: 1,
        serial_number: [0x00, 0x00, 0x02, 0x11],
        firmware_major: 1,
        firmware_minor: 0,
        firmware_build: 0,
    };
    let scene = osdp_scene(
        seed,
        secure_acu(&[0x01, 0x02]),
        alloc::vec![secure_pd(0x01), legacy],
        AccessList::new(),
        None,
    )?;
    let mut scene = scene;
    let duration = 20_000_000;
    scene.world.run_until(duration)?;

    Ok(Built::new(probe(&scene.world, scene.monitor)?, duration)
        .expect(
            Signal::CleartextBus,
            Verdict::Weakness,
            "the legacy reader at 0x02 is talked to in the clear, on a bus that is otherwise \
             secured",
        )
        .benign_at(
            0,
            duration,
            "a genuinely legacy reader was added at 0x02; it has never claimed AES-128, so it has \
             not been downgraded — it is just old",
            Signal::CapabilityDowngrade,
        ))
}

/// An installer commissions a door.
fn commissioning(seed: u64) -> Result<Built> {
    let acu = AcuConfig::polling([0x03])
        .with_site_key(SITE_KEY, ScRequirement::IfAvailable)
        .in_install_mode(true);
    // An uncommissioned reader, still on the published default key.
    let pd = PdConfig::at(0x03).with_default_key(ScRequirement::IfAvailable);
    let mut scene = osdp_scene(seed, acu, alloc::vec![pd], AccessList::new(), None)?;
    let duration = 15_000_000;
    scene.world.run_until(duration)?;

    Ok(Built::new(probe(&scene.world, scene.monitor)?, duration)
        .expect(
            Signal::KeysetObserved,
            Verdict::Ambiguous,
            "a CMD_KEYSET pushed the site key; the wire cannot say whether it was authorised",
        )
        .expect(
            Signal::DefaultKeyInUse,
            Verdict::Weakness,
            "the reader arrived on SCBK-D, so the channel that carried the site key was keyed \
             with a published key",
        )
        .benign_at(
            0,
            duration,
            "an installer commissioning a door: exactly the traffic an attacker in install mode \
             would produce",
            Signal::KeysetObserved,
        ))
}

/// The reader at an address is replaced by a different, legacy model.
fn reader_replaced(seed: u64) -> Result<Built> {
    // Before: a capable reader, running Secure Channel.
    let mut before = osdp_scene(
        seed,
        secure_acu(&[0x04]),
        alloc::vec![secure_pd(0x04)],
        AccessList::new(),
        None,
    )?;
    let before_end = 10_000_000;
    before.world.run_until(before_end)?;

    // The electrician's visit: the bus is quiet while the reader is swapped.
    let quiet = 30_000_000;

    // After: a different device at the same address, with no crypto at all.
    let mut legacy = PdConfig::at(0x04);
    legacy.capabilities = odr_bus::default_capabilities(false, false);
    legacy.sc = ScRequirement::Disabled;
    legacy.pd_id = PdId {
        vendor_code: [0x00, 0x11, 0x22],
        model: 3,
        version: 2,
        serial_number: [0x00, 0x00, 0x99, 0x44],
        firmware_major: 2,
        firmware_minor: 1,
        firmware_build: 0,
    };
    let mut after = osdp_scene(
        seed.wrapping_add(1),
        secure_acu(&[0x04]),
        alloc::vec![legacy],
        AccessList::new(),
        None,
    )?;
    let after_end = 20_000_000;
    after.world.run_until(after_end)?;

    let mut events = probe(&before.world, before.monitor)?;
    let shift = before_end + quiet;
    for mut e in probe(&after.world, after.monitor)? {
        e.t_us = e.t_us.saturating_add(shift);
        events.push(e);
    }
    let duration = shift + after_end;

    Ok(Built::new(events, duration)
        .expect(
            Signal::DeviceIdentityChanged,
            Verdict::Ambiguous,
            "REPLY_PDID at 0x04 reports a different device; the wire cannot say whether the swap \
             was authorised",
        )
        .expect_at(
            shift,
            Signal::CleartextBus,
            Verdict::Weakness,
            "the replacement reader cannot do crypto, so the door at 0x04 is now in the clear",
        )
        .benign_at(
            shift,
            after_end,
            "a reader was replaced with a legacy model at the same address: the AES-128 claim \
             disappears without anybody attacking anything",
            Signal::CapabilityDowngrade,
        ))
}

/// An unsecured bus, with somebody badging twice on it.
fn cleartext_bus(seed: u64) -> Result<Built> {
    let a = card(42, 2001);
    let b = card(42, 2002);
    let access = AccessList::new()
        .with_credential(&a)
        .and_then(|l| l.with_credential(&b))
        .map_err(|e| DetectError::Scenario(alloc::format!("access list: {e}")))?;
    let mut scene = osdp_scene(
        seed,
        AcuConfig::polling([0x05]),
        alloc::vec![PdConfig::at(0x05)],
        access,
        None,
    )?;
    let pd = scene.pds[0];
    present(&mut scene.world, pd, 3_000_000, 0, &a)?;
    // The door did not open the way they expected, so they badge again.
    present(&mut scene.world, pd, 7_000_000, 0, &a)?;
    present(&mut scene.world, pd, 12_000_000, 1, &b)?;
    let duration = 18_000_000;
    scene.world.run_until(duration)?;

    Ok(Built::new(probe(&scene.world, scene.monitor)?, duration)
        .expect(
            Signal::CleartextBus,
            Verdict::Weakness,
            "no Secure Channel at all on the bus at 0x05",
        )
        .expect(
            Signal::SensitiveCommandInClear,
            Verdict::Weakness,
            "the CMD_OUT that opens the door crosses the bus unprotected and can simply be \
             copied",
        )
        .benign_at(
            7_000_000,
            2_000_000,
            "the same person badged twice, four seconds apart, because the door did not open the \
             first time",
            Signal::ReplayedCredential,
        ))
}

/// Secure Channel under the published default key.
fn default_key(seed: u64) -> Result<Built> {
    let acu = AcuConfig::polling([0x06]).with_default_key(ScRequirement::Required);
    let pd = PdConfig::at(0x06).with_default_key(ScRequirement::Required);
    let mut scene = osdp_scene(seed, acu, alloc::vec![pd], AccessList::new(), None)?;
    let duration = 12_000_000;
    scene.world.run_until(duration)?;

    Ok(
        Built::new(probe(&scene.world, scene.monitor)?, duration).expect(
            Signal::DefaultKeyInUse,
            Verdict::Weakness,
            "the handshake at 0x06 announces key type 0x00, which is SCBK-D",
        ),
    )
}

/// Secure Channel with encryption turned off: the null ciphers.
fn null_cipher(seed: u64) -> Result<Built> {
    let c = card(42, 3001);
    let access = AccessList::new()
        .with_credential(&c)
        .map_err(|e| DetectError::Scenario(alloc::format!("access list: {e}")))?;
    let mut acu = secure_acu(&[0x07]);
    acu.encrypt_payloads = false;
    let mut scene = osdp_scene(seed, acu, alloc::vec![secure_pd(0x07)], access, None)?;
    let pd = scene.pds[0];
    scene.world.run_until(2_000_000)?;
    present(&mut scene.world, pd, 4_000_000, 0, &c)?;
    let duration = 12_000_000;
    scene.world.run_until(duration)?;

    Ok(Built::new(probe(&scene.world, scene.monitor)?, duration).expect(
        Signal::NullCipher,
        Verdict::Weakness,
        "SCS_15 frames with payloads: the link reports secure channel established and does not \
         encrypt",
    ))
}

/// The inline implant that strips the capability reply.
fn downgrade(seed: u64) -> Result<Built> {
    let c = card(42, 4001);
    let access = AccessList::new()
        .with_credential(&c)
        .map_err(|e| DetectError::Scenario(alloc::format!("access list: {e}")))?;
    let implant = InlineTap::rewrite_frames("downgrade implant", |frame: &mut Frame| {
        if frame.reply_code() != Some(Reply::PdCap) {
            return false;
        }
        match PdCapabilities::decode(&frame.payload) {
            Ok(mut caps) => {
                let changed = caps.strip_security_capability();
                frame.payload = caps.encode();
                changed
            }
            Err(_) => false,
        }
    });
    let mut scene = osdp_scene(
        seed,
        secure_acu(&[0x01]),
        alloc::vec![secure_pd(0x01)],
        access,
        Some(implant),
    )?;
    let pd = scene.pds[0];
    scene.world.run_until(3_000_000)?;
    present(&mut scene.world, pd, 5_000_000, 0, &c)?;
    let duration = 20_000_000;
    scene.world.run_until(duration)?;

    Ok(Built::new(probe(&scene.world, scene.monitor)?, duration)
        .expect(
            Signal::CapabilityDowngrade,
            Verdict::Attack,
            "the reader at 0x01 stopped claiming AES-128 it has claimed all day, with the same \
             reported identity",
        )
        .expect(
            Signal::SecureChannelLost,
            Verdict::Attack,
            "an address that has run Secure Channel is now carrying card reads in the clear",
        )
        .expect(
            Signal::CleartextBus,
            Verdict::Weakness,
            "the effect of the downgrade: the link at 0x01 is entirely unprotected",
        )
        .expect(
            Signal::SensitiveCommandInClear,
            Verdict::Weakness,
            "and the door command is now copyable",
        ))
}

/// An injector answers a poll that the real reader also answered.
fn forged_reply(seed: u64) -> Result<Built> {
    let ghost = card(42, 5099);
    let access = AccessList::new()
        .with_credential(&ghost)
        .map_err(|e| DetectError::Scenario(alloc::format!("access list: {e}")))?;
    let bits = ghost
        .encode()
        .map_err(|e| DetectError::Scenario(alloc::format!("credential does not encode: {e}")))?;
    let raw = odr_osdp::RawCardRead::from_bits(0, 0, bits.as_slice());
    let payload = raw.encode();

    let mut fired = false;
    let mut last_sequence = 0u8;
    let attacker = InjectingTap::reacting("injector", move |ctx, obs| {
        let frame = match obs.frame() {
            Some(f) => f,
            None => return,
        };
        if !frame.is_reply {
            last_sequence = frame.sequence & 0x03;
            return;
        }
        if fired || ctx.now() < 8_000_000 {
            return;
        }
        fired = true;
        // Answer the poll the real reader has just answered, with a card read
        // for a credential that was never presented to anything.
        let forged = Frame::reply(0x08, last_sequence, Reply::Raw, payload.clone());
        ctx.inject_at(
            ctx.now().saturating_add(20_000),
            InjectionPayload::BusFrame {
                dir: BusDir::PdToAcu,
                frame: Box::new(forged),
            },
        );
    });

    let mut scene = osdp_scene(
        seed,
        AcuConfig::polling([0x08]),
        alloc::vec![PdConfig::at(0x08)],
        access,
        None,
    )?;
    scene.world.add_tap(scene.link, Box::new(attacker))?;
    let duration = 20_000_000;
    scene.world.run_until(duration)?;

    Ok(Built::new(probe(&scene.world, scene.monitor)?, duration)
        .expect(
            Signal::DuplicateAddress,
            Verdict::Attack,
            "one poll drew two different replies from 0x08: the real reader and something else",
        )
        .expect(
            Signal::CleartextBus,
            Verdict::Weakness,
            "the bus at 0x08 has no Secure Channel, which is what makes the forgery free",
        )
        .expect(
            Signal::SensitiveCommandInClear,
            Verdict::Attack,
            "the controller believed the forged card read and sent the door-open command; the \
             only CMD_OUT on this bus all episode is the one the injector caused",
        ))
}

/// A captured card read, put back on the bus byte for byte.
fn bus_replay(seed: u64) -> Result<Built> {
    let c = card(42, 6001);
    let access = AccessList::new()
        .with_credential(&c)
        .map_err(|e| DetectError::Scenario(alloc::format!("access list: {e}")))?;

    let mut stored: Option<Vec<u8>> = None;
    let mut fired = false;
    let attacker = InjectingTap::reacting("replay box", move |ctx, obs| {
        let frame = match obs.frame() {
            Some(f) => f,
            None => return,
        };
        if frame.reply_code() == Some(Reply::Raw) && stored.is_none() {
            if let Some(bytes) = obs.bytes() {
                stored = Some(bytes.to_vec());
            }
            return;
        }
        if fired || ctx.now() < 10_000_000 {
            return;
        }
        if let Some(bytes) = stored.clone() {
            fired = true;
            ctx.inject_at(
                ctx.now().saturating_add(20_000),
                InjectionPayload::BusBytes {
                    dir: BusDir::PdToAcu,
                    bytes,
                },
            );
        }
    });

    let mut scene = osdp_scene(
        seed,
        AcuConfig::polling([0x09]),
        alloc::vec![PdConfig::at(0x09)],
        access,
        None,
    )?;
    scene.world.add_tap(scene.link, Box::new(attacker))?;
    let pd = scene.pds[0];
    present(&mut scene.world, pd, 3_000_000, 0, &c)?;
    let duration = 20_000_000;
    scene.world.run_until(duration)?;

    Ok(Built::new(probe(&scene.world, scene.monitor)?, duration)
        .expect(
            Signal::ReplayedFrame,
            Verdict::Attack,
            "a byte-identical card-read frame appeared again seven seconds later, with a \
             conversation in between",
        )
        .expect(
            Signal::ReplayedCredential,
            Verdict::Attack,
            "and the credential in it was one that had already been presented",
        )
        .expect(
            Signal::DuplicateAddress,
            Verdict::Attack,
            "the played-back frame is a second answer to a poll the real reader had already \
             answered, so two things are speaking as 0x09",
        )
        .expect(
            Signal::CleartextBus,
            Verdict::Weakness,
            "the bus at 0x09 has no Secure Channel, so the frame could simply be recorded",
        )
        .expect(
            Signal::SensitiveCommandInClear,
            Verdict::Weakness,
            "the door command on this bus is unprotected",
        ))
}

/// A Wiegand door with one replayed credential among genuine presentations.
fn wiegand_door(seed: u64) -> Result<Built> {
    let a = card(42, 7001);
    let b = card(42, 7002);
    let access = AccessList::new()
        .with_credential(&a)
        .and_then(|l| l.with_credential(&b))
        .map_err(|e| DetectError::Scenario(alloc::format!("access list: {e}")))?
        .assuming(CardFormat::H10301);
    let mut bench = wiegand_bench(seed, access)?;

    let mut stored: Option<odr_wiegand::BitVec> = None;
    let mut fired = false;
    let attacker = InjectingTap::reacting("wiegand replay box", move |ctx, obs| {
        if fired {
            return;
        }
        let bits = match obs.bits() {
            Some(b) => b.clone(),
            None => return,
        };
        match &stored {
            None => stored = Some(bits),
            Some(first) => {
                if *first == bits {
                    return;
                }
            }
        }
        if let Some(first) = stored.clone() {
            fired = true;
            ctx.inject_at(
                ctx.now().saturating_add(300_000),
                InjectionPayload::WireBits { bits: first },
            );
        }
    });
    let attacker_id = bench.world.add_tap(bench.link, Box::new(attacker))?;
    let monitor = bench
        .world
        .add_tap(bench.link, Box::new(PassiveTap::new("defender's monitor")))?;
    let _ = attacker_id;

    present(&mut bench.world, bench.reader, 2_000_000, 0, &a)?;
    present(&mut bench.world, bench.reader, 5_000_000, 1, &b)?;
    // The same person, badging again at a human pace.
    present(&mut bench.world, bench.reader, 9_000_000, 1, &b)?;
    let duration = 14_000_000;
    bench.world.run_until(duration)?;

    Ok(Built::new(probe(&bench.world, monitor)?, duration)
        .expect(
            Signal::UnauthenticatedWire,
            Verdict::Weakness,
            "a D0/D1 pair: nothing on it is authenticated, so anything driven onto it is believed",
        )
        .expect(
            Signal::ReplayedCredential,
            Verdict::Attack,
            "the first credential was put back on the wire 300 ms later, which is faster than a \
             person can present a badge twice",
        )
        .benign_at(
            9_000_000,
            2_000_000,
            "the same person badged twice, four seconds apart",
            Signal::ReplayedCredential,
        ))
}
