//! **Flag predicates: queries against engine state.**
//!
//! `DESIGN.md` §3, in full, because it governs every line of this file:
//!
//! > Drills do not describe attacks. They run them. A drill step is a scenario
//! > executed by the engine, and a flag is earned when the engine's own state
//! > satisfies a predicate — the attacker actually holds the SCBK, the
//! > controller actually ACKed a frame the attacker forged. There are no
//! > hardcoded answer strings to check against. If the engine is wrong, the
//! > drill fails rather than lying.
//!
//! Every predicate below reads one or more of three things:
//!
//! * the [`World`] and its [`EventLog`](odr_bus::EventLog), whose `cause` field
//!   makes it a graph rather than a list — "the PD ACKed a command originated
//!   by the attacker" is `log.originator(seq)` naming a tap;
//! * the attacker's [`Knowledge`], where every fact carries a
//!   [`Provenance`] saying how it was obtained;
//! * [`Facts`], which is what the run measured — a frame's layout, a card's
//!   provisioned keys, the cost of a sweep.
//!
//! A learner submission, where a drill has one, is compared against a value in
//! the third of those. See [`crate::submission`] for why that is not an answer
//! string.
//!
//! # Why the `outstanding` list matters
//!
//! A learner who has not earned a flag has to be told what the engine is still
//! waiting to see. "Not yet" is not feedback. Every predicate here produces a
//! sentence per unmet condition, in engine terms, with times and ids — and the
//! `evidence` list does the same for the conditions that *were* met, so a
//! learner can see how far they got rather than only that they stopped.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use odr_attack::{Knowledge, Provenance};
use odr_bus::{
    DecisionReason, Endpoint, LogRecord, Micros, Origin, RecordKind, ScEvent, SourceId, World,
};
use odr_osdp::codes::Reply;
use odr_wiegand::{BitVec, CardFormat};

use crate::drill::Drill;
use crate::facts::Facts;
use crate::ids::{Completion, DrillId};
use crate::submission::Submission;

/// How close a claimed badge-in time has to be to the engine's own record.
///
/// One second. The gap between a card touching the reader and the reply
/// crossing the bus is the read time plus up to one polling interval, and the
/// polling interval is the single most visible thing on an OSDP link — so an
/// attacker can measure this rather than being given it. It is a constant here
/// because drill 4.1 marks a list of times, and a marking scheme has to be
/// stated.
pub const BADGE_TIME_TOLERANCE_US: Micros = 1_000_000;

/// How long before a grant a credential must have been absent for the grant to
/// count as having nothing behind it. Drills 1.3 and 1.6.
pub const NO_CREDENTIAL_WINDOW_US: Micros = 5_000_000;

/// **A number a drill ends on**, where a flag would be the wrong shape.
///
/// Drill 1.5 and nothing else. The drill does not ask the learner to achieve
/// anything; it asks them to look at a figure and compare it with drill 1.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement {
    /// What was measured.
    pub label: String,
    /// The figure, in the engine's own words.
    pub value: String,
    /// What it is to be compared against.
    pub compare_with: String,
}

/// **The verdict on a drill.**
///
/// Shaped to match `site/ENGINE-API.md` §9's `Flag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flag {
    /// Which drill.
    pub drill: DrillId,
    /// How this drill finishes: a flag, a number, or being read.
    pub completion: Completion,
    /// The predicate in prose, shown verbatim.
    pub predicate: &'static str,
    /// Whether it is earned.
    pub earned: bool,
    /// What the engine observed, in its own words, with times and ids.
    pub evidence: Vec<String>,
    /// What is still missing. Shown only while unearned.
    pub outstanding: Vec<String>,
    /// The figure, for a drill that ends on one.
    pub measurement: Option<Measurement>,
}

impl Flag {
    /// Whether this drill runs a simulation at all.
    ///
    /// `site/ENGINE-API.md` renders `false` as "REFERENCE — no flag".
    pub fn is_simulated(&self) -> bool {
        self.completion.is_simulated()
    }
}

/// **Everything a predicate is allowed to look at.**
///
/// Deliberately narrow. There is no field here for "the drill's own opinion of
/// whether it worked", because a drill that could award itself a flag would be
/// exactly the hardcoded answer string `DESIGN.md` forbids.
#[derive(Debug, Clone, Copy)]
pub struct FlagContext<'a> {
    /// The world, once it has been run. `None` for the reference section and
    /// for the Module 5 drills, which score a capture rather than a bench.
    pub world: Option<&'a World>,
    /// What the attacker knows, and where each piece came from.
    pub knowledge: Option<&'a Knowledge>,
    /// What the run measured.
    pub facts: &'a Facts,
    /// The learner's claim, where the drill has one.
    pub submission: Option<&'a Submission>,
}

impl<'a> FlagContext<'a> {
    /// A context with nothing but facts. Used by the reference section and by
    /// the Module 5 drills.
    pub fn from_facts(facts: &'a Facts) -> FlagContext<'a> {
        FlagContext {
            world: None,
            knowledge: None,
            facts,
            submission: None,
        }
    }

    /// The same context with a submission attached.
    pub fn with_submission(mut self, submission: Option<&'a Submission>) -> FlagContext<'a> {
        self.submission = submission;
        self
    }
}

// ---------------------------------------------------------------------------
// The accumulator
// ---------------------------------------------------------------------------

/// Collects what held and what did not, so the two lists come out in the order
/// the predicate checked them.
struct Check {
    evidence: Vec<String>,
    outstanding: Vec<String>,
    measurement: Option<Measurement>,
}

impl Check {
    fn new() -> Check {
        Check {
            evidence: Vec::new(),
            outstanding: Vec::new(),
            measurement: None,
        }
    }

    /// Assert a condition, recording one sentence either way.
    fn require(&mut self, held: bool, yes: String, no: String) -> bool {
        if held {
            self.evidence.push(yes);
        } else {
            self.outstanding.push(no);
        }
        held
    }

    /// Record something that is worth showing but is not a condition.
    fn note(&mut self, s: String) {
        self.evidence.push(s);
    }

    /// Record a condition that cannot be evaluated yet.
    fn missing(&mut self, s: String) {
        self.outstanding.push(s);
    }

    fn finish(self, drill: &Drill) -> Flag {
        Flag {
            drill: drill.id,
            completion: drill.completion,
            predicate: drill.flag_text,
            earned: self.outstanding.is_empty(),
            evidence: self.evidence,
            outstanding: self.outstanding,
            measurement: self.measurement,
        }
    }
}

// ---------------------------------------------------------------------------
// Log queries the predicates share
// ---------------------------------------------------------------------------

fn secs(t: Micros) -> String {
    alloc::format!("{}.{:06} s", t / 1_000_000, t % 1_000_000)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for b in bytes {
        out.push_str(&alloc::format!("{b:02X}"));
    }
    out
}

/// Every credential presented to a reader: when, from which token, what bits.
fn presentations(world: &World) -> Vec<(Micros, SourceId, BitVec)> {
    world
        .log()
        .presentations()
        .filter_map(|r| match &r.kind {
            RecordKind::CredentialPresented { source, bits, .. } => {
                Some((r.t_us, *source, bits.clone()))
            }
            _ => None,
        })
        .collect()
}

/// Every grant the controller made.
fn grants(world: &World) -> Vec<&LogRecord> {
    world.log().grants().collect()
}

/// What each reader drove onto its own segment.
fn reader_output(world: &World) -> Vec<(Micros, BitVec)> {
    world
        .log()
        .records()
        .iter()
        .filter_map(|r| match &r.kind {
            RecordKind::WireTx {
                origin: Origin::Reader(_),
                bits,
                ..
            } => Some((r.t_us, bits.clone())),
            _ => None,
        })
        .collect()
}

/// What each controller received on its own segment.
fn controller_input(world: &World) -> Vec<(Micros, BitVec)> {
    world
        .log()
        .records()
        .iter()
        .filter_map(|r| match &r.kind {
            RecordKind::WireRx {
                receiver: Endpoint::Controller(_),
                bits,
                ..
            } => Some((r.t_us, bits.clone())),
            _ => None,
        })
        .collect()
}

/// Whether anything at all was driven onto a bus by a tap.
///
/// This is the world's statement rather than the actor's, which is what
/// curriculum 2.2's "zero frames injected" has to mean to be worth anything.
fn tap_transmissions(world: &World) -> usize {
    world
        .log()
        .records()
        .iter()
        .filter(|r| {
            matches!(
                r.kind,
                RecordKind::BusTx {
                    origin: Origin::Tap(_),
                    ..
                } | RecordKind::WireTx {
                    origin: Origin::Tap(_),
                    ..
                }
            )
        })
        .count()
}

/// Decode a bit pattern as H10301, best effort.
fn as_h10301(bits: &BitVec) -> Option<odr_wiegand::Decoded> {
    odr_wiegand::decode(CardFormat::H10301, bits).ok()
}

/// Does this knowledge base contain nothing it was handed?
fn honest(k: &Knowledge) -> bool {
    k.unearned().is_empty()
}

// ---------------------------------------------------------------------------
// The entry point
// ---------------------------------------------------------------------------

/// **Evaluate a drill's flag predicate against engine state.**
///
/// Never fails and never panics: a drill that has not been run yet comes back
/// unearned with an `outstanding` list saying so, which is the same shape as a
/// drill that was run and did not work.
pub fn evaluate(drill: &Drill, ctx: &FlagContext<'_>) -> Flag {
    let mut c = Check::new();
    let id = (drill.id.module, drill.id.index);
    match id {
        (0, 1) => drill_0_1(&mut c, ctx),
        (0, 2) => drill_0_2(&mut c, ctx),
        (0, 3) => drill_0_3(&mut c, ctx),
        (0, 4) => drill_0_4(&mut c, ctx),
        (0, 5) => drill_0_5(&mut c, ctx),
        (0, 6) => drill_0_6(&mut c, ctx),
        (1, 1) => drill_1_1(&mut c, ctx),
        (1, 2) => drill_1_2(&mut c, ctx),
        (1, 3) => drill_1_3(&mut c, ctx, "Wiegand"),
        (1, 4) => drill_1_4(&mut c, ctx),
        (1, 5) => drill_1_5(&mut c, ctx),
        (1, 6) => drill_1_6(&mut c, ctx),
        (2, 1) => drill_2_1(&mut c, ctx),
        (2, 2) => drill_2_2(&mut c, ctx),
        (2, 3) => drill_2_3(&mut c, ctx),
        (2, 4) => drill_2_4(&mut c, ctx),
        (3, 1) => drill_3_1(&mut c, ctx),
        (3, 2) => drill_3_2(&mut c, ctx),
        (3, 3) => drill_3_3(&mut c, ctx),
        (3, 4) => drill_3_4(&mut c, ctx),
        (3, 5) => drill_3_5(&mut c, ctx),
        (3, 6) => drill_3_6(&mut c, ctx),
        (4, 1) => drill_4_1(&mut c, ctx),
        (4, 2) => drill_4_2(&mut c, ctx),
        (4, 3) => drill_4_3(&mut c, ctx),
        (4, 4) => drill_4_4(&mut c, ctx),
        (5, 1) => drill_5_1(&mut c, ctx),
        (5, 2) => drill_5_2(&mut c, ctx),
        (5, 3) => drill_5_3(&mut c, ctx),
        _ => c.missing(String::from(
            "this drill has no predicate, which is a bug in the catalogue",
        )),
    }
    c.finish(drill)
}

// ---------------------------------------------------------------------------
// Module 0
// ---------------------------------------------------------------------------

/// **0.1** — the id you submit is the one the engine generated.
fn drill_0_1(c: &mut Check, ctx: &FlagContext<'_>) {
    let engine = match ctx.facts.tag_id40 {
        Some(v) => v,
        None => {
            c.missing(String::from(
                "no tag has been energised yet, so there is no carrier to read",
            ));
            return;
        }
    };
    if let Some(world) = ctx.world {
        let seen = presentations(world).len();
        c.require(
            seen > 0,
            alloc::format!("the tag answered the reader's field {seen} time(s)"),
            String::from("hold the tag in the reader's field: nothing has been energised yet"),
        );
    }
    match ctx.submission {
        Some(Submission::TagId(claim)) => {
            c.require(
                *claim == engine,
                alloc::format!("submitted id {claim:#012X} is the id the tag emitted"),
                alloc::format!(
                    "submitted id {claim:#012X} is not what the tag emitted; re-check the row and \
                     column parity before you submit again"
                ),
            );
        }
        _ => c.missing(String::from("submit the tag's 40-bit id")),
    }
}

/// **0.2** — a clone opened the door and the original was never there.
fn drill_0_2(c: &mut Check, ctx: &FlagContext<'_>) {
    let world = match ctx.world {
        Some(w) => w,
        None => {
            c.missing(String::from("run the bench"));
            return;
        }
    };
    let g = grants(world);
    c.require(
        !g.is_empty(),
        alloc::format!(
            "controller granted at {}",
            secs(g.first().map_or(0, |r| r.t_us))
        ),
        String::from("the controller has not granted: present the clone at the reader"),
    );
    let strikes = world.log().strikes().count();
    c.require(
        strikes > 0,
        alloc::format!("the strike fired {strikes} time(s)"),
        String::from("the strike has not fired"),
    );
    let presented = presentations(world);
    c.require(
        !presented.is_empty(),
        alloc::format!("{} credential(s) presented at the reader", presented.len()),
        String::from("nothing has been presented at the reader"),
    );
    let victim_seen = presented.iter().any(|(_, s, _)| *s == SourceId(0));
    c.require(
        !victim_seen,
        String::from("every token presented was the attacker's own; the victim's badge never touched the reader"),
        String::from("the victim's own token was presented, so the door did not open on a clone"),
    );
    if let Some(k) = ctx.knowledge {
        c.require(
            honest(k),
            String::from("nothing the cloner holds was handed to it"),
            String::from("the cloner is holding something it could not have obtained"),
        );
    }
}

/// **0.3** — the prediction matches the wire, bit for bit.
fn drill_0_3(c: &mut Check, ctx: &FlagContext<'_>) {
    let tx = match &ctx.facts.transmitted {
        Some(t) => t,
        None => {
            c.missing(String::from(
                "present the card so there is something on the wire to compare against",
            ));
            return;
        }
    };
    match ctx.submission {
        Some(Submission::Credential {
            facility_code,
            card_number,
            bits,
        }) => {
            c.require(
                Some(*facility_code) == tx.facility_code,
                alloc::format!("facility code {facility_code} is what crossed the wire"),
                alloc::format!(
                    "facility code {facility_code} is not what crossed the wire at {}",
                    secs(tx.t_us)
                ),
            );
            c.require(
                Some(*card_number) == tx.card_number,
                alloc::format!("card number {card_number} is what crossed the wire"),
                alloc::format!(
                    "card number {card_number} is not what crossed the wire at {}",
                    secs(tx.t_us)
                ),
            );
            c.require(
                bits.as_slice() == tx.bits.as_slice(),
                alloc::format!(
                    "all {} predicted bits match the frame the reader emitted at {}",
                    tx.bits.len(),
                    secs(tx.t_us)
                ),
                alloc::format!(
                    "the {} bits submitted are not the {} the reader emitted; check the two parity \
                     bits first",
                    bits.len(),
                    tx.bits.len()
                ),
            );
        }
        _ => c.missing(String::from(
            "submit a facility code, a card number and the 26 bits",
        )),
    }
}

/// **0.4** — every recovered key is the key that sector holds, and the block
/// read back is the card's own.
fn drill_0_4(c: &mut Check, ctx: &FlagContext<'_>) {
    let m = match &ctx.facts.mifare {
        Some(m) => m,
        None => {
            c.missing(String::from("run the nested attack"));
            return;
        }
    };
    c.require(
        !m.recovered.is_empty(),
        alloc::format!("{} sector key(s) recovered", m.recovered.len()),
        String::from("no sector key has been recovered yet"),
    );
    let all_correct = m
        .recovered
        .iter()
        .all(|(sector, key)| m.configured.iter().any(|(s, k)| s == sector && k == key));
    c.require(
        all_correct,
        String::from("every recovered key equals the key that sector is provisioned with"),
        String::from("a recovered key does not match the card's provisioning"),
    );
    match &m.read_back {
        Some(read) => {
            c.require(
                read.as_slice() == m.credential.as_slice(),
                alloc::format!(
                    "block {} read back as {}, which is the card's own contents",
                    m.credential_block,
                    hex(read)
                ),
                alloc::format!(
                    "block {} read back as {}, which is not what the card holds",
                    m.credential_block,
                    hex(read)
                ),
            );
        }
        None => c.missing(alloc::format!(
            "read block {} with a recovered key",
            m.credential_block
        )),
    }
    if let Some(k) = ctx.knowledge {
        let brute = k
            .keys
            .iter()
            .filter(|x| matches!(x.provenance, Provenance::BruteForced { .. }))
            .count();
        c.require(
            brute > 0,
            alloc::format!("{brute} key(s) were found by searching rather than by being told"),
            String::from("no key in the attacker's hands was actually searched for"),
        );
        c.require(
            honest(k),
            String::from("nothing the attacker holds was handed to it"),
            String::from("the attacker is holding something it could not have obtained"),
        );
    }
}

/// **0.5** — every attack stopped, and the diagnosis is right.
fn drill_0_5(c: &mut Check, ctx: &FlagContext<'_>) {
    if ctx.facts.diagnoses.is_empty() {
        c.missing(String::from(
            "run the three Module 0 attacks against the card",
        ));
        return;
    }
    c.require(
        ctx.facts.all_attacks_failed,
        alloc::format!(
            "all {} attack(s) stopped against this card",
            ctx.facts.diagnoses.len()
        ),
        String::from("an attack succeeded, which means this is not the card the drill describes"),
    );
    match ctx.submission {
        Some(Submission::Diagnoses(claimed)) => {
            let mut want = ctx.facts.diagnoses.clone();
            let mut got = claimed.clone();
            want.sort_by_key(|d| d.name());
            got.sort_by_key(|d| d.name());
            c.require(
                want == got,
                alloc::format!(
                    "diagnosis correct for all {} attacks: {}",
                    want.len(),
                    want.iter().map(|d| d.name()).collect::<Vec<_>>().join(", ")
                ),
                alloc::format!(
                    "the diagnoses submitted are not the failures the engine observed ({})",
                    want.len()
                ),
            );
        }
        _ => c.missing(String::from("submit one diagnosis per attack")),
    }
}

/// **0.6** — not a flag. It completes by being read.
fn drill_0_6(c: &mut Check, ctx: &FlagContext<'_>) {
    c.note(String::from(
        "this section simulates nothing: there is no bench, no bus and no flag",
    ));
    match ctx.submission {
        Some(Submission::Acknowledged) | Some(Submission::Note(_)) => {
            c.note(String::from("marked as read"));
        }
        _ => c.missing(String::from("read docs/BYPASS.md and mark it as read")),
    }
}

// ---------------------------------------------------------------------------
// Module 1
// ---------------------------------------------------------------------------

/// **1.1** — the submitted credential is what the engine transmitted.
fn drill_1_1(c: &mut Check, ctx: &FlagContext<'_>) {
    let tx = match &ctx.facts.transmitted {
        Some(t) => t,
        None => {
            c.missing(String::from(
                "present the card and run: nothing has crossed the wire yet",
            ));
            return;
        }
    };
    c.note(alloc::format!(
        "{} bits crossed the wire at {}, parity {}",
        tx.bits.len(),
        secs(tx.t_us),
        if tx.parity_valid { "valid" } else { "invalid" }
    ));
    match ctx.submission {
        Some(Submission::Credential {
            facility_code,
            card_number,
            ..
        }) => {
            c.require(
                Some(*facility_code) == tx.facility_code,
                alloc::format!("facility code {facility_code} matches the transmitted frame"),
                alloc::format!(
                    "facility code {facility_code} is not the one transmitted at {}",
                    secs(tx.t_us)
                ),
            );
            c.require(
                Some(*card_number) == tx.card_number,
                alloc::format!("card number {card_number} matches the transmitted frame"),
                alloc::format!(
                    "card number {card_number} is not the one transmitted at {}",
                    secs(tx.t_us)
                ),
            );
        }
        _ => c.missing(String::from("submit a facility code and a card number")),
    }
}

/// **1.2** — a clean, parity-valid frame reached the panel carrying a number
/// nobody presented.
fn drill_1_2(c: &mut Check, ctx: &FlagContext<'_>) {
    let world = match ctx.world {
        Some(w) => w,
        None => {
            c.missing(String::from("run the bench"));
            return;
        }
    };
    let presented_numbers: Vec<u64> = presentations(world)
        .iter()
        .filter_map(|(_, _, bits)| as_h10301(bits).and_then(|d| d.card_number))
        .collect();
    let arrivals = controller_input(world);
    if arrivals.is_empty() {
        c.missing(String::from(
            "nothing has reached the controller: present a card",
        ));
        return;
    }
    let forged = arrivals.iter().find_map(|(t, bits)| {
        let d = as_h10301(bits)?;
        let cn = d.card_number?;
        if d.parity_valid() && !presented_numbers.contains(&cn) {
            Some((*t, cn))
        } else {
            None
        }
    });
    match forged {
        Some((t, cn)) => {
            c.note(alloc::format!(
                "credentials presented at the reader carried card number(s) {presented_numbers:?}"
            ));
            c.note(alloc::format!(
                "a frame reached the controller at {} carrying card number {cn}, which no \
                 credential at the reader had",
                secs(t)
            ));
            c.note(String::from(
                "it parsed cleanly and both parity bits were valid, which is everything the panel \
                 checks",
            ));
        }
        None => c.missing(String::from(
            "no frame has reached the controller that both passes parity and carries a card \
             number nothing presented: arm the implant and recompute the parity",
        )),
    }
}

/// **1.3 and 1.6** — a grant with no credential behind it, attributed to a tap.
fn drill_1_3(c: &mut Check, ctx: &FlagContext<'_>, medium: &str) {
    let world = match ctx.world {
        Some(w) => w,
        None => {
            c.missing(String::from("run the bench"));
            return;
        }
    };
    let presented = presentations(world);
    let g = grants(world);
    if g.is_empty() {
        c.missing(String::from(
            "the controller has not granted: capture a badge-in and re-emit it",
        ));
        return;
    }
    let orphan = g.iter().find(|r| {
        !presented
            .iter()
            .any(|(t, _, _)| *t <= r.t_us && r.t_us.saturating_sub(*t) < NO_CREDENTIAL_WINDOW_US)
    });
    match orphan {
        Some(r) => {
            c.note(alloc::format!(
                "controller granted at {} with no credential presented in the preceding {}",
                secs(r.t_us),
                secs(NO_CREDENTIAL_WINDOW_US)
            ));
            let from_tap = matches!(world.log().originator(r.seq), Some(Origin::Tap(_)));
            c.require(
                from_tap,
                alloc::format!(
                    "the engine traces that grant back to the attacker's tap on the {medium} link"
                ),
                String::from(
                    "the engine does not attribute that grant to a tap, so something other than \
                     the attacker caused it",
                ),
            );
        }
        None => c.missing(String::from(
            "every grant so far has a credential behind it: take the card away before you replay",
        )),
    }
}

/// **1.4** — inline substitution, with the reader's own output untouched.
fn drill_1_4(c: &mut Check, ctx: &FlagContext<'_>) {
    let world = match ctx.world {
        Some(w) => w,
        None => {
            c.missing(String::from("run the bench"));
            return;
        }
    };
    let swap = world.log().records().iter().find_map(|r| match &r.kind {
        RecordKind::TapAction {
            tap,
            action: odr_bus::TapAction::ReplacedBits { before, after },
            ..
        } if before != after => Some((r.t_us, *tap, before.clone(), after.clone())),
        _ => None,
    });
    let (swap_t, tap, before, after) = match swap {
        Some(v) => v,
        None => {
            c.missing(String::from(
                "no tap has replaced a credential in flight: cut the implant in and arm it",
            ));
            return;
        }
    };
    let inline = world.tap_kind(tap).map(|k| k == odr_bus::TapKind::Inline);
    c.require(
        inline == Ok(true),
        alloc::format!(
            "the tap that made the substitution at {} is inline",
            secs(swap_t)
        ),
        String::from("the tap that changed the traffic is not inline, which should be impossible"),
    );
    c.note(alloc::format!(
        "it consumed {} bits and emitted {} in their place",
        before.len(),
        after.len()
    ));

    let presented = presentations(world);
    let emitted = reader_output(world);
    let reader_untouched = emitted
        .iter()
        .all(|(_, bits)| presented.iter().any(|(_, _, p)| p == bits));
    c.require(
        reader_untouched,
        alloc::format!(
            "the reader's own output, all {} frame(s) of it, is exactly the credentials that were \
             presented to it",
            emitted.len()
        ),
        String::from("the reader emitted something that was not presented to it"),
    );

    let arrived = controller_input(world);
    c.require(
        arrived.iter().any(|(_, bits)| *bits == after),
        String::from("the controller received the substituted credential"),
        String::from("the substituted credential never reached the controller"),
    );
    let g = grants(world);
    match g.iter().find(|r| match &r.kind {
        RecordKind::AccessDecision { bits, .. } => *bits == after,
        _ => false,
    }) {
        Some(r) => c.note(alloc::format!(
            "the controller granted at {} on the substituted credential",
            secs(r.t_us)
        )),
        None => c.missing(String::from(
            "the controller has not granted on the substituted credential: check it is on the \
             access list",
        )),
    }
}

/// **1.5** — not a flag. A number.
fn drill_1_5(c: &mut Check, ctx: &FlagContext<'_>) {
    let sweep = match &ctx.facts.sweep {
        Some(s) => s,
        None => {
            c.missing(String::from(
                "run the sweep: the drill ends on a figure and there is no figure yet",
            ));
            return;
        }
    };
    let whole = &sweep.format_space_cost;
    c.note(alloc::format!(
        "{} credentials were actually put on the wire, over {}",
        sweep.attempted,
        secs(sweep.elapsed_us)
    ));
    if let Some(hit) = &sweep.hit {
        c.note(alloc::format!(
            "the door opened on facility code {:?}, card number {}",
            hit.facility_code,
            hit.card_number
        ));
    }
    c.note(alloc::format!(
        "the configured sweep would cost {}",
        sweep.sweep_cost.describe()
    ));
    c.measurement = Some(Measurement {
        label: alloc::format!(
            "the whole {}-bit credential space at this bench's wire timing",
            whole.bits_per_credential
        ),
        value: whole.describe(),
        compare_with: String::from(
            "drill 1.3, which opened the same door with one captured frame and a transmitter",
        ),
    });
}

/// **1.6** — the same replay on clock-and-data, and the capture says so.
fn drill_1_6(c: &mut Check, ctx: &FlagContext<'_>) {
    drill_1_3(c, ctx, "clock-and-data");
    if let Some(world) = ctx.world {
        let cd = world.log().records().iter().any(|r| {
            matches!(
                r.kind,
                RecordKind::WireTx {
                    kind: odr_bus::WireKind::ClockData,
                    ..
                }
            )
        });
        c.require(
            cd,
            String::from("the traffic on this link is clock-and-data, not Wiegand"),
            String::from("no clock-and-data traffic on this link"),
        );
    }
    if let Some(k) = ctx.knowledge {
        let from_cd = k
            .credentials
            .iter()
            .any(|x| x.value.medium == odr_attack::CaptureMedium::ClockData);
        c.require(
            from_cd,
            String::from("the attacker's capture is a clock-and-data capture"),
            String::from("the attacker has not captured anything off a clock-and-data link"),
        );
    }
}

// ---------------------------------------------------------------------------
// Module 2
// ---------------------------------------------------------------------------

/// **2.1** — every field offset is right.
fn drill_2_1(c: &mut Check, ctx: &FlagContext<'_>) {
    let layout = match &ctx.facts.frame_layout {
        Some(l) => l,
        None => {
            c.missing(String::from(
                "no card read has crossed the bus yet: present a card and find REPLY_RAW",
            ));
            return;
        }
    };
    c.note(alloc::format!(
        "the frame is {} at {}, {} octets, sequence {}",
        layout.code_name,
        secs(layout.t_us),
        layout.bytes.len(),
        layout.sequence
    ));
    match ctx.submission {
        Some(Submission::FrameLayout(claimed)) => {
            let required = layout.required();
            let mut wrong = Vec::new();
            for want in &required {
                match claimed.iter().find(|s| s.field == want.field) {
                    Some(got) if got == want => {}
                    Some(got) => wrong.push(alloc::format!(
                        "{} is at offset {} for {} byte(s), not offset {} for {}",
                        want.field.name(),
                        want.offset,
                        want.length,
                        got.offset,
                        got.length
                    )),
                    None => wrong.push(alloc::format!("{} was not labelled", want.field.name())),
                }
            }
            if wrong.is_empty() {
                c.note(alloc::format!(
                    "all {} field offsets match the frame the engine generated",
                    required.len()
                ));
            } else {
                for w in wrong {
                    c.missing(w);
                }
            }
        }
        _ => c.missing(String::from(
            "submit a byte offset and length for each field",
        )),
    }
}

/// **2.2** — a card number off the bus, with nothing transmitted.
fn drill_2_2(c: &mut Check, ctx: &FlagContext<'_>) {
    let world = match ctx.world {
        Some(w) => w,
        None => {
            c.missing(String::from("run the bench"));
            return;
        }
    };
    let presented = presentations(world);
    let k = match ctx.knowledge {
        Some(k) => k,
        None => {
            c.missing(String::from(
                "clip a probe onto the pair and harvest what it saw",
            ));
            return;
        }
    };
    let matched = k
        .credentials
        .iter()
        .find(|x| presented.iter().any(|(_, _, bits)| *bits == x.value.bits));
    match matched {
        Some(x) => {
            c.note(alloc::format!(
                "the attacker holds {} bits captured at {}, identical to the credential presented \
                 at the reader",
                x.value.bits.len(),
                secs(x.value.t_us)
            ));
            c.require(
                x.provenance.is_observation(),
                String::from("it was read straight off the link"),
                String::from("that credential was not observed off the link"),
            );
        }
        None => c.missing(String::from(
            "the attacker does not hold a credential matching anything presented at the reader",
        )),
    }
    let sent = tap_transmissions(world);
    c.require(
        sent == 0,
        String::from("the world's own log records zero frames driven by any tap"),
        alloc::format!("{sent} frame(s) were driven onto the link by a tap; this drill is passive"),
    );
    c.require(
        k.keys.is_empty(),
        String::from("no key was needed and none was invented"),
        String::from("the attacker is holding a key, which this drill does not need"),
    );
}

/// **2.3** — the PD ACKed a command the engine attributes to the attacker.
fn drill_2_3(c: &mut Check, ctx: &FlagContext<'_>) {
    let world = match ctx.world {
        Some(w) => w,
        None => {
            c.missing(String::from("run the bench"));
            return;
        }
    };
    let injected = world
        .log()
        .records()
        .iter()
        .filter(|r| {
            matches!(
                r.kind,
                RecordKind::BusTx {
                    origin: Origin::Tap(_),
                    ..
                }
            )
        })
        .count();
    c.require(
        injected > 0,
        alloc::format!("the attacker drove {injected} frame(s) onto the bus"),
        String::from("nothing has been injected: clip a transmitter on and forge a command"),
    );

    let ack = world.log().records().iter().find(|r| match &r.kind {
        RecordKind::BusTx {
            origin: Origin::Reader(_),
            frame: Some(f),
            ..
        } => {
            f.reply_code() == Some(Reply::Ack)
                && matches!(world.log().originator(r.seq), Some(Origin::Tap(_)))
        }
        _ => false,
    });
    match ack {
        Some(r) => c.note(alloc::format!(
            "the PD ACKed at {}, and the engine's cause chain traces that reply back to the \
             attacker's tap",
            secs(r.t_us)
        )),
        None => c.missing(String::from(
            "no ACK has come back that the engine attributes to the attacker: check the address \
             and the sequence number, and mind the gap between polls",
        )),
    }
}

/// **2.4** — the link came back, on the same running world.
fn drill_2_4(c: &mut Check, ctx: &FlagContext<'_>) {
    let d = match ctx.facts.desync {
        Some(d) => d,
        None => {
            c.missing(String::from(
                "push the controller's sequence numbering out of step first",
            ));
            return;
        }
    };
    c.note(alloc::format!(
        "the sequence was pushed out of step at {}",
        secs(d.forced_at_us)
    ));
    match d.noticed_at_us {
        Some(t) => c.note(alloc::format!(
            "the peripheral objected at {} with a sequence error",
            secs(t)
        )),
        None => c.missing(String::from(
            "the peripheral has not objected yet: keep running",
        )),
    }
    match d.recovered_at_us {
        Some(t) => c.note(alloc::format!("normal traffic resumed at {}", secs(t))),
        None => c.missing(String::from(
            "the link has not carried normal traffic since the fault: keep running",
        )),
    }
    c.require(
        d.starts == 1,
        String::from("the simulation was started exactly once, so the link recovered rather than being rebuilt"),
        alloc::format!(
            "the simulation was started {} times; reloading the drill fixes this and proves \
             nothing",
            d.starts
        ),
    );
}

// ---------------------------------------------------------------------------
// Module 3
// ---------------------------------------------------------------------------

/// **3.1** — the predicted cryptogram is the one the PD sent.
fn drill_3_1(c: &mut Check, ctx: &FlagContext<'_>) {
    let engine = match ctx.facts.client_cryptogram {
        Some(v) => v,
        None => {
            c.missing(String::from(
                "no handshake has completed yet, so there is no cryptogram to compare against",
            ));
            return;
        }
    };
    match ctx.submission {
        Some(Submission::Cryptogram(claim)) => {
            c.require(
                *claim == engine,
                String::from("the sixteen bytes submitted are the client cryptogram the peripheral transmitted"),
                alloc::format!(
                    "the cryptogram submitted is not the one on the wire; check whether you \
                     derived S-ENC (constant 0x82) rather than S-MAC1, and that you used only the \
                     first six bytes of RND.A: {}",
                    hex(claim)
                ),
            );
        }
        _ => c.missing(String::from("submit the sixteen-byte client cryptogram")),
    }
}

/// **3.2** — the attacker decrypted a card read that was genuinely encrypted.
fn drill_3_2(c: &mut Check, ctx: &FlagContext<'_>) {
    let world = match ctx.world {
        Some(w) => w,
        None => {
            c.missing(String::from("run the bench"));
            return;
        }
    };
    let k = match ctx.knowledge {
        Some(k) => k,
        None => {
            c.missing(String::from("clip a probe onto the pair"));
            return;
        }
    };
    let encrypted_read = world
        .log()
        .bus_frames()
        .find(|(_, _, f)| f.reply_code() == Some(Reply::Raw) && f.is_encrypted());
    c.require(
        encrypted_read.is_some(),
        String::from("the card read on the bus was genuinely encrypted"),
        String::from(
            "no encrypted card read has crossed the bus: let the handshake finish, then present a \
             card",
        ),
    );
    c.require(
        k.holds_scbk(&odr_osdp::SCBK_D),
        String::from("the attacker holds SCBK-D"),
        String::from("the attacker does not hold the base key yet: run the sweep"),
    );
    let searched = k
        .keys
        .iter()
        .any(|x| matches!(x.provenance, Provenance::BruteForced { .. }));
    c.require(
        searched,
        String::from("it was found by sweeping candidates against the captured handshake"),
        String::from("the key the attacker holds was not searched for"),
    );
    let presented = presentations(world);
    let read = ctx
        .facts
        .recovered_credentials
        .iter()
        .find(|x| presented.iter().any(|(_, _, b)| *b == x.bits));
    match read {
        Some(x) => c.note(alloc::format!(
            "the attacker recovered the plaintext of the card read captured at {}, and it is the \
             credential that was presented",
            secs(x.t_us)
        )),
        None => c.missing(String::from(
            "the attacker has not recovered the card read's plaintext",
        )),
    }
    let sent = tap_transmissions(world);
    c.require(
        sent == 0,
        String::from("it transmitted nothing"),
        alloc::format!("{sent} frame(s) were driven onto the bus; this attack is passive"),
    );
}

/// **3.3** — the recovered key is the key the peripheral holds.
fn drill_3_3(c: &mut Check, ctx: &FlagContext<'_>) {
    let world = match ctx.world {
        Some(w) => w,
        None => {
            c.missing(String::from("run the bench"));
            return;
        }
    };
    let configured = match ctx.facts.site_key {
        Some(key) => key,
        None => {
            c.missing(String::from("this bench has no site key configured"));
            return;
        }
    };
    let k = match ctx.knowledge {
        Some(k) => k,
        None => {
            c.missing(String::from("clip a probe onto the pair"));
            return;
        }
    };
    c.require(
        configured != odr_osdp::SCBK_D,
        String::from("the site key is not SCBK-D, so recognising it is not enough"),
        String::from("this bench is on the default key, which is drill 3.2 rather than 3.3"),
    );
    c.require(
        k.holds_scbk(&configured),
        String::from("the key the attacker recovered is the key the peripheral is configured with"),
        String::from(
            "the attacker does not hold the peripheral's key: capture a complete handshake and \
             sweep the published family",
        ),
    );
    let from_sweep = k.keys.iter().any(|x| {
        x.value.key == configured && matches!(x.provenance, Provenance::BruteForced { .. })
    });
    c.require(
        from_sweep,
        String::from("it was recovered from the capture alone, by trying candidates"),
        String::from("that key was not recovered by searching"),
    );
    let sent = tap_transmissions(world);
    c.require(
        sent == 0,
        String::from("nothing went back onto the bus, which is why this attack is invisible"),
        alloc::format!("{sent} frame(s) were driven onto the bus; this attack is passive"),
    );
}

/// **3.4** — the site key, obtained by asking, with nothing malformed sent.
fn drill_3_4(c: &mut Check, ctx: &FlagContext<'_>) {
    let world = match ctx.world {
        Some(w) => w,
        None => {
            c.missing(String::from("run the bench"));
            return;
        }
    };
    let configured = match ctx.facts.site_key {
        Some(key) => key,
        None => {
            c.missing(String::from("this bench has no site key configured"));
            return;
        }
    };
    let k = match ctx.knowledge {
        Some(k) => k,
        None => {
            c.missing(String::from("clip a transceiver onto the pair"));
            return;
        }
    };
    c.require(
        k.holds_scbk(&configured),
        String::from("the attacker holds the key the real reader was commissioned with"),
        String::from(
            "the attacker does not hold the site key: answer for the unfitted address and let the \
             controller push it",
        ),
    );

    let mut sent = 0usize;
    let mut malformed = Vec::new();
    for r in world.log().records() {
        if let RecordKind::BusTx {
            origin: Origin::Tap(_),
            frame,
            ..
        } = &r.kind
        {
            sent += 1;
            match frame.as_deref() {
                Some(f) if f.is_reply && Reply::from_u8(f.id).is_some() => {}
                Some(f) => malformed.push(alloc::format!(
                    "{} at {}: id {:#04x}",
                    if f.is_reply { "reply" } else { "command" },
                    secs(r.t_us),
                    f.id
                )),
                None => malformed.push(alloc::format!(
                    "octets at {} that do not decode",
                    secs(r.t_us)
                )),
            }
        }
    }
    c.require(
        sent > 0,
        alloc::format!("the attacker sent {sent} frame(s)"),
        String::from("the attacker has sent nothing: it has to answer the controller's polls"),
    );
    c.require(
        malformed.is_empty(),
        String::from("every one of them was a well-formed OSDP reply with a code in the standard"),
        alloc::format!("the attacker sent something that is not a valid reply: {malformed:?}"),
    );
    let collisions = world
        .log()
        .records()
        .iter()
        .filter(|r| matches!(r.kind, RecordKind::BusCollision { .. }))
        .count();
    c.require(
        collisions == 0,
        String::from("and it never spoke over anybody"),
        alloc::format!("{collisions} collision(s): the attacker transmitted over somebody else"),
    );
    c.require(
        honest(k),
        String::from("nothing it holds was handed to it"),
        String::from("the attacker is holding something it could not have obtained"),
    );
}

/// **3.5** — the key came out of a `CMD_KEYSET`, and the traffic after it is
/// readable.
fn drill_3_5(c: &mut Check, ctx: &FlagContext<'_>) {
    let world = match ctx.world {
        Some(w) => w,
        None => {
            c.missing(String::from("run the bench"));
            return;
        }
    };
    let configured = match ctx.facts.site_key {
        Some(key) => key,
        None => {
            c.missing(String::from("this bench has no site key configured"));
            return;
        }
    };
    let k = match ctx.knowledge {
        Some(k) => k,
        None => {
            c.missing(String::from("clip a probe onto the pair"));
            return;
        }
    };
    let keyset = world.log().records().iter().find(|r| {
        matches!(
            &r.kind,
            RecordKind::SecureChannel {
                event: ScEvent::KeysetSent { .. },
                ..
            }
        )
    });
    match keyset {
        Some(r) => c.note(alloc::format!(
            "a CMD_KEYSET crossed the bus at {}",
            secs(r.t_us)
        )),
        None => c.missing(String::from(
            "no CMD_KEYSET has crossed the bus: be on the pair before the installer starts",
        )),
    }
    c.require(
        k.holds_scbk(&configured),
        String::from("the attacker holds the key the peripheral is now commissioned with"),
        String::from("the attacker has not captured the key out of the keyset payload"),
    );
    let presented = presentations(world);
    let after = ctx
        .facts
        .recovered_credentials
        .iter()
        .find(|x| presented.iter().any(|(_, _, b)| *b == x.bits));
    match after {
        Some(x) => c.note(alloc::format!(
            "and decrypted the card read that followed commissioning, captured at {}",
            secs(x.t_us)
        )),
        None => c.missing(String::from(
            "the attacker has not read anything from after the re-handshake",
        )),
    }
    let sent = tap_transmissions(world);
    c.require(
        sent == 0,
        String::from("it transmitted nothing throughout"),
        alloc::format!("{sent} frame(s) were driven onto the bus; this attack is passive"),
    );
}

/// **3.6** — a steady link carrying card reads in the clear, both ends
/// configured to require Secure Channel.
fn drill_3_6(c: &mut Check, ctx: &FlagContext<'_>) {
    let world = match ctx.world {
        Some(w) => w,
        None => {
            c.missing(String::from("run the bench"));
            return;
        }
    };
    let controller = match world.controllers().next() {
        Some(c) => c,
        None => {
            c.missing(String::from("this bench has no controller"));
            return;
        }
    };
    let address = controller
        .acu_config()
        .and_then(|a| a.addresses.first().copied())
        .unwrap_or(1);

    let acu_required = controller
        .acu_config()
        .map(|a| a.sc == odr_bus::ScRequirement::Required)
        .unwrap_or(false);
    let pd_required = world
        .readers()
        .filter_map(|r| r.pd_config())
        .any(|p| p.sc == odr_bus::ScRequirement::Required);
    c.require(
        acu_required && pd_required,
        String::from("both endpoints are configured to require Secure Channel"),
        String::from(
            "one of the endpoints is not configured to require Secure Channel, so nothing here \
             was downgraded",
        ),
    );
    c.require(
        !controller.is_secure(address),
        alloc::format!(
            "the controller is not running a secure channel with address {address:#04x}"
        ),
        String::from("the link is secured, so the capability reply was not believed"),
    );
    let online = controller
        .session(address)
        .map(|s| s.stage == odr_bus::SessionStage::Online)
        .unwrap_or(false);
    c.require(
        online,
        String::from(
            "and the session is Online, so this is a working link rather than a broken one",
        ),
        String::from("the session is not Online: a denial of service is not a downgrade"),
    );
    let clear_read = world
        .log()
        .bus_frames()
        .find(|(_, _, f)| f.reply_code() == Some(Reply::Raw) && f.security.is_none());
    match clear_read {
        Some((r, _, _)) => c.note(alloc::format!(
            "a card read crossed at {} with no security block at all",
            secs(r.t_us)
        )),
        None => c.missing(String::from(
            "no card read has crossed in the clear: present a card once the link is up",
        )),
    }
    let pd_still_capable = world
        .readers()
        .filter_map(|r| r.pd_config())
        .any(|p| p.capabilities.claims_aes128());
    c.require(
        pd_still_capable,
        String::from("the peripheral itself still claims AES-128: only the wire changed"),
        String::from("the peripheral's own configuration changed, which is not this attack"),
    );
}

// ---------------------------------------------------------------------------
// Module 4
// ---------------------------------------------------------------------------

/// **4.1** — the schedule, read through encryption, with no key.
fn drill_4_1(c: &mut Check, ctx: &FlagContext<'_>) {
    let world = match ctx.world {
        Some(w) => w,
        None => {
            c.missing(String::from("run the day"));
            return;
        }
    };
    let truth = &ctx.facts.badge_times;
    if truth.is_empty() {
        c.missing(String::from("no badge-ins have happened yet: run the day"));
        return;
    }
    let all_encrypted = world
        .log()
        .bus_frames()
        .filter(|(_, _, f)| f.reply_code() == Some(Reply::Raw))
        .all(|(_, _, f)| f.is_encrypted());
    c.require(
        all_encrypted,
        String::from("every card read on the bus was encrypted"),
        String::from("a card read crossed in the clear, so this is not the drill's lesson"),
    );

    match ctx.submission {
        Some(Submission::BadgeTimes(claimed)) => {
            let mut used = alloc::vec![false; claimed.len()];
            let mut missed = Vec::new();
            for t in truth {
                let hit = claimed
                    .iter()
                    .enumerate()
                    .position(|(i, ct)| !used[i] && ct.abs_diff(*t) <= BADGE_TIME_TOLERANCE_US);
                match hit {
                    Some(i) => used[i] = true,
                    None => missed.push(secs(*t)),
                }
            }
            let spurious = used.iter().filter(|u| !**u).count();
            c.require(
                missed.is_empty(),
                alloc::format!("every one of the {} badge-ins is in the list", truth.len()),
                alloc::format!("badge-ins at {missed:?} are missing from the list"),
            );
            c.require(
                spurious == 0,
                String::from("and nothing in the list was invented"),
                alloc::format!("{spurious} time(s) in the list do not correspond to any badge-in"),
            );
        }
        _ => c.missing(String::from(
            "submit the time of every badge-in over the day",
        )),
    }

    if let Some(k) = ctx.knowledge {
        c.require(
            k.keys.is_empty(),
            String::from("the attacker held no key at any point"),
            String::from("the attacker is holding a key, which makes this a different drill"),
        );
        c.require(
            k.frames.is_empty(),
            String::from("and kept no frame, so it has no payload byte to have used"),
            String::from(
                "the attacker kept whole frames, so it cannot claim to have read only headers",
            ),
        );
        c.require(
            !k.badge_events.is_empty(),
            alloc::format!(
                "it inferred {} badge-in(s) from plaintext headers alone",
                k.badge_events.len()
            ),
            String::from("the attacker has inferred nothing from the traffic"),
        );
    }
}

/// **4.2** — a frame the PD accepted whose MAC was not derived from the session
/// key.
fn drill_4_2(c: &mut Check, ctx: &FlagContext<'_>) {
    let f = match &ctx.facts.forgery {
        Some(f) => f,
        None => {
            c.missing(String::from("run the forgery"));
            return;
        }
    };
    c.require(
        f.accepted,
        alloc::format!(
            "the peripheral accepted a forged frame after {} attempt(s)",
            f.attempts
        ),
        alloc::format!(
            "the peripheral has not accepted anything after {} attempt(s): calibrate first, then \
             sweep the sequence class",
            f.attempts
        ),
    );
    c.require(
        f.attributable,
        String::from("the engine's cause chain attributes the acceptance to the attacker's frame"),
        String::from("the engine does not attribute the acceptance to the attacker"),
    );
    c.note(alloc::format!(
        "the attacker measured {} significant MAC byte(s) on this bus from genuine frames; a real \
         bus gives 4",
        f.effective_mac_bytes
    ));
    if let Some(k) = ctx.knowledge {
        let calibrated = k
            .mac_facts
            .iter()
            .any(|x| matches!(x.provenance, Provenance::Calibrated { .. }));
        c.require(
            calibrated,
            String::from("that width was measured rather than being read out of the configuration"),
            String::from("the MAC width was not measured from the wire"),
        );
    }
    let genuine = ctx.facts.tasks.iter().find(|t| t.id == "mac-forge");
    match genuine {
        Some(t) => c.note(alloc::format!(
            "the genuine {}-candidate search is running alongside at {:.1} candidates a second: {}",
            f.genuine_space,
            t.per_second,
            f.genuine_projected
        )),
        None => c.missing(String::from(
            "the genuine search is not running; it is half the drill",
        )),
    }
}

/// **4.3** — plaintext from a frame the attacker's own decryptor could not
/// open.
fn drill_4_3(c: &mut Check, ctx: &FlagContext<'_>) {
    let iv = match &ctx.facts.iv_reuse {
        Some(v) => v,
        None => {
            c.missing(String::from("run the implant"));
            return;
        }
    };
    c.require(
        iv.suppressed > 0,
        alloc::format!(
            "{} reply(ies) were swallowed, freezing the command chain's IV",
            iv.suppressed
        ),
        String::from("no replies have been suppressed, so the IV chain is still advancing"),
    );
    c.require(
        iv.collisions > 0,
        alloc::format!(
            "{} group(s) of byte-identical ciphertext found at a frozen IV",
            iv.collisions
        ),
        String::from(
            "no two frames share a ciphertext yet: the controller has to retransmit under the \
             same IV",
        ),
    );
    c.require(
        iv.decryptor_refused,
        alloc::format!(
            "a chained decryptor built from the recovered key refuses the frame at {}",
            secs(iv.recovered_at_us)
        ),
        String::from(
            "the frame in question can be decrypted normally, so nothing here needed the codebook",
        ),
    );
    c.require(
        !iv.plaintext.is_empty(),
        alloc::format!(
            "its plaintext was recovered anyway by matching it to a frame already known: id \
             {:#04x}, {} byte(s)",
            iv.recovered_id,
            iv.plaintext.len()
        ),
        String::from("no plaintext has been recovered from the codebook"),
    );
    if let Some(k) = ctx.knowledge {
        c.require(
            !k.plaintexts.is_empty(),
            alloc::format!(
                "the attacker holds {} recovered plaintext(s)",
                k.plaintexts.len()
            ),
            String::from("the attacker holds no recovered plaintext"),
        );
        c.require(
            honest(k),
            String::from("nothing it holds was handed to it"),
            String::from("the attacker is holding something it could not have obtained"),
        );
    }
}

/// **4.4** — a payload read off a MACed, unencrypted link.
fn drill_4_4(c: &mut Check, ctx: &FlagContext<'_>) {
    let world = match ctx.world {
        Some(w) => w,
        None => {
            c.missing(String::from("run the bench"));
            return;
        }
    };
    let k = match ctx.knowledge {
        Some(k) => k,
        None => {
            c.missing(String::from("clip a probe onto the pair"));
            return;
        }
    };
    let controller = match world.controllers().next() {
        Some(c) => c,
        None => {
            c.missing(String::from("this bench has no controller"));
            return;
        }
    };
    let address = controller
        .acu_config()
        .and_then(|a| a.addresses.first().copied())
        .unwrap_or(1);
    c.require(
        controller.is_secure(address),
        String::from("Secure Channel is established, and the status display says so"),
        String::from("no secure channel is established, so there is no null cipher to read"),
    );
    let null = world
        .log()
        .bus_frames()
        .find(|(_, _, f)| f.mac.is_some() && !f.is_encrypted() && !f.payload.is_empty());
    match null {
        Some((r, _, f)) => c.note(alloc::format!(
            "a frame at {} carries a MAC, a {}-byte payload and no encryption: security block {}",
            secs(r.t_us),
            f.payload.len(),
            f.scs_type()
                .map(|s| alloc::format!("{s:?}"))
                .unwrap_or_else(|| "none".to_string())
        )),
        None => c.missing(String::from(
            "no MACed-but-unencrypted frame with a payload has crossed yet: present a card so the \
             controller drives the strike",
        )),
    }
    c.require(
        !k.plaintexts.is_empty(),
        alloc::format!(
            "the attacker read {} payload(s) off the link with no key at all",
            k.plaintexts.len()
        ),
        String::from("the attacker has not read a payload off the link"),
    );
    c.require(
        k.plaintexts.iter().all(|p| p.provenance.is_observation()),
        String::from("each of them was observed rather than decrypted"),
        String::from("a payload the attacker holds was not simply observed"),
    );
    let sent = tap_transmissions(world);
    c.require(
        sent == 0,
        String::from("it transmitted nothing"),
        alloc::format!("{sent} frame(s) were driven onto the bus; this attack is passive"),
    );
}

// ---------------------------------------------------------------------------
// Module 5
// ---------------------------------------------------------------------------

/// The detection outcome a Module 5 predicate scores.
///
/// Normally the run already applied the learner's rule set, because a rule set
/// is run rather than compared. A caller that scored a report elsewhere can
/// hand it over as a [`Submission::Detection`] instead, and it is re-scored
/// here against the same day's answer key.
fn detection(c: &mut Check, ctx: &FlagContext<'_>) -> Option<crate::module5::DetectionOutcome> {
    let base = match &ctx.facts.detection {
        Some(d) => d,
        None => {
            c.missing(String::from(
                "run a rule set against the generated day; there is nothing to score yet",
            ));
            return None;
        }
    };
    match ctx.submission {
        Some(Submission::Detection(report)) => match base.day.monitor() {
            Ok(monitor) => Some(crate::module5::score_report(
                &base.day,
                &monitor,
                report.clone(),
            )),
            Err(_) => {
                c.missing(String::from(
                    "the day's capture would not re-parse, so the submitted report cannot be \
                     checked against it",
                ));
                None
            }
        },
        _ => Some(base.clone()),
    }
}

/// **5.1** — everything visible found, nothing invented.
fn drill_5_1(c: &mut Check, ctx: &FlagContext<'_>) {
    let d = match detection(c, ctx) {
        Some(d) => d,
        None => return,
    };
    let d = &d;
    c.note(d.summary());
    c.require(
        d.evidence_checks,
        String::from("every citation in the report still names the bytes it claims to"),
        String::from(
            "a finding cites frames that do not say what it claims; the report is not checkable",
        ),
    );
    c.require(
        d.score.false_negatives().is_empty(),
        alloc::format!(
            "every attack in the answer key was found: {} true positive(s)",
            d.score.true_positives().len()
        ),
        alloc::format!(
            "{} attack(s) in the key were missed: {}",
            d.score.false_negatives().len(),
            d.score
                .false_negatives()
                .iter()
                .map(|e| e.label.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );
    c.require(
        d.score.is_quiet_on_benign(),
        String::from("and nothing fired on the benign traffic"),
        alloc::format!(
            "{} false positive(s) on benign traffic",
            d.score.false_positives().len()
        ),
    );
    c.note(alloc::format!(
        "of Module 3's attacks, the weak-key crack is absent from the key on purpose: a passive \
         capture and an offline sweep leave no observable, so no rule could have caught it. What \
         is visible is {}",
        crate::module5::MODULE_3_VISIBLE
            .iter()
            .map(|s| alloc::format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
}

/// **5.2** — the downgrade caught, the two benign look-alikes left alone.
fn drill_5_2(c: &mut Check, ctx: &FlagContext<'_>) {
    let d = match detection(c, ctx) {
        Some(d) => d,
        None => return,
    };
    let d = &d;
    c.note(d.summary());
    c.require(
        d.evidence_checks,
        String::from("every citation in the report checks out"),
        String::from("a finding cites frames that do not say what it claims"),
    );
    c.require(
        d.fired_during(
            odr_detect::Signal::CapabilityDowngrade,
            odr_detect::Episode::Downgrade,
        ),
        String::from("a capability downgrade was reported inside the downgrade episode"),
        String::from(
            "no capability downgrade was reported during the downgrade episode: a rule needs a \
             prior claim from the same address to compare against",
        ),
    );
    for benign in crate::module5::DOWNGRADE_FALSE_POSITIVE_CASES {
        c.require(
            !d.fired_during(odr_detect::Signal::CapabilityDowngrade, *benign),
            alloc::format!(
                "no downgrade was reported during the {} episode",
                benign.name()
            ),
            alloc::format!(
                "a downgrade was reported during the {} episode, which is benign: {}",
                benign.name(),
                benign.describe()
            ),
        );
    }
    // A legacy reader on a cleartext bus is still a cleartext bus, and saying
    // so is a finding rather than a false alarm. What the scorer counts is
    // whether anything was called an *attack* that was not one.
    c.require(
        d.score.is_quiet_on_benign(),
        String::from("and nothing on the benign traffic was called an attack"),
        alloc::format!(
            "{} false positive(s) on benign traffic",
            d.score.false_positives().len()
        ),
    );
}

/// **5.3** — the keyset reported, and reported as undecidable.
fn drill_5_3(c: &mut Check, ctx: &FlagContext<'_>) {
    let d = match detection(c, ctx) {
        Some(d) => d,
        None => return,
    };
    let d = &d;
    c.note(d.summary());
    c.require(
        d.fired_during(
            odr_detect::Signal::KeysetObserved,
            odr_detect::Episode::Commissioning,
        ),
        String::from("the keyset was reported during the commissioning episode"),
        String::from("no keyset was reported during the commissioning episode"),
    );
    c.require(
        d.is_ambiguous(odr_detect::Signal::KeysetObserved),
        String::from(
            "and it was reported as undecidable: the event is on the wire and the authorisation \
             never is",
        ),
        String::from(
            "the keyset was reported with a confidence the link does not permit; nothing in any \
             frame says whether it was authorised",
        ),
    );
    let counted = d
        .score
        .ambiguous()
        .iter()
        .any(|h| h.finding.what == odr_detect::Signal::KeysetObserved);
    c.require(
        counted,
        String::from(
            "the scorer counted it as ambiguous, excluded from both precision and recall — which \
             is exactly the position a defender is in",
        ),
        String::from("the scorer did not count it as ambiguous"),
    );
    c.require(
        d.score.is_quiet_on_benign(),
        String::from("and nothing was called an attack that was not one"),
        alloc::format!(
            "{} false positive(s) on benign traffic",
            d.score.false_positives().len()
        ),
    );
}

/// Unused today; kept so a predicate that needs the decision reason can reach
/// for it without re-deriving the match.
#[allow(dead_code)]
fn decision_reason(record: &LogRecord) -> Option<&DecisionReason> {
    match &record.kind {
        RecordKind::AccessDecision { reason, .. } => Some(reason),
        _ => None,
    }
}
