//! **The catalogue: all twenty-nine drills, in curriculum order.**
//!
//! This file is the course. `docs/CURRICULUM.md` is authoritative for what each
//! drill is and what its flag says; this is that document as data, with the
//! guidance a learner actually reads written out beside it.
//!
//! # On the guidance
//!
//! It is written to the voice of `docs/BYPASS.md`: plain, direct, not
//! patronising, and not over-claiming. Where a drill teaches something the
//! range cannot fully show — the real cost of a 32-bit MAC, the fact that an
//! offline weak-key sweep is invisible, the null cipher's reply direction that
//! this engine cannot produce — the guidance says so rather than papering over
//! it. A learner who finishes a drill believing the range showed them more than
//! it did has been taught something false, and that is worse than being taught
//! nothing.
//!
//! # On the counts
//!
//! Six modules, 6 + 6 + 4 + 6 + 4 + 3 = **29** drills, which is what
//! `site/ENGINE-API.md` says the site must render from `drillCount` rather than
//! hardcode. There is a test asserting the arithmetic.

use alloc::vec::Vec;

use crate::drill::{Drill, Guidance, Module};
use crate::error::{Result, ScenarioError};
use crate::ids::{Band, Completion, DrillId, LinkRole, ModuleId, TapMode, TapPlan};
use crate::scenario::ScenarioId;

// ---------------------------------------------------------------------------
// Tap positions, named once
// ---------------------------------------------------------------------------

const WIRE_SNIFF: TapPlan = TapPlan {
    link: LinkRole::ReaderToController,
    mode: TapMode::Sniff,
    label: "a passive clip on the D0/D1 pair",
};
const WIRE_INJECT: TapPlan = TapPlan {
    link: LinkRole::ReaderToController,
    mode: TapMode::Inject,
    label: "a transmitter on the D0/D1 pair",
};
const WIRE_INLINE: TapPlan = TapPlan {
    link: LinkRole::ReaderToController,
    mode: TapMode::Inline,
    label: "an implant cut into the cable behind the reader",
};
const BUS_SNIFF: TapPlan = TapPlan {
    link: LinkRole::ReaderToController,
    mode: TapMode::Sniff,
    label: "a passive clip on the RS-485 pair",
};
const BUS_INJECT: TapPlan = TapPlan {
    link: LinkRole::ReaderToController,
    mode: TapMode::Inject,
    label: "an RS-485 transceiver on the pair",
};
const BUS_INLINE: TapPlan = TapPlan {
    link: LinkRole::ReaderToController,
    mode: TapMode::Inline,
    label: "an implant cut into the RS-485 pair",
};
const MONITOR: TapPlan = TapPlan {
    link: LinkRole::ReaderToController,
    mode: TapMode::Sniff,
    label: "a monitoring probe in the riser",
};

const NO_TAPS: &[TapPlan] = &[];
const SNIFF_WIRE: &[TapPlan] = &[WIRE_SNIFF];
const INJECT_WIRE: &[TapPlan] = &[WIRE_INJECT];
const INLINE_WIRE: &[TapPlan] = &[WIRE_INLINE];
const SNIFF_BUS: &[TapPlan] = &[BUS_SNIFF];
const INJECT_BUS: &[TapPlan] = &[BUS_INJECT];
const INLINE_BUS: &[TapPlan] = &[BUS_INLINE];
const INLINE_AND_SNIFF_BUS: &[TapPlan] = &[BUS_INLINE, BUS_SNIFF];
const MONITOR_BUS: &[TapPlan] = &[MONITOR];

const NO_GUIDANCE: &[&str] = &[];

// ---------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------

/// The six modules, in order.
pub const MODULES: &[Module] = &[
    Module {
        id: ModuleId(0),
        number: 0,
        title: "The credential",
        blurb: "Before the wire, the card. This module exists because the reader was never the \
                weak part, and a learner who starts at Wiegand has already skipped the cheapest \
                attack in the building.",
    },
    Module {
        id: ModuleId(1),
        number: 1,
        title: "The wire (Wiegand)",
        blurb: "Two wires, a pulse train, and no authentication of any kind. Everything in this \
                module follows from the fact that there is nothing here to attack — which is a \
                different problem from something that is attackable.",
    },
    Module {
        id: ModuleId(2),
        number: 2,
        title: "OSDP as it is usually deployed",
        blurb: "OSDP is sold as the answer to Module 1, and it can be. This module is what it \
                looks like when nobody switched the answer on.",
    },
    Module {
        id: ModuleId(3),
        number: 3,
        title: "Secure Channel",
        blurb: "The part that is actually cryptography — the handshake, the session keys, the \
                packet format — and the five ways the Bishop Fox research walked past it.",
    },
    Module {
        id: ModuleId(4),
        number: 4,
        title: "The weaknesses nobody mentions",
        blurb: "Not the headline attacks. The medium and low findings, which are the more \
                interesting teaching material because they survive a deployment that did \
                everything right.",
    },
    Module {
        id: ModuleId(5),
        number: 5,
        title: "The other chair",
        blurb: "The same traffic with a monitor clipped to it instead of an attacker, and one \
                question: what could a defender have concluded, and when?",
    },
];

// ---------------------------------------------------------------------------
// The drills
// ---------------------------------------------------------------------------

/// Every drill, in curriculum order.
pub const DRILLS: &[Drill] = &[
    // === Module 0 — the credential ==========================================
    Drill {
        id: DrillId::new(0, 1),
        title: "What a prox card is",
        module: ModuleId(0),
        band: Band::Bronze,
        completion: Completion::Flag,
        scenario: ScenarioId::CardEm4100,
        summary: "A 125 kHz EM4100 tag has no processor, no key and no challenge. It shouts its \
                  number at anything that energises it, forever, to anyone holding a coil.",
        objective: "Read the tag's 40-bit id off the modulated carrier and submit it.",
        flag_text: "The id you submit is the one the engine generated for this session's tag, and \
                    the only place that number appeared was on the carrier.",
        note: "The format has parity, and parity here is error *detection* and nothing else. A \
               marginal read is reportable as one — the engine will even tell you which bit went \
               wrong — and there is still nothing stopping anybody writing a different id with \
               correct parity.",
        guidance: Guidance {
            bronze: &[
                "Hold the tag in the reader's field. The carrier panel shows the modulation the \
                 tag produces: 64 clocks per bit, Manchester coded.",
                "The frame is nine header ones, then ten rows of four data bits and a row parity \
                 bit, then four column parity bits and a stop bit. Sixty-four bits in total.",
                "Strip the header. Read the ten rows of four bits, most significant first. That \
                 is the 40-bit id.",
                "Check the row and column parity. If they pass, you have read it correctly.",
                "Submit the id.",
            ],
            silver: &[
                "The whole id is on the carrier and nothing protects it. Demodulate, drop the \
                 header, read the rows.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "Manchester coding puts a transition in the middle of every bit. The direction of \
             that transition is the bit.",
            "Nine ones in a row cannot appear anywhere else in the frame, by construction. That \
             is how you find the start.",
            "Every fifth bit after the header is a parity bit, not data.",
        ],
        taps: NO_TAPS,
        submission: Some("the tag's 40-bit id"),
    },
    Drill {
        id: DrillId::new(0, 2),
        title: "Cloning 125 kHz",
        module: ModuleId(0),
        band: Band::Bronze,
        completion: Completion::Flag,
        scenario: ScenarioId::CardClone,
        summary: "Copy the number onto a writable tag and present it. There is nothing to defeat: \
                  the format has no concept of authentication, so a copy of the number is the \
                  credential.",
        objective: "Open the door with a tag the building has never seen, without the original \
                    badge ever reaching the reader.",
        flag_text: "The controller granted, the strike fired, and every credential presented to \
                    the reader came from the attacker's own token — the victim's badge was never \
                    in the building.",
        note: "The clone's modulation is equal to the original's, event for event. No property of \
               the signal differs, so there is no reader anywhere that could tell them apart. \
               This is not a gap in the model; it is what the format is.",
        guidance: Guidance {
            bronze: &[
                "Brush the coil past the victim's pocket. One pass in the field is enough — the \
                 tag answers whenever it is energised and has no way to decline.",
                "Write the capture to a blank. The blank now emits the same bit stream.",
                "Walk to the door with the blank and present it.",
                "Compare the two modulation traces side by side. They are identical.",
            ],
            silver: &[
                "Capture the victim's field response, write it to a blank, present the blank. The \
                 panel is configured for a number, and you have the number.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "The cloner will refuse to write a blank before it has captured anything. It has \
             nothing to write.",
            "The engine tracks which physical token was presented, separately from the bits it \
             produced. That distinction is the whole flag.",
        ],
        taps: NO_TAPS,
        submission: None,
    },
    Drill {
        id: DrillId::new(0, 3),
        title: "HID Prox and the format problem",
        module: ModuleId(0),
        band: Band::Silver,
        completion: Completion::Flag,
        scenario: ScenarioId::CardHidProx,
        summary: "H10301 over the air carries a facility code and a card number. You will meet \
                  the identical payload again on the wire in Module 1, with the identical absence \
                  of protection, and seeing it twice is the point.",
        objective: "Pull the facility code and card number off the RF layer, then predict the \
                    exact 26 bits the reader will put on D0/D1 — before it does.",
        flag_text: "Your facility code, your card number and your 26 predicted bits all match \
                    what the reader subsequently transmitted, bit for bit.",
        note: "There is no step between the card and the wire where anything could be checked. \
               The reader demodulates, re-frames and clocks out; it has no key, no list, and \
               nothing to compare against. That is why the prediction works, and it is the same \
               reason the clone in 0.2 works.",
        guidance: Guidance {
            bronze: &[
                "Demodulate the card's field response. HID Prox carries a 44-bit block, not the \
                 26 bits you are about to see on the wire.",
                "Decode the block: a fixed preamble, then the 26-bit payload.",
                "Split the payload: one leading parity bit, eight bits of facility code, sixteen \
                 bits of card number, one trailing parity bit.",
                "Recompute both parity bits yourself — even over the first thirteen, odd over the \
                 last thirteen — and assemble the 26 bits.",
                "Submit the facility code, the card number and the bit string, then present the \
                 card and compare.",
            ],
            silver: &[
                "Two encodings of the same number, with a reader in between that checks nothing. \
                 Get the credential off the air, then write down what the wire will carry.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "The 44-bit air block is not the 26-bit wire frame. The reader strips the preamble.",
            "H10301's leading parity is even over bits 1..13 and its trailing parity is odd over \
             bits 13..25. Those two ranges overlap by one bit on purpose.",
            "If your bit string is right but your card number is not, you have the facility code \
             and card number boundary in the wrong place.",
        ],
        taps: NO_TAPS,
        submission: Some("a facility code, a card number, and the 26 bits"),
    },
    Drill {
        id: DrillId::new(0, 4),
        title: "13.56 MHz: the upgrade that mostly was not",
        module: ModuleId(0),
        band: Band::Silver,
        completion: Completion::Flag,
        scenario: ScenarioId::CardMifare,
        summary: "MIFARE Classic answered the 125 kHz problem with sector keys and a stream \
                  cipher. The cipher is Crypto1, it was broken in 2008, and it is on badges \
                  today.",
        objective: "Recover the sector keys from observed reader traffic alone, then read the \
                    credential block.",
        flag_text: "Every key the attacker recovered equals the key that sector is actually \
                    provisioned with, each one found by searching rather than by being told, and \
                    the block it then read matches the card's contents.",
        note: "The attack needs one sector still on a factory key. That is not a contrived \
               starting position — the transport key is printed in the datasheet and a large \
               number of deployed cards have at least one sector nobody changed. The recovery \
               step here is handed a capture and a measured timing distance and has no path to \
               the card at all, which is the honest shape of the attack.",
        guidance: Guidance {
            bronze: &[
                "Authenticate to sector 0 with the published transport key. This is the foothold \
                 and it is the only thing you are given.",
                "Measure the card's nonce distance: how far its PRNG advances between one \
                 authentication and the next. This is a timing measurement, not a secret.",
                "Probe a target sector while still inside the sector 0 session. The card's nonce \
                 comes back encrypted under the key you are trying to find.",
                "Search for the key that turns the observed ciphertext back into a nonce on the \
                 PRNG's orbit. That is the recovery.",
                "Repeat for the remaining sectors, then read the credential block with the key \
                 you found.",
            ],
            silver: &[
                "One sector on a factory default is enough. Use it to get encrypted nonces out of \
                 the sectors you do not have, and solve for the keys.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "The probes are abandoned before the third pass. The attacker never completes an \
             authentication it could not pay for, and the card grants nothing.",
            "The nonce distance has to be measured before the nested probes, because the search \
             needs to know which nonce the card would have produced.",
            "A recovered key is only a recovered key if running the authentication forward from \
             it reproduces the ciphertext you observed.",
        ],
        taps: NO_TAPS,
        submission: None,
    },
    Drill {
        id: DrillId::new(0, 5),
        title: "The ones that hold up",
        module: ModuleId(0),
        band: Band::Bronze,
        completion: Completion::Flag,
        scenario: ScenarioId::CardDesfire,
        summary: "DESFire EV2 and Seos do real mutual authentication with real keys. Run 0.2's \
                  clone and 0.4's key recovery against one and watch them stop.",
        objective: "Run each Module 0 attack against the card and record, correctly, why it \
                    failed.",
        flag_text: "Every attack failed, and your diagnosis of why each one failed matches what \
                    the engine observed it hitting.",
        note: "This drill passes on correct diagnosis, not on a successful attack, and that is \
               deliberate. \"It did not work\" is not a finding. \"It did not work because there \
               is no static secret on the card to copy\" is one, and it is the sentence that \
               tells a defender what they bought.",
        guidance: Guidance {
            bronze: &[
                "Authenticate honestly first, with the key. Both ends derive the same session key \
                 and neither of them transmits it. Look at the transcript and confirm that.",
                "Now try the clone from 0.2: capture a field response and replay it. Note where \
                 it stops.",
                "Now try the replay: record one complete authentication and play it back. Note \
                 where that stops, and why it is a different reason.",
                "Now try 0.4's nested recovery: collect the card's nonces and check whether they \
                 lie on a 16-bit LFSR orbit. They do not, and the engine counts how many of your \
                 samples did.",
                "Submit one diagnosis per attack.",
            ],
            silver: &[
                "Three attacks, three different reasons they stop. Name each one; the drill marks \
                 the reasoning, not the outcome.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "A clone copies what the card emits. Ask what this card emits that is the same twice.",
            "A replay needs the other end to accept a message it has seen before. Ask what makes \
             each exchange different.",
            "Crypto1 recovery needs the card's nonces to be predictable. The engine measures that \
             rather than asserting it — check how many sampled pairs sat on the orbit.",
        ],
        taps: NO_TAPS,
        submission: Some("a diagnosis per attack"),
    },
    Drill {
        id: DrillId::new(0, 6),
        title: "The attacks that skip all of this",
        module: ModuleId(0),
        band: Band::Reference,
        completion: Completion::Reference,
        scenario: ScenarioId::NoBench,
        summary: "Request-to-exit sensors triggered from outside, door position switches, crash \
                  bars, under-door tools, and the plain fact that many doors are opened by \
                  defeating the mechanics rather than the electronics.",
        objective: "Read it. There is nothing to run.",
        flag_text: "No flag. This section simulates nothing, and saying it did would be the one \
                    dishonest thing in the course.",
        note: "It is here because a course that teaches only the electronic attacks leaves a \
               learner with a badly calibrated sense of where the risk is — and because a \
               defender who hardens the bus and leaves a gap under the door has bought nothing. \
               The full text is `docs/BYPASS.md`.",
        guidance: Guidance {
            bronze: &[
                "Read the four categories: the request-to-exit path, the door and its frame, the \
                 reader's own housing, and everything that is not the door.",
                "Note which of them the rest of this course can model. The answer is the third \
                 one, partly, and only because drill 1.4's implant is what being behind the \
                 reader buys you.",
                "Nothing here is simulated and nothing here is a technique. It is a list of \
                 categories and roughly where they sit in the ordering.",
                "If you want the mechanical side, find a physical security village at a \
                 conference and spend an afternoon there.",
            ],
            silver: &[
                "Prose, not a bench. It is here so that finishing Modules 1 to 5 does not leave \
                 you with a confident and wrong model of how people get through doors.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[],
        taps: NO_TAPS,
        submission: Some("an acknowledgement that it has been read"),
    },
    // === Module 1 — the wire ================================================
    Drill {
        id: DrillId::new(1, 1),
        title: "What a badge actually says",
        module: ModuleId(1),
        band: Band::Bronze,
        completion: Completion::Flag,
        scenario: ScenarioId::WiegandDoor,
        summary: "Present a card at the reader, watch twenty-six pulses cross the wire, and \
                  decode them by hand with the decoder open beside you.",
        objective: "Submit the facility code and card number the engine transmitted.",
        flag_text: "Your facility code and card number match what crossed the wire, for a \
                    credential the engine randomised from this session's seed.",
        note: "There is no protocol here. Two wires idle high; a zero is a pulse on D0 and a one \
               is a pulse on D1, and the frame ends when the pulses stop. Nothing numbers the \
               frames, nothing signs them, and nothing detects a missing one.",
        guidance: Guidance {
            bronze: &[
                "Clip the sniffer onto the pair. It transmits nothing — the engine enforces that, \
                 so you can leave it there for the rest of the module.",
                "Present the card and run.",
                "Open the captured frame. Twenty-six bits, in transmission order, most \
                 significant first.",
                "Bit 0 is even parity over bits 1 to 13. Bit 25 is odd parity over bits 13 to 25. \
                 Everything between is the payload.",
                "Bits 1 to 8 are the facility code; bits 9 to 24 are the card number. Read them \
                 as plain binary and submit.",
            ],
            silver: &[
                "One badge-in, twenty-six bits, two parity bits and no protection. Decode it by \
                 hand and submit what it says.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "The two parity ranges overlap at bit 13. That is the format, not a mistake.",
            "Eight bits of facility code is 0 to 255. If your number is larger than that you have \
             counted the leading parity bit as data.",
        ],
        taps: SNIFF_WIRE,
        submission: Some("a facility code and a card number"),
    },
    Drill {
        id: DrillId::new(1, 2),
        title: "Parity is not integrity",
        module: ModuleId(1),
        band: Band::Bronze,
        completion: Completion::Flag,
        scenario: ScenarioId::WiegandParityFlip,
        summary: "Flip one bit of the card number, recompute the two parity bits, and watch the \
                  panel accept a badge that was never presented to the reader.",
        objective: "Make the panel act on a card number that no credential at the reader ever \
                    carried.",
        flag_text: "A frame reached the controller that parses cleanly, has valid parity, and \
                    carries a card number that no credential presented to the reader had.",
        note: "Parity is two bits of error detection against noise on a cable. It was never an \
               integrity check and it cannot be one: anybody who can change the payload can \
               recompute it, because the rule is published and there is no key in it.",
        guidance: Guidance {
            bronze: &[
                "Cut the implant into the cable behind the reader. It has to be inline — a clip \
                 that cannot drive the wire cannot change what crosses it, and the engine will \
                 log the attempt as ignored if you try.",
                "Leave it passing through first and present the card, so you can see what the \
                 panel normally receives.",
                "Now arm it: same facility code, card number with the bottom bit flipped.",
                "Recompute both parity bits for the new payload. The implant does this for you; \
                 look at what it produced and check it by hand.",
                "Present the card again. The reader emits your number; the panel receives \
                 somebody else's.",
            ],
            silver: &[
                "The panel checks parity and nothing else. Change the payload and fix the parity.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "The neighbouring card number is on the access list and yours is not. That is why the \
             door opens on the forged frame and not on the genuine one.",
            "A passive tap that asks to modify traffic gets a 'verdict ignored' record rather \
             than a silent no-op. If nothing changed, check the tap's mode.",
        ],
        taps: INLINE_WIRE,
        submission: None,
    },
    Drill {
        id: DrillId::new(1, 3),
        title: "Replay",
        module: ModuleId(1),
        band: Band::Bronze,
        completion: Completion::Flag,
        scenario: ScenarioId::WiegandDoor,
        summary: "Sniff one badge-in, take the card away, and re-emit the captured bits hours \
                  later.",
        objective: "Open the door at a moment when no credential was presented to the reader.",
        flag_text: "The controller granted access at a time when no credential was presented to \
                    the reader, and the engine attributes the frame that caused it to the \
                    attacker's tap.",
        note: "Nothing about this is clever. There is no sequence number to advance, no nonce to \
               match and no timestamp to be stale, so a recording is as good as the card. The \
               only thing that makes a Wiegand replay hard is physical access to the pair.",
        guidance: Guidance {
            bronze: &[
                "Clip the transmitter onto the pair. This one has to be able to drive the wire, \
                 so it is an injecting tap rather than a passive one.",
                "Present the card once and run. The box captures the frame.",
                "Take the card out of the scenario. Nothing else is presented after this point.",
                "Re-emit the captured bits thirty seconds later.",
                "Look at the strike record and at the presentation log. The strike has no \
                 credential behind it.",
            ],
            silver: &["Capture a badge-in and put it back on the wire with no card present."],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "The replay box refuses to transmit bits it never captured, and says so. Capture \
             first.",
            "The flag is about the *absence* of a presentation near the grant, not about the \
             grant on its own. A grant with a card behind it earns nothing.",
        ],
        taps: INJECT_WIRE,
        submission: None,
    },
    Drill {
        id: DrillId::new(1, 4),
        title: "The implant",
        module: ModuleId(1),
        band: Band::Silver,
        completion: Completion::Flag,
        scenario: ScenarioId::WiegandImplant,
        summary: "Insert an inline device between reader and panel. Pass everything through \
                  untouched, then selectively rewrite one credential into another.",
        objective: "Have the panel grant on a badge that never existed, while the reader's own \
                    output is exactly what it always was.",
        flag_text: "The tap is inline, the reader's credential was consumed by it, the controller \
                    granted on a substituted one, and the reader's transmitted bits are unchanged \
                    from the genuine card.",
        note: "This is the class of device an ESPKey or a Tick is. It works because the reader is \
               mounted on the unsecured side of the wall and the conductors are behind it — which \
               is `docs/BYPASS.md`'s third category, and the one place that reference section and \
               this course touch.",
        guidance: Guidance {
            bronze: &[
                "Cut the implant in behind the reader and leave it transparent.",
                "Present your badge. It is not on the access list, so nothing opens. Confirm the \
                 implant swapped nothing.",
                "Arm it with the manager's credential. You know the number because you sniffed it \
                 on a previous day; the drill gives it to you here.",
                "Present your badge again.",
                "Compare two records: what the reader transmitted, and what the panel received. \
                 They differ, and only the second one opened anything.",
            ],
            silver: &[
                "Prove the implant transparent first, then arm it. The interesting assertion is \
                 that the reader's own output never changed.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "An inline tap cuts the link into two electrically separate segments. What the reader \
             drives and what the panel receives are two different records in the log.",
            "Prove transparency before you arm it. An implant that was never transparent is an \
             implant somebody noticed during installation.",
        ],
        taps: INLINE_WIRE,
        submission: None,
    },
    Drill {
        id: DrillId::new(1, 5),
        title: "What brute force actually costs",
        module: ModuleId(1),
        band: Band::Silver,
        completion: Completion::Measurement,
        scenario: ScenarioId::WiegandSweep,
        summary: "Sweep a facility code at real wire timing and watch the clock. Then look at \
                  what the whole space costs at the same timing.",
        objective: "Get the number, and compare it with what drill 1.3 cost you.",
        flag_text: "Not a flag. The drill ends on a figure: the wall-clock cost of the format's \
                    entire credential space at the timing this bench is running.",
        note:
            "This is the drill that puts the rest of the module in proportion. One facility code \
               is minutes. The whole space is days to weeks, at a door, driving pulses onto a \
               cable, with nothing throttling you — and a replay of one captured frame is a \
               second. Brute force is the expensive way to do something you already know how to \
               do cheaply, and that ordering is the finding.",
        guidance: Guidance {
            bronze: &[
                "Clip the transmitter on and choose a facility code to sweep.",
                "Run it. Watch the virtual clock rather than the wall clock — the engine is \
                 running the real frame timing, it is just not running it in real time.",
                "When the door opens, note how many credentials it took.",
                "Now read the figure for the whole space. Turn the wire timing up and read it \
                 again.",
                "Compare both numbers with drill 1.3, which took one frame.",
            ],
            silver: &[
                "Sweep one facility code, then look at what the whole space would cost at the \
                 timing you chose.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "A 26-bit format is not a 26-bit space. Two of those bits are parity and are \
             determined by the other twenty-four.",
            "The fastest plausible wire timing still leaves the full sweep in days. The timing \
             knob changes the answer by an order of magnitude and does not change the \
             conclusion.",
        ],
        taps: INJECT_WIRE,
        submission: None,
    },
    Drill {
        id: DrillId::new(1, 6),
        title: "Clock-and-data",
        module: ModuleId(1),
        band: Band::Silver,
        completion: Completion::Flag,
        scenario: ScenarioId::ClockDataDoor,
        summary: "The same exercise on ABA track 2 — magstripe emulation over two wires. \
                  Different encoding, identical outcome.",
        objective: "Replay a badge-in on a clock-and-data link.",
        flag_text: "The controller granted on bits the attacker re-emitted, and the capture the \
                    attacker holds is a clock-and-data capture rather than a Wiegand one.",
        note: "Worth doing precisely because it is boring. The encoding changed completely — a \
               clock line and a data line instead of two data lines, five-bit BCD characters with \
               odd parity instead of a 26-bit frame — and not one thing about the attack changed. \
               The weakness was never in the encoding.",
        guidance: Guidance {
            bronze: &[
                "Note the link type in the bench strip. This is a CLOCK/DATA pair, not D0/D1.",
                "Clip the transmitter on and present the card.",
                "Look at the capture. The engine records which medium it came off; it is not a \
                 Wiegand frame and the attacker's own notes say so.",
                "Re-emit it later with no card present.",
            ],
            silver: &["Same attack as 1.3, different two-wire protocol. Confirm it is different."],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "The panel here is configured for a track-2 bit pattern rather than a card number, \
             because a track-2 bit pattern is all a panel on this link ever has.",
            "The clock line tells the receiver when to sample. It does not authenticate anything \
             and there is nothing on the pair that does.",
        ],
        taps: INJECT_WIRE,
        submission: None,
    },
    // === Module 2 — OSDP as it is usually deployed ==========================
    Drill {
        id: DrillId::new(2, 1),
        title: "Reading the bus",
        module: ModuleId(2),
        band: Band::Bronze,
        completion: Completion::Flag,
        scenario: ScenarioId::OsdpClear,
        summary: "A controller polling a reader, tens of times a second. Find the frame carrying \
                  the card read and label it byte by byte.",
        objective: "Label the byte offsets of every field of the card-read reply.",
        flag_text: "Every field offset you submitted matches the layout of the frame the engine \
                    generated and put on the bus.",
        note: "The timeline shows the polling honestly by default, which means it looks like a \
               solid bar. That is what a real OSDP link looks like, and it is also exactly what \
               makes drill 4.1 work — so the collapse control is there, it is obvious, and it is \
               always something you chose.",
        guidance: Guidance {
            bronze: &[
                "Clip a passive probe onto the RS-485 pair and run.",
                "Filter the traffic list for the card read. It is a reply, and its code is \
                 REPLY_RAW.",
                "Open it in the inspector. Byte 0 is SOM, 0x53. Byte 1 is the address, with bit 7 \
                 set because this is a reply.",
                "Bytes 2 and 3 are the length, LSB first, counting SOM through the trailer. Byte \
                 4 is the control byte: sequence in bits 0 and 1, CRC flag in bit 2, security \
                 block flag in bit 3.",
                "After the control byte comes the reply code, then the payload, then the \
                 two-byte CRC. Submit the offsets.",
                "Look at the 'requires the session key' column in the inspector. It is empty, and \
                 that is the Module 2 lesson.",
            ],
            silver: &[
                "Find the card read on the bus and label its fields. The inspector will confirm \
                 you, but do it by hand first.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "The length field counts from SOM to the end of the trailer, and it is little-endian.",
            "Bit 3 of the control byte is clear on this bench, so there is no security block and \
             no MAC. The reply code sits immediately after the control byte.",
            "The trailer is two bytes here because bit 2 of the control byte is set: CRC-16, not \
             the one-byte checksum.",
        ],
        taps: SNIFF_BUS,
        submission: Some("byte offsets for each field"),
    },
    Drill {
        id: DrillId::new(2, 2),
        title: "It is still in the clear",
        module: ModuleId(2),
        band: Band::Bronze,
        completion: Completion::Flag,
        scenario: ScenarioId::OsdpClear,
        summary: "No Secure Channel configured, which is how a large share of OSDP installations \
                  are running right now. Sniff a badge-in.",
        objective: "Extract the card number from passive observation, having injected nothing.",
        flag_text: "The attacker holds a card number matching the credential presented at the \
                    reader, bit for bit, and the world's own log says it transmitted zero frames.",
        note: "\"Zero frames injected\" is the engine's statement, not the attacker's. A passive \
               tap physically cannot drive the pair in this model, and the count comes from the \
               world's injection log rather than from the actor claiming good behaviour.",
        guidance: Guidance {
            bronze: &[
                "Check the security panel in the bench strip. It says Secure Channel is off. Do \
                 not change it.",
                "Clip a passive probe on and run.",
                "Present the card.",
                "Find REPLY_RAW and read the payload. It is the same bit pattern Module 1 put on \
                 D0/D1, wrapped in a frame.",
            ],
            silver: &[
                "The bus carries the credential in the clear. Take it without touching anything.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "REPLY_RAW carries a format byte, a bit count and then the bits. The bit count \
             matters — four bytes of payload could be twenty-six bits or thirty-two.",
            "If the attacker's injection count is not zero, something on the bench is not passive.",
        ],
        taps: SNIFF_BUS,
        submission: None,
    },
    Drill {
        id: DrillId::new(2, 3),
        title: "Injection on an unsecured bus",
        module: ModuleId(2),
        band: Band::Bronze,
        completion: Completion::Flag,
        scenario: ScenarioId::OsdpClear,
        summary: "Nothing authenticates the controller. If you can drive the pair and hit the gap \
                  between polls, you are the controller.",
        objective: "Get the peripheral to acknowledge a command you sent.",
        flag_text: "The PD ACKed a command whose origin the engine's cause chain traces back to \
                    the attacker's tap.",
        note: "A well-formed injected frame on an unsecured bus is not merely hard to spot, it is \
               *indistinguishable*: there is no origin field, no signature and no per-device \
               secret outside Secure Channel, so the bytes you send are the bytes a legitimate \
               controller would have sent. Module 5 comes back to this, and the answer there is \
               that injection on an unsecured bus is a configuration problem rather than a \
               monitoring one.",
        guidance: Guidance {
            bronze: &[
                "Clip a transmitter onto the pair and run for a second so it can hear who is on \
                 the bus.",
                "Check which addresses answered. The injector will refuse to forge to an address \
                 it has never heard, and says so.",
                "Send a command. Sequence zero means 'I have just started' and any peripheral \
                 accepts it from anybody — which is the protocol's own doing.",
                "Watch for the ACK, and check the cause chain: the engine attributes the reply to \
                 your frame rather than to the controller's.",
            ],
            silver: &[
                "Listen until you know who is out there, then talk to them. Mind the gap between \
                 polls; two transmitters at once destroy each other.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "The injector refuses an address it has not heard answering. That is deliberate — an \
             attacker cannot forge to a device it does not know is there.",
            "Sequence zero is the reset value. A peripheral takes it without checking, which is \
             why two bits of sequence number were never an anti-replay measure.",
        ],
        taps: INJECT_BUS,
        submission: None,
    },
    Drill {
        id: DrillId::new(2, 4),
        title: "Sequence numbers and BUSY",
        module: ModuleId(2),
        band: Band::Silver,
        completion: Completion::Flag,
        scenario: ScenarioId::OsdpClear,
        summary: "What the protocol does defend against: desynchronised sequence numbers, \
                  retries, and the BUSY reply. None of it is security, and knowing which is which \
                  matters.",
        objective: "Push the link out of step and bring it back without restarting the \
                    simulation.",
        flag_text: "The peripheral objected to a sequence number, and the same running world went \
                    on to carry normal traffic again — one simulation start, not two.",
        note:
            "Sequence numbers are two bits. They cycle 1, 2, 3, so one repeat in three collides, \
               and two genuine card reads four seconds apart can be byte-for-byte identical, CRC \
               included. They are a link-layer retransmission aid and they were never anything \
               else. Module 5 has a test named after what that costs a defender.",
        guidance: Guidance {
            bronze: &[
                "Run until the link is in its steady polling state.",
                "Push the controller's sequence numbering one step out of line with the \
                 peripheral's.",
                "Watch what the peripheral does: a sequence mismatch, then a NAK with error code \
                 0x04.",
                "Keep running. The controller resynchronises from sequence zero on its own — do \
                 not reload the drill.",
                "Read the log from the moment of the fault to the moment traffic resumed, and \
                 write down how long the link was unusable.",
            ],
            silver: &[
                "Break the sequence, then get the link back without reloading. The recovery \
                 mechanism is in the protocol; find it in the log.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "A NAK with error 0x04 is 'sequence number error'. It is the peripheral asking for a \
             restart rather than refusing to talk.",
            "Reloading the drill would also fix it, and would prove nothing. The flag counts how \
             many times the simulation started.",
        ],
        taps: NO_TAPS,
        submission: None,
    },
    // === Module 3 — Secure Channel ==========================================
    Drill {
        id: DrillId::new(3, 1),
        title: "The handshake, step by step",
        module: ModuleId(3),
        band: Band::Bronze,
        completion: Completion::Flag,
        scenario: ScenarioId::OsdpDefaultKey,
        summary: "CHLNG, CCRYPT, SCRYPT, RMAC_I. Watch the session keys derive, with every \
                  intermediate value on screen.",
        objective: "Given the key and both nonces, predict the client cryptogram before the \
                    peripheral transmits it.",
        flag_text: "The sixteen bytes you submitted are the client cryptogram the peripheral \
                    subsequently put on the bus.",
        note: "Two things are worth noticing while you do this. Only forty-eight bits of the \
               controller's nonce reach the session keys, and the peripheral's nonce contributes \
               none of them — so the key space of a session is smaller than the key. And the \
               whole exchange is unprotected, because there is no session yet to protect it with.",
        guidance: Guidance {
            bronze: &[
                "Clip a passive probe on and run until the handshake completes.",
                "Find CMD_CHLNG. Its payload is RND.A, the controller's eight-byte nonce, in the \
                 clear.",
                "Find REPLY_CCRYPT. Its payload is the peripheral's identifier, then RND.B, then \
                 the sixteen-byte client cryptogram.",
                "Derive the session keys yourself: S-ENC is AES-ECB under the SCBK of a fixed \
                 prefix, the constant 0x82, and the first six bytes of RND.A.",
                "The client cryptogram is AES-ECB under S-ENC of RND.A followed by RND.B. Compute \
                 it and submit it before you look at the reply's last sixteen bytes.",
            ],
            silver: &[
                "Everything you need is on the wire except the key, and this bench is using the \
                 published one. Derive S-ENC and compute the cryptogram.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "Only six bytes of RND.A go into the key derivation. The other two are on the wire \
             and do nothing.",
            "The cryptogram is a single AES-ECB block: RND.A ‖ RND.B is exactly sixteen bytes.",
            "If your cryptogram is wrong, check whether you derived S-ENC or S-MAC1. They differ \
             by one constant byte.",
        ],
        taps: SNIFF_BUS,
        submission: Some("the sixteen-byte client cryptogram"),
    },
    Drill {
        id: DrillId::new(3, 2),
        title: "The default key",
        module: ModuleId(3),
        band: Band::Bronze,
        completion: Completion::Flag,
        scenario: ScenarioId::OsdpDefaultKey,
        summary: "A peripheral commissioned with SCBK-D. Recognise it from the security block's \
                  key-type byte, then decrypt everything.",
        objective: "Decrypt a card read, given nothing but the bus traffic.",
        flag_text: "The attacker holds the session keys and has recovered the plaintext of a card \
                    read that was genuinely encrypted on the wire, having transmitted nothing.",
        note: "The key-type byte announces which key is in use, in the clear, in the handshake. \
               An eavesdropper does not have to guess that a link is on the default key; it is \
               told. That costs the attacker nothing and it is in the specification.",
        guidance: Guidance {
            bronze: &[
                "Clip a passive probe on and run until the handshake completes.",
                "Open the security block on CMD_CHLNG. The key-type byte says 'default'.",
                "Let the sweep run. SCBK-D is the first candidate it tries and it takes four AES \
                 operations to confirm.",
                "Present a card and look at REPLY_RAW. It really is encrypted — check the \
                 inspector's 'requires the session key' column.",
                "Now read it anyway. The plaintext appears beneath the ciphertext with a KEY HELD \
                 marker, so it can never be mistaken for something an observer had for free.",
            ],
            silver: &[
                "The handshake tells you which key class is in use. One of those classes is \
                 published.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "A wrong key is rejected in four AES operations. The sweep is not slow because the \
             candidate list is short and the check is cheap.",
            "The attacker is neither endpoint, so it cannot use a normal secure channel object. \
             It reconstructs both MAC chains from what it observed.",
        ],
        taps: SNIFF_BUS,
        submission: None,
    },
    Drill {
        id: DrillId::new(3, 3),
        title: "Weak keys",
        module: ModuleId(3),
        band: Band::Silver,
        completion: Completion::Flag,
        scenario: ScenarioId::OsdpWeakKey,
        summary: "A site key that is not SCBK-D and is still out of a vendor's sample code: a \
                  repeated byte, or an ascending or descending run. About 768 of them are \
                  published.",
        objective: "Recover the site key from one captured handshake.",
        flag_text: "The key the attacker recovered equals the key the peripheral is actually \
                    configured with, found by sweeping candidates against a captured handshake \
                    and nothing else.",
        note: "This attack is completely invisible. The capture is passive, the sweep happens on \
               a laptop in a car park, and nothing goes back onto the bus. Module 5 asks which \
               Module 3 attacks a monitor can see, and this is the one that is not on the list — \
               not because the rule is hard to write but because there is no observable to write \
               it against.",
        guidance: Guidance {
            bronze: &[
                "Clip a passive probe on and capture one complete handshake. One is enough.",
                "Note that the key-type byte says 'site key', not 'default'. This is not 3.2.",
                "Run the sweep. It generates the published family and tests each candidate \
                 against the captured cryptograms.",
                "Compare what it found with what the peripheral is configured with.",
                "Then switch the bench to a real key and run the sweep again. It tries all 768 \
                 and finds nothing, which is the control that makes the first result mean \
                 something.",
            ],
            silver: &[
                "One handshake, a published family of about 768 candidates, and four AES \
                 operations per candidate.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "The family is repeated bytes, ascending runs and descending runs. It is not a \
             dictionary of guesses; it is what the sample code in several vendors' documentation \
             actually contains.",
            "The negative control matters more than the attack. A key outside the family survives \
             all 768, and the attacker gets an honest failure rather than a plausible-looking \
             wrong answer.",
        ],
        taps: SNIFF_BUS,
        submission: None,
    },
    Drill {
        id: DrillId::new(3, 4),
        title: "Install mode",
        module: ModuleId(3),
        band: Band::Silver,
        completion: Completion::Flag,
        scenario: ScenarioId::OsdpInstallMode,
        summary: "A controller left in install mode after commissioning. Answer for an address \
                  nobody fitted, and it will push you the site key.",
        objective: "End up holding the site key, having sent nothing but well-formed protocol \
                    traffic.",
        flag_text: "The attacker holds the key the real reader was commissioned with, every frame \
                    it sent was a valid OSDP reply to the command immediately before it, and it \
                    never collided with anybody.",
        note: "The curriculum calls these 'legitimate protocol requests'. What the attacker \
               actually sends here are *replies*: it impersonates a peripheral at an address the \
               installer configured and never fitted, and the controller volunteers the key. The \
               checkable claim is the stronger one — every frame well-formed, addressed to the \
               address it claimed, with a reply code in the standard, and no collisions.",
        guidance: Guidance {
            bronze: &[
                "Look at the controller's configuration. It is polling two addresses and only one \
                 reader exists.",
                "Clip a transceiver onto the pair and have it answer for the unused address.",
                "Let it complete the identity and capability exchange, then the handshake under \
                 the default key — which is what an uncommissioned reader would do.",
                "The controller, being in install mode, sends CMD_KEYSET with the site key.",
                "Check what it holds against what the real reader is configured with. Then turn \
                 install mode off and run it again: it gets nothing.",
            ],
            silver: &[
                "The controller is polling an address that has no reader on it. Be that reader.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "A fresh peripheral comes up on SCBK-D. Claim to be one.",
            "The negative control is the point of the drill. With install mode off the same \
             sequence of frames yields nothing at all, which tells a defender exactly which \
             setting to go and look at.",
        ],
        taps: INJECT_BUS,
        submission: None,
    },
    Drill {
        id: DrillId::new(3, 5),
        title: "Keyset capture",
        module: ModuleId(3),
        band: Band::Silver,
        completion: Completion::Flag,
        scenario: ScenarioId::OsdpCommissioning,
        summary: "Be on the bus during commissioning. There is no key exchange to attack, because \
                  there is no key exchange — the site key is pushed to the peripheral in a \
                  command.",
        objective: "Capture the CMD_KEYSET payload and read the traffic that follows it.",
        flag_text: "The attacker captured the site key out of a CMD_KEYSET, that key is the one \
                    the reader is now commissioned with, and the attacker decrypted a card read \
                    from after the re-handshake.",
        note: "The commissioning flow here — meet an uncommissioned peripheral on SCBK-D, push \
               the site key, re-handshake under it — follows the published description rather \
               than a captured session from real hardware. Whether a real controller \
               re-handshakes immediately or waits for the next reset is worth checking against a \
               panel, and it would change how the capture has to be split.",
        guidance: Guidance {
            bronze: &[
                "Clip a passive probe on before the installer starts. Everything after this is \
                 just watching.",
                "The peripheral is fresh, so the first channel comes up under SCBK-D — which is \
                 published, so you can read the commissioning session.",
                "Find CMD_KEYSET inside it. Its payload is the site key.",
                "The peripheral accepts and both ends re-handshake under the new key. You have \
                 that key, so you can follow.",
                "Present a card after commissioning and decrypt the read.",
            ],
            silver: &[
                "The site key crosses the bus inside a channel keyed with a published default. \
                 Be there when it does.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "The first channel is protected by a key anybody can look up. That is the whole \
             weakness — the protection on the key exchange is the default key.",
            "The last handshake for an address is the site-key one. Split your capture there.",
        ],
        taps: SNIFF_BUS,
        submission: None,
    },
    Drill {
        id: DrillId::new(3, 6),
        title: "Downgrade",
        module: ModuleId(3),
        band: Band::Gold,
        completion: Completion::Flag,
        scenario: ScenarioId::OsdpRequiredSc,
        summary: "Inline, before the handshake. Rewrite the capability reply so the reader claims \
                  it cannot do crypto, and the controller believes it.",
        objective: "Get card reads flowing in the clear on a link where both ends were configured \
                    to require Secure Channel.",
        flag_text: "The link reached a steady online state carrying a card read with no security \
                    block at all, where both endpoints were configured to require Secure Channel \
                    and the peripheral's own configuration never changed.",
        note: "The setting that makes this work is the controller deciding whether to run a \
               handshake *from the peripheral's capability reply* — an unauthenticated frame sent \
               before any key material exists. 'Required' in this class of product means \
               'required of readers that support it'. That sentence is the vulnerability. Turn \
               that setting off and the same attack becomes a no-op, and a genuinely legacy \
               reader is refused rather than downgraded.",
        guidance: Guidance {
            bronze: &[
                "Read both configurations first. The controller requires Secure Channel and so \
                 does the reader. Write down what you expect to see on the bus.",
                "Cut an implant into the RS-485 pair before the controller starts polling. After \
                 the handshake is too late — you would have to forge a MAC you have no key for.",
                "Let the controller ask for capabilities. Rewrite the reply on its way past: \
                 remove the 0x09 communication-security entry so the reader claims no AES-128.",
                "Pass everything else through untouched, original CRC included. A tap that \
                 disturbs the rest of the bus is a tap somebody notices.",
                "Present a card. The read crosses with no security block at all, and both \
                 endpoints still believe they are configured correctly.",
                "Check the reader's own configuration afterwards. It never changed. Only the wire \
                 did.",
            ],
            silver: &[
                "Both ends require Secure Channel, and the controller decides whether to run one \
                 from an unauthenticated frame. Get between them before it asks.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "It has to be inline, and it has to be inline before the handshake. A tap that cannot \
             cut the cable cannot change what crosses it.",
            "Replacing a frame does not recompute its MAC — you have no session key. That is why \
             the only frame worth rewriting is one sent before there is a session.",
            "Look at REPLY_PDCAP and at the 0x09 communication-security entry in it.",
        ],
        taps: INLINE_BUS,
        submission: None,
    },
    // === Module 4 — the weaknesses nobody mentions ==========================
    Drill {
        id: DrillId::new(4, 1),
        title: "Traffic analysis through encryption",
        module: ModuleId(4),
        band: Band::Silver,
        completion: Completion::Flag,
        scenario: ScenarioId::OsdpEncryptedDay,
        summary: "The command and reply code byte is plaintext even inside Secure Channel. You \
                  cannot read the card number. You can read the building's schedule.",
        objective: "Report the time of every badge-in over the simulated day, without ever \
                    holding a key.",
        flag_text: "Every badge-in in the engine's own presentation log appears in your list, \
                    nothing you listed is invented, and the attacker held no key and no payload \
                    byte.",
        note: "This is the one in the module that a correct deployment does not fix. Encrypt \
               everything, use a real site key, keep your firmware current — and the times people \
               come and go are still legible from the riser, because the id byte has to be \
               readable for the protocol to work at all.",
        guidance: Guidance {
            bronze: &[
                "Clip a passive probe on. It will never hold a key in this drill and it does not \
                 need one.",
                "Run the day. The bus is fully encrypted; confirm that in the security panel and \
                 in the inspector.",
                "Look at the readable column of an encrypted frame. The reply code is in it.",
                "A badge-in is a REPLY_RAW: a reply code the analyst can read, at a time the \
                 analyst can measure. A grant is the CMD_OUT that follows it.",
                "List the times and submit them.",
            ],
            silver: &[
                "You will not get a card number. Get the schedule instead, from the one field the \
                 protocol cannot hide.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "The analyst here never stores a frame — only a header: time, direction, address, id \
             byte, security block type, length. There is no payload byte in its possession to \
             accidentally use.",
            "The gap between a card touching the reader and the reply crossing the bus is the \
             read time plus up to one polling interval. The polling interval is the most visible \
             thing on the link, so you can measure it.",
        ],
        taps: SNIFF_BUS,
        submission: Some("a list of badge-in times"),
    },
    Drill {
        id: DrillId::new(4, 2),
        title: "Truncated MACs",
        module: ModuleId(4),
        band: Band::Gold,
        completion: Completion::Flag,
        scenario: ScenarioId::OsdpShortMac,
        summary: "Thirty-two bits of MAC, no attempt limiter, and a peripheral that does not \
                  advance its chain when it rejects a frame. Work out what that is worth.",
        objective: "Produce a frame the peripheral accepts whose MAC was not derived from the \
                    session key.",
        flag_text: "The peripheral accepted a frame the attacker built, its MAC was not computed \
                    with the session key, and the engine's cause chain attributes the acceptance \
                    to the attacker's frame.",
        note: "**This bench is rigged and the drill will not pretend otherwise.** The MAC is \
               shortened so the search finishes while you are watching. Four MAC bytes still go \
               on the wire; only the first carries anything, and the attacker *measures* that \
               from genuine frames rather than being told — on a real bus that measurement \
               returns four and this does not finish. Beside the rigged attack, the genuine \
               32-bit search is running on a bar that will still be moving when you close the \
               tab. That bar is the drill.",
        guidance: Guidance {
            bronze: &[
                "Let the session come up first. There is nothing to forge into until there is a \
                 channel.",
                "Calibrate. Count how many MAC bytes on this bus actually carry anything — do not \
                 read it out of the configuration, measure it off genuine frames.",
                "Note what the measurement returned, and note what it would return on a real bus. \
                 The difference is the rigging, and it is visible from the wire.",
                "Isolate the peripheral by dropping the controller's commands, so its session \
                 stays alive and its sequence numbering is yours.",
                "Sweep. A rejected frame advances neither chain, so the target is fixed and you \
                 can enumerate rather than guess.",
                "Now look at the second bar. That is the same attack against four MAC bytes \
                 instead of one, at this bus's own round-trip rate. Leave it running.",
            ],
            silver: &[
                "The bench is rigged so this finishes. Measure by how much, then read the \
                 genuine figure off the bar beside it.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "Calibrate before you forge. Count the significant bytes in genuine MACs on this bus \
             and you will know what you are up against.",
            "A rejected frame advances neither MAC chain, so the target is fixed for a given \
             sequence number. That makes this a sweep rather than a guess.",
            "Isolating the peripheral keeps its session alive and its sequence numbering \
             attributable to you. It is also loud: the controller times out, retries, and \
             eventually marks the address offline.",
        ],
        taps: INLINE_BUS,
        submission: None,
    },
    Drill {
        id: DrillId::new(4, 3),
        title: "IV reuse",
        module: ModuleId(4),
        band: Band::Gold,
        completion: Completion::Flag,
        scenario: ScenarioId::OsdpCommissioning,
        summary: "IVs derive from the previous MAC, and the chain in each direction only advances \
                  when the *other* direction speaks. Freeze one direction and identical plaintext \
                  produces identical ciphertext.",
        objective: "Read the contents of a frame your own decryptor cannot open.",
        flag_text: "The attacker recovered the plaintext of a frame by matching its ciphertext to \
                    one whose contents it already knew, on a frame its own chained decryptor \
                    could not open.",
        note: "Be precise about what this buys, because the loose version of the claim is wrong. \
               A reused IV does not turn ciphertext into plaintext on its own; no arithmetic does \
               that without an anchor. What it yields is **equality** — the knowledge that two \
               frames carry the same thing. That becomes recovery the moment one member of the \
               group is known, and an attacker who has watched a building for a day knows plenty \
               of them. This drill teaches the codebook, not a decryption.",
        guidance: Guidance {
            bronze: &[
                "Two boxes on one pair: a passive analyser and an inline implant. A real operator \
                 has both.",
                "The analyser cracks the commissioning channel, which is keyed with the published \
                 default. That gives you an anchor — one plaintext you know for certain.",
                "Have the implant start swallowing replies once it sees a particular command \
                 byte. The command byte is plaintext at every security level, so this trigger \
                 needs no key.",
                "The controller times out and retransmits. Its IV is the last reply MAC and no \
                 reply has arrived, so the IV has not moved and the ciphertext is identical.",
                "Group the identical ciphertexts. That grouping needs no key at all — it is just \
                 equality.",
                "Attach the anchor's plaintext to its group. Every other member of that group is \
                 now readable, including frames your own chained decryptor refuses to open.",
            ],
            silver: &[
                "Freeze one direction's IV chain and collect the retransmissions. Then find one \
                 plaintext you already know.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "A command's IV is the last reply MAC and a reply's IV is the last command MAC. Only \
             one of those two chains can be frozen from an inline position.",
            "Suppress replies and the controller retransmits. Its IV has not moved, so the \
             retransmission is byte-identical.",
            "You need an anchor: one frame in the group whose plaintext you know by other means. \
             The commissioning channel is keyed with a published default.",
        ],
        taps: INLINE_AND_SNIFF_BUS,
        submission: None,
    },
    Drill {
        id: DrillId::new(4, 4),
        title: "The null ciphers",
        module: ModuleId(4),
        band: Band::Silver,
        completion: Completion::Flag,
        scenario: ScenarioId::OsdpNullCipher,
        summary: "SCS_15 and SCS_16 authenticate without encrypting. The status display says \
                  'secure channel established' and the payloads are in the clear.",
        objective: "Read a payload off a link that is MACed and not encrypted.",
        flag_text: "The attacker recovered a payload in the clear from a link with Secure Channel \
                    established, where the frames carried a MAC and no encryption.",
        note: "The curriculum words this flag as reading a *card number*, and this bench cannot \
               produce that frame: the peripheral model in `odr-bus` always asks for encryption \
               on its card reads, so the null cipher is reachable in the command direction only. \
               What you will read here is the door-open command, in the clear, inside an \
               established session — which is the same lesson and arguably a worse finding. \
               Making the literal flag reachable needs one field on the peripheral's \
               configuration, and that is a change to another crate rather than something to work \
               around here.",
        guidance: Guidance {
            bronze: &[
                "Check the security panel. Secure Channel is established and encryption is off.",
                "Clip a passive probe on and run.",
                "Present a card so the controller drives the strike.",
                "Find CMD_OUT. The security block is SCS_15, the frame carries a MAC, and the \
                 payload is readable without any key.",
                "Compare that with the same drill in 3.2, where the payload was genuinely \
                 opaque.",
            ],
            silver: &[
                "Authenticated is not encrypted. Find the frames that say SCS_15 or SCS_16 and \
                 read them.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "An empty payload legitimately uses SCS_15, because there is nothing to encrypt. A \
             non-empty SCS_15 payload is the finding.",
            "The MAC still verifies. Nothing here is forged; it is simply readable.",
        ],
        taps: SNIFF_BUS,
        submission: None,
    },
    // === Module 5 — the other chair =========================================
    Drill {
        id: DrillId::new(5, 1),
        title: "What a monitor can see",
        module: ModuleId(5),
        band: Band::Silver,
        completion: Completion::Flag,
        scenario: ScenarioId::MonitoredDay,
        summary: "Of the attacks in Module 3, which are visible to a passive monitor at all? \
                  Build a rule set and run it against a generated day.",
        objective: "Score full marks on the day's attacks without a single false positive.",
        flag_text: "Your rule set found every attack the answer key says a monitor could have \
                    found, raised nothing on the benign traffic, and every citation in your \
                    report still names the bytes it claims to.",
        note: "The interesting result here is the one that is missing. Drill 3.3's weak-key crack \
               is not in the key, because it produces no observable: the capture is passive, the \
               sweep happens elsewhere, and nothing goes back on the bus. A rule set that claimed \
               to catch it would be claiming something a defender cannot have. Install mode and \
               keyset capture do show up, and only ever ambiguously — see 5.3.",
        guidance: Guidance {
            bronze: &[
                "Generate the day. Twelve episodes, each its own little story, with a minute of \
                 silence between them.",
                "Everything your rules get is the capture file: timestamps and hex. Not the \
                 configuration, not the keys, not the engine's cause chain.",
                "Start with the standard rule set and read what each rule says it looks for and \
                 what it deliberately does not fire on.",
                "Run it and read the score. Check the false-positive list before the \
                 true-positive one.",
                "Then check each finding's evidence: which frames it cites, and whether the \
                 benign explanation was considered and excluded.",
            ],
            silver: &[
                "A day of mixed traffic and an answer key you do not get to see. Precision \
                 matters more than recall here.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "Four confidence levels, and they are statements about the *link* rather than about \
             your code. 'Ambiguous' means nobody could determine the cause from traffic, ever.",
            "A rule set that catches less and never cries wolf is a better rule set than one that \
             catches more and does.",
        ],
        taps: MONITOR_BUS,
        submission: None,
    },
    Drill {
        id: DrillId::new(5, 2),
        title: "A rule that does not cry wolf",
        module: ModuleId(5),
        band: Band::Silver,
        completion: Completion::Flag,
        scenario: ScenarioId::MonitoredDay,
        summary: "Build a detection rule that catches the downgrade and does not fire on a \
                  genuine legacy reader being added to the bus.",
        objective: "Catch the downgrade, stay silent on the two benign episodes that look exactly \
                    like it.",
        flag_text: "Your rule set reported a capability downgrade inside the downgrade episode, \
                    and raised nothing during the legacy-reader-added and reader-replaced \
                    episodes.",
        note: "Three things make the difference: a downgrade is a *change* and needs a prior \
               claim from the same address; device memory outlives link continuity, so a monitor \
               may remember 'address 1 claimed AES-128' across a silence even though it may not \
               remember a sequence number across one; and the identity reply separates a \
               capability drop from a reader replacement. That last one buys **quiet, not \
               security** — the identity reply is exactly as unauthenticated as the capability \
               reply, and an attacker already rewriting one can rewrite the other for free.",
        guidance: Guidance {
            bronze: &[
                "Find the three episodes that all look like 'this address stopped claiming \
                 AES-128': the downgrade, the legacy reader added at a new address, and the \
                 reader replaced at an existing one.",
                "Write the naive rule first — alert on any peripheral not claiming AES-128 — and \
                 run it. It catches the attack and fires on both benign cases.",
                "Now require a prior claim from the same address. The new address drops out.",
                "Now compare the reported device identity across the change. The replacement \
                 drops out too.",
                "Run the strict variant, which turns the identity check off. It catches the \
                 identity-spoofing version of the attack and alerts on every reader swap. Both \
                 halves of that trade are real; pick one deliberately.",
            ],
            silver: &[
                "The naive rule catches the attack and every legacy reader ever installed. Find \
                 what separates them, and be honest about what it costs.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "A reader that has never claimed AES-128 has not been downgraded. It has been \
             installed.",
            "A monitor cannot prove the earlier capability claim was the true one rather than an \
             implant that has just been removed. That is why this finding is never 'certain'.",
        ],
        taps: MONITOR_BUS,
        submission: None,
    },
    Drill {
        id: DrillId::new(5, 3),
        title: "The one you cannot call",
        module: ModuleId(5),
        band: Band::Silver,
        completion: Completion::Flag,
        scenario: ScenarioId::MonitoredDay,
        summary: "What does install mode look like in a log, and why is it usually \
                  indistinguishable from a real commissioning?",
        objective: "Report the keyset event, and report it as undecidable.",
        flag_text: "Your rule set reported the keyset during the commissioning episode, marked it \
                    as undecidable from traffic, and the scorer counted it as ambiguous rather \
                    than as a hit or a false alarm.",
        note: "The event is unmistakable and the authorisation is not in any frame. OSDP has no \
               notion of who a controller is, so a commissioning and an attacker in install mode \
               produce identical traffic, and the only thing that separates them is whether an \
               installer was booked — which is a change record, not a capture. A learner is \
               neither rewarded for reporting this nor punished for it, which is exactly the \
               position a defender is in.",
        guidance: Guidance {
            bronze: &[
                "Find CMD_KEYSET in the day. There is exactly one commissioning episode.",
                "Ask what in the frame tells you whether it was authorised. Work through the \
                 fields; the answer is nothing.",
                "Report it anyway. Severity is critical — it is site key material on a bus — and \
                 confidence is 'ambiguous', which means the cause cannot be determined from \
                 traffic by anybody, ever.",
                "Look at how the scorer treats it. It is counted separately and excluded from \
                 both precision and recall.",
                "Write down what a site would need in order to resolve it. It is a change-control \
                 record, and it is not on the wire.",
            ],
            silver: &[
                "One event, two completely different causes, identical bytes. Report it and say \
                 so.",
            ],
            gold: NO_GUIDANCE,
        },
        hints: &[
            "'Critical' and 'ambiguous' are not a contradiction. Severity is about impact; \
             confidence is about what the link permits.",
            "If your rule set marks this as certain, it is claiming to know something that is not \
             in any frame.",
        ],
        taps: MONITOR_BUS,
        submission: None,
    },
];

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// How many drills the course has.
pub fn drill_count() -> usize {
    DRILLS.len()
}

/// Look a drill up by id.
pub fn drill(id: DrillId) -> Option<&'static Drill> {
    DRILLS.iter().find(|d| d.id == id)
}

/// Look a drill up by the string the site uses: `"1.3"`.
pub fn drill_by_name(name: &str) -> Option<&'static Drill> {
    DrillId::parse(name).and_then(drill)
}

/// Look a drill up, or say why not.
pub fn require(id: DrillId) -> Result<&'static Drill> {
    drill(id).ok_or(ScenarioError::UnknownDrill { id: id.as_string() })
}

/// Look a module up by id.
pub fn module(id: ModuleId) -> Option<&'static Module> {
    MODULES.iter().find(|m| m.id == id)
}

/// The drills in one module, in curriculum order.
pub fn drills_in(module: ModuleId) -> Vec<&'static Drill> {
    DRILLS.iter().filter(|d| d.module == module).collect()
}

/// The drills that run on one bench.
pub fn drills_using(scenario: ScenarioId) -> Vec<&'static Drill> {
    DRILLS.iter().filter(|d| d.scenario == scenario).collect()
}
