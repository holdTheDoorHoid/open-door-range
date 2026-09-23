# Curriculum

The drill list. Each drill names the flag predicate — the condition the *engine* must
report before the flag is awarded. No drill checks a typed answer; every flag is earned by
the simulation actually reaching a state. If a predicate here cannot be expressed against
engine state, the drill is wrong and needs redesigning, not a workaround.

Difficulty bands: **Bronze** (guided, a beginner cannot get stuck), **Silver** (the
sandbox with objectives, hints on request), **Gold** (an objective and nothing else).

---

## Module 0 — The credential

Before the wire, the card. This module exists because the reader was never the weak part,
and a learner who starts at Wiegand has already skipped the cheapest attack in the
building.

**0.1 What a prox card is** · Bronze
A 125 kHz EM4100 tag: no processor, no key, no challenge. It shouts its number at anything
that energises it, forever, to anyone.
*Flag:* the learner reads a tag's ID off the modulated carrier and matches the engine's
value.

**0.2 Cloning 125 kHz** · Bronze
Copy the number onto a writable tag. There is nothing to defeat — the format has no
concept of authentication.
*Flag:* a cloned tag presents to the reader and the controller grants, where the original
tag was never presented.

**0.3 HID Prox and the format problem** · Silver
H10301 over the air. The same facility-code-and-card-number payload you will meet again on
the wire in Module 1 — and seeing it twice is the point, because the credential and the
wire protocol carry the identical bits with the identical absence of protection.
*Flag:* the learner extracts facility code and card number from the RF layer, then
predicts the exact Wiegand bit pattern the reader will emit before it emits it.

**0.4 13.56 MHz: the upgrade that mostly was not** · Silver
MIFARE Classic, its sector keys, and Crypto1 — a cipher broken in 2008 and still on
badges today. What a nested attack recovers and how fast.
*Flag:* attacker recovers all sector keys from a simulated card given only observed reader
traffic, then reads the credential block.

**0.5 The ones that hold up** · Bronze
DESIGNED CONTRAST: DESFire EV2 and Seos do real mutual authentication with real keys.
Present the same attacks; watch them fail.
*Flag:* the learner runs 0.2 and 0.4's attacks against a DESFire card and records why each
one stops — the drill passes on correct diagnosis, not on a successful attack.

**0.6 The attacks that skip all of this** · Reference, not simulated
Request-to-exit sensors triggered from outside, door position switches, crash bars,
under-door tools, and the plain fact that many doors are opened by defeating the
*mechanics* rather than the electronics. This section does not simulate anything and says
so. It is here because a course that teaches only the electronic attacks leaves a learner
with a badly calibrated sense of where the risk is — and because a defender who hardens
the bus and leaves a gap under the door has bought nothing.

---

## Module 1 — The wire (Wiegand)

**1.1 What a badge actually says** · Bronze
Present a card at the reader, watch 26 pulses cross the wire, decode them by hand with the
decoder open beside you.
*Flag:* learner-submitted facility code and card number match what the engine transmitted,
for a credential the engine randomised from the session seed.

**1.2 Parity is not integrity** · Bronze
Flip a bit in the card number, fix the parity bits, watch the panel accept a different
badge.
*Flag:* a frame reaches the controller that parses cleanly, has valid parity, and carries
a different card number than any credential ever presented to the reader.

**1.3 Replay** · Bronze
Sniff one badge-in, unplug the card, re-emit the captured bits.
*Flag:* the controller grants access at a time when no credential was presented to the
reader.

**1.4 The implant** · Silver
Insert an inline device between reader and panel. Pass everything through untouched, then
selectively rewrite one credential into another.
*Flag:* the tap is inline, the reader's original credential was consumed, and the
controller granted on a substituted one — with the reader's own output unchanged.

**1.5 What brute force actually costs** · Silver
Sweep a facility code at real wire timing. Watch the clock.
*Flag:* not a flag — a number. The drill ends by showing the wall-clock cost of the full
26-bit space at the timing the learner chose, and asks them to compare it to 1.3.

**1.6 Clock-and-data** · Silver
The same exercise on ABA track 2. Different encoding, identical outcome.
*Flag:* replay succeeds on a clock-and-data link.

---

## Module 2 — OSDP as it is usually deployed

**2.1 Reading the bus** · Bronze
A controller polling a reader. Identify SOM, address, length, control byte, sequence
number, command code, CRC. Find the card read.
*Flag:* learner correctly labels the byte offsets of a frame the engine generated.

**2.2 It is still in the clear** · Bronze
No Secure Channel configured. Sniff a badge-in.
*Flag:* the attacker actor has extracted a card number matching the credential presented,
from passive observation only — zero frames injected.

**2.3 Injection on an unsecured bus** · Bronze
Nothing authenticates the controller. Send your own commands.
*Flag:* the PD ACKs a command originated by the attacker actor.

**2.4 Sequence numbers and BUSY** · Silver
Learn what the protocol does defend against — desynchronised sequence numbers, retries,
the BUSY reply — and why none of it is security.
*Flag:* the learner recovers a desynchronised link without resetting the simulation.

---

## Module 3 — Secure Channel

**3.1 The handshake, step by step** · Bronze
CHLNG, CCRYPT, SCRYPT, RMAC_I. Watch the keys derive. Every intermediate value visible.
*Flag:* the learner predicts the client cryptogram before the engine transmits it, given
the key and both nonces.

**3.2 The default key** · Bronze
A PD commissioned with SCBK-D. Recognise it from the security block byte, then decrypt
everything.
*Flag:* the attacker actor holds the session keys and has decrypted a card read, having
been given only the bus traffic.

**3.3 Weak keys** · Silver
A site key that is not SCBK-D but is still from the sample-code family. Recover it from a
captured handshake.
*Flag:* attacker-recovered SCBK equals the PD's configured SCBK, recovered from capture
alone.

**3.4 Install mode** · Silver
A controller left in install mode. Ask it for the key. It tells you.
*Flag:* attacker holds the SCBK and the only frames it sent were legitimate protocol
requests.

**3.5 Keyset capture** · Silver
Be on the bus during commissioning. There is no key exchange to attack because there is no
key exchange.
*Flag:* attacker captured a CMD_KEYSET payload and can decrypt subsequent traffic.

**3.6 Downgrade** · Gold
Inline. Rewrite the PDCAP reply so the reader claims it cannot do crypto. The controller
believes it.
*Flag:* the link reaches a steady state carrying card reads with no security block, where
both endpoints were configured to require Secure Channel.

---

## Module 4 — The weaknesses nobody mentions

**4.1 Traffic analysis through encryption** · Silver
The command byte is plaintext even inside Secure Channel. You cannot read the card number.
You can read the building's schedule.
*Flag:* the learner reports the times of every badge-in over a simulated day, correct to
the engine's log, without ever holding a key.

**4.2 Truncated MACs** · Gold
32 bits of MAC. Compute what that is worth.
*Flag:* the learner produces a frame the PD accepts whose MAC was not derived from the
session key. (Engine runs this with a shortened MAC length so it completes in seconds; the
drill states the real cost plainly and does not pretend otherwise.)

**4.3 IV reuse** · Gold
IVs derive from the previous MAC. Find the collision, recover plaintext.
*Flag:* attacker recovers a plaintext payload from two frames sharing an IV.

**4.4 The null ciphers** · Silver
SCS_15 and SCS_16 authenticate without encrypting. Some deployments use them believing
otherwise.
*Flag:* attacker reads a card number from a MACed-but-unencrypted link.

---

## Module 5 — The other chair

Every module above, replayed from a monitoring position. Same traffic, `odr-detect`
running, and the question is what a defender could have concluded and when.

**5.1** Which of the four attacks in module 3 are visible to a passive monitor at all?
**5.2** Build a detection rule that catches the downgrade and does not fire on a genuine
legacy reader being added to the bus.
**5.3** What does install mode look like in a log, and why is it usually indistinguishable
from a real commissioning?
*Flags:* the learner's rule set is run against a generated day of traffic containing both
attacks and benign events, and is scored on true positives and false positives.
