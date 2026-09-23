# Interface design

A proposal, with the tensions stated rather than resolved silently.

## The central problem

One bench, two audiences. A beginner who opens this and sees a frame inspector, a bus
timing view, a key vault and an attacker console will close the tab. A practitioner handed
a wizard will close it faster. The usual answer is progressive disclosure — hide the
advanced things until asked for.

**That answer is half wrong here**, because hiding a control that is still affecting the
simulation is how people end up with a mental model that does not match what they are
looking at. A learner who cannot see that Secure Channel is enabled, but is wondering why
their replay failed, has been actively misled by the interface.

So the rule is: **collapse, never remove.** The bench is one bench. Detail panels fold up
to a single summary line, and that line always states the thing that matters — "Secure
Channel: on, SCBK-D" — even when everything beneath it is folded. Nothing that changes the
simulation's behaviour is ever invisible.

## Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  CARD ──rf──▶ READER ──wire──▶ CONTROLLER ──▶ DOOR              │  topology
│                      ▲                                          │
│                     tap                                         │
├─────────────────────────────────────────────────────────────────┤
│  timeline ▁▁█▁▁▁▁██▁▁▁▁▁▁█▁▁▁▁  ◀ scrub · step · run · speed    │
├──────────────────────────────┬──────────────────────────────────┤
│  traffic                     │  inspector                       │
│  t=0.412  ACU→PD  POLL       │  53 02 0e 00 04 60 ...           │
│  t=0.418  PD→ACU  RAW  ◀     │  ├ SOM       53                  │
│  t=0.900  ACU→PD  POLL       │  ├ address   02  (PD 2)          │
│                              │  ├ length    0e  (14)            │
│                              │  └ ...                           │
├──────────────────────────────┴──────────────────────────────────┤
│  drill: 1.3 Replay          ▸ objective · hint · flag           │
└─────────────────────────────────────────────────────────────────┘
```

**Topology strip.** The physical truth, drawn. Card, reader, wire, controller, door, and
the taps you have placed on the links. This is not decoration: the reason an inline
implant works is that it *sits between two things*, and a learner who has seen the box
appear on the link between reader and panel understands that without being told.

**Timeline.** One time axis for everything — RF, wire, bus, door state. Scrub it. This is
the logic-analyser mental model, which is the correct one, and it is also what makes
"step slowly through the handshake" and "run a simulated day of traffic" the same control
rather than two modes.

**Traffic and inspector.** Wireshark's arrangement, because it is right and because a
practitioner already knows it. Selecting a decoded field highlights its bytes.

## The inspector does the teaching

For an encrypted frame, the inspector shows — always, not as a toggle — the split between
what an observer can read without a key and what they cannot. The command byte sits in the
readable column. A learner meets "the command byte is plaintext even inside Secure
Channel" by *looking at it*, three modules before the drill that makes it matter.

This is the single highest-value thing in the interface and it should be built early.

## Difficulty

Bronze, Silver and Gold change the drill's guidance, not the bench. Bronze pre-places the
taps and says which control to touch. Gold gives an objective and nothing else. The bench
is identical in all three, so a learner moving up is not learning a new interface, and a
practitioner in free play has the same instrument as everyone else.

## Tensions, now resolved

All three were decided by the owner on 2026-09-23. **DECIDED** items do not change
without asking.

**Realism versus legibility in the timeline.** Real OSDP polls run tens of times a second,
so an honest timeline of a real bus is a solid bar. Compressing idle polling makes it
readable and makes it a lie — and the amount of idle traffic is exactly what makes traffic
analysis work in drill 4.1. Current thinking: show it honestly by default with a
prominent, non-sticky "collapse idle polling" control, so compression is always a thing
the learner chose and can see they chose.

**DECIDED: honest by default, collapse on request.** The learner's first sight of a bus is
the real thing. Compression is available and obvious, and is always a choice they made.

**Whether the door should be animated.** A door that visibly opens is a strong reward
signal and makes success unmistakable. It is also the thing most likely to make this feel
like a toy to the practitioner audience. **DECIDED: animate it.** The door swings. It is the payoff, it is what people carry out of
a workshop, and the seriousness of the rest of the instrument can carry the cost. The
strike-fire event still lands on the timeline as the authoritative record — the animation
is the reward, the timeline is the evidence.

**How honest to be about attack costs.** Drill 4.2 shortens the MAC so it completes in
seconds. The drill says so. But a learner who runs it and sees "MAC forged" has
experienced something that does not happen in the time they just spent, and experience
overwrites text. **DECIDED: run the real one on a bar that never finishes.** The shortened attack completes
and the drill proceeds. Alongside it, the genuine computation starts and keeps running,
with a progress bar that crawls and a projected completion date rendered in full. It will
still be running when the learner closes the tab. Nobody who sees that forgets what 32
bits of MAC is actually worth, and no amount of explanatory text achieves the same thing.

## Accessibility

Colour never carries meaning alone — granted/denied, attack success/failure, and
readable/unreadable in the inspector all carry a shape or a word as well. Every value in
the inspector is selectable text, because people paste these into notes. Full keyboard
operation of the bench, since the timeline and inspector are exactly where a mouse is
slowest.
