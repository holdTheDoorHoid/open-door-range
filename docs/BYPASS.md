# Drill 0.6 — the attacks that skip all of this

**This section simulates nothing.** Everything else in the range is a working model you can
poke. This is prose, and it is here on purpose.

## Why a course about protocols contains a section about doors

A learner who completes Modules 1 through 5 finishes with a detailed understanding of how
to attack the conversation between a reader and a controller, and a badly calibrated sense
of how anyone actually gets through a door.

That miscalibration is not harmless. It produces a defender who spends a budget hardening
a bus while the risk sits somewhere else entirely, and it produces an assessor who reports
that a building's access control is sound because its OSDP deployment is.

So: the electronic attack surface this range teaches is frequently *not* the cheapest way
in. Often it is not even close.

## The categories

**The request-to-exit path.** Almost every controlled door has a way to leave without a
credential — a motion sensor above the door, a push bar, a button. That path is, by
design, unauthenticated: it exists so people can get out in a fire. Anything that reaches
it from the wrong side reaches it with full authority, and none of it touches the reader,
the wire, the controller or any key.

**The door and its frame.** Latches, strikes, gaps, hinges, and the physical relationship
between a door and the wall it sits in. A door is a mechanical object with a mechanical
failure mode, and the credential system is bolted onto it.

**The reader's own housing.** The reason implants like the one modelled in drill 1.4 work
is that the reader is mounted on the unsecured side of the wall, and behind it are the
wires. The protocol is irrelevant if the attacker is holding the conductors.

**Everything that is not the door.** Other doors, windows, loading bays, ceilings above
partition walls, and the person who holds the door open because you have your hands full.

## What this means for the rest of the course

Two things, and they pull in opposite directions, which is the point.

The electronic attacks are real, and OSDP's weaknesses are real, and a deployment running
Wiegand in 2026 is carrying a genuine unnecessary risk. Nothing here is an argument that
protocol security does not matter.

But the honest ordering, on most buildings, puts several of the categories above ahead of
the bus. A defender who reads Module 3, buys new readers, and does not look at their
request-to-exit sensors has spent money and bought very little.

## Why this is prose and not a simulation

Partly because a browser cannot model a doorframe usefully.

Mostly because it does not need to. The purpose of this section is calibration, not
capability — a learner needs to know these categories exist and roughly where they sit in
the ordering, and that is fully served by naming them. Detailed technique is available
elsewhere from people who teach it properly, with hardware, in a room, which is where it
belongs.

If you want to learn the mechanical side, find a physical security village at a
conference and spend an afternoon there. The people running it will be delighted to see
you and you will learn more in that afternoon than any amount of reading achieves.
