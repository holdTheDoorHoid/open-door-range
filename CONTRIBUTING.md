# Contributing

## The most valuable thing you can give this project

**Corrections from real hardware.**

Every protocol crate here ships a ledger of what it was unsure about. Those ledgers exist
because the OSDP specification is paywalled, several command codes disagree between
open-source implementations, and published descriptions of some card formats are simply
wrong — we found one while building this.

So the contribution that matters most is not a feature. It is: *I ran this against a real
reader and here is where it differs.* If you have a bench, you have something this project
cannot buy.

A hardware correction should say:

1. **What you tested against** — reader and controller make and model, firmware version
2. **What the range predicted** and what the hardware actually did
3. **The bytes**, as a capture, ideally in the project's own capture format
4. **Which uncertainty ledger entry it resolves**, if it resolves one

Open an issue with that and it will be treated as a finding, not a bug report.

## The rule that governs the drills

Drills run attacks; they do not describe them. A flag is awarded when the simulation's own
state satisfies a predicate — the attacker really holds the key, the controller really
accepted the forged frame. There are no answer strings.

If you add a drill and find its success condition cannot be expressed as a query against
engine state, **that is a signal the engine is missing something**, not an invitation to
check a typed answer. Say so in the issue and we will fix the engine.

## The rule that governs the interface

**Collapse, never remove.** A folded panel still states the thing that matters on its
summary line. Nothing that changes the simulation's behaviour is ever invisible, because a
learner who cannot see that Secure Channel is enabled while wondering why their replay
failed has been actively misled rather than merely underserved.

## Faithful, not fixed

Where the protocol is weak, the implementation reproduces the weakness exactly. The MAC
chain reuses its IV; we did not correct it. If you find code here doing something that
looks wrong, check whether it is wrong or whether it is *accurate*, and if it is accurate,
the fix is a comment and a test that demonstrates it — never a correction.

## Code

- Rust, `no_std` + `alloc`, `#![forbid(unsafe_code)]`, everything must build for
  `wasm32-unknown-unknown`
- Deterministic: virtual clock, seeded randomness, no wall clock, no OS entropy
- No panics on parsed input, ever. Structured errors
- `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings` and
  `cargo fmt --all --check` must all pass
- The site is plain HTML, CSS and ES modules. No framework, no build step, no runtime
  network requests. That last one is a privacy promise, not a preference

## What will be turned down

- Anything targeting a specific vendor's product
- Real credentials, real keys, real captures containing someone's actual badge number
- Attacks not already published elsewhere. This project teaches known work; it is not a
  venue for disclosure
- Telemetry, analytics, or anything that makes a network request from the site

## Scope

See [DESIGN.md](DESIGN.md). Items marked **DECIDED** came from the maintainer and are not
open for redesign without asking first — ask in an issue before building against them.
