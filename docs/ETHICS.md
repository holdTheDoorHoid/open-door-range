# Ethics and scope

## What this project is

A training range. Every reader, controller, credential, bus and key in it is simulated in
software. Running the most damaging attack in here opens a door that does not exist.

## What it deliberately is not

- **No vendor-specific exploit code.** Nothing here targets a named product or a
  particular manufacturer's firmware.
- **No real credentials.** The card numbers are made up.
- **No novel offence.** Every attack taught here was published before this project
  existed — principally Bishop Fox's 2023 "Badge of Shame" research and the design
  weaknesses visible in the OSDP specification itself.
- **No capture of anybody's traffic.** There is no backend. Nothing you do in the range
  leaves your browser.

## Why publish it at all

Because the defenders are the ones currently locked out. An attacker willing to spend a
few hundred dollars on a reader, a panel and two RS-485 adapters already has a bench.
A security team being told "your access control is fine, it runs OSDP" has no way to see
for themselves what that sentence is worth.

The defensive half of this project is not a disclaimer bolted on the front. `odr-detect`
is a first-class crate: the range shows you what each attack looks like from a monitoring
position, so the same afternoon that teaches you the downgrade attack teaches you what
the downgrade looks like on your own bus.

## Using it on real systems

Don't, without written authorisation. Testing physical access control on a building you
do not own or have not been engaged to test is a crime in most places, and unlike a
network engagement, the failure mode involves police.

The capture-import feature planned for phase two reads recordings you made elsewhere. The
project does not help you make them and takes no position on whether you were allowed to.
That is on you and your scope document.
