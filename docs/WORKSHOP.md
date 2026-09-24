# Running Open Door Range as a workshop

This is the practical guide to putting the range in front of a room. It assumes
you already know the material; what follows is how to get thirty people onto the
same bench, how to spend the hour, and how to run it when the conference Wi-Fi
does what conference Wi-Fi does.

The range has no backend and collects nothing. Everything below happens in each
person's own browser.

## Getting everyone on the same bench

The problem with a live demo is that "open drill 1.3" does not put the room on
the *same* 1.3 — the credential the engine randomises is derived from the
scenario's seed, and a room where everyone sees different card numbers cannot
follow a worked example.

So: **share a bench link.** Configure the bench the way you want it — pick the
drill, set the band, change any settings — then press **Share this bench** in the
top bar. You get a link, already copied to your clipboard. Anyone who opens it
lands on exactly that bench: same drill, same band, same settings, same seed, so
the same bytes cross the wire for all of them. Project it, drop it in the event
Slack, or put a QR code of it on the slide.

What the link carries:

- the drill (or the free-play scenario),
- the difficulty band,
- every bench setting you changed from its default (Secure Channel on/off, the
  key, MAC width, install mode, and so on),
- the seed, as a stamp — see below.

What it does **not** carry: anyone's progress, any personal data, or any of the
things a laptop remembers between people. A link is a starting point, nothing
more.

### A note on the seed

The seed is in the link, but it is a *stamp that gets verified*, not a dial you
can turn. The engine derives a scenario's seed itself and there is no seam to
override it (see `site/ENGINE-API.md` §2). This is fine for a room, because the
seed is deterministic: the same drill always produces the same seed and the same
bench for everyone, which is the whole point. What you cannot currently do is
hand out an *arbitrary* seed to reroll the randomised credential into something
fresh — that would need an engine change. If a link ever reports that the seed
did not match, it means the engine's seed derivation changed since the link was
made, and the bench may differ; the range says so rather than pretending.

## A 60-minute session

Assumes a mixed room, mostly newcomers, one screen at the front.

- **0–5 min — the frame.** Open drill **0.1**. A prox card has no processor, no
  key, no challenge; it shouts its number forever at anyone. Set the tone: the
  reader was never the weak part.
- **5–20 min — the wire has no crypto.** Share **1.1** (decode a badge by hand),
  then **1.3** (Replay). 1.3 is the money demo — sniff one badge-in, pull the
  card, re-emit the bits, watch the door swing on a credential that was never
  presented. Everyone runs it on your link, so the granted credential matches
  what you are pointing at.
- **20–35 min — OSDP is sold as the fix.** Share **2.2** (it is still in the
  clear) and **2.3** (inject your own commands on an unsecured bus). The point
  lands hard right after Wiegand: the upgrade everyone paid for is wide open in
  its default deployment.
- **35–50 min — Secure Channel, and its default key.** Share **3.2**. A PD
  commissioned with SCBK-D; recognise it from the security-block byte, then
  decrypt the card read. This is where the inspector earns its keep — the command
  byte sits in the readable column even here.
- **50–60 min — the one they remember.** Share **4.1** (traffic analysis through
  encryption). You cannot read the card number; you can read the building's
  schedule, because the command byte is plaintext in every security mode. Close
  on it. If there is a minute, mention drill **4.2** and let its "real MAC"
  progress bar keep crawling on the projector while people leave — the projected
  completion date is the lesson.

If the room is more advanced, drop 0.1 and 1.1, and spend the reclaimed time on
**3.6** (downgrade) and **5.2** (detecting it) as an attack-then-defence pair.

## A longer session (half a day)

Run the modules in order, 0 through 5, one shared link per drill. The arc is the
content: legacy is broken by design, OSDP is the fix, OSDP's own failures are
most of the course, and Module 5 replays all of it from the defender's chair.
Budget roughly:

- Module 0 (the credential) — 40 min
- Module 1 (Wiegand) — 45 min
- Module 2 (OSDP as deployed) — 30 min
- Module 3 (Secure Channel) — 60 min, the heart of it
- Module 4 (the weaknesses nobody mentions) — 45 min
- Module 5 (the other chair) — 30 min, and the note to end on

Read **drill 0.6** out loud somewhere in the first hour even though it simulates
nothing. It is the calibration: the electronic attacks are real, and are
frequently *not* the cheapest way through a door. A course that skips it leaves
people with a badly aimed sense of where the risk is.

## The best live demos

Ranked by how well they land cold, in front of people:

1. **1.3 Replay** — the door swings on a card that is not there. Nothing beats it.
2. **4.1 Traffic analysis** — "I can't read the card, but I know when the CEO
   arrives" reliably changes how people think about "we encrypted it."
3. **3.2 The default key** — the padlock everyone trusts, opened with the key
   printed in the manual.
4. **2.3 Injection** — send your own commands; the PD does as it is told.
5. **4.2 Truncated MACs** — for the projected-completion-date moment. Start it
   and leave it running.

The three flag predicates that read best on a screen are 1.3, 2.3 and 3.2:
each awards the flag because the *engine's own state* says the attack worked,
with evidence and timestamps, not because an answer string matched.

## At a booth: resetting between people

A booth laptop is a shared laptop. When one person finishes and the next steps
up, open the **Course** panel and press **Reset session**. It confirms first,
then clears saved progress and settings in **that browser only** — nothing was
ever stored anywhere else, so no other laptop is affected — and drops back to a
clean start at drill 1.1. It also strips any shared-bench link out of the address
bar, so a reload is a genuine fresh start rather than re-loading the last bench.

Theme choice is left alone, so you are not re-blinding people in a dark room.

## Running it offline

A room usually shares one access point, and that access point is usually the
first thing to fall over. The range is entirely static and makes no network
request at runtime, so it does not *need* to be online — you just need the files
reachable. Two ways:

### Warm-browser offline (the service worker)

The site registers a service worker (`site/sw.js`) that caches the app shell and
the wasm engine the first time a browser loads it. After that, that browser keeps
working with the network off — reloads, drill switches, everything. So if you
load the live site once on the venue Wi-Fi (or on your phone's hotspot on the way
in), it survives the Wi-Fi dying mid-session.

Caveats worth knowing:

- It is per-browser. Each attendee's browser has to load the site once while it
  still has a connection for their copy to go offline-capable.
- The worker only ever caches **same-origin** files and never originates a
  request of its own, so it does not weaken the "nothing leaves the browser"
  promise. If you read only one line of `sw.js`, read the privacy note at the top.
- It needs `http://` or `https://` — a service worker will not register from a
  `file://` page. That is what the next option is for.

### Cold offline (a folder or USB stick)

To run with no network at all — a locked-down room, an air-gapped laptop, or just
handing people a stick — build a self-contained bundle:

```
tools/make-offline-bundle.sh
```

This copies the whole site (including the built `site/pkg/` wasm) into
`dist/open-door-range-offline/` and zips it. It refuses to build if the wasm
engine has not been built yet, and tells you the one command that builds it. The
bundle contains a `START-HERE.txt` in plain language for whoever receives it.

Hand out the zip. The recipient unzips it and serves the folder with any tiny
local web server — the note spells out `python3 -m http.server`, which is already
on most machines. A browser will not load the ES modules or the wasm straight off
the disk over `file://`, which is why a one-line local server is the step rather
than "double-click index.html". Once it is served and loaded once, the service
worker takes over and it works offline from then on too.

Nothing in either path phones home. That is not a nice-to-have here; it is the
promise the whole project is built on.
