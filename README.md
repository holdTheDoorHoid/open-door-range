# Open Door Range

A browser-based virtual range for physical access control. Wire up a door system —
credential, reader, wire or bus, controller, strike — then tap it, attack it, and watch
what a defender would see.

Nothing here needs hardware. No reader, no panel, no RS-485 adapters, no bench. That is
the point: learning reader-to-panel attacks has until now required owning a lab, and
that gate keeps the subject in the hands of people who already have one.

**Status: early development.** Not yet deployed.

## What it covers

**Legacy wire protocols.** Wiegand 26/34/35/37-bit and clock-and-data, down to the
D0/D1 pulse train. Sniffing, replay, inline implants, brute force. There is no
cryptography in these protocols, and seeing exactly how little there is to defeat is the
first lesson.

**OSDP.** Frame structure, the full v2.2.2 command and reply set, and Secure Channel:
the handshake, the keys, the MAC, the encryption. Then the five attacks Bishop Fox
published in 2023 — passive eavesdropping on an unencrypted bus, capability downgrade,
install-mode key disclosure, weak keys, and keyset capture during commissioning — plus
the quieter weaknesses that matter more in practice, like the fact that the command byte
stays in the clear even inside an encrypted channel, so watching *when* someone badges in
never needed a key at all.

## How it is built

One Rust engine, compiled to WebAssembly for the website and to a native binary for
offline analysis. That is not a language preference; it means the teaching simulation and
the real-capture analyser are the same code, so a drill cannot teach something the
analyser disagrees with.

Drills do not describe attacks — they run them. A flag is awarded when the simulation's
own state says the attack worked: the attacker really holds the key, the controller
really accepted a forged frame. There are no answer strings to check against.

See [DESIGN.md](DESIGN.md) for the full specification.

## Privacy

There is no backend. Progress is stored in your browser and goes nowhere. No accounts,
no analytics, nothing collected about anyone who uses this.

## Ethics

Everything is simulated. No real credentials, no vendor-specific exploit code, no named
products targeted. The weak-key material is already public. The defensive half is a
first-class part of the project — a defender can run the same range to learn what their
own bus looks like under each attack. See [docs/ETHICS.md](docs/ETHICS.md).

## Credits

The OSDP attack set is the work of Dan Petro and David Vargas at Bishop Fox, published as
"Badge of Shame" with the `mellon` tool. This project teaches their findings; it does not
claim them.

Maintained by [LSOH](https://github.com/holdTheDoorHoid).

## Licence

GPLv3. See [LICENSE](LICENSE).
