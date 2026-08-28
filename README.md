# lex-depot-demo

**One depot, one night, three settlements.** The 03:14 curtailment, end to end, on one attested chain — runnable in a few seconds.

```bash
sh demo/run.sh
```

A recording of that run is committed at [`demo/depot.cast`](demo/depot.cast) — about fifteen seconds:

```bash
asciinema play demo/depot.cast
```

The program finishes in well under a second. `demo/record.sh` paces the *playback* so it can be watched; nothing about what runs changes.

## What it shows

A depot runs 18 electric vans on a connection that cannot carry them all. At 03:14 the aggregator wants to curtail four of them. By morning three parties settle money against that one physical event.

**Act 1 — the meter reports.** Quarter-hourly readings, each signed by the charge point's own key and verifiable offline by anyone holding the platform's public key. The chain starts at the meter, not at a server.

**Act 2 — the aggregator asks.** The same command, presented four ways:

| presented | answer |
|---|---|
| with no capability | refused |
| with a capability from an untrusted issuer | refused |
| with the real capability, 15 kW shed | **held for review** — within the grant, past the unattended threshold |
| re-presented as a 7 kW shed | allowed, and dispatched |

The held command is **not dispatched**. No operator is wired in, and `[approval]`'s default sink refuses, so the deep shed simply does not happen — which is what fail-closed means when nobody is there at 03:14. Every one of those four answers is on the record.

**Act 3 — morning.** The energy bill and the flexibility payment, both derived from the same signed readings, with the baseline and the method's fingerprint recorded beside the volume. Walking up from either settlement reaches the authority that permitted the command and the reading it was computed from.

Then the invoice, next to the meter. The aggregator bills for the 15 kW shed it *asked for* at 03:14 — 10 kWh. That shed was held in Act 2 and never reached the charge point; what was dispatched, and metered, is 4666 Wh. The gap is a **114% over-claim**, and the flexibility payment is the measured figure, not the claimed one.

The percentage is recorded, not enforced. A threshold belongs in a contract, not in a library — the point is that over-claiming becomes *visible* and repeatable, not that this decides what to do about it.

**Act 4 — somebody edits a reading.** Not prevention — **localisation**. Every reading is re-verified, and the one that no longer matches its signature is named. The others still verify, so the chain says exactly where the edit was.

**Which** reading gets edited is the room's choice, not the demo's:

```
TAMPER=03:45 ./demo/run.sh
```

Readings exist at 02:00 through 03:45, quarter-hourly; unset, it edits 03:15. A time that was never sampled — or anything that is not a clock — is refused by name with the real times listed, rather than quietly tampering with nothing. A chain that localises a reading the audience picked is a harder thing to wave away than one catching a reading the author picked.

## What is real, and what is staged

**Real:** the capability check ([lex-gridguard](https://github.com/alpibrusl/lex-gridguard)), the signature verification ([lex-device-identity](https://github.com/alpibrusl/lex-device-identity)), the volume computation ([lex-baseline](https://github.com/alpibrusl/lex-baseline)), and the hash chain ([lex-trail](https://github.com/alpibrusl/lex-trail)). No mocks — the demo composes the same packages the services run.

**Staged:** the plumbing that would otherwise be four HTTP services is collapsed into one process, and the clock is fixed so the run prints the same story every time. The event vocabulary is exactly what `lex-csms` and `lex-ems` write in production; this replays it on one in-memory trail so the whole night is visible at once.

The numbers are checkable by hand throughout. A demo whose arithmetic can only be taken on faith is asking for exactly the trust the design exists to remove.

## What it does not claim

The baseline is a model. The chain makes the flexibility claim **checkable and replayable**, not true — a counterparty re-running the named method on the same readings gets the same number, or has found a real disagreement. That is the whole claim, and it is a smaller one than "the dispute goes away".

`tests/test_scenario.lex` pins each thing the run asserts out loud, so the demo cannot drift from its own story without CI going red first.

## License


Copyright (c) 2026 lex-depot-demo contributors.

Licensed under the [EUPL-1.2](LICENSE) — the European Union Public Licence, as used across the `lex-*` ecosystem.

