# PSAP — Predicate-Scoped Authority Protocol

**Provable authority resolution between mutually-untrusted AI agents.**

When autonomous agents from different trust domains exchange conflicting claims, *which claim governs?* PSAP answers that by deriving authority at an **authenticated boundary** (who sent it, over what verified channel, under what grant) and scoping it **per predicate** — never by trusting what a message asserts about itself. A spoofed or compromised agent cannot escalate its authority by asserting more loudly, more often, or more recently. It loses **by construction**, not because a detector caught it.

> Originated as the **Inbin Context Protocol (ICP)** at [inbin.dev](https://inbin.dev). PSAP is the general, product-neutral form of that protocol.

---

## The threat: a commander-agent's squad, turned against itself

A commander agent directs a squad. A `recon` sensor has authority to establish enemy positions. A `strike` agent fires on whatever the commander treats as operative. An **adversary injects a spoofed report**, impersonating recon, asserting a *false* enemy position that is actually **friendly coordinates** — the classic "turn the force on itself" attack.

Run the same attack against two commanders:

```
npx tsx examples/commander-under-attack.ts
```

```
RUN 1 -- NAIVE commander (trusts the claim, latest wins)
  commander accepts: "34.05N,118.24W (FRIENDLY FORCES)"
  >>> STRIKE ORDERED on FRIENDLY FORCES
  >>> RESULT: FRIENDLY FIRE. Fratricide. <<<

RUN 2 -- PSAP commander (authority derived at the boundary)
  real recon report  -> ESTABLISHING (verified channel)
  adversary's spoof  -> PROPOSING   (agent-self channel)
  OPERATIVE (what governs): "34.20N,118.50W (hostile armor)"
  >>> STRIKE ORDERED on hostile armor
  >>> RESULT: hostile target neutralized.
```

**Same adversary. Same injection. Opposite outcome.** The spoof arrived over the unauthenticated agent plane, which binds no capability, so it can only ever be `PROPOSING`. The real recon report arrived over the sensor's *verified* channel, matching a capability that grants `ESTABLISHING`. A louder, later, or more confident claim cannot change that. The reason is printed in the derivation trace, and it is structural.

## Why this is different from "detect the bad input"

The mainstream defense against agent spoofing / prompt injection is a better classifier: try to *detect* the malicious message. That is an arms race the adversary wins, because a sufficiently good forgery looks legitimate. PSAP does not try to tell a good forgery from a real message. It removes the question: authority is a property of the **authenticated channel a claim arrived over**, which the message content cannot manufacture. This is the zero-trust principle ("never trust, always verify; verify at the boundary") applied to agent-to-agent authority.

## Two theorems (this is a proven protocol, not a heuristic)

The design rests on two formal results (preprints linked below):

1. **Expressiveness.** Authority over a contested fact must be scoped to the `(principal, predicate)` pair, not to the principal alone. *A per-predicate authority assignment is not representable by any global ranking of principals* (Theorem 1). A sensor has authority over *what it sees*, not over *who to strike* — a rank-based trust model cannot express that distinction, and an adversary exploits exactly that gap.
2. **Soundness.** When the authority class is *derived* from the authenticated circumstances of a write and never read from the submission, a writer that **over-asserts** its own authority cannot change which value governs.

Papers:
- *Predicate-Scoped Authority for Conflict Resolution Between Mutually Untrusted Agents* — [zenodo.org/records/22062440](https://zenodo.org/records/22062440)
- *Provenance-Tiered Conflict Resolution in Agent Memory* — [zenodo.org/records/21635490](https://zenodo.org/records/21635490)

## The core, in three functions

```ts
import { emptyStore, mint, operative } from "./src/authority";
import { channelFor, agentSelfChannel } from "./src/channel";

const store = emptyStore([capability]);        // policy: who may establish what
mint(store, submission, channel, now, opts);   // write a claim; class is DERIVED
operative(store, subject, predicate, at);       // resolve: what governs, and why
```

- **`mint`** takes the authenticated channel and derives an authority *class* (`ESTABLISHING` / `RESERVING` / `PROPOSING`) by matching the write against the capabilities bound to that channel. Nothing in the payload can raise the class.
- **`operative`** resolves conflicting claims: it partitions by authority class first, and only breaks ties *within* a class by server ingestion time. A `PROPOSING` claim can never defeat an `ESTABLISHING` one, no matter how recent.

The core (`src/authority.ts`) is pure and dependency-free — no transport, no database. `src/channel.ts` shows the canonical mapping from an authenticated transport (mTLS, verified device, DMARC-passed email, signed webhook) to a channel; plug in your own.

## This is the real, tested core

`src/authority.ts` and `test/acceptance.test.ts` are the same proven implementation running in production at [inbin.dev](https://inbin.dev), extracted verbatim. The acceptance suite is the protocol's spec conformance tests:

```
npm test
```

## Status

Reference implementation, Apache-2.0. The authority-derivation mechanism is the subject of a pending US provisional patent (informational; this repository is offered under Apache-2.0, which includes an explicit patent grant).

## License

Apache License 2.0. See [LICENSE](LICENSE).
