# PSAP — Predicate-Scoped Authority Protocol

**Provable authority resolution between mutually-untrusted AI agents.**

When autonomous agents from different trust domains exchange conflicting claims, *which claim governs?* PSAP answers that by deriving authority at an **authenticated boundary** (who sent it, over what verified channel, under what grant) and scoping it **per predicate** — never by trusting what a message asserts about itself. Given valid grants and an authenticated channel the adversary cannot forge, a spoofed or compromised agent cannot escalate its authority by asserting more loudly, more often, or more recently. It loses **by construction**, not because a detector caught it.

> Originated as the **Inbin Context Protocol (ICP)** at [inbin.dev](https://inbin.dev). PSAP is the general, product-neutral form of that protocol.

---

## The threat: a grant holder reaching past its grant

A commander agent runs a squad. A `recon` drone holds a genuine capability, `ESTABLISHING` over `enemy_position`, on its own verified channel. A second agent, `watch`, holds a genuine capability of its own — `ESTABLISHING` over a *different* predicate, `target.confirmed` — on its own verified channel. `watch` is not a stranger with no grant; it is authenticated, and it attacks `enemy_position` anyway, writing later and forging an authority designation inside its own submission (`authority: ESTABLISHING`, `_class: ESTABLISHING`, `trusted: true`, `source: recon-drone-1`) — the same attack Section 6.2 of the paper runs: a grant holder reaching past its grant, not a channel with nothing bound to it.

```
npx tsx examples/commander-under-attack.ts
```

Before trusting a result, the script runs Section 6.3's three falsification gates — conditions where the attacker legitimately should win, and does — then a naive resolver on the same incident (latest write wins, no channel check: it falls for the forgery and strikes the friendly coordinates), then the real attack:

```
THE REAL ATTACK -- watch holds target.confirmed, not position.enemy
  real report (34.20N,118.50W (hostile armor)) -> ESTABLISHING
  watch's forged claim (34.05N,118.24W (FRIENDLY FORCES)) -> PROPOSING

  What governs position.enemy: "34.20N,118.50W (hostile armor)" (ESTABLISHING)
  watch's write is retained and named as defeated, not discarded.
```

**Same grant holder. Same forged designation. It still loses.** `watch`'s channel is genuinely authenticated and its capability is genuine — the forged fields inside its own submission are simply never read, and its grant names `target.confirmed`, not `enemy_position`. A louder, later, or more confidently-asserted claim cannot change that; the reason is printed in the derivation trace, and it is structural, not a detector that happened to catch this one attack.

## Why this is different from "detect the bad input"

The mainstream defense against agent spoofing / prompt injection is a better classifier: try to *detect* the malicious message. That is an arms race the adversary wins, because a sufficiently good forgery looks legitimate. PSAP does not try to tell a good forgery from a real message. It removes the question: authority is a property of the **authenticated channel a claim arrived over**, which the message content cannot manufacture. This is the zero-trust principle ("never trust, always verify; verify at the boundary") applied to agent-to-agent authority.

## Two formal results

The design rests on two results proved in the paper (preprints linked below):

1. **Expressiveness (Proposition 2, inversion).** Authority over a contested fact must be scoped to the `(principal, predicate)` pair, not to the principal alone. When two predicates have different, unique maximal holders, *no single ranking of principals represents both* — a sensor has authority over *what it sees*, not over *who to strike*, and a rank-based trust model cannot express that distinction.
2. **Soundness (conditional).** When the authority class is *derived* from the authenticated circumstances of a write and never read from the submission, a writer cannot raise its own class by asserting authority, and so cannot displace a value held at a higher class. A writer at the same class can still replace it by writing later — that's the protocol's treatment of co-holders, not an escalation.

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

- **`mint`** takes the authenticated channel and derives an authority *class* (`ESTABLISHING` / `CORROBORATING` / `PROPOSING`) by matching the write against the capabilities bound to that channel. Nothing in the payload can raise the class.
- **`operative`** resolves conflicting claims: it partitions by authority class first, and only breaks ties *within* a class by server ingestion time. A `PROPOSING` claim can never defeat an `ESTABLISHING` one, no matter how recent.

The core (`src/authority.ts`) is pure and dependency-free — no transport, no database. `src/channel.ts` shows the canonical mapping from an authenticated transport (mTLS, verified device, DMARC-passed email, signed webhook) to a channel; plug in your own.

## This is the real, tested core

`src/authority.ts` and `test/acceptance.test.ts` are the same implementation the paper's experiments run against, extracted verbatim with one comment word redacted (the deployment name). The acceptance suite covers grant-ceiling derivation, opacity to the submission payload, and class-then-recency resolution; it does not yet cover revocation or read-time demotion (reevaluated mode):

```
npm test
```

## Status

Reference implementation, Apache-2.0. The authority-derivation mechanism is the subject of a pending US provisional patent (informational; this repository is offered under Apache-2.0, which includes an explicit patent grant).

## License

Apache License 2.0. See [LICENSE](LICENSE).
