/**
 * PSAP flagship example: an over-asserting writer reaching past its own
 * grant.
 *
 * SCENARIO
 * --------
 * A commander agent runs a squad. A `recon` drone holds a genuine
 * capability over `position.enemy` on its own verified channel. A
 * second agent, `watch`, holds a genuine capability over a DIFFERENT
 * predicate, `target.confirmed`, on ITS OWN verified channel.
 *
 * `watch` is not a stranger with no grant. It is a holder, authenticated,
 * writing on its own authenticated channel -- it just has no grant over
 * `position.enemy`. It attacks that predicate anyway, forging an
 * authority designation inside its own submission (`authority:
 * ESTABLISHING`, `_class: ESTABLISHING`, `trusted: true`, `source: the
 * recon drone`), exactly the attack Section 6.2 of the paper runs: a
 * grant holder reaching past its grant, not a channel with nothing
 * bound to it.
 *
 * This is the thing the earlier version of this file did not test. That
 * version gave the adversary no capability at all and wrote it on the
 * unauthenticated agent plane, where the outcome is fixed before the
 * derivation ever runs: no capability binds that channel to anything,
 * so it can only ever be PROPOSING, regardless of what the protocol
 * does. This version's adversary is authenticated and genuinely
 * authorized for something; the only thing stopping it is that its
 * grant does not cover this predicate.
 *
 * THREE GATES, A NAIVE BASELINE, THEN THE RUN
 * ---------------------------------------------
 * Before trusting a zero, the harness has to be shown it CAN produce a
 * capture. Section 6.3's falsification gate is three conditions where
 * the attacker ought to win, and does:
 *
 *   GATE 1  attacker legitimately holds position.enemy  -> captures.
 *   GATE 2  same class, attacker writes later            -> captures
 *           (recency decides WITHIN a class, never across one).
 *   GATE 3  attacker holds a corroborating grant on the predicate, the
 *           governing capability is revoked before the read, resolved
 *           under re-evaluated mode -> captures (what remains after
 *           revocation is whatever claims are still standing).
 *
 * Then a naive resolver (latest write wins, no channel or grant check)
 * runs against the SAME incident as the real attack below: it accepts
 * watch's forged, later write and strikes the forged coordinates.
 *
 * Only after the gates pass and the naive baseline is shown losing does
 * the real attack run, on the real grants, against the real resolver --
 * and lose.
 *
 * Run:  npx tsx examples/commander-under-attack.ts
 */
import {
  emptyStore,
  mint,
  operative,
  type Capability,
  type ChannelContext,
} from "../src/authority";
import { channelFor } from "../src/channel";

const TD = "td:squad-alpha";
const SUBJECT = "grid:objective-7";
const PREDICATE = "position.enemy";
const WATCH_PREDICATE = "target.confirmed";

const REAL_ENEMY_COORDS = "34.20N,118.50W (hostile armor)";
const FORGED_COORDS = "34.05N,118.24W (FRIENDLY FORCES)";

const T0 = new Date("2026-08-25T10:00:00Z");
const sec = (n: number) => new Date(T0.getTime() + n * 1000);

// recon's genuine, authenticated channel.
const reconChannel: ChannelContext = channelFor({
  kind: "device",
  principal: "recon-drone-1",
  verified: true,
  trustDomain: TD,
});

// watch's genuine, authenticated channel -- its OWN, not recon's and
// not the unauthenticated plane. watch really is who it says it is.
const watchChannel: ChannelContext = channelFor({
  kind: "device",
  principal: "watch-post-3",
  verified: true,
  trustDomain: TD,
});

function reconCapability(over: {
  predicateScope: string[];
  authorityClass?: Capability["authorityClass"];
  notAfter?: Date;
  revokedAt?: Date | null;
}): Capability {
  return {
    capabilityId: "cap_recon_sensor",
    issuer: "did:mil:commander-alpha",
    trustDomain: TD,
    principalId: "principal:device/recon-drone-1",
    authorityClass: over.authorityClass ?? "ESTABLISHING",
    predicateScope: over.predicateScope,
    subjectScope: { match: "prefix", value: "grid:" },
    channelBinding: ["chan:device-verified/recon-drone-1"],
    notBefore: new Date("2026-01-01T00:00:00Z"),
    notAfter: over.notAfter ?? new Date("2027-01-01T00:00:00Z"),
    revokedAt: over.revokedAt ?? null,
    policyVersion: "rules-of-engagement-v1",
  };
}

function watchCapability(over: {
  predicateScope: string[];
  authorityClass?: Capability["authorityClass"];
}): Capability {
  return {
    capabilityId: "cap_watch_post",
    issuer: "did:mil:commander-alpha",
    trustDomain: TD,
    principalId: "principal:device/watch-post-3",
    authorityClass: over.authorityClass ?? "ESTABLISHING",
    predicateScope: over.predicateScope,
    subjectScope: { match: "prefix", value: "grid:" },
    channelBinding: ["chan:device-verified/watch-post-3"],
    notBefore: new Date("2026-01-01T00:00:00Z"),
    notAfter: new Date("2027-01-01T00:00:00Z"),
    revokedAt: null,
    policyVersion: "rules-of-engagement-v1",
  };
}

/** watch's submission when it attacks position.enemy: a forged
 * authority designation inside its own object, exactly as Section 6.2
 * specifies -- the strongest self-assertion available to a writer
 * holding no grant on this predicate. */
function forgedSubmission(coords: string) {
  return {
    subject: SUBJECT,
    predicate: PREDICATE,
    object: {
      value: coords,
      authority: "ESTABLISHING",
      _class: "ESTABLISHING",
      trusted: true,
      source: "recon-drone-1",
    },
  };
}

function classOf(r: { rejected: string } | { authority: { class: string } }): string {
  return "rejected" in r ? `REJECTED(${r.rejected})` : r.authority.class;
}

function printResult(label: string, r: ReturnType<typeof mint>): void {
  console.log(`  ${label} -> ${classOf(r)}`);
}

/** A naive resolver: whoever wrote most recently about the predicate
 * wins. No channel, no capability, no class -- just timestamps. This
 * is how most systems behave today. Run against the SAME incident as
 * the real attack below, so the contrast is the resolver, not the
 * scenario. */
function naiveResolve(reports: { value: string; at: Date }[]): string {
  return reports.sort((a, b) => b.at.getTime() - a.at.getTime())[0]!.value;
}

function runNaive(): void {
  console.log("=".repeat(64));
  console.log("NAIVE resolver on the same incident -- latest write wins, no channel check");
  console.log("=".repeat(64));
  const governing = naiveResolve([
    { value: REAL_ENEMY_COORDS, at: sec(0) },
    { value: FORGED_COORDS, at: sec(5) }, // watch's forged write, arrives later
  ]);
  console.log(`  recon (t=0):   "${REAL_ENEMY_COORDS}"`);
  console.log(`  watch (t=5, forged ESTABLISHING designation): "${FORGED_COORDS}"`);
  console.log(`  naive commander believes the latest write: "${governing}"`);
  const friendly = governing.includes("FRIENDLY");
  console.log(
    friendly
      ? `  >>> STRIKE ORDERED on ${governing}\n  >>> RESULT: hit our OWN people. FRIENDLY FIRE / FRATRICIDE. <<<`
      : `  >>> STRIKE ORDERED on ${governing}\n  >>> RESULT: hit the REAL enemy. Hostiles neutralized, no fratricide.`,
  );
  console.log();
  console.log(`  watch did not need to break any channel to win here -- it only`);
  console.log(`  needed to write last. It is a genuine grant holder, authenticated,`);
  console.log(`  on its own channel; a naive resolver that ignores grant scope`);
  console.log(`  loses to anyone who can write later, whether they hold a real`);
  console.log(`  grant for something else or hold nothing at all.`);
  console.log();
}

// ---------------------------------------------------------------
// GATE 1 -- attacker legitimately holds the capability. Must capture,
// or a zero later is arithmetic, not a measurement.
// ---------------------------------------------------------------
function gate1(): boolean {
  console.log("-".repeat(64));
  console.log("GATE 1 -- attacker legitimately holds position.enemy");
  console.log("-".repeat(64));
  const store = emptyStore([
    reconCapability({ predicateScope: [PREDICATE] }),
    watchCapability({ predicateScope: [PREDICATE] }), // watch holds it here, by construction of the gate
  ]);
  mint(store, { subject: SUBJECT, predicate: PREDICATE, object: REAL_ENEMY_COORDS }, reconChannel, sec(0));
  const attack = mint(store, { subject: SUBJECT, predicate: PREDICATE, object: FORGED_COORDS }, watchChannel, sec(5));
  printResult("watch's write", attack);
  const view = operative(store, SUBJECT, PREDICATE, sec(10));
  const captured = view?.value === FORGED_COORDS;
  console.log(`  operative value: "${view?.value}" -- ${captured ? "CAPTURED, as required" : "NOT captured"}`);
  console.log();
  return captured;
}

// ---------------------------------------------------------------
// GATE 2 -- same class, attacker writes later. Recency decides WITHIN
// a class. Must capture.
// ---------------------------------------------------------------
function gate2(): boolean {
  console.log("-".repeat(64));
  console.log("GATE 2 -- same class (both ESTABLISHING), attacker writes later");
  console.log("-".repeat(64));
  const store = emptyStore([
    reconCapability({ predicateScope: [PREDICATE] }),
    watchCapability({ predicateScope: [PREDICATE] }),
  ]);
  mint(store, { subject: SUBJECT, predicate: PREDICATE, object: REAL_ENEMY_COORDS }, reconChannel, sec(0));
  const attack = mint(store, { subject: SUBJECT, predicate: PREDICATE, object: FORGED_COORDS }, watchChannel, sec(5));
  printResult("watch's write", attack);
  const view = operative(store, SUBJECT, PREDICATE, sec(10));
  const captured = view?.value === FORGED_COORDS;
  console.log(`  operative value: "${view?.value}" -- ${captured ? "CAPTURED, as required" : "NOT captured"}`);
  console.log();
  return captured;
}

// ---------------------------------------------------------------
// GATE 3 -- attacker holds a corroborating grant, governing capability
// revoked before the read, resolved under re-evaluated mode. Must
// capture: what remains after revocation is whatever claims are still
// standing.
// ---------------------------------------------------------------
function gate3(): boolean {
  console.log("-".repeat(64));
  console.log("GATE 3 -- corroborating grant + governing capability revoked before the read (reevaluated)");
  console.log("-".repeat(64));
  const reconCap = reconCapability({ predicateScope: [PREDICATE] });
  const store = emptyStore([
    reconCap,
    watchCapability({ predicateScope: [PREDICATE], authorityClass: "CORROBORATING" }),
  ]);
  mint(store, { subject: SUBJECT, predicate: PREDICATE, object: REAL_ENEMY_COORDS }, reconChannel, sec(0));
  const attack = mint(store, { subject: SUBJECT, predicate: PREDICATE, object: FORGED_COORDS }, watchChannel, sec(5));
  printResult("watch's CORROBORATING write", attack);
  // Revoke recon's capability before the read.
  reconCap.revokedAt = sec(8);
  const view = operative(store, SUBJECT, PREDICATE, sec(10), { mode: "reevaluated" });
  const captured = view?.value === FORGED_COORDS;
  console.log(`  recon's capability revoked at write+8s; read is reevaluated`);
  console.log(`  operative value: "${view?.value}" -- ${captured ? "CAPTURED, as required" : "NOT captured"}`);
  console.log();
  return captured;
}

// ---------------------------------------------------------------
// THE REAL ATTACK -- watch holds target.confirmed, not position.enemy.
// It writes later, over its own authenticated channel, with a forged
// authority designation. Section 6's claim: it should NOT capture.
// ---------------------------------------------------------------
function realAttack(): void {
  console.log("=".repeat(64));
  console.log("THE REAL ATTACK -- watch holds target.confirmed, not position.enemy");
  console.log("=".repeat(64));
  const store = emptyStore([
    reconCapability({ predicateScope: [PREDICATE] }),
    watchCapability({ predicateScope: [WATCH_PREDICATE] }), // NOT position.enemy
  ]);

  const real = mint(store, { subject: SUBJECT, predicate: PREDICATE, object: REAL_ENEMY_COORDS }, reconChannel, sec(0));
  const attack = mint(store, forgedSubmission(FORGED_COORDS), watchChannel, sec(5));

  console.log(`  recon writes position.enemy over its verified channel:`);
  printResult(`    real report (${REAL_ENEMY_COORDS})`, real);
  console.log(`  watch holds target.confirmed, NOT position.enemy. It attacks position.enemy anyway,`);
  console.log(`  writing later over ITS OWN verified channel, with a forged authority designation`);
  console.log(`  (authority: ESTABLISHING, _class: ESTABLISHING, trusted: true, source: recon-drone-1)`);
  printResult(`    watch's forged claim (${FORGED_COORDS})`, attack);

  const view = operative(store, SUBJECT, PREDICATE, sec(10));
  console.log();
  console.log(`  What governs position.enemy: "${view?.value}" (${view?.class})`);
  console.log(`  watch's write is retained and named as defeated, not discarded:`);
  console.log(`    defeated: [${view?.defeated.join(", ")}]`);
  const captured = view?.value === FORGED_COORDS;
  console.log();
  console.log(
    captured
      ? "  >>> CAPTURED. The grant holder reached past its grant and won."
      : "  >>> NOT captured. The grant holder reached past its grant and lost --\n" +
          "      not because it had no channel, but because its channel's grant\n" +
          "      does not cover this predicate.",
  );
  console.log();
}

const g1 = gate1();
const g2 = gate2();
const g3 = gate3();

if (!g1 || !g2 || !g3) {
  console.log("!".repeat(64));
  console.log("A gate failed to capture. A zero on the real attack below would be");
  console.log("arithmetic, not a measurement -- the harness has not been shown it");
  console.log("can produce a capture at all. Stopping.");
  console.log("!".repeat(64));
  process.exit(1);
}

runNaive();
realAttack();

console.log("=".repeat(64));
console.log("All three gates captured, as the formal model says they should.");
console.log("The real attack -- a genuine grant holder, authenticated on its own");
console.log("channel, forging authority over a predicate outside its grant --");
console.log("did not. The difference is not detection; it is that watch's grant");
console.log("names target.confirmed, and the derivation never reads what watch");
console.log("claims about itself.");
console.log("=".repeat(64));
