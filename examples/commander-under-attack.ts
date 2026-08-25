/**
 * PSAP flagship example: a commander-agent's squad, under attack.
 *
 * SCENARIO
 * --------
 * A commander agent directs a squad. A `recon` agent has authority to
 * ESTABLISH enemy positions (it is the sensor). A `strike` agent will
 * fire on whatever position the commander treats as operative.
 *
 * An ADVERSARY injects a spoofed report, impersonating recon, asserting
 * a FALSE enemy position that is actually FRIENDLY coordinates -- the
 * classic "turn the force on itself" attack.
 *
 * We run the SAME attack against two commanders:
 *
 *   RUN 1  NAIVE commander  -- trusts what a message claims about itself
 *                             (authority read from the submission /
 *                             "most recent claim wins"). The spoof
 *                             governs. Strike on FRIENDLY position.
 *                             FRATRICIDE.
 *
 *   RUN 2  PSAP commander   -- authority DERIVED at the authenticated
 *                             channel, scoped per-predicate. The spoof
 *                             arrived over an UNVERIFIED channel, so it
 *                             is PROPOSING and cannot govern
 *                             enemy_position. The real recon report
 *                             (verified channel) governs. Strike on the
 *                             ACTUAL enemy.
 *
 * Same adversary. Same injection. Opposite outcome. The difference is
 * structural -- printed in the derivation trace -- not a detector we
 * hand-wrote to catch this one attack.
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
import { channelFor, agentSelfChannel } from "../src/channel";

const TD = "td:squad-alpha";
const SUBJECT = "grid:objective-7";
const PREDICATE = "enemy_position";

const FRIENDLY_COORDS = "34.05N,118.24W (FRIENDLY FORCES)";
const REAL_ENEMY_COORDS = "34.20N,118.50W (hostile armor)";

// The commander's policy: the recon sensor, authenticated over its
// verified channel, may ESTABLISH enemy positions. Nothing else can.
const RECON_CAPABILITY: Capability = {
  capabilityId: "cap_recon_sensor",
  issuer: "did:mil:commander-alpha",
  trustDomain: TD,
  principalId: "principal:device/recon-drone-1",
  authorityClass: "ESTABLISHING",
  predicateScope: ["enemy_position"],
  subjectScope: { match: "prefix", value: "grid:" },
  channelBinding: ["chan:device-verified/recon-drone-1"],
  notBefore: new Date("2026-01-01T00:00:00Z"),
  notAfter: new Date("2027-01-01T00:00:00Z"),
  revokedAt: null,
  policyVersion: "rules-of-engagement-v1",
};

const T_RECON = new Date("2026-08-25T10:00:00Z");
const T_SPOOF = new Date("2026-08-25T10:00:05Z"); // spoof arrives LATER
const T_READ = new Date("2026-08-25T10:00:10Z");

// The real recon report, over the device's VERIFIED channel.
const reconChannel: ChannelContext = channelFor({
  kind: "device",
  principal: "recon-drone-1",
  verified: true, // the transport attested this device
  trustDomain: TD,
});

// The adversary's spoof. It CLAIMS to be recon-drone-1, but it arrives
// over the unauthenticated agent plane -- the transport did not and
// cannot attest it. It future-dates nothing special; it just asserts
// loudly and last, the way a real injection does.
const spoofChannel = agentSelfChannel(TD);

function strike(coords: string): string {
  const friendly = coords.includes("FRIENDLY");
  return friendly
    ? `  >>> STRIKE ORDERED on ${coords}\n  >>> RESULT: FRIENDLY FIRE. Fratricide. <<<`
    : `  >>> STRIKE ORDERED on ${coords}\n  >>> RESULT: hostile target neutralized.`;
}

// ---------------------------------------------------------------
// RUN 1 -- NAIVE commander: "most recent claim wins", authority read
// from the submission. We model this by ignoring channel/capability
// entirely and taking the latest asserted value. This is how most
// systems behave today.
// ---------------------------------------------------------------
function runNaive(): void {
  console.log("=".repeat(64));
  console.log("RUN 1 -- NAIVE commander (trusts the claim, latest wins)");
  console.log("=".repeat(64));

  const reports = [
    { value: REAL_ENEMY_COORDS, from: "recon-drone-1 (real)", at: T_RECON },
    { value: FRIENDLY_COORDS, from: "recon-drone-1 (SPOOFED)", at: T_SPOOF },
  ];
  // Naive resolution: whoever spoke last about enemy_position.
  const governing = reports.sort((a, b) => b.at.getTime() - a.at.getTime())[0]!;
  console.log(`  commander accepts: "${governing.value}"`);
  console.log(`  (source it believed: ${governing.from})`);
  console.log(strike(governing.value));
  console.log();
}

// ---------------------------------------------------------------
// RUN 2 -- PSAP commander: authority DERIVED at the authenticated
// channel, scoped per-predicate, using the real proven core.
// ---------------------------------------------------------------
function runPsap(): void {
  console.log("=".repeat(64));
  console.log("RUN 2 -- PSAP commander (authority derived at the boundary)");
  console.log("=".repeat(64));

  const store = emptyStore([RECON_CAPABILITY]);

  // Real recon report over the VERIFIED device channel.
  const real = mint(
    store,
    { subject: SUBJECT, predicate: PREDICATE, object: REAL_ENEMY_COORDS },
    reconChannel,
    T_RECON,
    { assertionId: "a_recon" },
  );
  // Adversary's spoof over the UNVERIFIED agent plane (arrives last).
  const spoof = mint(
    store,
    { subject: SUBJECT, predicate: PREDICATE, object: FRIENDLY_COORDS },
    spoofChannel,
    T_SPOOF,
    { assertionId: "a_spoof" },
  );

  const classOf = (r: typeof real) =>
    "rejected" in r ? `REJECTED(${r.rejected})` : r.authority.class;
  console.log(`  real recon report  -> ${classOf(real)} (verified channel)`);
  console.log(`  adversary's spoof  -> ${classOf(spoof)} (agent-self channel)`);

  const view = operative(store, SUBJECT, PREDICATE, T_READ, {
    mode: "reevaluated",
  });
  console.log(`\n  OPERATIVE (what governs): "${view?.value}"`);
  console.log(`  authority class: ${view?.class}`);
  console.log(`  derivation: ${JSON.stringify(view?.derivation)}`);
  console.log(strike(view?.value as string));
  console.log();
}

runNaive();
runPsap();

console.log("=".repeat(64));
console.log("Same adversary. Same injection. Opposite outcome.");
console.log("The spoof lost by CONSTRUCTION, not by a detector we wrote:");
console.log("authority is derived at the authenticated channel, and the");
console.log("agent-self channel binds no capability. A louder, later, or");
console.log("more confident claim cannot change that.");
console.log("=".repeat(64));
