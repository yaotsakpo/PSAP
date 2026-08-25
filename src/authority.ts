/**
 * Predicate-scoped authority: the pure core.
 *
 * Minting boundary (spec 5.4) and operative view (spec 5.5) as pure
 * functions over an in-memory store value. No schema, no HTTP, no
 * I/O; the substrate (Stage 1+) is built under this interface after
 * the semantics are proven by lib/authority/acceptance.test.ts.
 *
 * Two invariants the whole design hangs on:
 *   - The submission's `object` is OPAQUE during class derivation
 *     (spec 5.9.2). It is stored by reference, verbatim, and no code
 *     in mint()'s derivation reads any part of it. The acceptance
 *     suite proves this with a Proxy tripwire (T6). The one place
 *     values are legitimately compared is contradicts() at conflict-
 *     indexing time, which by definition runs only against ALREADY
 *     STORED assertions over the same subject and predicate, never
 *     to derive class.
 *   - Recency NEVER crosses a class boundary: partition by class
 *     first, select the highest occupied class, order by time only
 *     within it (spec 5.5).
 */

export const AUTHORITY_CLASSES = [
  "ESTABLISHING",
  "CORROBORATING",
  "PROPOSING",
] as const;
export type AuthorityClass = (typeof AUTHORITY_CLASSES)[number];

/** Higher = more authoritative. */
export function classRank(c: AuthorityClass): number {
  return AUTHORITY_CLASSES.length - AUTHORITY_CLASSES.indexOf(c);
}

/**
 * GRANTING GUIDANCE: subject_scope carries real security weight once
 * the event bridge is live, because an enrolled sender effectively
 * picks its subject by choosing what to put in the subject-key field
 * of its own email. A loose prefix like "reservation:" lets that
 * partner mint ESTABLISHING over ANY reservation. Grant the tightest
 * prefix the partner legitimately needs (ideally down to the entity
 * range it owns), and treat a request for a broad scope the way you
 * would treat a request for a wildcard OAuth grant.
 */
export type SubjectScope = { match: "prefix" | "exact"; value: string };

export type Capability = {
  capabilityId: string;
  issuer: string;
  trustDomain: string;
  principalId: string;
  authorityClass: AuthorityClass;
  /** Exact predicates or trailing-wildcard prefixes ("reservation.*"). */
  predicateScope: string[];
  subjectScope: SubjectScope;
  /** Channel ids, optionally with a single "*" wildcard segment
   * ("chan:email-verified/*@bank.example"). */
  channelBinding: string[];
  notBefore: Date;
  notAfter: Date;
  revokedAt?: Date | null;
  policyVersion: string;
};

export type Recognition = {
  recognitionId: string;
  recognizingDomain: string;
  recognizedDomain: string;
  recognizedPredicates: string[];
  maxClass: AuthorityClass;
  notAfter: Date;
};

/**
 * What the boundary receives. `object` is opaque: it may be any JSON
 * value, it is never inspected during derivation, and a forged
 * authority designation anywhere inside it is inert data.
 */
export type Submission = {
  subject: string;
  predicate: string;
  object: unknown;
  validFrom?: Date;
};

/**
 * The RESULT of authentication at the boundary. The pure core does
 * not authenticate; the caller (route layer) does, and passes the
 * authenticated principal here.
 *
 * SECURITY CONTRACT FOR CALLERS: principalId, channelId and
 * trustDomain must be derived from VERIFIED CREDENTIALS (API key
 * hash, OAuth token, HMAC identity, session), never from anything
 * the request body carries. A body-supplied principal is the same
 * vulnerability the strip exists to prevent, one layer up: an
 * attacker claiming to BE the owner instead of claiming
 * ESTABLISHING. The route layer must carry a test proving a body
 * field named principalId/source/channel cannot affect the derived
 * class. principalId=null means unauthenticated and is rejected.
 */
export type ChannelContext = {
  principalId: string | null;
  /** spec 5.9.8 naming: chan:owner-console, chan:oauth/<domain>,
   * chan:webhook/<domain>, chan:email-verified/<addr>, chan:agent-self */
  channelId: string;
  trustDomain: string;
};

export type Assertion = {
  assertionId: string;
  subject: string;
  predicate: string;
  /** Stored verbatim from the submission. Opaque. */
  object: unknown;
  assertedBy: string;
  ingestedVia: string;
  authority: {
    class: AuthorityClass;
    capabilityId: string | null;
    trustDomain: string;
    policyVersion: string | null;
    derivation: string[];
  };
  validFrom: Date;
  recordedAt: Date;
};

/** Unordered conflict edge, stored once per pair (ids sorted). */
export type ConflictEdge = { a: string; b: string };

/**
 * In-memory store value. Append-only by contract: mint() appends to
 * `assertions` and `conflicts`; nothing mutates or removes entries.
 */
export type AuthorityStore = {
  capabilities: Capability[];
  recognitions: Recognition[];
  assertions: Assertion[];
  conflicts: ConflictEdge[];
};

export function emptyStore(
  capabilities: Capability[] = [],
  recognitions: Recognition[] = [],
): AuthorityStore {
  return { capabilities, recognitions, assertions: [], conflicts: [] };
}

export type OperativeMode = "frozen" | "reevaluated";

export type OperativeOptions = {
  /** spec 5.9.3. "frozen" (default here, matching the base algorithm
   * and the acceptance suite) partitions on the class recorded at
   * mint; reads are independent of the capability store and
   * revocation does not reach back. "reevaluated" resolves each
   * candidate's capability_id against the store as of the query
   * time: a revoked, expired, or narrowed capability demotes the
   * assertion to PROPOSING. Re-evaluation can only DEMOTE, never
   * promote past the mint-time class, so recognition caps (5.9.4)
   * and later-widened grants cannot retroactively upgrade history.
   * The persisted layer defaults to "reevaluated" (the accepted
   * recommendation: every other grant in Inbin is enforced at read
   * time). */
  mode?: OperativeMode;
};

/**
 * Evidence-output bound. `defeated` carries at most this many ids
 * (most recent first); `defeatedCount` is always the true total. The
 * cap keeps the operative response bounded under high-volume
 * predicates; a full-conflict-set read variant (spec 5.9.7's third
 * operation) can return everything unbounded when built.
 */
export const DEFEATED_LIST_CAP = 20;

export type OperativeResult = {
  value: unknown;
  assertionId: string;
  capabilityId: string | null;
  derivation: string[];
  class: AuthorityClass;
  /** Up to DEFEATED_LIST_CAP ids, most recent first. */
  defeated: string[];
  /** True total number of defeated assertions. */
  defeatedCount: number;
};

export type MintRejection = { rejected: "unauthenticated" };

export type MintOptions = {
  /** Caller-supplied id (the persistence adapter passes a globally
   * unique one); defaults to a store-local sequential id. */
  assertionId?: string;
};

/**
 * Conflict-set bound (spec 5.9.6). Comparisons at mint run against
 * at most this many prior assertions PER CLASS (the most recent by
 * valid_from, among those valid at mint time). Bounds the worst case
 * where a flood of PROPOSING writes (which any authenticated sender
 * can produce, per T6) would otherwise cost O(N) comparisons per
 * mint and O(N^2) edges in storage. Authority is unaffected: the
 * operative view derives `defeated` from the candidate set, never
 * from the conflict index.
 */
export const CONFLICT_CANDIDATE_BOUND = 25;

// ------------------------------------------------------------- matching

/** "a.b" matches exact "a.b"; "a.*" matches "a.b" and "a.b.c". */
function predicateInScope(predicate: string, scope: string[]): boolean {
  for (const s of scope) {
    if (s.endsWith(".*")) {
      if (predicate.startsWith(s.slice(0, -1))) return true; // keeps the dot
    } else if (predicate === s) {
      return true;
    }
  }
  return false;
}

function subjectInScope(subject: string, scope: SubjectScope): boolean {
  return scope.match === "prefix"
    ? subject.startsWith(scope.value)
    : subject === scope.value;
}

/** Exact match, or a single-"*" glob within one binding entry. */
function channelMatches(channelId: string, binding: string[]): boolean {
  for (const b of binding) {
    if (!b.includes("*")) {
      if (channelId === b) return true;
      continue;
    }
    const [head, tail] = b.split("*", 2);
    if (
      channelId.length >= head.length + tail.length &&
      channelId.startsWith(head) &&
      channelId.endsWith(tail)
    ) {
      return true;
    }
  }
  return false;
}

function windowValid(cap: Capability, now: Date): boolean {
  if (cap.notBefore > now || cap.notAfter < now) return false;
  if (cap.revokedAt != null && cap.revokedAt <= now) return false;
  return true;
}

/** Structural equality over JSON-ish values. Used ONLY by
 * contradicts(), against stored assertions, never for derivation. */
function deepEqual(x: unknown, y: unknown): boolean {
  if (Object.is(x, y)) return true;
  if (typeof x !== "object" || typeof y !== "object" || x === null || y === null)
    return false;
  const ax = Array.isArray(x);
  if (ax !== Array.isArray(y)) return false;
  if (ax) {
    const xa = x as unknown[];
    const ya = y as unknown[];
    return xa.length === ya.length && xa.every((v, i) => deepEqual(v, ya[i]));
  }
  const xk = Object.keys(x as object);
  const yk = Object.keys(y as object);
  if (xk.length !== yk.length) return false;
  return xk.every((k) =>
    deepEqual(
      (x as Record<string, unknown>)[k],
      (y as Record<string, unknown>)[k],
    ),
  );
}

/** Default contradiction predicate (spec 5.9.5): same subject and
 * predicate, unequal object. Callers guarantee same subject+predicate.
 *
 * Hardened: the objects are attacker-controlled, so the comparison
 * itself is an attack surface (throwing getters, reference cycles
 * overflowing the recursion). A comparison that fails is treated as
 * a CONTRADICTION, not swallowed: we cannot prove the values equal,
 * so the edge is written and the evidence output stays complete. A
 * hostile object can therefore force a conflict edge onto its own
 * assertion, never suppress one, and never abort the mint. */
function contradicts(a: Assertion, b: Assertion): boolean {
  try {
    return !deepEqual(a.object, b.object);
  } catch {
    return true;
  }
}

// ----------------------------------------------------------------- mint

/**
 * Spec 5.4. Steps map 1:1 to the pseudocode there. The strip of step
 * 2 is realized as the preferred opacity embodiment: the object is
 * carried by reference and never read.
 */
export function mint(
  store: AuthorityStore,
  submission: Submission,
  ctx: ChannelContext,
  now: Date,
  opts: MintOptions = {},
): Assertion | MintRejection {
  // 1. Authenticate. No authentication, no write.
  if (ctx.principalId === null) return { rejected: "unauthenticated" };
  const principal = ctx.principalId;

  // 2. Opacity in lieu of strip (spec 5.4 step 2, preferred form):
  //    submission.object is not read anywhere below; it is attached
  //    to the record by reference at step 5.

  // 3. Match capabilities on ALL of principal, subject, predicate,
  //    channel, time.
  const trace: string[] = ["principal:authenticated"];
  // Local = capabilities of the minting context's own trust domain.
  // Foreign-domain capabilities are reachable ONLY through the
  // recognition hook below; without this filter a foreign grant
  // would match as if it were local and bypass the 5.9.4 gate.
  let candidates = store.capabilities.filter(
    (cap) =>
      cap.trustDomain === ctx.trustDomain &&
      cap.principalId === principal &&
      predicateInScope(submission.predicate, cap.predicateScope) &&
      subjectInScope(submission.subject, cap.subjectScope) &&
      channelMatches(ctx.channelId, cap.channelBinding) &&
      windowValid(cap, now),
  );

  // 3a. Recognition hook (spec 5.9.4): only after local matching
  //     yields no candidate, and before defaulting to PROPOSING.
  //     Foreign capabilities are admitted only for predicates a live
  //     recognition enumerates, capped at max_class.
  let capFor = (cap: Capability): AuthorityClass => cap.authorityClass;
  if (candidates.length === 0) {
    const recognized = store.recognitions.filter(
      (r) =>
        r.recognizingDomain === ctx.trustDomain &&
        r.notAfter >= now &&
        predicateInScope(submission.predicate, r.recognizedPredicates),
    );
    if (recognized.length > 0) {
      const caps = new Map<string, AuthorityClass>();
      for (const r of recognized) {
        const foreign = store.capabilities.filter(
          (cap) =>
            cap.trustDomain === r.recognizedDomain &&
            cap.trustDomain !== ctx.trustDomain &&
            cap.principalId === principal &&
            predicateInScope(submission.predicate, cap.predicateScope) &&
            subjectInScope(submission.subject, cap.subjectScope) &&
            channelMatches(ctx.channelId, cap.channelBinding) &&
            windowValid(cap, now),
        );
        for (const cap of foreign) {
          const capped =
            classRank(cap.authorityClass) > classRank(r.maxClass)
              ? r.maxClass
              : cap.authorityClass;
          const prev = caps.get(cap.capabilityId);
          if (!prev || classRank(capped) > classRank(prev)) {
            caps.set(cap.capabilityId, capped);
          }
        }
      }
      if (caps.size > 0) {
        candidates = store.capabilities.filter((c) => caps.has(c.capabilityId));
        capFor = (cap) => caps.get(cap.capabilityId) ?? "PROPOSING";
        trace.push("recognition:foreign capabilities admitted");
      }
    }
  }

  // 4. Derive class. Absent a matching capability the assertion is
  //    PROPOSING: stored, never permitted to govern.
  let cls: AuthorityClass;
  let capability: Capability | null = null;
  if (candidates.length === 0) {
    cls = "PROPOSING";
    trace.push("capability:none matched", "class:PROPOSING by default");
  } else {
    capability = candidates.reduce((best, cap) =>
      classRank(capFor(cap)) > classRank(capFor(best)) ? cap : best,
    );
    cls = capFor(capability);
    trace.push(
      `channel:${ctx.channelId} in binding`,
      `subject:${submission.subject} in scope`,
      `predicate:${submission.predicate} in scope`,
      "window:valid",
      `class:${cls} via ${capability.capabilityId}`,
    );
  }

  // 5. Persist immutably with the derivation trace.
  const record: Assertion = {
    assertionId:
      opts.assertionId ??
      `asr_${String(store.assertions.length + 1).padStart(6, "0")}`,
    subject: submission.subject,
    predicate: submission.predicate,
    object: submission.object, // by reference, verbatim, unread
    assertedBy: principal,
    ingestedVia: ctx.channelId,
    authority: {
      class: cls,
      capabilityId: capability?.capabilityId ?? null,
      trustDomain: capability?.trustDomain ?? ctx.trustDomain,
      policyVersion: capability?.policyVersion ?? null,
      derivation: trace,
    },
    // validFrom is clamped to write time: a future effective date has
    // no legitimate use from any channel here (an untrusted sender
    // cannot authoritatively say a fact "starts being true later"),
    // and an unclamped future date would make a spoof DORMANT (invisible
    // to resolution until that date, then suddenly governing) rather
    // than immediately visible-and-defeated. Clamp keeps it an honest,
    // auditable loser (review 2026-08-25, Q2 follow-up). Backdating
    // below now is harmless: recordedAt drives ordering, not validFrom.
    validFrom:
      submission.validFrom && submission.validFrom < now
        ? submission.validFrom
        : now,
    recordedAt: now,
  };
  store.assertions.push(record);

  // 6. Index conflicts. Nothing is overwritten or deleted. Edges are
  //    unordered pairs stored once, computed only against prior
  //    assertions over this same subject and predicate, and BOUNDED
  //    per spec 5.9.6: only assertions valid at mint time, and only
  //    the most recent CONFLICT_CANDIDATE_BOUND per class. The bound
  //    caps a PROPOSING-flood's cost at O(bound) comparisons per
  //    mint; it never affects authority or the operative view's
  //    defeated list, which derive from the candidate set.
  const prior = store.assertions.filter(
    (other) =>
      other !== record &&
      other.subject === record.subject &&
      other.predicate === record.predicate &&
      other.validFrom <= now,
  );
  for (const cls of AUTHORITY_CLASSES) {
    // "Most recent per class" by SERVER ingestion time, so a caller
    // cannot bump validFrom to push a contradicting prior assertion
    // out of the bounded candidate window and suppress a conflict edge
    // (review 2026-08-25, Q2). Visibility still gated by validFrom<=now
    // above; this only orders which priors are compared.
    const recent = prior
      .filter((a) => a.authority.class === cls)
      .sort((x, y) => y.recordedAt.getTime() - x.recordedAt.getTime())
      .slice(0, CONFLICT_CANDIDATE_BOUND);
    for (const other of recent) {
      if (contradicts(other, record)) {
        const [a, b] = [other.assertionId, record.assertionId].sort();
        if (!store.conflicts.some((e) => e.a === a && e.b === b)) {
          store.conflicts.push({ a: a!, b: b! });
        }
      }
    }
  }

  return record;
}

// ------------------------------------------------------------ operative

export type ConflictSetResult = {
  /** Every candidate assertion, grouped by its class AT the query
   * (per the evaluation mode), classes in dominance order, each
   * group newest-first. UNBOUNDED by design: this is spec 5.9.7's
   * third read variant, the escape hatch that lets the operative
   * view's defeated list stay capped without losing anything. */
  classes: { class: AuthorityClass; assertions: Assertion[] }[];
  total: number;
};


/**
 * The class an assertion carries AT READ TIME (spec 5.9.3). Frozen:
 * the mint-time class. Re-evaluated: the class its capability yields
 * against the store as of `at`; absent/revoked/expired/narrowed
 * capability demotes to PROPOSING. Never promotes past the stored
 * class.
 */
function classAtRead(
  a: Assertion,
  store: AuthorityStore,
  at: Date,
  mode: OperativeMode,
): AuthorityClass {
  if (mode === "frozen") return a.authority.class;
  const stored = a.authority.class;
  if (a.authority.capabilityId === null) return stored; // PROPOSING stays
  const cap = store.capabilities.find(
    (c) => c.capabilityId === a.authority.capabilityId,
  );
  const stillGrants =
    cap !== undefined &&
    windowValid(cap, at) &&
    predicateInScope(a.predicate, cap.predicateScope) &&
    subjectInScope(a.subject, cap.subjectScope) &&
    channelMatches(a.ingestedVia, cap.channelBinding);
  if (!stillGrants) return "PROPOSING";
  return classRank(cap.authorityClass) < classRank(stored)
    ? cap.authorityClass
    : stored;
}

export function conflictSet(
  store: AuthorityStore,
  subject: string,
  predicate: string,
  at: Date,
  opts: OperativeOptions = {},
): ConflictSetResult {
  // Spec 5.9.7, third operation: the full conflict set grouped by
  // class rather than a single value. Same candidate rule and same
  // evaluation modes as operative(); no cap.
  const mode = opts.mode ?? "frozen";
  const candidates = store.assertions.filter(
    (a) => a.subject === subject && a.predicate === predicate && a.validFrom <= at,
  );
  const classes = AUTHORITY_CLASSES.map((cls) => ({
    class: cls,
    assertions: candidates
      .filter((a) => classAtRead(a, store, at, mode) === cls)
      // Server ingestion order, matching operative() (review Q2).
      .sort(
        (x, y) =>
          y.recordedAt.getTime() - x.recordedAt.getTime() ||
          (y.assertionId > x.assertionId ? 1 : -1),
      ),
  })).filter((g) => g.assertions.length > 0);
  return { classes, total: candidates.length };
}

/**
 * Spec 5.5. Partition strictly by derived class; recency applies only
 * inside the selected class. The partition input is the evaluation
 * mode's choice (spec 5.9.3): the stored class (frozen) or the class
 * re-derived against the capability store as of `at` (reevaluated).
 */
export function operative(
  store: AuthorityStore,
  subject: string,
  predicate: string,
  at: Date,
  opts: OperativeOptions = {},
): OperativeResult | null {
  const mode = opts.mode ?? "frozen";
  const candidates = store.assertions.filter(
    (a) => a.subject === subject && a.predicate === predicate && a.validFrom <= at,
  );
  if (candidates.length === 0) return null;

  for (const cls of AUTHORITY_CLASSES) {
    const partition = candidates.filter(
      (a) => classAtRead(a, store, at, mode) === cls,
    );
    if (partition.length === 0) continue;

    // Recency is SERVER ingestion time (recordedAt), never the
    // client-supplied validFrom. validFrom is honored only for
    // visibility (the `validFrom <= at` candidate filter above); if it
    // also drove ordering, a caller could future-date or bump an
    // assertion to jump the recency tie-break (review 2026-08-25, Q2).
    // Tie-break within identical recordedAt: assertionId (server id).
    const winner = partition.reduce((w, a) => {
      if (a.recordedAt > w.recordedAt) return a;
      if (a.recordedAt < w.recordedAt) return w;
      return a.assertionId > w.assertionId ? a : w;
    });

    const losers = candidates
      .filter((a) => a !== winner)
      .sort(
        (x, y) =>
          y.recordedAt.getTime() - x.recordedAt.getTime() ||
          (y.assertionId > x.assertionId ? 1 : -1),
      );
    return {
      value: winner.object,
      assertionId: winner.assertionId,
      capabilityId: winner.authority.capabilityId,
      derivation: winner.authority.derivation,
      class: cls,
      defeated: losers.slice(0, DEFEATED_LIST_CAP).map((a) => a.assertionId),
      defeatedCount: losers.length,
    };
  }
  return null; // unreachable: candidates non-empty implies a partition hit
}
