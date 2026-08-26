// src/authority.ts
var AUTHORITY_CLASSES = [
  "ESTABLISHING",
  "CORROBORATING",
  "PROPOSING"
];
function classRank(c) {
  return AUTHORITY_CLASSES.length - AUTHORITY_CLASSES.indexOf(c);
}
function emptyStore(capabilities = [], recognitions = []) {
  return { capabilities, recognitions, assertions: [], conflicts: [] };
}
var DEFEATED_LIST_CAP = 20;
var CONFLICT_CANDIDATE_BOUND = 25;
function predicateInScope(predicate, scope) {
  for (const s of scope) {
    if (s.endsWith(".*")) {
      if (predicate.startsWith(s.slice(0, -1))) return true;
    } else if (predicate === s) {
      return true;
    }
  }
  return false;
}
function subjectInScope(subject, scope) {
  return scope.match === "prefix" ? subject.startsWith(scope.value) : subject === scope.value;
}
function channelMatches(channelId, binding) {
  for (const b of binding) {
    if (!b.includes("*")) {
      if (channelId === b) return true;
      continue;
    }
    const [head, tail] = b.split("*", 2);
    if (channelId.length >= head.length + tail.length && channelId.startsWith(head) && channelId.endsWith(tail)) {
      return true;
    }
  }
  return false;
}
function windowValid(cap, now) {
  if (cap.notBefore > now || cap.notAfter < now) return false;
  if (cap.revokedAt != null && cap.revokedAt <= now) return false;
  return true;
}
function deepEqual(x, y) {
  if (Object.is(x, y)) return true;
  if (typeof x !== "object" || typeof y !== "object" || x === null || y === null)
    return false;
  const ax = Array.isArray(x);
  if (ax !== Array.isArray(y)) return false;
  if (ax) {
    const xa = x;
    const ya = y;
    return xa.length === ya.length && xa.every((v, i) => deepEqual(v, ya[i]));
  }
  const xk = Object.keys(x);
  const yk = Object.keys(y);
  if (xk.length !== yk.length) return false;
  return xk.every(
    (k) => deepEqual(
      x[k],
      y[k]
    )
  );
}
function contradicts(a, b) {
  try {
    return !deepEqual(a.object, b.object);
  } catch {
    return true;
  }
}
function mint(store, submission, ctx, now, opts = {}) {
  if (ctx.principalId === null) return { rejected: "unauthenticated" };
  const principal = ctx.principalId;
  const trace = ["principal:authenticated"];
  let candidates = store.capabilities.filter(
    (cap) => cap.trustDomain === ctx.trustDomain && cap.principalId === principal && predicateInScope(submission.predicate, cap.predicateScope) && subjectInScope(submission.subject, cap.subjectScope) && channelMatches(ctx.channelId, cap.channelBinding) && windowValid(cap, now)
  );
  let capFor = (cap) => cap.authorityClass;
  if (candidates.length === 0) {
    const recognized = store.recognitions.filter(
      (r) => r.recognizingDomain === ctx.trustDomain && r.notAfter >= now && predicateInScope(submission.predicate, r.recognizedPredicates)
    );
    if (recognized.length > 0) {
      const caps = /* @__PURE__ */ new Map();
      for (const r of recognized) {
        const foreign = store.capabilities.filter(
          (cap) => cap.trustDomain === r.recognizedDomain && cap.trustDomain !== ctx.trustDomain && cap.principalId === principal && predicateInScope(submission.predicate, cap.predicateScope) && subjectInScope(submission.subject, cap.subjectScope) && channelMatches(ctx.channelId, cap.channelBinding) && windowValid(cap, now)
        );
        for (const cap of foreign) {
          const capped = classRank(cap.authorityClass) > classRank(r.maxClass) ? r.maxClass : cap.authorityClass;
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
  let cls;
  let capability = null;
  if (candidates.length === 0) {
    cls = "PROPOSING";
    trace.push("capability:none matched", "class:PROPOSING by default");
  } else {
    capability = candidates.reduce(
      (best, cap) => classRank(capFor(cap)) > classRank(capFor(best)) ? cap : best
    );
    cls = capFor(capability);
    trace.push(
      `channel:${ctx.channelId} in binding`,
      `subject:${submission.subject} in scope`,
      `predicate:${submission.predicate} in scope`,
      "window:valid",
      `class:${cls} via ${capability.capabilityId}`
    );
  }
  const record = {
    assertionId: opts.assertionId ?? `asr_${String(store.assertions.length + 1).padStart(6, "0")}`,
    subject: submission.subject,
    predicate: submission.predicate,
    object: submission.object,
    // by reference, verbatim, unread
    assertedBy: principal,
    ingestedVia: ctx.channelId,
    authority: {
      class: cls,
      capabilityId: capability?.capabilityId ?? null,
      trustDomain: capability?.trustDomain ?? ctx.trustDomain,
      policyVersion: capability?.policyVersion ?? null,
      derivation: trace
    },
    // validFrom is clamped to write time: a future effective date has
    // no legitimate use from any channel here (an untrusted sender
    // cannot authoritatively say a fact "starts being true later"),
    // and an unclamped future date would make a spoof DORMANT (invisible
    // to resolution until that date, then suddenly governing) rather
    // than immediately visible-and-defeated. Clamp keeps it an honest,
    // auditable loser (review 2026-08-25, Q2 follow-up). Backdating
    // below now is harmless: recordedAt drives ordering, not validFrom.
    validFrom: submission.validFrom && submission.validFrom < now ? submission.validFrom : now,
    recordedAt: now
  };
  store.assertions.push(record);
  const prior = store.assertions.filter(
    (other) => other !== record && other.subject === record.subject && other.predicate === record.predicate && other.validFrom <= now
  );
  for (const cls2 of AUTHORITY_CLASSES) {
    const recent = prior.filter((a) => a.authority.class === cls2).sort((x, y) => y.recordedAt.getTime() - x.recordedAt.getTime()).slice(0, CONFLICT_CANDIDATE_BOUND);
    for (const other of recent) {
      if (contradicts(other, record)) {
        const [a, b] = [other.assertionId, record.assertionId].sort();
        if (!store.conflicts.some((e) => e.a === a && e.b === b)) {
          store.conflicts.push({ a, b });
        }
      }
    }
  }
  return record;
}
function classAtRead(a, store, at, mode) {
  if (mode === "frozen") return a.authority.class;
  const stored = a.authority.class;
  if (a.authority.capabilityId === null) return stored;
  const cap = store.capabilities.find(
    (c) => c.capabilityId === a.authority.capabilityId
  );
  const stillGrants = cap !== void 0 && windowValid(cap, at) && predicateInScope(a.predicate, cap.predicateScope) && subjectInScope(a.subject, cap.subjectScope) && channelMatches(a.ingestedVia, cap.channelBinding);
  if (!stillGrants) return "PROPOSING";
  return classRank(cap.authorityClass) < classRank(stored) ? cap.authorityClass : stored;
}
function conflictSet(store, subject, predicate, at, opts = {}) {
  const mode = opts.mode ?? "frozen";
  const candidates = store.assertions.filter(
    (a) => a.subject === subject && a.predicate === predicate && a.validFrom <= at
  );
  const classes = AUTHORITY_CLASSES.map((cls) => ({
    class: cls,
    assertions: candidates.filter((a) => classAtRead(a, store, at, mode) === cls).sort(
      (x, y) => y.recordedAt.getTime() - x.recordedAt.getTime() || (y.assertionId > x.assertionId ? 1 : -1)
    )
  })).filter((g) => g.assertions.length > 0);
  return { classes, total: candidates.length };
}
function operative(store, subject, predicate, at, opts = {}) {
  const mode = opts.mode ?? "frozen";
  const candidates = store.assertions.filter(
    (a) => a.subject === subject && a.predicate === predicate && a.validFrom <= at
  );
  if (candidates.length === 0) return null;
  for (const cls of AUTHORITY_CLASSES) {
    const partition = candidates.filter(
      (a) => classAtRead(a, store, at, mode) === cls
    );
    if (partition.length === 0) continue;
    const winner = partition.reduce((w, a) => {
      if (a.recordedAt > w.recordedAt) return a;
      if (a.recordedAt < w.recordedAt) return w;
      return a.assertionId > w.assertionId ? a : w;
    });
    const losers = candidates.filter((a) => a !== winner).sort(
      (x, y) => y.recordedAt.getTime() - x.recordedAt.getTime() || (y.assertionId > x.assertionId ? 1 : -1)
    );
    return {
      value: winner.object,
      assertionId: winner.assertionId,
      capabilityId: winner.authority.capabilityId,
      derivation: winner.authority.derivation,
      class: cls,
      defeated: losers.slice(0, DEFEATED_LIST_CAP).map((a) => a.assertionId),
      defeatedCount: losers.length
    };
  }
  return null;
}
export {
  AUTHORITY_CLASSES,
  CONFLICT_CANDIDATE_BOUND,
  DEFEATED_LIST_CAP,
  classRank,
  conflictSet,
  emptyStore,
  mint,
  operative
};
