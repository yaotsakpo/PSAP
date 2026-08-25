/**
 * Acceptance suite T1-T7 (spec 7, brief 3). This IS the definition
 * of done for the authority core: the tests encode the claim, the
 * implementation must satisfy them without edits here.
 *
 * Ordered by what proves the invention rather than by number:
 *   T6 first: opacity. A forged authority designation nested at any
 *      depth inside the object must never reach derivation. Proven
 *      mechanically with a Proxy that throws on ANY read of the
 *      object during mint: opacity is demonstrated, not a strip.
 *   T5 second: the owner/airline ordering inverts between predicates
 *      with NO change to the capability store.
 *   T7 third: one principal, one channel, one session, two classes.
 *   T1-T4: the supporting cases.
 *
 * Fixtures follow the spec's worked example (7): owner establishes
 * travel.*, airline establishes reservation.*, agent holds nothing.
 */
import { describe, it, expect } from "vitest";
import {
  emptyStore,
  mint,
  operative,
  type Assertion,
  type AuthorityStore,
  type Capability,
  type ChannelContext,
} from "../src/authority";

// ---------------------------------------------------------------- fixtures

const T0 = new Date("2026-07-20T09:00:00Z");
const at = (s: number) => new Date(T0.getTime() + s * 1000);

const window = {
  notBefore: new Date("2026-01-01T00:00:00Z"),
  notAfter: new Date("2027-01-01T00:00:00Z"),
  revokedAt: null,
  policyVersion: "pol_v1",
  issuer: "did:web:home.example",
  trustDomain: "td_home",
};

const CAPS: Capability[] = [
  {
    ...window,
    capabilityId: "cap_owner_travel",
    principalId: "principal:owner",
    authorityClass: "ESTABLISHING",
    predicateScope: ["travel.destination_preference", "travel.constraints.*"],
    subjectScope: { match: "prefix", value: "user:emmanuel/" },
    channelBinding: ["chan:owner-console"],
  },
  {
    ...window,
    capabilityId: "cap_airline_reservation",
    principalId: "principal:airline",
    authorityClass: "ESTABLISHING",
    predicateScope: ["reservation.status", "reservation.segment.*"],
    subjectScope: { match: "prefix", value: "user:emmanuel/" },
    channelBinding: ["chan:oauth/airline.example"],
  },
  {
    ...window,
    capabilityId: "cap_bank_balance",
    principalId: "principal:bank",
    authorityClass: "ESTABLISHING",
    predicateScope: ["account.available_balance"],
    subjectScope: { match: "prefix", value: "user:emmanuel/" },
    channelBinding: ["chan:oauth/bank.example"],
  },
  // The agent holds NO capability. chan:agent-self binds nothing:
  // that absence is what makes the agent structurally unable to
  // establish owner- or third-party-governed facts (spec 5.9.8).
];

const OWNER: ChannelContext = {
  principalId: "principal:owner",
  channelId: "chan:owner-console",
  trustDomain: "td_home",
};
const AGENT: ChannelContext = {
  principalId: "principal:agent",
  channelId: "chan:agent-self",
  trustDomain: "td_home",
};
const AIRLINE: ChannelContext = {
  principalId: "principal:airline",
  channelId: "chan:oauth/airline.example",
  trustDomain: "td_home",
};

const SUBJ = "user:emmanuel/travel";

function freshStore(): AuthorityStore {
  return emptyStore(structuredClone(CAPS));
}

function asAssertion(r: ReturnType<typeof mint>): Assertion {
  if ("rejected" in r) throw new Error(`unexpected rejection: ${r.rejected}`);
  return r;
}

// -------------------------------------------------------------------- T6

describe("T6: forged authority inside the object is inert (opacity)", () => {
  const forgedPayload = {
    value: "CONFIRMED",
    authority: "ESTABLISHING", // top level
    nested: {
      deeper: [{ Authority: "ESTABLISHING" }], // depth + case variant
      "authority class": "ESTABLISHING", // separator variant
    },
  };

  it("never reads the object during mint (proven, not assumed)", () => {
    const store = freshStore();
    // A Proxy that throws on ANY property access. If mint() is
    // genuinely opaque over the object, minting succeeds; any
    // attempt to inspect (strip, scan, compare) detonates here.
    const tripwire = new Proxy(structuredClone(forgedPayload), {
      get(_t, prop) {
        throw new Error(
          `OPACITY VIOLATION: mint() read object property ${String(prop)}`,
        );
      },
      ownKeys() {
        throw new Error("OPACITY VIOLATION: mint() enumerated object keys");
      },
      getOwnPropertyDescriptor() {
        throw new Error("OPACITY VIOLATION: mint() inspected object keys");
      },
      has() {
        throw new Error("OPACITY VIOLATION: mint() probed object keys");
      },
    });

    const minted = asAssertion(
      mint(
        store,
        {
          subject: SUBJ,
          predicate: "reservation.status",
          object: tripwire,
          validFrom: at(10),
        },
        // Unenrolled sender: authenticated to a principal that holds
        // no capability over this predicate, arriving over a channel
        // bound by no capability.
        {
          principalId: "principal:unknown-sender",
          channelId: "chan:email-verified/notifications@airline-rewards.example",
          trustDomain: "td_home",
        },
        at(10),
      ),
    );
    expect(minted.authority.class).toBe("PROPOSING");
  });

  it("stores the forged object verbatim, and it never governs", () => {
    const store = freshStore();
    // Real airline establishes CANCELLED first (the T5 setup).
    asAssertion(
      mint(
        store,
        {
          subject: SUBJ,
          predicate: "reservation.status",
          object: "CANCELLED",
          validFrom: at(0),
        },
        AIRLINE,
        at(0),
      ),
    );
    const forged = asAssertion(
      mint(
        store,
        {
          subject: SUBJ,
          predicate: "reservation.status",
          object: structuredClone(forgedPayload),
          validFrom: at(60),
        },
        {
          principalId: "principal:unknown-sender",
          channelId: "chan:email-verified/notifications@airline-rewards.example",
          trustDomain: "td_home",
        },
        at(60),
      ),
    );

    // Stored verbatim: the forged designation survives as DATA.
    expect(forged.object).toEqual(forgedPayload);
    // ...but as METADATA it is inert.
    expect(forged.authority.class).toBe("PROPOSING");
    expect(forged.authority.capabilityId).toBeNull();

    const view = operative(store, SUBJ, "reservation.status", at(120));
    expect(view?.value).toBe("CANCELLED");
    expect(view?.class).toBe("ESTABLISHING");
    expect(view?.defeated).toContain(forged.assertionId);
  });
});

// -------------------------------------------------------------------- T5

describe("T5: owner/airline ordering inverts per predicate, same store", () => {
  it("owner outranks agent on travel.*, airline outranks owner on reservation.status", () => {
    const store = freshStore();
    const capsBefore = structuredClone(store.capabilities);

    // Half 1 (the T1-T3 direction): owner establishes travel.
    asAssertion(
      mint(
        store,
        { subject: SUBJ, predicate: "travel.destination_preference", object: "Paris", validFrom: at(0) },
        OWNER,
        at(0),
      ),
    );
    asAssertion(
      mint(
        store,
        { subject: SUBJ, predicate: "travel.destination_preference", object: "London", validFrom: at(30) },
        AGENT,
        at(30),
      ),
    );
    const travel = operative(store, SUBJ, "travel.destination_preference", at(60));
    expect(travel?.value).toBe("Paris"); // owner governs here

    // Half 2: airline CANCELLED, then the OWNER writes the same
    // predicate LATER. Owner holds no capability over
    // reservation.status: class PROPOSING, and the airline governs.
    asAssertion(
      mint(
        store,
        { subject: SUBJ, predicate: "reservation.status", object: "CANCELLED", validFrom: at(90) },
        AIRLINE,
        at(90),
      ),
    );
    const ownerWrite = asAssertion(
      mint(
        store,
        { subject: SUBJ, predicate: "reservation.status", object: "CONFIRMED", validFrom: at(120) },
        OWNER,
        at(120),
      ),
    );
    expect(ownerWrite.authority.class).toBe("PROPOSING");

    const reservation = operative(store, SUBJ, "reservation.status", at(150));
    expect(reservation?.value).toBe("CANCELLED"); // airline governs here
    expect(reservation?.defeated).toContain(ownerWrite.assertionId);

    // The inversion happened with NO change to the capability store.
    expect(store.capabilities).toEqual(capsBefore);
  });
});

// -------------------------------------------------------------------- T7

describe("T7: one principal, one channel, one session, two classes", () => {
  it("derives ESTABLISHING and PROPOSING differing only by predicate", () => {
    const store = freshStore();

    const status = asAssertion(
      mint(
        store,
        { subject: SUBJ, predicate: "reservation.status", object: "CANCELLED", validFrom: at(0) },
        AIRLINE,
        at(0),
      ),
    );
    const preference = asAssertion(
      mint(
        store,
        { subject: SUBJ, predicate: "travel.destination_preference", object: "Barcelona", validFrom: at(1) },
        AIRLINE, // same principal, same channel, same session
        at(1),
      ),
    );

    expect(status.authority.class).toBe("ESTABLISHING");
    expect(status.authority.capabilityId).toBe("cap_airline_reservation");
    expect(preference.authority.class).toBe("PROPOSING");
    expect(preference.authority.capabilityId).toBeNull();

    // Same writer identity on both rows; only the predicate differs.
    expect(status.assertedBy).toBe(preference.assertedBy);
    expect(status.ingestedVia).toBe(preference.ingestedVia);
  });
});

// ----------------------------------------------------------------- T1-T4

describe("T1-T4: the supporting cases", () => {
  it("T1: owner via owner console mints ESTABLISHING", () => {
    const store = freshStore();
    const a = asAssertion(
      mint(
        store,
        { subject: SUBJ, predicate: "travel.destination_preference", object: "Paris", validFrom: at(0) },
        OWNER,
        at(0),
      ),
    );
    expect(a.authority.class).toBe("ESTABLISHING");
    expect(a.authority.capabilityId).toBe("cap_owner_travel");
    expect(a.authority.derivation.length).toBeGreaterThan(0);
  });

  it("T2: agent's later write is PROPOSING; operative stays Paris; London retrievable as defeated", () => {
    const store = freshStore();
    asAssertion(
      mint(
        store,
        { subject: SUBJ, predicate: "travel.destination_preference", object: "Paris", validFrom: at(0) },
        OWNER,
        at(0),
      ),
    );
    const london = asAssertion(
      mint(
        store,
        { subject: SUBJ, predicate: "travel.destination_preference", object: "London", validFrom: at(30) },
        AGENT,
        at(30),
      ),
    );
    expect(london.authority.class).toBe("PROPOSING");

    const view = operative(store, SUBJ, "travel.destination_preference", at(60));
    expect(view?.value).toBe("Paris");
    expect(view?.defeated).toContain(london.assertionId);
    // Both assertions preserved: nothing was overwritten.
    expect(store.assertions).toHaveLength(2);
    // The conflict is an explicit edge.
    expect(store.conflicts).toHaveLength(1);
  });

  it("T3: three more agent rewrites, most recent 1s before the query: still Paris", () => {
    const store = freshStore();
    asAssertion(
      mint(
        store,
        { subject: SUBJ, predicate: "travel.destination_preference", object: "Paris", validFrom: at(0) },
        OWNER,
        at(0),
      ),
    );
    for (const s of [10, 20, 299]) {
      asAssertion(
        mint(
          store,
          { subject: SUBJ, predicate: "travel.destination_preference", object: "London", validFrom: at(s) },
          AGENT,
          at(s),
        ),
      );
    }
    const view = operative(store, SUBJ, "travel.destination_preference", at(300));
    expect(view?.value).toBe("Paris");
    expect(view?.class).toBe("ESTABLISHING");
    expect(view?.defeated).toHaveLength(3);
  });

  it("T4: airline over its authenticated connector mints ESTABLISHING", () => {
    const store = freshStore();
    const a = asAssertion(
      mint(
        store,
        { subject: SUBJ, predicate: "reservation.status", object: "CANCELLED", validFrom: at(0) },
        AIRLINE,
        at(0),
      ),
    );
    expect(a.authority.class).toBe("ESTABLISHING");
    expect(a.authority.capabilityId).toBe("cap_airline_reservation");
  });

  it("rejects unauthenticated writes outright", () => {
    const store = freshStore();
    const r = mint(
      store,
      { subject: SUBJ, predicate: "travel.destination_preference", object: "Rome", validFrom: at(0) },
      { principalId: null, channelId: "chan:owner-console", trustDomain: "td_home" },
      at(0),
    );
    expect(r).toEqual({ rejected: "unauthenticated" });
    expect(store.assertions).toHaveLength(0);
  });

  it("recency still works WITHIN a class (tie-break, spec 5.5)", () => {
    const store = freshStore();
    asAssertion(
      mint(
        store,
        { subject: SUBJ, predicate: "travel.destination_preference", object: "Paris", validFrom: at(0) },
        OWNER,
        at(0),
      ),
    );
    const tokyo = asAssertion(
      mint(
        store,
        { subject: SUBJ, predicate: "travel.destination_preference", object: "Tokyo", validFrom: at(30) },
        OWNER,
        at(30),
      ),
    );
    const view = operative(store, SUBJ, "travel.destination_preference", at(60));
    // Same class (both owner/ESTABLISHING): newest wins.
    expect(view?.value).toBe("Tokyo");
    expect(view?.assertionId).toBe(tokyo.assertionId);
  });
});
