/**
 * Channel derivation: turn the AUTHENTICATED CIRCUMSTANCES of a write
 * into a ChannelContext the authority core can reason about.
 *
 * This is the whole point of the protocol. Authority is derived from
 * HOW a message arrived (which authenticated channel, under what
 * verification), never from what the message claims about itself. A
 * spoofed sender cannot manufacture a verified channel; it can only
 * arrive over an unverified one, which binds no capability.
 *
 * The core (authority.ts) is transport-agnostic. This helper shows the
 * canonical mapping for two common transports; a real deployment plugs
 * in its own (mutual TLS, signed webhooks, DKIM/DMARC on email, a
 * hardware root of trust on a device). The rule never changes:
 *   verified boundary  -> chan:<kind>-verified/<principal>
 *   unverified/unknown -> chan:<kind>-unverified/<principal>
 * and a capability is only ever bound to a *-verified channel.
 */
import type { ChannelContext } from "./authority";

/** A transport's verdict on who it authenticated. Domain-agnostic:
 *  the transport (not the message) fills this in. `verified` is true
 *  only when the transport cryptographically bound the principal. */
export interface TransportAuth {
  /** The kind of channel: "mtls", "email", "webhook", "device", ... */
  kind: string;
  /** The principal the transport observed (a domain, address, node id).
   *  This is a CLAIM until `verified` is true. */
  principal: string;
  /** True only when the transport AUTHENTICATED that principal
   *  (valid mTLS cert, DMARC pass, verified signature, attested device).
   *  A forged header or a self-asserted identity is NOT verified. */
  verified: boolean;
  /** The trust domain this write belongs to (the recipient's domain). */
  trustDomain: string;
}

/**
 * Derive the channel context. The verified flag comes from the
 * transport's own authentication result, never from message content.
 */
export function channelFor(auth: TransportAuth): ChannelContext {
  const channelId = auth.verified
    ? `chan:${auth.kind}-verified/${auth.principal}`
    : `chan:${auth.kind}-unverified/${auth.principal}`;
  return {
    principalId: `principal:${auth.kind}/${auth.principal}`,
    channelId,
    trustDomain: auth.trustDomain,
  };
}

/** The unauthenticated agent plane: any agent can write here, and it
 *  can only ever produce PROPOSING (no capability binds it). */
export function agentSelfChannel(trustDomain: string): ChannelContext {
  return {
    principalId: "principal:agent",
    channelId: "chan:agent-self",
    trustDomain,
  };
}
