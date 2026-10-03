# Interactive demo: try to spoof the commander

A self-contained web page that runs the **real** PSAP core client-side.
You play the adversary, in one of two modes. Every injection is minted
through the actual `mint()` and resolved through the actual `operative()`
from `../../src/authority.ts` — no scripted "if spoof then reject".

- **Stranger** — you hold no capability at all. No wording wins; you can
  only see the spoof succeed by literally checking a "cheat" box that
  simulates holding the verified channel. This tests that message
  content cannot manufacture a channel.
- **Grant holder** — you hold a genuine capability, `ESTABLISHING` over
  `target.confirmed`, on your own authenticated channel. You attack
  `enemy_position` anyway, forging an authority designation inside your
  own submission. This is the attack Section 6.2 of the paper runs: a
  grant holder reaching past its grant, not a channel with nothing bound
  to it. It also loses, for a different reason: the derivation never
  reads what you claim about yourself, and your grant names a different
  predicate.

## Run locally
    npx serve examples/web        # or any static server
    # open index.html

## Regenerate the bundled core (after changing src/authority.ts)
    npx esbuild src/authority.ts --bundle --format=esm \
      --outfile=examples/web/authority.js

Deployable as-is to GitHub Pages (serve the repo, open /examples/web/).
