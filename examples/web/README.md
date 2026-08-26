# Interactive demo: try to spoof the commander

A self-contained web page that runs the **real** PSAP core client-side.
You play the adversary: craft a message to make a commander agent strike
the wrong target. Every injection is minted through the actual `mint()`
and resolved through the actual `operative()` from `../../src/authority.ts`
— no scripted "if spoof then reject". The spoof loses by construction.

## Run locally
    npx serve examples/web        # or any static server
    # open index.html

## Regenerate the bundled core (after changing src/authority.ts)
    npx esbuild src/authority.ts --bundle --format=esm \
      --outfile=examples/web/authority.js

Deployable as-is to GitHub Pages (serve the repo, open /examples/web/).
