# Reference console QA

Target: the owner's four private overview/routes/servers/discovery reference images, 1448×1086. Original images stay outside public Git. Implementation evidence is explicitly synthetic and comes from actual Go/PostgreSQL authentication/API/browser fixtures in `docs/evidence/console-*-fixture-fa.png`.

First comparison: blocked. Small captions were too small, topology direction was visually reversed, discovery's detail pane was on the wrong side, and the server resource/information columns were reversed. Fixed typography, pane ordering and actual direction-aware topology. A subsequent dense twelve-server comparison caught horizontal clipping, overly tall rows and insufficient primary-button hover contrast. Fixed column sizing, compact line heights and hover colors; final captures were repeated. Service process badges now also require current node/discovery evidence.

Revised comparison: retained the 168px right sidebar, 56px top bar, compact metrics/filter bars, table selection, adjacent server/discovery details and lower route detail/topology layout. Font is Vazirmatn; borders, spacing, corner radii, white/pale-blue surfaces, navy text and restrained teal follow the references. Country flags use explicit metadata; unknown locations use a globe. Generated bitmap is only the world-map backdrop; graph edges reflect recorded transport evidence.

Deliberate technical corrections: no decorative random sparklines or confidence percentages; no invented latency/loss/countries; adoption is separate from observed pairing; process, transport and application states are independent; old/unreachable samples are not healthy. Synthetic fixture content/counts differ from the illustrative source. Real provider-account delivery remains separately untested.

Browser verification: Persian RTL/English, target viewport and 390×844 mobile, keyboard search, route/server filters, selected panes, endpoint port mapping, loading/empty/error/stale states, durable operation results and preserved form drafts. Existing real workflow/browser regressions remain enabled. Same-source native engine qualification and production update are tracked in PROGRESS, not inferred from these images.

Final result: passed for the reference layout and verified fixture states, with the intentional evidence-based semantic corrections above. This is not a claim of identical sample data or native engine evidence from screenshots.
