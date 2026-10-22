# Independent engines and included libraries
Backhaul 0.7.2: [official source](https://github.com/Musixal/Backhaul/tree/v0.7.2), [AGPL-3.0 license](https://github.com/Musixal/Backhaul/blob/v0.7.2/LICENSE). Rathole 0.5.0: [official source](https://github.com/rathole-org/rathole/tree/v0.5.0), [Apache-2.0 license](https://github.com/rathole-org/rathole/blob/v0.5.0/LICENSE). Engine code/binaries are not embedded in this panel or relicensed by it. Typed installation downloads the chosen official release into a separate root-owned cache.

Exact architecture URLs, archive entries and SHA256 are pinned in internal/engine/engine.go. Backhaul digests match official release checksums. Rathole's older release lacks publisher digest metadata: fixed hashes were recorded from first official HTTPS downloads, not an upstream signature. Cache use and mutations check the extracted binary digest; unsupported binaries remain read-only.

Vazirmatn: [SIL Open Font License 1.1](https://github.com/rastikerdar/vazirmatn/blob/master/OFL.txt), served locally. React/React DOM and Vite: MIT. Go module licenses remain in upstream module sources; go.mod, go.sum and npm lock integrity pin dependencies. Private provider credentials and deployment artifacts never belong in the repository.

Backhaul WSS uses that version's certificate behavior; explicit acknowledgement prevents a false identity-verification claim. Unsupported proxy/mutual-auth semantics stay read-only.

Console icons: @tabler/icons-react (MIT), pinned in web/package-lock.json. Decorative topology-world.png generated with the built-in Image Generation tool, 2026-10-22: pale dotted world map, no labels/borders/flags/connectors/text; operational nodes and directions are rendered from records. Generated source was inspected and resized to 640×280.

Country flags: selected unmodified flag-icons v7.6.0 SVG files (MIT), bundled locally with LICENSE. Unknown country uses a globe; country metadata is explicit and never guessed from IP/name.
