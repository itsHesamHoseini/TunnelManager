> Scope update 2026-10-23: the second engine was removed by explicit owner request. Earlier multi-engine requirements/results below are historical; they do not qualify the current Backhaul-only revision. Current acceptance: docs/REVISION-2.md.

# TunnelManager
One integrated control panel for Backhaul. The controller uses Go, PostgreSQL and React/TypeScript. Native agents connect outbound over authenticated TLS WebSocket. No SSH configuration changes and no management listeners on nodes.
Three independent endpoints: user entry, inter-node transport listener, destination. Engine connection direction is independent of user traffic. Tunnel TLS and application TLS are separate.
M1: security, bilingual shell, authentication, TOTP/recovery and optional Telegram approval, abuse protection, Compose.
M2: single binary CLI, verified install, controller wizard and reversible lifecycle.
M3: one-time enrollment, explicit approval, persistent channel, native metrics and practical server pages.
M4: engine adapters, tunnel workflows, preflight and local commit/confirm rollback.
M5: certificate workflows, diagnostics, logs, alerts and Telegram operations.
M6: release and full-history/dependency security review.
No application user/inbound/subscription management. Later features listed in the release brief are out of the present implementation.
