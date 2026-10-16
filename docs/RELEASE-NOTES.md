# TunnelManager 0.6.0
Integrated two-node native Linux operations: pinned Backhaul/Rathole installation, discovery/import/adoption, configuration plans, shared-service impact, local commit/confirm rollback, service/batch actions, certificate lifecycle, scoped diagnostics/logs and persistent recovery/monitoring.

Qualification is recorded in REQUIREMENTS.md and PROGRESS.md. Publishing is gated on successful exact-source Verify, clean OS and native engine workflows; a version string or this document does not establish acceptance. Multi-architecture static binaries and SHA256 are built reproducibly. The tagged workflow publishes the controller GHCR image and verifies the actual published bootstrap download. Check progress for actual publication/deployment status.

Live Let's Encrypt/Cloudflare and Telegram delivery remain untested without owner accounts; protocol fixtures are separate evidence. Native ARM64 and Debian 11 remain untested. Backhaul 0.7.2 WSS does not verify peer certificate identity. Unsupported ranges, proxy/mutual-auth identities and versions are visible/read-only. VLESS application health is not synthesized from TCP. Traffic history is observed host-interface data with explicit gaps and partial coverage.

Upgrade with a verified binary after an encrypted independent backup. No existing service is adopted by an upgrade. Update the controller-host agent through its native installer, retaining identity. Finish local pending rollback sessions before uninstalling. Production fault injection and unrequested existing-tunnel changes are excluded.
