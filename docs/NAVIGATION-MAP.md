# WP4 navigation proposal — owner approval pending

This is a reviewable mapping, not implemented navigation or tested redirects. The correction prompt explicitly asks for owner confirmation before merging Routes and Tunnels. No Backhaul operation is removed. Existing stack, privileges and ownership boundaries remain unchanged.

The six primary destinations would be: نمای کلی، تونل‌ها، سرورها، رویدادها و هشدارها، گواهی‌ها، تنظیمات. Each has a distinct existing-library icon.

| Existing destination/state | Proposed destination | Preserved behavior |
|---|---|---|
| Overview | Overview | Action-first home, health summary, server actions, collapsed real topology |
| Routes | Tunnels, route view | Flattened mappings, three independent endpoints, logical traffic and reverse connection direction |
| Tunnels | Tunnels, main view | Inspect/edit/create/clone, coordinated plans, rollback, classification and explicit adoption |
| Discovery | Tunnels, existing-services view | Selected-server discovery, evidence, manual pairing/import and read-only adoption preview |
| Servers | Servers | Attention ordering, registration, metadata and per-server tools |
| Services | Servers, advanced services view | All-server searchable inventory, affected routes, configuration/log/service deep links |
| Ports | Servers, advanced ports view | Real listeners and conflicts; unrelated ports remain available in details |
| Tags | Servers, metadata grouping | Existing tag filters and editable server metadata |
| Monitoring | Servers, monitoring view | Host measurements/history and links to tunnel-layer checks; no fabricated health |
| Operations | Events and alerts, operations tab | Durable job progress, confirmation, per-side results, retry/rollback actions |
| Alerts | Events and alerts, alerts tab | Reasons, next action, suppression and history |
| Certificates | Certificates | Issue/renew/deploy, consumer impact and local rollback |
| Security | Settings, security tab | Active sessions, explicit revocation and human-readable audit |
| Settings | Settings | Retention, access/rate policy, preferences and existing integrations |

The present console primarily keeps navigation in component state; it does not provide a complete stable URL contract for all these views. After approval, introduce small dependency-free hash navigation, retain aliases for the old destination names and use replacement navigation for aliases. Example proposed targets: `#/tunnels`, `#/tunnels?view=discovery`, `#/servers?view=services`, `#/events?view=alerts`, `#/settings?view=security`. Node/instance selection would retain contextual deep links with friendly visible labels.

Acceptance after approval: no more than six primary items, distinct icons, keyboard/back navigation, retained unsaved-form guards, aliases reaching every listed capability and actual Chrome daily-workflow tests. This file does not authorize an SSH/root/VLESS architecture change, production access or deployment.
