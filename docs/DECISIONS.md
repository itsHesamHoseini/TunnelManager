# Decisions
2026-10-15: The user authorized M1–M3, private milestone pushes and installer deployment. The existing clean main commit is the sole history base; no previous history is imported.
D1: Native agents initiate outbound TLS WebSocket; typed actions only. No SSH edits.
D2: PostgreSQL is the durable authority for sessions, enrollment, audit and measurements. No Redis.
D3: Single static Go CLI embeds UI and deployment templates. A small line-oriented wizard has explicit steps, inline validation, masked passwords and NO_COLOR support; external terminal frameworks are unnecessary.
D4: CSS design tokens and reusable React controls preserve the restrained visual direction. No chart library until real measurements require it.
D5: Initial account must enroll TOTP before ordinary API access. Telegram approval is optional, TOTP/recovery remains available during messaging outages.
D6: Existing shared reverse proxies are preserved. Cutover disables only the previous panel site and panel unit after a working replacement and rollback snapshot exist.
D7: Production is never used for fault injection. Native deployment is normal-path evidence; clean OS/failure tests run in CI on isolated disposable machines.

D8: Enrollment token is pasted into a hidden prompt instead of shell arguments/history. Command and token are supplied separately; the security tradeoff adds one paste.
D9: UI polls visible pages every 15 seconds; agent uses persistent TLS WebSocket and 30-second host samples. No extra collector or queue.
