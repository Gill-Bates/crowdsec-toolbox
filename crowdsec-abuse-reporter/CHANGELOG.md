## [1.0.4] - 2026-xx-xx
- `New` The start banner is followed by a release check: it compares the running version with the latest GitHub release of crowdsec-toolbox and prints either a new-version notice with a link or "Your version is up to date.". The lookup times out after 3 seconds and stays silent when offline, rate-limited or on a `dev` build; it never blocks or fails the start.
- `Changed` The release check moved into the `gillbates-logging` package (`app/version_check.py` removed). The notice now also reports "Your version (vX) is newer than the latest release.", its link has the form `https://github.com/Gill-Bates/crowdsec-toolbox/releases/latest`, and colour follows `NO_COLOR` (non-empty), `FORCE_COLOR`, `TERM=dumb` and a TTY like the log lines.
- `Changed` The QuestDB client (`/exec` retries, dedup gate, version check, TTL, rollup retention) moved into the external `gillbates-questdb-client` package (`Gill-Bates/python-libraries`, pinned by tag in `[project].dependencies`); QuestDB behaviour and log output are unchanged. Local dev installs it with `pip install -e <checkout>/packages/questdb-client`.
- `Changed` The logging core moved into the external `gillbates-logging` package (`Gill-Bates/python-libraries`, pinned by tag in the `default` group); log output is unchanged. Local dev installs it with `pip install -e <checkout>/packages/logging`.

<details markdown="1">
<summary>Previous versions...</summary>

## [1.0.3] - 2026-11-20

- `New` `QUESTDB_DOWNSAMPLING=low|medium|high` (off by default) adds a QuestDB rollup of the report table with the same profiles as the metrics exporter; the rollup keeps `host`, `country`, `scenario` and `status` and aggregates counts and processing time.
- `Changed` **Breaking:** X-ARF reports now follow XARF v4.2.0: reporter and sender carry a `domain`, CrowdSec data travels as a base64 evidence item, and scenarios map to valid category/type pairs. Brute-force reports without a known source port and unmapped scenarios are filed as `reputation/threat_intelligence`.
- `Changed` **Breaking:** Report mails use the XARF e-mail layout (`multipart/report` with a feedback-report part and an `xarf.json` attachment instead of `abuse-report.xarf`); the text body is wrapped to 76 columns.
- `Changed` Abuse contacts that the mail sender would reject are now skipped as "No contact found" before claiming and sending, instead of failing at SMTP; the alert is looked up again next run.
- `Changed` The first start of this version drops two redundant SQLite indexes once; stored reports are unchanged.
- `Changed` **Breaking:** `CROWDSEC_LAPI_VERIFY_TLS` is now `CROWDSEC_LAPI_VALIDATE_CERTIFICATE` and `SMTP_VERIFY_SSL` is now `SMTP_VALIDATE_CERTIFICATE`, matching the `*_VALIDATE_CERTIFICATE` names of the metrics backends; the old names are no longer read.
- `Changed` QuestDB dedup verification now requires the table DDL to show `DEDUP UPSERT KEYS`; a table whose DDL cannot be read blocks the write instead of passing on the key check alone.
- `Changed` Report mails use the subject `XARF Abuse Report - <type> from <ip> (<scenario>)` and a `Date` header with an explicit `+0000` offset; a report whose source is not a valid IP address is recorded as failed instead of being sent.
- `Changed` Quieter INFO log: the static feature block becomes one `Settings:` line, and per-mail details, GeoIP/QuestDB checks, the whitelist table, the sent-mail list and the LAPI heartbeat move to DEBUG; all `print_*` helpers now honour `LOG_LEVEL`. SMTP TLS without certificate verification warns once per run, and error paths log at ERROR/WARNING. LAPI requests log their duration and size at DEBUG, and `Retrieved N alerts` shows the elapsed time.
- `Fix` QuestDB rollup readiness is judged against the base-table state before this run's write, so the asynchronous refresh no longer keeps the raw TTL at full length with a warning on every run; a lag persisting over five runs warns, and NULL symbols in the state table no longer re-insert a state row each run.
- `Fix` The entrypoint's chown warning now names the affected paths, and the container exits `1` with a clear error when `/data` or the database file is not writable by the app user.
- `Fix` A failed flush of spooled metrics at startup now fails the run (exit `1`) even when there are no new alerts to report.
- `Fix` The run summary counts only reports that actually failed as `failed`.
- `Fix` An alert without a usable `start_at` or `created_at`, or with X-ARF evidence above the 5 MiB item limit, is now recorded as failed instead of being mailed with an invented incident time or an invalid attachment.
- `Fix` A locked database gives up after five seconds, and a connection whose setup failed is no longer reused.
- `Fix` X-ARF scenario classification matches whole name tokens instead of substrings: `http-wordpress-*` is no longer reported as service `rdp`, `*-sqli-probing` maps to `sql_injection`, `*-xss-probing` and `*-path-traversal-probing` to a web vulnerability scan, and `rce`/`c2` no longer match inside words such as `resource`.
- `Fix` The `From` header is built from a proper address object, so a `SENDER_NAME` with non-ASCII characters, commas or parentheses yields one valid sender address.
- `Fix` Alerts whose source IP is only present in the alert context or event meta are now reported instead of failing on every run.
- `Security` Folded (multi-line) `Authorization`, `Cookie` and similar header values are now redacted completely in mail text and X-ARF evidence.
- `Security` `SMTP_SENDER` must be a plain e-mail address; anything else (empty, `Name <addr>`, no domain) stops startup instead of producing invalid X-ARF reports.
- `Security` Control characters in log messages (ESC, tab, Unicode line separators) are escaped, so untrusted values cannot forge log lines or terminal output.

## [1.0.2] - 2026-11-19

- `New` Container health checks now monitor helper loops and successful metrics snapshots. A dead loop stops the container for restart, while service outages only mark it unhealthy.
- `Changed` **Breaking:** QuestDB 10.x is required for report metrics. Older servers fail before mail or metric writes, and their stored data is not migrated.
- `Changed` **Breaking:** `RUN_JITTER` is no longer supported; scheduling uses a fixed interval with automatic jitter capped at 300 seconds.
- `Changed` Python and entrypoint logs now use a consistent single-line UTC format. Compose uses `unless-stopped`; run one-shot jobs with `docker compose run --rm -e RUN_ONCE=true crowdsec-abuse-reporter`.
- `Changed` Image rebuilds fetch the current GeoLite2 City and ASN databases from P3TERX, so identical commits can use different database releases.
- `Fix` Healthcheck limits now follow configured intervals and jitter; leading-zero values are decimal, and oversized settings fail startup.
- `Fix` Full LAPI responses retry with tenfold limits; if completeness remains unproven, usable reports still process and the run exits nonzero. Malformed decisions are skipped.
- `Fix` Outbox saturation, dropped points, or simultaneous spool/backend failures now fail the run; delivered points are not resent when post-write TTL setup fails.
- `Fix` Invalid whitelist entries stop startup; local GeoIP ASN is checked when CrowdSec has none, and reports are still sent if both sources lack an ASN. Expired negative-cache entries become misses even when database cleanup is disabled.
- `Security` Permanent tombstones keep expired sent and `unknown_send_state` reports unclaimable after retention cleanup; ambiguous SMTP outcomes are never retried.
- `Security` Sensitive `Name: value` headers are masked in report emails and X-ARF attachments.

## [1.0.1] - 2026-09-25

- ``New`` Grafana dashboard: added `scenario` and `country` filter variables, now available on every panel like on the metrics-exporter dashboard.
- ``Fix`` Grafana dashboard: "Success rate" and "Total reports" no longer count `METRICS_ONLY` observation snapshots as delivery attempts, so both KPIs reflect actual send outcomes.
- ``Fix`` Grafana dashboard: the "Alert" column in the report detail table no longer renders the alert ID as a compressed value (e.g. "6.43 K").
- ``Fix`` Grafana dashboard: removed the "Top abuse recipients" panel, whose data was unreliable, and cleaned up the layout.

## [1.0.0] - 2026-09-24
- Project initialization
</details>
