<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-11-18 | Updated: 2026-11-18 -->

# tests

## Purpose
Plain pytest functions over the exporter's logic. No network, no backend,
no CrowdSec instance; QuestDB is an in-memory fake behind `httpx.MockTransport`.

## Key Files
| File | Description |
|------|-------------|
| `conftest.py` | Removes the exporter's environment variables before `app.config` is first imported (it reads them at import time and exits on invalid values); shared fixtures `isolated_main` (stubs `main`'s process wiring) and `sent_payloads` (captures `main._send`) |
| `test_config.py` | 53 tests: `settings.env` line parser and loader precedence, strict boolean and QuestDB table-name validation, bare-host validation, timeout validation (invalid values abort) |
| `test_crowdsec.py` | 16 tests: LAPI fetch behavior, retry logging, the fetch ceiling and successful-but-incomplete event-detail responses, with `main()` exit codes |
| `test_entrypoint.py` | 35 tests: `docker/entrypoint.sh` run through bash with a stub `python` and a patched copy (private state dir): `RUN_EVERY_HOUR`/`RUN_INTERVAL` leading zeros read as decimal, automatic jitter (`min(interval / 10, 300)`, start offset, next-run bounds, skipped slots of an overrunning run, `EVENTS_SINCE` warning; `sleep` is stubbed), validation messages and exit code `1`, oversized values (above 8760 hours or 31536000 seconds) rejected and the maximum accepted, `RUN_ONCE` heartbeat and exit-code propagation |
| `test_line_protocol.py` | 72 tests: InfluxDB line-protocol escaping, unrepresentable backslashes skipped, control-character replacement, non-integer `events_count` dropped, timestamp handling, malformed event and scenario handling, invalid coordinates, record ids, transport warnings, the InfluxDB write against an in-memory `httpx.MockTransport` (status, TLS, error mapping), and the invariant that every dedup key is a **tag** column |
| `test_questdb.py` | 45 tests: the dedup and version gates before the first write, verified keys/mode/WAL, retries and polling, failed TTL/downsampling retention, and independent alert and event passes |

## For AI Agents

### Working In This Directory
- Run from the tool directory: `cd crowdsec-metrics-exporter && python -m pytest`
  (`pythonpath = ["."]` makes `app` and `main` importable).
- Do not re-import `app.config` with changed environment variables; test the
  helper functions directly or patch module attributes.
- Tests assert contracts (escaping, validation, dedup keys), not implementation
  details. Keep them offline.
