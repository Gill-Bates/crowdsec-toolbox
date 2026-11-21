# Log Format

Both tools and both container entrypoints write one line per event in the same
layout:

```text
2026-11-19 12:13:50 UTC | INFO     | crowdsec_abuse | Retrieved 12 alerts from CrowdSec LAPI in 22.1s
```

| Column | Content |
|---|---|
| Time | UTC, `%Y-%m-%d %H:%M:%S UTC`; there is no timezone setting |
| Level | `DEBUG`, `INFO`, `WARNING`, `ERROR`, padded to 8 characters. The abuse reporter adds the domain values `MAIL`, `DNS` and `PROCESS`; `CRITICAL` is logged as `ERROR` |
| Source | `crowdsec_abuse` (reporter), `crowdsec_metrics` (exporter); the entrypoints use `entrypoint`, `heartbeat` and `metrics` |
| Message | One line, and a traceback follows after ` | ` on the same line. Both tools escape `\r`, `\n`, `\t`, other control characters (as `\xNN`) and the Unicode line/paragraph separators (as `\u2028`/`\u2029`) |

## Streams and colour

`WARNING`, `ERROR` and `CRITICAL` lines go to stderr, everything else to stdout.
This also holds for `MAIL` error lines. Colour follows one rule for log lines, banner and
release notice: a non-empty `NO_COLOR` disables it, a non-empty `FORCE_COLOR` other than `0` enables it, otherwise
it needs a TTY and `TERM` other than `dumb`, so `docker logs` output is plain text.

## Banners

The start banner is the only multi-line output. It has no blank lines around it.
A release notice line follows it (`A new version is available: ...` or `Your version is up to date.`). It is printed like the banner, independent of the log level, and is omitted when GitHub cannot be reached, on a `dev` build, or when the version cannot be compared. A running version newer than the latest release reports `Your version (vX) is newer than the latest release.`
