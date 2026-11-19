# Log Format

Both tools and both container entrypoints write one line per event in the same
layout:

```text
2026-11-19 12:13:50 UTC | INFO     | crowdsec_abuse | Retrieved 12 alerts from CrowdSec LAPI
```

| Column | Content |
|---|---|
| Time | UTC, `%Y-%m-%d %H:%M:%S UTC`; there is no timezone setting |
| Level | `DEBUG`, `INFO`, `WARNING`, `ERROR`, padded to 8 characters. The abuse reporter adds the domain values `MAIL`, `DNS` and `PROCESS`; `CRITICAL` is logged as `ERROR` |
| Source | `crowdsec_abuse` (reporter), `crowdsec_metrics` (exporter); the entrypoints use `entrypoint`, `heartbeat` and `metrics` |
| Message | One line: `\r` and `\n` are escaped, and a traceback follows after ` | ` on the same line |

## Streams and colour

`WARNING`, `ERROR` and `CRITICAL` lines go to stderr, everything else to stdout.
This also holds for `MAIL` error lines. Colour is used only on a TTY and only
when `NO_COLOR` is unset, so `docker logs` output is plain text.

## Banners

The start banner is the only multi-line output. It has no blank lines around it.
