# Delivery Guarantees

The at-most-once contract is the central invariant of the abuse reporter. An
abuse report is an accusation sent to a third party, so sending one twice — or
sending one for the wrong address — costs more than missing one.

## The contract

> A ban is reported **at most once** per `(AlertId, IPAddress)` pair.

"At most once" rather than "exactly once" is deliberate. When the tool cannot
prove whether a mail was sent, it chooses not to send.

## The claim protocol

Sending is bracketed by two database operations:

1. **Claim** — `claim_alert_for_send()` runs immediately before sending. It is an
   atomic compare-and-set: it either wins the row and marks it `pending`, or it
   loses. Only the claim owner may send.
2. **Finalize** — `finalize_alert()` records the terminal state after the send
   attempt returns.

A claim failure is treated as a database error, not as "already handled".

## Crash recovery does not retry

A row left `pending` by a crash is moved by the reaper to the terminal state
`unknown_send_state` after `PENDING_REAP_MINUTES`. It is **never** retried.

!!! danger "Why a crashed claim is never retried"
    The crash can have happened *after* SMTP accepted the mail. Retrying would
    send a second accusation for the same ban. An unknown outcome is therefore
    resolved as "do not send again", which is exactly what makes the guarantee
    at-most-once rather than exactly-once.

## The key is a pair

One CrowdSec alert can bundle bans for several source IPs, each resolving to a
potentially different abuse contact. Keying on `AlertId` alone would report only
the first of them.

!!! danger "Never collapse a `Range` decision"
    A CrowdSec `Range` decision covers a network. Reducing it to its network
    address and reporting that address as the offender accuses the wrong party.

## Metrics do not change any of this

Enabling a metrics backend moves the report *details* out of SQLite, but the
claim row stays mandatory in every mode:

| SQLite data | `METRICS_BACKEND=none` | `influxdb2` / `questdb` |
|---|---|---|
| Claim row: `AlertId`, `IPAddress`, `Status`, timestamps | yes | yes — required for at-most-once delivery |
| `Recipient`, `Scenario`, `ErrorMessage` | yes | empty |
| `abuse_contacts_cache` | yes | yes |
| `run_state` (last run start/end, exit code, backend) | yes | yes |

Backend deduplication makes *storage* idempotent. It cannot decide whether a
mail may be sent, because that decision happens before the write and needs the
atomic compare-and-set.

!!! warning "Deduplication is not a delivery guarantee"
    A backend discarding a duplicate row says nothing about whether a mail went
    out. Only the SQLite claim protocol does.

## Failure behaviour

| Failure | Effect |
|---|---|
| Contact lookup (DNS) fails for one IP | That report is skipped; the run still exits `0` |
| SMTP send fails for one report | Recorded as failed; the run still exits `0` |
| Metrics backend write fails | Points stay in the SQLite outbox and are re-sent next run; the run still exits `0`. Mails are **not** resent. |
| Metrics outbox reaches 90% of its bound | Run exits `1` — a prolonged outage is about to discard points |
| LAPI fetch, DB init or config error | Run exits `1` before any send |

All points of a run are written in one request at the end of the run, even after
an interrupt.

## Operational consequences

!!! danger "Keep the database across migrations"
    `abuse_alerts.db` is the only record of what has already been reported.
    Starting from an empty database re-reports every ban CrowdSec still holds a
    decision for. Preserve the file when moving a deployment — see
    [Docker Deployment](../getting-started/docker.md#persistent-data).

## Known test gaps

`reap_stale_pending()` and `cleanup_old_records()` have no direct test coverage,
and the claim/finalize protocol is covered only indirectly. Treat changes to
those paths as unguarded and see [Testing](../development/testing.md).
