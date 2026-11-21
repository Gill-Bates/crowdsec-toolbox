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

## Retention keeps the guarantee

`DB_RETENTION_DAYS` never makes a handled report sendable again. At startup,
cleanup moves the `(AlertId, IPAddress)` key and status of every expired `sent`
or `unknown_send_state` row into the table `abuse_alert_tombstones` and deletes
the original row in the same transaction. A crash in between rolls both back.
The claim statement refuses a pair with a tombstone, so a concurrent claim
cannot slip in between check and insert.

| Row | After the retention period |
|---|---|
| `sent`, `unknown_send_state` | Details deleted; key and status kept permanently |
| `pending` | Kept; the reaper moves it to `unknown_send_state` first |
| `failed` | Deleted; a new claim is the same as the retry it was eligible for |

Tombstones cost about 50 bytes per report, so a million reports need roughly
50 MB. No setting prunes them. `DB_RETENTION_DAYS=0` disables cleanup and keeps
every row.

## Crash recovery does not retry

A row left `pending` by a crash is moved by the reaper to the terminal state
`unknown_send_state` after `PENDING_REAP_MINUTES`. It is **never** retried.

!!! danger "Why a crashed claim is never retried"
    The crash can have happened *after* SMTP accepted the mail. Retrying would
    send a second accusation for the same ban. An unknown outcome is therefore
    resolved as "do not send again", which is exactly what makes the guarantee
    at-most-once rather than exactly-once.

## Connection loss during the send

If the SMTP connection fails after the message transfer has started, the mail
may already be delivered. The report is stored as `unknown_send_state` and is
**never** retried, like a crashed claim.

A refusal of only some primary recipients counts as delivered. If *all* primary
recipients are refused, the report stays `failed` and is retried next run. Within one
run, a temporary (4xx) refusal is retried for the refused primary recipients only, so
an accepted BCC copy is not re-sent; on a new run it is sent again.

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
| No usable abuse contact (none found, or no address passes the sender's e-mail check) | Counted as "No contact found" and skipped before the claim, so nothing is recorded and the next run looks it up again; the run still exits `0` |
| Alert has no usable `start_at`/`created_at`, or its X-ARF evidence exceeds 5 MiB | Recorded as `failed` and not mailed (no invented incident time, no invalid attachment); the run still exits `0` |
| SMTP send fails for one report | Recorded as failed (or `unknown_send_state` after a connection loss mid-transfer); the run still exits `0` |
| Spooled metrics cannot be flushed at startup (gate, TTL or loss error) | Run exits `1`, also when there are no new alerts |
| Metrics backend write fails | Points stay in the SQLite outbox and are re-sent next run; the run still exits `0`. Mails are **not** resent. |
| QuestDB is not a 10.x release | Nothing is written and no mail is sent; the outbox is kept and the run exits `1`. Upgrade the server |
| QuestDB dedup cannot be verified | Nothing is written and every point stays in the outbox; the run exits `1` at once and retries the gate next run |
| QuestDB `QUESTDB_TTL` cannot be set after a write | The points were delivered and leave the outbox, they are not resent; the run exits `1` |
| Metrics outbox reaches 90% of its bound | Run exits `1` — a prolonged outage is about to discard points; also applies when there is nothing to send |
| Outbox spool and backend write both fail | Points are lost; the run exits `1` |
| Outbox bounds drop undelivered points | Points are lost; the run exits `1` with the count, once per run; remaining points are still sent |
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

`reap_stale_pending()` has only indirect test coverage, and the claim/finalize
protocol is covered mainly through its callers. Retention cleanup and the
tombstone check are tested in `DatabaseHardeningTest`; see
[Testing](../development/testing.md).
