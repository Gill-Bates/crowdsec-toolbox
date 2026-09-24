## [1.0.1] - 2026-09-25

- ``New`` Grafana dashboard: added chart overviews ("Alerts by Host", "Scenarios by Host", "Top 15 Networks / ASN") above the existing detail tables for a quicker at-a-glance read.
- ``Fix`` Guarded against a potential invalid Line Protocol payload if a data point were ever written without tags (not currently reachable, since every point always has at least one tag).


<details markdown="1">
<summary>Previous versions...</summary>

## [1.0.0] - 2026-09-24
- Project initialization
