# v2 performance stats (derived from raw JSONL)

SHA `3d4d9dd4bf8b6f6071fd823e17fb96110c11ccd1`.
Artifact SHA-256 `8f1882ab7a7cc2a1aa05337e5b302502cfd9cb73360f5944d40e32684f481f70`
(`performance.jsonl`). Driver exit 0. `2026-08-29T17:56:14Z`–`18:42:10Z`.

91 rows: 21 warmup + 70 measured. Failures 0. `incomplete_run` 91/91
(`MIN_OPS=10000`). Seed 104729. Pacer `sleep-until-next-beat`.
`target_rate_enforced` is **hardcoded True** in `_measure_loop`; it is not
proof that 10/s was achieved.

Measured n=10 per baseline:

| ID | median ops/s | min–max ops/s | pstdev | median p50 ms | median p95 ms | median p99 ms | completed sum | error rate |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| B0 | 10.0262 | 10.0224–10.0263 | 0.00114 | 21.204 | 24.628 | 33.541 | 3010 | 0 |
| B1 | 10.0262 | 10.0244–10.0263 | 0.00058 | 21.176 | 26.641 | 34.045 | 3010 | 0 |
| B2 | 10.0262 | 10.0238–10.0263 | 0.00075 | 21.206 | 27.690 | 33.858 | 3010 | 0 |
| B3 | 10.0262 | 10.0205–10.0262 | 0.00188 | 21.319 | 29.829 | 35.715 | 3010 | 0 |
| B4 | 10.0225 | 10.0209–10.0233 | 0.00076 | 30.578 | 39.230 | 49.125 | 3010 | 0 |
| B5 | 8.8518 | 8.3329–9.2578 | 0.404 | 108.110 | 145.425 | 163.581 | 2655 | 0 |
| B6 | 6.6722 | 6.3824–9.2936 | 0.805 | 147.791 | 172.163 | 209.612 | 2077 | 0 |

B6 workload `QL-INDEP-NODE`; `nodes_used` measured: 279,206,203,200,201,200,195,202,192,199.

B0–B4 all measured ops/s in [10.0205, 10.0263]. B5 and B6 all < 10/s.

Confounders: SwapFree ~215 MiB of 16 GiB; PG `shared_buffers=128MB` (plan 4GB);
not a dedicated host. Do not claim frozen-plan W1.
Do not mix with `9c37e34` v1 rows.
`summary.json` writes `status: LIVE_MEASURED` — classify in Results, do not
copy that label onto the frozen-plan cell.
