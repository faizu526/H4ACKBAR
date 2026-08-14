# Detector

H4ACKBAR's detector goes **2 levels above traditional single-payload probing**.

## Level Model

| Level | Method                                                     | H4ACKBAR |
|:-----:|-----------------------------------------------------------|:--------:|
| 0     | Fire one payload, grep for known DBMS error strings        | included |
| 1     | Differential — send true-vs-false, compare response bodies | included |
| 2     | Multi-signal — baseline + true + false + time + union;     | ✅        |
|       | require ≥ 2 orthogonal signals to confirm                  |          |

## Signals

| Sig | Name       | Trigger                                                                     |
|-----|------------|-----------------------------------------------------------------------------|
| E   | Error      | Probe response body matches a `DBMS_ERROR_PATTERNS` regex                   |
| B   | Boolean    | `sim(true,base) > 0.92` **and** `sim(true,false) < 0.85` **and** length delta > 20 bytes |
| T   | Time       | DBMS-specific sleep probe delays ≥ 3 s over baseline                        |
| U   | Union      | ≥ 2 UNION column-count probes alter body length without erroring            |

## Probe Payloads

```
ERROR   :  '   "   ')   ";   ' AND CAST('x' AS INT)-- -
BOOLEAN :  ' AND '1'='1     vs     ' AND '1'='2
TIME    :  ' AND SLEEP(4)-- -           (mysql)
           '; SELECT pg_sleep(4)-- -   (postgres)
           '; WAITFOR DELAY '0:0:4'-- - (mssql)
           ' AND DBMS_LOCK.SLEEP(4)-- - (oracle)
           SQLite heavy-LIKE stall
UNION   :  ' UNION SELECT NULL[,NULL,...]-- -   (n=1..10)
```

## Confidence Tiers

| Signals | Confidence |
|:-------:|------------|
| 0       | none       |
| 1       | low        |
| 2       | medium (**confirmed**) |
| 3+      | high (**confirmed**)   |

## Request Budget

Per parameter, at most ~12 requests:
- 1 baseline
- 5 error probes
- 2 boolean probes (true + false)
- ≤ 2 time probes (per candidate DBMS)
- ≤ 10 union probes (early-exits on second change)

## Evidence Format

Every Finding carries a machine-parseable evidence list, e.g.:

```
E: probe="'" → dbms=mysql
B: sim(true,base)=0.98 sim(false,base)=0.42 sim(true,false)=0.44 len(true)=8712 len(false)=310
T: dbms=mysql delay=4.13s baseline=112ms probe=4243ms
U: 3 column-count probes altered response length
```
EOF
