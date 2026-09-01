# Alpha control-plane cost model

This offline worksheet supports
[ADR 0001](../0001-alpha-operational-bounds.md). It makes every quantity, rate,
source, and ceiling reviewable without AWS credentials or network access.

The model is a design comparison, not a quote. It prices a Veer control plane
in `us-east-1` with recovery data in `us-west-2` as of 2026-08-31. Actual bills
vary with usage, negotiated discounts, taxes, support plans, and price changes.

## Verify

From the repository root:

```sh
docs/architecture/cost-model/verify.sh
```

The command validates the worksheet schema and source references, recalculates
monthly totals with the system `awk`, compares them with
[`expected.tsv`](expected.tsv), and fails if a profile exceeds its ceiling. It
does not contact AWS or read environment credentials.

## Files

- [`sources.tsv`](sources.tsv) records the primary pricing source, retrieval
  date, region, and rate scope.
- [`profiles.tsv`](profiles.tsv) records accepted profile ceilings.
- [`inputs.tsv`](inputs.tsv) contains quantities and unit rates. Quantities
  already include resource count where the unit is hourly.
- [`calculate.awk`](calculate.awk) validates and calculates deterministic
  output.
- [`expected.tsv`](expected.tsv) is the reviewed result checked by verification.

## Reference topology assumptions

| Input | Small production | Target-scale qualification |
| --- | ---: | ---: |
| Hard billing month | 744 hours | 744 hours |
| Active zones | 2 | 3 |
| EKS clusters under standard support | 1 | 1 |
| m7g.xlarge on-demand node count | 2 | 6 |
| gp3 root storage per node | 30 GiB | 30 GiB |
| Multi-AZ database proxy | db.t4g.medium | db.r7g.large |
| Billable T4g surplus CPU credits | 2,976 vCPU-hours | 0 |
| Database gp3 storage | 50 GiB | 500 GiB |
| Database changed blocks per 30 days | 50 GiB | 500 GiB |
| Primary backup storage, current plus 35 days of changes | 108.34 GB-month | 1,083.34 GB-month |
| Recovery backup storage, current plus 7 days of changes | 61.67 GB-month | 616.67 GB-month |
| Modeled 64 KiB queue request units with no free allowance | 20 million | 100 million |
| Encoded queue message body hard limit | 2 KiB | 2 KiB |
| Aggregate encoded queue body byte limit | 40 GB | 200 GB |
| New TLS connections/second | 20 | 100 |
| Active TLS connections, one-minute sample | 2,500 | 12,000 |
| ALB processed bytes/hour | 0.5 GB | 4 GB |
| Billable rule evaluations/second | 500 | 4,000 |
| Billable ALB capacity | 1 LCU | 5 LCU |
| Derived provider traffic through NAT | 87.77 GB | 877.66 GB |
| Telemetry/queue/other AWS-service NAT wire caps | 81/80/20 GB | 806/400/100 GB |
| Billable NAT processed data | 300 GB | 2,250 GB |
| Derived client plus provider-request egress | 159.64 GB | 907.93 GB |
| Billable internet egress with no free allowance | 200 GB | 1,000 GB |
| Billable directional cross-AZ transfer | 200 GB | 2,000 GB |
| CloudWatch log ingestion | 50 GiB | 500 GiB |
| OpenTelemetry trace ingestion | 10 GiB | 100 GiB |
| Custom metrics | 50 | 500 |
| Stored archive ingress per 31-day month | 16 GB | 80 GB |
| Archive objects written | 33,000 | 157,000 |
| S3 tier-1 archive requests, primary plus recovery | 99,000 | 471,000 |
| KMS archive requests, primary plus recovery | 132,000 | 628,000 |
| Encrypted primary archive/object storage | 208 GB | 1,040 GB |
| Encrypted recovery archive/object storage | 208 GB | 1,040 GB |
| Secrets Manager API requests, primary region | 45,000 | 450,000 |
| Secrets Manager API requests, recovery region | 5,000 | 50,000 |
| Recovery-region secret replicas | 10 | 100 |
| Recovery-region Synthetics canary runs | 44,640 | 44,640 |
| Canary Lambda duration | 892,800 GB-seconds | 892,800 GB-seconds |
| Canary logs/artifacts retained 30 days | 6.696/44.64 GB | 6.696/44.64 GB |

The database and queue rows are price proxies so issue #12 can compare
alternatives on equal assumptions. They do not select the final implementation.
RDS Multi-AZ rates include the standby instance. Database storage uses the
Multi-AZ gp3 rate. Database recovery storage and transfer model one provisioned
copy plus one full-dataset equivalent of monthly changed data. Archive rows
retain 13 ingress envelopes in each region and price one full retained-archive
reseed; incremental replication may cost less.

The small CPU-credit quantity is the physical 31-day maximum for both
db.t4g.medium Multi-AZ copies: `2 vCPU * 2 copies * 744 hours = 2,976`
vCPU-hours. This deliberately overprices baseline credits so background and
maintenance CPU cannot exceed the accepted ceiling.

Queue units derive from the accepted 15% write-and-cancellation share of the
generated request schedule after reserving two synthetic calls per minute. One
send, receive, and delete consumes 10,506,015 units small and 52,690,815 target.
The remaining units are hard partitions for retries/redeliveries, empty polls,
and critical work, enforced by the fail-closed meter in the ADR. Encoded bodies
are capped at 2 KiB even though each request is conservatively priced as a 64
KiB billable unit.
A separate counter expands batches and caps all send, receive, redelivery, and
recovery body occurrences at 40/200 GB. That queue budget, 140/1,600 GB for
database and internal service traffic, and 20/200 GB for failover and retries
form the 200/2,000 GB directional cross-AZ cap. The ADR makes those partitions
measurable admission limits rather than usage forecasts.

Provider traffic units allow at most 4 KiB outbound and 12 KiB inbound across
requests, responses, pagination, observations, and retries. The continuous
120/1,200 unit-per-minute limits derive 21.94/219.42 GB internet egress and
87.77/877.66 GB combined NAT processing per 744-hour month. Adding bounded
telemetry, queue-service, and other AWS-service wire traffic produces
268.77/2,183.66 GB; the worksheet rounds those quantities to 300/2,250 GB and
does not subtract free allowances.

ALB limits use the maximum of the four AWS LCU dimensions. Small remains below
one LCU at 20 new and 2,500 active TLS connections, 0.5 GB/hour, and 500
billable rule evaluations/second. Target caps each dimension at four LCUs and
prices five. See the
[AWS LCU definition](https://aws.amazon.com/elasticloadbalancing/faqs/).

Backup storage conservatively applies no included allocation. At one
dataset-equivalent of changed blocks per 30 days, primary storage is
`dataset * (1 + 35/30)` and recovery storage is `dataset * (1 + 7/30)`, rounded
up to two decimals. Cross-region transfer retains the one-dataset monthly change
assumption.

The archive quantities price 13 complete 31-day ingress envelopes, or 208/1,040
GB in each region, because a 365-day retention interval can intersect 13 windows
under boundary-concentrated traffic. The 7/50 million event limits include one
record per provider mutation attempt. Worst-case audit packing uses 500 records
per object to reserve 192 KiB for framing, compression expansion, and encryption.
Audit and compact non-audit record multiplicity derives the object/request quantities.
Secret values use a version-aware, single-flight cache; the request rows are
hard monthly budgets rather than an assumption that every provider operation
reads Secrets Manager.

Egress is derived from the exact monthly request schedule and fixed response
distribution in the ADR: 70% reads at a 6.34 KiB mean, remaining response bodies
at no more than 1 KiB, and 1 KiB of header/TLS allowance for every request.
The 23,436,000/117,180,000 total API envelopes already contain the external
synthetic. Adding bounded outbound provider traffic yields 159.64/907.93 GB;
the worksheet prices 200/1,000 GB.

The one-minute recovery-region canary uses 44,640 runs in a 744-hour month. Its
dependent Lambda, log, S3 artifact, three-metric, and one-alarm quantities use
the bounded assumptions from the
[AWS CloudWatch pricing example](https://aws.amazon.com/cloudwatch/pricing/).
Free service allowances are not subtracted.

## Immutable rate evidence

Every billable worksheet row points to a versioned AWS Offers file. The
calculator rejects `current` aliases and ordinary mutable pricing pages.

| Category | Immutable offer evidence | SKU and captured rate |
| --- | --- | --- |
| EKS | [AmazonEKS 20260831092157](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEKS/20260831092157/us-east-1/index.json) | `ZYWMR684YSMFHWEU` at USD 0.10/cluster-hour; extended-support surcharge `M7977BSVFGDUJZ67` at USD 0.50/cluster-hour |
| EC2 compute and root storage | [AmazonEC2 20260831181331](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/20260831181331/us-east-1/index.json) | `Y7X6HJY9G859NU23` at USD 0.1632/m7g.xlarge-hour; `JG3KUJMBRGHV3N8G` at USD 0.08/gp3 GB-month |
| RDS compute | [AmazonRDS 20260831092223](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonRDS/20260831092223/us-east-1/index.json) | `SCBZU9XX357QUA4D` at USD 0.129/db.t4g.medium Multi-AZ-hour; `QPKXCKEKNV5DW3QA` at USD 0.478/db.r7g.large Multi-AZ-hour; PostgreSQL T4g credit `DXW9ERDR4STYT9D7` at USD 0.075/vCPU-hour |
| RDS primary storage and backup | [AmazonRDS 20260831092223](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonRDS/20260831092223/us-east-1/index.json) | `J7S7KD4WFDNQWKNX` at USD 0.23/GB-month Multi-AZ gp3; charged PostgreSQL backup `6W8ECRFVDATCER7J` at USD 0.095/GB-month |
| RDS recovery storage | [AmazonRDS 20260831092223](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonRDS/20260831092223/us-west-2/index.json) | `PAHDKG6EF4XSHYXC` at USD 0.095/GB-month |
| Queue | [AWSQueueService 20250828200713](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSQueueService/20250828200713/us-east-1/index.json) | `8RN6B8U4MERHRXP3` at USD 0.40/million standard requests |
| Load balancer | [AWSELB 20260831092255](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSELB/20260831092255/us-east-1/index.json) | `37CUWUT8GSNQEPUV` at USD 0.0225/hour; `P2XGEJ8N3KU52WA8` at USD 0.008/LCU-hour |
| NAT | [AmazonEC2 20260831181331](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/20260831181331/us-east-1/index.json) | `M2YSHUBETB3JX4M4` at USD 0.045/hour; `59S5R83GFPUAGVR5` at USD 0.045/GB |
| Public IPv4 | [AmazonVPC 20260831092232](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonVPC/20260831092232/us-east-1/index.json) | `4GQUNXTFWVSGPUZK` at USD 0.005/address-hour |
| Data transfer | [AWSDataTransfer 20260831121448](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSDataTransfer/20260831121448/us-east-1/index.json) | `HQEH3ZWJVT46JHRG` at USD 0.09/GB internet egress; `PNUBVW4CPC8XA46W` at USD 0.01/directional-GB cross-AZ; `XGXYRYWGNXSSEUVT` at USD 0.02/GB cross-region |
| Telemetry | [AmazonCloudWatch 20260831092148](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonCloudWatch/20260831092148/us-east-1/index.json) | `S8QGXX5R2BKKMDSJ` at USD 0.50/GB log ingest; `GF9Q9S5QWW3RHMGQ` at USD 0.50/GB OTEL ingest; `6K9ADYQAHV5KX9KZ` at USD 0.03/GB-month; `KG586CTNGQ4VRZKZ` at USD 0.30/metric-month |
| Recovery monitoring | [AmazonCloudWatch 20260831092148 us-west-2](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonCloudWatch/20260831092148/us-west-2/index.json) | Synthetics `96EA6YQSXFE9MUK5` at USD 0.0012/run; logs `CWY7X4MZ4F3MP5SD` at USD 0.50/GB and `MN45SJANDTCPR9QA` at USD 0.03/GB-month; metrics `CN6TP6ZEVS58RK7M` at USD 0.30/month; alarm `SJTFAZNHSW2WVZB2` at USD 0.10/month |
| Recovery canary compute | [AWSLambda 20260831092318 us-west-2](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSLambda/20260831092318/us-west-2/index.json) | Request `ZWHFK83WS2P4WZR6` at USD 0.0000002/request; tier-one duration `XCU6U9G4FCKZQWG9` at USD 0.0000166667/GB-second |
| Primary object storage | [AmazonS3 20260831092225 us-east-1](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonS3/20260831092225/us-east-1/index.json) | `WP9ANXZGBYYSGJEA` at USD 0.023/GB-month; tier-one request `E9YHNFENF4XQBZR6` at USD 0.000005/request |
| Recovery object storage | [AmazonS3 20260831092225 us-west-2](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonS3/20260831092225/us-west-2/index.json) | `Z3FQZG73HYSPVABR` at USD 0.023/GB-month; tier-one request `D4PMUVH6F64HK2D6` at USD 0.000005/request |
| Encryption keys | [awskms 20260831092318](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/awskms/20260831092318/index.json) | `U553K98XGDXCYHWS` and `S8HBXBVJKWKDP9AS` at USD 1/key-month; request SKUs `MFEBZPX8NHM5FY7Z` and `SE9KXT6M6JTP7E4W` at USD 0.000003/request |
| Managed secrets | [AWSSecretsManager 20260831092330 primary](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSSecretsManager/20260831092330/us-east-1/index.json), [recovery](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSSecretsManager/20260831092330/us-west-2/index.json) | Primary `BJ3PQ9BYGU6P632F` and recovery `DWJP9S4V3HP98UNC` at USD 0.40/secret-month; request SKUs `4MDZ5VNEJPMUTG9B` and `AEBQHWFEG8Q4Y7AT` at USD 0.000005/request |

## Updating the model

1. Read each current primary pricing source and record its retrieval date.
2. Add a new source ID instead of silently changing the meaning of an existing
   source.
3. Update rates or quantities in `inputs.tsv`.
4. Run `calculate.awk` manually and review category changes:

   ```sh
   LC_ALL=C awk -f docs/architecture/cost-model/calculate.awk \
     docs/architecture/cost-model/sources.tsv \
     docs/architecture/cost-model/profiles.tsv \
     docs/architecture/cost-model/inputs.tsv
   ```

5. If a total exceeds its ceiling, change capacity or approve a replacement
   ADR. Do not raise a ceiling only to make verification green.
6. After review, replace `expected.tsv` with the calculator output and run
   `verify.sh`.

Rates are snapshots because runtime price fetching would make CI
non-deterministic and introduce network and credential dependencies. The
`sources.tsv` URLs are the audit trail for a human refresh.
