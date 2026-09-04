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
[`expected.tsv`](expected.tsv), verifies that the ADR's monthly-cost table
matches those reviewed results, and fails if a profile exceeds its ceiling. It
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
| Database changed blocks per rolling 7 days | 11.67 GiB | 116.67 GiB |
| Database changed blocks per rolling 30 days | 50 GiB | 500 GiB |
| Database changed blocks per rolling 35 days | 58.34 GiB | 583.34 GiB |
| Primary backup storage, current plus 35 days of changes | 108.34 GB-month | 1,083.34 GB-month |
| Recovery backup storage, current plus 7 days of changes | 61.67 GB-month | 616.67 GB-month |
| Modeled 64 KiB queue request units with no free allowance | 23.546645 million | 152.824735 million |
| Derived queue baseline, including synthetic writes | 10,639,935 units | 52,824,735 units |
| Pre-reserved visibility-change requests | 3,546,645 units | 52,824,735 units |
| Encoded queue message body hard limit | 2 KiB | 2 KiB |
| Aggregate encoded queue body byte limit | 40 GB | 200 GB |
| New TLS connections/second | 20 | 100 |
| Encoded server TLS handshake bytes/new connection | 8 KiB | 8 KiB |
| Server TLS handshake bytes/month | 14 GB | 70 GB |
| Active TLS connections, one-minute sample | 2,500 | 12,000 |
| ALB processed bytes/hour | 0.5 GB | 4 GB |
| Billable rule evaluations/second | 500 | 4,000 |
| Billable ALB capacity | 1 LCU | 5 LCU |
| Provider total units/minute, steady/15-minute peak | 120/250 | 1,200/1,500 |
| Derived provider traffic through NAT | 111.54 GB | 932.51 GB |
| Telemetry/queue/other AWS-service NAT wire caps | 81/80/20 GB | 806/400/100 GB |
| Billable NAT processed data | 300 GB | 2,250 GB |
| Derived client, handshake, and provider-request egress | 179.59 GB | 991.64 GB |
| Billable internet egress with no free allowance | 200 GB | 1,000 GB |
| Billable directional cross-AZ transfer | 200 GB | 2,000 GB |
| CloudWatch log ingestion | 50 GiB | 500 GiB |
| Retained CloudWatch log storage, uncompressed plus framing | 135 GB | 1,343 GB |
| OpenTelemetry trace ingestion | 10 GiB | 100 GiB |
| Custom metrics | 50 | 500 |
| Primary-region standard alarm metrics | 64 | 64 |
| Stored archive ingress per 31-day month | 16 GB | 80 GB |
| Archive objects written/month | 37,000 | 163,000 |
| Normal S3 tier-1 archive requests, both regions | 111,000 | 489,000 |
| Normal KMS archive requests, both regions | 148,000 | 652,000 |
| Encrypted primary archive/object storage | 208 GB | 1,040 GB |
| Encrypted recovery archive/object storage | 208 GB | 1,040 GB |
| Normal archive cross-region transfer | 16 GB | 80 GB |
| Retained current archive data versions per region | 481,000 | 2,119,000 |
| Physical archive versions plus delete markers per region | 518,000 | 2,282,000 |
| Retention-cleanup ListObjectVersions requests, both regions | 148,002 | 652,002 |
| Delete-marker cleanup-overlap storage per region | 0.02 GB-month | 0.09 GB-month |
| Full-reseed source GET/destination PUT attempts | 530,000 each | 2,331,000 each |
| Full-reseed KMS source-decrypt/destination-encrypt/validation-data-key-and-decrypt requests | 2,120,000 | 9,324,000 |
| Full-reseed cross-region transfer | 229 GB | 1,144 GB |
| Full-reseed S3 Batch Operations jobs | 1 | 1 |
| Full-reseed S3 Batch object operations | 530,000 | 2,331,000 |
| Full-reseed generated-manifest source objects scanned | 481,000 | 2,119,000 |
| Full-reseed transient manifest objects | 1 | 1 |
| Full-reseed transient manifest storage | 0.28 GB-month | 0.28 GB-month |
| Full-reseed candidate overlap storage | 7.39 GB-month | 36.91 GB-month |
| Full-reseed destination GET validation attempts | 530,000 | 2,331,000 |
| Full-reseed cleanup ListObjectVersions requests | 530,001 | 2,331,001 |
| Secrets Manager API requests, primary region | 45,000 | 450,000 |
| Secrets Manager API requests, recovery region | 5,000 | 50,000 |
| Recovery-region secret replicas | 10 | 100 |
| Recovery-region intended probe identities | 44,640 | 44,640 |
| Scheduler/Lambda delivery attempts, including reserves | 93,744 | 93,744 |
| Duplicate/shutdown-race delivery reserves | 44,640/4,464 | 44,640/4,464 |
| Retained recovery-probe identity claims | 46,080 | 46,080 |
| Encoded recovery-probe identity claim | 256 bytes | 256 bytes |
| Probe Lambda duration | 937,440 GB-seconds | 937,440 GB-seconds |
| Probe logs/artifacts retained 30 days | 14.0616/44.64 GB | 14.0616/44.64 GB |
| Probe artifact PUT attempts | 44,640 | 44,640 |

The database and queue rows preserve the accepted ADR 0002 stack and ADR 0012
reliability envelope on equal assumptions. They are design estimates, not
provider invoices or evidence that runtime meters exist.
RDS Multi-AZ rates include the standby instance. Database storage uses the
Multi-AZ gp3 rate. Database recovery storage models one provisioned copy plus a
full-dataset equivalent of rolling 7-day changed data; recovery transfer uses
the rolling 30-day changed-data bound. Relational occupancy includes one bounded
current-state integrity anchor per resource and its index. Archive rows
retain 13 ingress envelopes in each region and price one full retained-archive
reseed; incremental replication may cost less.

The small CPU-credit quantity is the physical 31-day maximum for both
db.t4g.medium Multi-AZ copies: `2 vCPU * 2 copies * 744 hours = 2,976`
vCPU-hours. This deliberately overprices baseline credits so background and
maintenance CPU cannot exceed the accepted ceiling.

Queue units derive from the accepted 15% write-and-cancellation share of the
generated request schedule after reserving two synthetic calls per minute. One
send, receive, and delete for every generated and synthetic write consumes
10,639,935 units small and 52,824,735 target. The prior 20/100-million envelope
already assigned every remaining unit to retries/redeliveries, empty polls, and
critical work. ADR 0012 therefore adds separate 3,546,645/52,824,735-unit
visibility-change partitions instead of silently borrowing from those reserves.
The small profile reserves one reset for each 30-second work item; the target
profile reserves three resets at the 15-, 30-, and 45-second boundaries for
each 60-second work item. A future durable schedule ledger must pre-reserve the
complete baseline and visibility allowance at admission and atomically charge
retries, partial-batch failures, and completion races. The reference
`QueueBudget` is process-local and proves only those accounting transitions.

The fixed workload remains admissible after the 90% warning while excess bursts
are fenced before they can steal future slots. Encoded bodies are capped at 2
KiB even though each request is conservatively priced as a 64 KiB billable unit.
A separate counter expands batches and caps all send, receive, redelivery, and
recovery body occurrences at 40/200 GB. That queue budget, 140/1,600 GB for
database and internal service traffic, and 20/200 GB for failover and retries
form the 200/2,000 GB directional cross-AZ cap. The ADR makes those partitions
measurable admission limits rather than usage forecasts.

Provider traffic units allow at most 4 KiB outbound and 12 KiB inbound across
requests, responses, pagination, observations, and retries. Every hour has 45
steady minutes capped at 120/1,200 units per minute and 15 peak minutes capped
at 250/1,500. This schedule derives 27.88/233.13 GB internet egress and
111.54/932.51 GB combined NAT processing per 744-hour month. Adding bounded
telemetry, queue-service, and other AWS-service wire traffic produces
292.54/2,238.51 GB; the worksheet prices the 300/2,250 GB hard caps and does not
subtract free allowances.

Log storage assumes no compression. Two complete boundary-concentrated 31-day
ingestion envelopes can coexist in the 14/30-day retention windows. Converting
to decimal GB, adding 25% for service framing, and rounding up produces retained
storage caps of 135/1,343 GB. Compression is unpriced headroom, and the
qualification stream uses incompressible input.

CloudWatch's pricing unit is labeled GB, but its official tier examples convert
TB to billed GB with a factor of 1,024. The ingestion rows therefore multiply
the 50/500 GiB log and 10/100 GiB trace caps by 50/500 and 10/100 AWS-priced GB,
respectively; converting those quantities to decimal GB first would apply the
binary-to-decimal factor twice. The operational wire and retained-storage caps
remain decimal-byte envelopes and are rounded up before pricing, which is
conservative against the binary-scaled billing unit. See the
[CloudWatch pricing examples](https://aws.amazon.com/cloudwatch/pricing/).

Custom metric quantities count every unique metric name plus complete dimension
set first emitted during the billing month. A linearizable conditional insert
and counter increment admits a new identity before emission; concurrent duplicate
identities are idempotent and distinct identities cannot exceed the durable
50/500 cap. Deletion or relabeling does not reclaim budget, new identities freeze
at 90%, and unknown series are rejected when the registry is full or stale.

Log and trace collectors atomically check and reserve exact uncompressed
serialized batch bytes before any billable ingestion call. Confirmed acceptance
settles the reservation, confirmed pre-ingestion failure releases it
idempotently, and an uncertain outcome retains it. The byte caps include settled
plus outstanding reservations. Missing state, or state whose last confirmed
durable read is older than two minutes, drops telemetry before ingestion without
failing business work. The 10/100 GiB trace quantities are separate accepted-
byte caps; threshold and concurrent-collector qualification verifies sampling,
dropped-byte observability, seven-day expiry, and inclusion in the telemetry
wire budget.

ALB limits use the maximum of the four AWS LCU dimensions. Small remains below
one LCU at 20 new and 2,500 active TLS connections, 0.5 GB/hour, and 500
billable rule evaluations/second. Target caps each dimension at four LCUs and
prices five. See the
[AWS LCU definition](https://aws.amazon.com/elasticloadbalancing/faqs/).

Backup storage conservatively applies no included allocation. A durable byte
meter caps every rolling 7/30/35-day interval at 7/30, 1, and 35/30 dataset
equivalents, including database maintenance and write amplification. Primary
storage is therefore `dataset * (1 + 35/30)` and recovery storage is
`dataset * (1 + 7/30)`, rounded up to two decimals, without a calendar-boundary
smoothing assumption. Cross-region transfer prices the rolling 30-day cap.

The archive quantities price 13 complete 31-day ingress envelopes, or 208/1,040
GB in each region, because a 365-day retention interval can intersect 13 windows
under boundary-concentrated traffic. The 9/52 million event limits include one
record per provider mutation attempt. Worst-case audit packing uses 500 records
per object to reserve 192 KiB for framing, compression expansion, and
encryption. Audit and compact non-audit multiplicity includes both transitions
for every non-interruptible cancellation and three compact records for every
synthetic write. It yields monthly maxima of 36,985/162,826 objects inside
37,000/163,000 caps, 111,000/489,000 normal S3 requests across both regions, and
148,000/652,000 normal KMS requests. Every data object embeds its signed Veer
manifest in reserved framing, and the stream root is relational state; there are
zero separate persistent Veer manifest objects.

Thirteen retained envelopes cap each region at 481,000/2,119,000 objects. S3
CRR continues copying new versions into the active generation while one S3 Batch
Replication job builds a fresh candidate generation from retained versions. The
full reseed prices 530,000/2,331,000 Batch object operations, source GET
attempts, destination PUT attempts, and destination validation GET attempts;
four KMS requests per attempt; 229/1,144 GB transferred; and a generated-
manifest scan of 481,000/2,119,000 source objects. One generated manifest object
lives in a source-region recovery-control prefix for at most 24 hours, is capped
at 8 GiB, and is priced as 0.28 decimal GB-month plus one tier-one write;
completion-report output is disabled. Candidate overlap is capped at the retry-inclusive
transfer envelope for 24 hours, yielding 7.39/36.91 GB-month. Each exact
destination version is read with checksum mode, its service checksum is checked,
and its body digest and embedded signature are recomputed. The
530,000/2,331,000 validation attempts use the destination Tier-2 GET rate and
conservatively account for both KMS `GenerateDataKey` and `Decrypt` operations.
Same-region validation reads use an S3
gateway endpoint; the Batch service performs the cross-region copy path, so
neither sends bytes through NAT. This separation prevents normal monthly work
from hiding recovery work. Secret values use a version-aware, single-flight
cache plus a durable pre-call request ledger; the request rows are hard monthly
budgets rather than an assumption that every provider operation reads Secrets
Manager.

Archive objects use immutable, date-partitioned keys capped at 512 encoded
bytes. Both regions use S3 Object Lock with default 365-day governance
retention, expire current versions at 365 days, permanently expire noncurrent
versions after one day, remove expired delete markers, and abort incomplete
multipart uploads after one day. Replication preserves source retention
metadata and creation time. Runtime and active-retention roles cannot bypass or
shorten governance retention. A separate signed cleanup role may bypass only a
tagged, non-authoritative recovery candidate or retired generation so failed
reseed storage can still meet its 24-hour teardown bound. A daily exact-version
sweeper is the
24-hour hard bound and verifies an empty expired prefix; lifecycle remains
defense in depth. One boundary-concentrated envelope of noncurrent versions and
markers raises the physical cap to 518,000/2,282,000 entries per region and
marker-key storage to 0.02/0.09 GB-month. The worksheet prices a deliberately
pessimistic one LIST response per version and marker plus the final empty proof:
74,001/326,001 per region, 148,002/652,002 total. DELETE requests remain free.
Protected data bytes are already priced as S3 Standard storage; the default
retention path adds no separate API request row.

Failed candidates and retired active generations are cleaned by exact version.
The LIST budget assumes only one returned version per request plus one final
empty proof—530,001/2,331,001 requests—rather than relying on full 1,000-entry
pages. LIST uses the destination Tier-1 rate; DELETE requests are free under the
dated S3 price contract.

Egress is derived from the exact monthly request schedule and fixed response
distribution in the ADR: 70% reads at a 6.34 KiB mean, remaining response bodies
at no more than 1 KiB, and 1 KiB of response-header allowance for every request.
The 23,436,000/117,180,000 total API envelopes already contain the external
synthetic. Response bodies and one KiB of response headers consume
137.70/688.52 GB. The ingress enforces an eight KiB encoded server-handshake
flight and reserves 14/70 GB of monthly handshake bytes while retaining the
20/100-per-second burst limit. Adding bounded outbound provider traffic yields
179.59/991.64 GB; the worksheet prices 200/1,000 GB.

The one-minute recovery-region probe uses 44,640 immutable schedule identities
in a 744-hour month. EventBridge Scheduler target retries and Lambda asynchronous
retries are zero, but at-least-once delivery is not treated as exactly once.
The worksheet reserves one duplicate per intended identity plus 4,464
non-borrowable shutdown-race attempts: 93,744 paid Scheduler/Lambda attempts.
Every attempt is allowed the full 1 GB, ten-second timeout and 0.00015 GB log
envelope, producing 937,440 GB-seconds and 14.0616 GB. The identity is also the
idempotency key for the probe's no-op write; only a newly committed claim
proceeds to the read, result metric, and artifact paths. At duplicate-reserve
exhaustion a delete-only circuit breaker removes the exact schedule, while the
shutdown partition absorbs in-flight delivery. The 44,640 artifact attempts and
44.64 GB artifact storage remain winner-only bounds.
The worksheet prices Scheduler at its USD 1 per million paid tier even though the
published offer includes a free tier, then prices Lambda, logs, one artifact
attempt, three custom metrics, and one high-resolution alarm. Free service
allowances are not subtracted.

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
| Primary alarms | [AmazonCloudWatch 20260831092148](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonCloudWatch/20260831092148/us-east-1/index.json) | Standard-resolution alarm metric `EVETVUGEN3MUTMXM` at USD 0.10/alarm-metric-month |
| Recovery scheduling | [AWSEvents 20260831092301](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSEvents/20260831092301/index.json) | us-west-2 scheduled invocation `QNGCFAB5SW8AUQEB` at USD 0.000001 after the free tier; the worksheet applies that paid rate to every dispatch |
| Recovery monitoring | [AmazonCloudWatch 20260831092148 us-west-2](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonCloudWatch/20260831092148/us-west-2/index.json) | Logs `CWY7X4MZ4F3MP5SD` at USD 0.50/GB and `MN45SJANDTCPR9QA` at USD 0.03/GB-month; metrics `CN6TP6ZEVS58RK7M` at USD 0.30/month; high-resolution alarm `JQ7VDDDHEZA9XV78` at USD 0.30/alarm-metric-month |
| Recovery probe compute | [AWSLambda 20260831092318 us-west-2](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSLambda/20260831092318/us-west-2/index.json) | Request `ZWHFK83WS2P4WZR6` at USD 0.0000002/request; tier-one duration `XCU6U9G4FCKZQWG9` at USD 0.0000166667/GB-second |
| Primary object storage and Batch Operations | [AmazonS3 20260831092225 us-east-1](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonS3/20260831092225/us-east-1/index.json) | `WP9ANXZGBYYSGJEA` at USD 0.023/GB-month; tier-one PUT/LIST request `E9YHNFENF4XQBZR6` at USD 0.000005/request; tier-two GET request `ZWQ6Q48CRJXX4FXE` at USD 0.0000004/request; Batch job `JS698V37SA2BFFYW` at USD 0.25/job; object operation `VFSW6ADYJ5NS2Z6P` at USD 0.000001/object; generated-manifest scan `VUCQUWK8JADFEN65` at USD 0.000000015/source object; DELETE requests are free |
| Recovery object storage | [AmazonS3 20260831092225 us-west-2](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonS3/20260831092225/us-west-2/index.json) | `Z3FQZG73HYSPVABR` at USD 0.023/GB-month; Tier-1 PUT/LIST request `D4PMUVH6F64HK2D6` at USD 0.000005/request; Tier-2 GET request `E77AQEM2DC4VV3FC` at USD 0.0000004/request; DELETE requests are free |
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
