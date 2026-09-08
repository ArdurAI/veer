# Alpha control-plane cost model

This offline worksheet supports
[ADR 0001](../0001-alpha-operational-bounds.md). It makes every quantity, rate,
source, and ceiling reviewable without AWS credentials or network access.

The model is a design comparison, not a quote. It prices a Veer control plane
in `us-east-1` with recovery data in `us-west-2` from immutable offers retrieved
through 2026-09-08. Actual bills vary with usage, negotiated discounts, taxes,
support plans, and price changes.

## Verify

From the repository root:

```sh
docs/architecture/cost-model/verify.sh
```

The command validates the worksheet schema and source references, recalculates
monthly totals with the system `awk`, compares them with
[`expected.tsv`](expected.tsv), verifies that the ADR 0001 and dependent ADR
0002 monthly-cost tables match those reviewed results, and checks the executable relationships in
[`operational-bounds.tsv`](operational-bounds.tsv). Seeded negative fixtures
must reject broken network, egress, KMS-retry, live-validator, schedule-shutdown,
and regional-detection bounds. The command fails if a profile exceeds its
ceiling. It does not contact AWS or read environment credentials.

## Files

- [`sources.tsv`](sources.tsv) records the primary pricing source, retrieval
  date, region, and rate scope.
- [`profiles.tsv`](profiles.tsv) records accepted profile ceilings.
- [`inputs.tsv`](inputs.tsv) contains quantities and unit rates. Quantities
  already include resource count where the unit is hourly.
- [`operational-bounds.tsv`](operational-bounds.tsv) records enforceable budget
  inputs that must remain synchronized with billable worksheet rows.
- [`calculate.awk`](calculate.awk) validates and calculates deterministic
  output.
- [`verify-operational-bounds.awk`](verify-operational-bounds.awk) checks the
  cross-row admission, retry, shutdown, and detection invariants.
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
| ALB-native entire request-header limit/new request | 64 KiB | 64 KiB |
| ALB-native request-line limit/new request | 16 KiB | 16 KiB |
| Server TLS handshake bytes/month | 14 GB | 70 GB |
| Durably admitted HTTP response bytes/month | 150 GB | 690 GB |
| Active TLS connections, one-minute sample | 2,500 | 12,000 |
| ALB processed bytes/hour | 6.324512 GB | 33.12256 GB |
| Billable rule evaluations/second | 500 | 4,000 |
| Billable ALB capacity | 7 LCU | 34 LCU |
| Provider total units/minute, steady/15-minute peak | 120/250 | 1,200/1,500 |
| Derived provider traffic through NAT | 111.54 GB | 932.51 GB |
| Telemetry/queue/other AWS-service NAT wire caps | 81/80/20 GB | 806/400/100 GB |
| Billable NAT processed data | 300 GB | 2,250 GB |
| Response-ledger, handshake, and provider-request egress cap | 191.88 GB | 993.13 GB |
| Billable internet egress with no free allowance | 195 GB | 995 GB |
| Billable directional cross-AZ transfer | 200 GB | 2,000 GB |
| CloudWatch log ingestion | 50 GiB | 500 GiB |
| Retained CloudWatch log storage, uncompressed plus framing | 135 GB | 1,343 GB |
| OpenTelemetry trace ingestion | 10 GiB | 100 GiB |
| Custom metrics | 50 | 500 |
| Primary-region standard alarm metrics | 64 | 64 |
| Stored archive ingress per 31-day month | 16 GB | 80 GB |
| Archive objects written/month | 37,000 | 163,000 |
| Normal S3 tier-1 archive requests, both regions | 111,000 | 489,000 |
| Normal KMS archive requests, both regions, including 10% retries | 81,400 | 358,600 |
| Encrypted primary archive/object storage | 208 GB | 1,040 GB |
| Encrypted recovery archive/object storage | 208 GB | 1,040 GB |
| Normal archive cross-region transfer | 16 GB | 80 GB |
| Live archive validator attempts | 40,700 | 179,300 |
| Live archive validator retry attempts | 3,700 | 16,300 |
| Live archive validator Fargate vCPU/GB hours | 375.104167/750.208333 | 375.104167/750.208333 |
| Live archive validator public-IPv4 hours | 1,500.416667 | 1,500.416667 |
| Live archive validator launch tokens | 745 | 745 |
| Live archive validator exact-version HEADs plus GETs | 81,400 | 358,600 |
| Live archive validator source-send retries | 3,700 | 16,300 |
| Live archive validator quarantine sends | 40,700 | 179,300 |
| Live archive validator DLQ repair jobs | 3,700 | 16,300 |
| Live archive validator DLQ empty/retried receives | 370 | 1,630 |
| Live archive validator DLQ redrive-send retries | 370 | 1,630 |
| Live archive validator DLQ receive/send/post-send-delete operations | 11,840 | 52,160 |
| Live archive validator queue message operations | 133,940 | 590,060 |
| Live archive validator queue poll requests | 2,678,400 | 2,678,400 |
| Live archive validator total FIFO request units | 2,812,340 | 3,268,460 |
| Live archive validator receipt-cleanup writes | 74,000 | 326,000 |
| Live archive validator pre-HEAD lease ConditionCheck reads/writes | 81,400/81,400 units | 358,600/358,600 units |
| Live archive validator final-lease ConditionCheck reads/writes | 81,400/81,400 units | 358,600/358,600 units |
| Live archive validator launch-guard conditional writes | 187,488 | 187,488 |
| Live archive validator launch-result conditional writes | 1,490 | 1,490 |
| Live archive validator state reads/writes | 248,140/1,287,058 units | 941,140/3,202,258 units |
| Live archive validator state storage | 1 GB-month | 4.4 GB-month |
| Live archive validator cross-region message wire | 0.3334144 GB | 1.4688256 GB |
| Live archive validator same-region reads | 47.0378496 GB | 216.7343104 GB |
| Live archive validator log ingestion/storage | 0.824/1.648 GB | 3.596/7.192 GB |
| Retained current archive data versions per region | 481,000 | 2,119,000 |
| Physical archive versions plus delete markers per region | 555,000 | 2,445,000 |
| Retention-cleanup ListObjectVersions requests, both regions | 296,004 | 1,304,004 |
| Retention-cleanup Object Lock metadata reads, both regions | 296,000 | 1,304,000 |
| Delete-marker cleanup-overlap storage per region | 0.04 GB-month | 0.17 GB-month |
| Full-reseed source GET/destination PUT attempts | 530,000 each | 2,331,000 each |
| Full-reseed KMS client-envelope decrypt requests | 530,000 | 2,331,000 |
| Full-reseed cross-region transfer | 229 GB | 1,144 GB |
| Full-reseed S3 Batch Operations jobs | 1 | 1 |
| Full-reseed S3 Batch object operations | 530,000 | 2,331,000 |
| Full-reseed generated-manifest source objects scanned | 481,000 | 2,119,000 |
| Full-reseed transient manifest data/set objects | 481,000/481,003 | 2,119,000/2,119,003 |
| Full-reseed transient manifest write/validation-read/consumption-read requests | 481,003/481,003/481,003 | 2,119,003/2,119,003/2,119,003 |
| Full-reseed transient manifest cleanup LIST/DELETE requests | 483/482 | 2,121/2,120 |
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
| Probe Lambda duration | 468,720 GB-seconds | 468,720 GB-seconds |
| Probe logs/artifact data retained 30 days plus cleanup overlap | 14.0616/44.64 GB | 14.0616/44.64 GB |
| Probe artifact PUT attempts | 44,640 | 44,640 |
| Probe artifact current maximum or post-Lifecycle current/noncurrent/marker state | 44,640 or 43,200/1,440/1,440 | 44,640 or 43,200/1,440/1,440 |
| Probe artifact cleanup LIST/DELETE requests | 1,488/93 | 1,488/93 |
| Probe artifact marker-key storage | 0.00073728 GB-month | 0.00073728 GB-month |

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

ALB limits use the maximum of the four AWS LCU dimensions. The provider's
[non-adjustable 64 KiB entire-request-header and separate 16 KiB request-line limits](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html)
are the enforceable edge bounds. The prior non-request-header envelopes are
426,272,000/3,631,360,000 bytes/hour; adding both full native allowances at
20/100 requests per second yields 6,324,512,000/33,122,560,000 bytes/hour and
therefore 7/34 billed LCUs. The reference does not claim that AWS WAF's
all-headers inspection is an aggregate-header size gate because the primary WAF
contract does not make that guarantee. See the
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
37,000/163,000 caps and 111,000/489,000 normal S3 requests across both regions.
Two application-controlled KMS calls per object consume 74,000/326,000 base
requests: one primary `GenerateDataKey` and one recovery validation `Decrypt`.
A separate 10% retry reserve, split equally between writer and validator,
raises the hard bounds to 81,400/358,600. The
writer encrypts a unique per-object AES-256-GCM client envelope under a KMS
multi-Region key; both S3 buckets require SSE-S3 around that ciphertext. Native
S3 and CRR work therefore cannot consume the KMS ledger. Every data object
embeds its signed Veer manifest in reserved framing, and the stream root is
relational state; there are zero separate persistent Veer manifest objects.

Normal live CRR uses the durable archive outbox to send signed bucket, key,
version, content-length, stream, and sequence jobs to an encrypted FIFO SQS
queue in `us-west-2`. Ordered per-stream sends and `MessageGroupId` preserve
sequence; SHA-256 over the length-delimited bucket/key/version tuple is both the
deduplication identity and fixed 32-byte durable receipt key. The raw, signed
tuple remains in the job, archive index, and reconciliation proof rather than
the size-capped receipt. Archive admission pre-reserves one baseline
send plus a 10% retry partition, and every attempt has an enforced 8 KiB
complete-wire cap. Each successful send acknowledgement is bounded to 60 seconds
after its job becomes the head of the ordered outbox. The FIFO queue then applies
a 300-second queue-level delay, so a message is never visible before the complete
accepted CRR boundary.

Two always-on 0.25-vCPU/0.5-GB ARM Fargate tasks use a 30-second DynamoDB
fencing lease; one leader polls while the other remains hot. Two concurrent
loops keep batch processing off the receive path, each uses a 20-second long
poll and 21-second response deadline, and each starts its next receive within
one second. A shared token bucket permits at most one aggregate
`ReceiveMessage` start per second, capping polling at 2,678,400 requests per
744-hour month. Because SQS can split the four
same-stream objects across four receives, the timing bounds reserve four full
inter-poll, receive-response, execution, final-transaction, and acknowledged-
delete cycles. The source-to-completion
budget is `4 * 60 + 300 + 4 * (1 + 21 + 2) = 636` seconds. This charges four
sequential acknowledged sends as well as four receive cycles and is a successful
first-attempt bound; a retry makes the interval unavailable and closes archive
admission. The four-object same-stream burst is admitted only from an empty
stream outbox and blocks refill until its fourth send is acknowledged and
checkpointed; otherwise one stream waits at least 61 seconds between objects.
The two-second deadline ends only after `DeleteMessage` is acknowledged. Even
with one message per receive, each loop's worst complete cycle is 24 seconds;
the two loops therefore provide five messages per minute, above the target
four-object rate plus its 10% reserve. The validators are standalone tasks,
because an [ECS service replaces tasks below `desiredCount`](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateService.html)
outside an application budget. The existing one-minute recovery-probe Lambda is
the only `StopTask` and `RunTask` principal, but every invocation completes and
records the normal API synthetic under a one-second sub-deadline before its
four-second lifecycle phase. The 2 KiB launch ledger holds two slot records,
byte-exact request parameters, client tokens, deterministic `startedBy`
identities, first-attempt timestamps, returned task ARNs, a five-second exclusive
lifecycle claim, and a service-wide capacity-two bucket that refills one
token/hour.
A desired-digest transition reserves both tokens before stopping an old task;
insufficient capacity leaves the old topology running and closes admission. It
stops at most one obsolete task per invocation and launches nothing until all
obsolete tasks reach `STOPPED`; the combined old/new non-stopped count therefore
never exceeds the two continuous slots. The next lifecycle owner concurrently
starts two independently tokened
[`RunTask(count=1)`](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html)
calls, bounded through ARN persistence at 125 seconds after the obsolete tasks
stop after accounting for the one-minute schedule, full 60-second delivery
window, and five-second invocation. An unplanned one-slot loss starts one call.
Each request has a deterministic
[idempotent client token](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ECS_Idempotency.html)
and stamps the slot identity in `startedBy`.
The owner conditionally persists each response ARN against its claim, slot, and
token before that slot is populated. An uncertain response can be replayed only
by a later claim owner after `ListTasks`/`DescribeTasks` finds no exact
`startedBy` match, using the affected slot's byte-identical request and only
before 3,000 seconds from its durable first-attempt timestamp. A match is
persisted without replay; at or after the deadline, no new `RunTask` is issued,
the slot remains unresolved, and archive admission closes for audited repair.
The probe role has only the four required ECS actions in the exact recovery
cluster, `UpdateItem` on the launch-control key, and `PassRole` for the two exact
validator roles conditioned on `ecs-tasks.amazonaws.com`.
The two initial tokens plus 743 hourly refills strictly inside the half-open
744-hour window permit at most 745 launches; the refill at hour 744 belongs to
the next window. The
guard prices two conditional write units for every 93,744 probe attempt and two
result-write units per launch, and pre-reserves every 60-second
[Fargate](https://aws.amazon.com/fargate/pricing/) and
[public-IPv4](https://aws.amazon.com/vpc/pricing/) minimum, and fails archive
admission closed at exhaustion. The resulting two continuous task slots plus
launch reserve cost 375.104167 vCPU-hours, 750.208333 GB-hours, and 1,500.416667
public-IPv4 hours.

Before any S3 or KMS call, each attempt atomically reserves two S3 requests, one
KMS decrypt, the signed expected content length, and a composite pending receipt,
while a third action checks the separate current, unexpired lease generation.
An expired pending receipt for the same signed job can be taken over with a
higher attempt generation. The validator then performs one exact-version HEAD
that requires `REPLICA` and the signed content length, then performs the
checksum-enabled GET and validates its S3 checksum. Only after parsing the
bounded ciphertext envelope can it extract and decrypt the encrypted data key;
GCM, full-body digest, and embedded-signature validation follow. The final
three-action transaction writes the receipt and next
per-stream checkpoint in a single-region on-demand DynamoDB table and performs
a `ConditionCheck` on the separate current, unexpired lease item. The
[DynamoDB transaction contract](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html)
charges the underlying transactional capacity even on a canceled condition. The
model reserves eight receipt/checkpoint write units plus two read and two write
units for each of the pre-HEAD and final lease checks per attempt. A daily
exact-version sweep conditionally deletes a digest-keyed receipt only after both archive
copies are gone and no signed checkpoint references it. Because one shifted
31-day expiry interval can intersect two fixed admission windows, the model
reserves 74,000/326,000 cleanup writes. The launch guard additionally prices one
2 KiB conditional update as two write units for all 93,744 probe invocations
because failed conditions still consume write capacity, plus two units to
persist the returned task ARN for each of 745 launches. With lease contention and source heartbeat
checks, the complete state ceilings are 248,140/941,140 reads and
1,287,058/3,202,258 writes; DynamoDB TTL is only defense in depth. Each 1 KiB
application receipt prices a 2 KiB billed-storage envelope for DynamoDB's
documented 100-byte base overhead plus transaction metadata. Thirteen retained
monthly envelopes plus one cleanup day for two boundary envelopes require at
most 0.990/4.362 decimal GB before bounded counters, inside the 1/4.4 GB-month
caps. Qualification reconciles provider-billed storage and fails if the 2 KiB
envelope is insufficient. The 10% validation retry
partition is 3,700/16,300 attempts. A separate 3,700/16,300 source-send retry
partition and one terminal delete plus quarantine send per baseline or retry
attempt reserve 40,700/179,300 of each operation. At most 3,700/16,300 signed
DLQ jobs are redriven into the validation retry partition. The reconciliation
role can receive/delete only on the DLQ and send only to the validation FIFO;
it preserves the stream group and derives a deterministic deduplication ID from
the complete object identity plus repair generation. Each repair reserves
a DLQ receive, validation-queue send, and DLQ delete only after send
acknowledgement; separate 370/1,630 partitions cover empty/retried receives and
uncertain sends. The durable first-send timestamp permits a source or redrive
retry only when its acknowledgement completes within 240 seconds, inside SQS
FIFO's five-minute deduplication interval; afterward no repeated send occurs and
the outbox or DLQ copy remains durable with admission closed. This produces
11,840/52,160 repair-before-delete requests and
2,812,340/3,268,460 complete FIFO request units. Exhaustion preserves the DLQ
copy and keeps archive admission closed; implicit reconciliation SDK retries
are disabled.
At an enforced 8 KiB per baseline or retry send, it also reserves
0.3334144/1.4688256 GB of cross-region wire. The path otherwise prices
81,400/358,600 S3 requests, 0.824/3.596 GB of log ingestion, two retained
boundary envelopes at 1.648/7.192 GB-month, and 47.0378496/216.7343104 GB of
ledger-enforced same-region reads. The read envelope contains the complete
baseline ingress plus every retry at the 8 MiB object maximum. This transfer
remains inside the existing private-node other-service NAT cap.
Implicit SDK retries are disabled for the writer, outbox dispatcher, validator,
and DLQ reconciliation; every retry must consume an explicit operation or
attempt reserve.

Thirteen retained envelopes cap each region at 481,000/2,119,000 objects. The
verifier pins normal archive ingress to 16/80 GB per month, derives each
region's storage as `13 * ingress`, and derives normal CRR transfer as
`1 * ingress`; these three cost roots cannot drift independently. S3 CRR
continues copying new versions into the active generation while one S3 Batch
Replication job builds a fresh candidate generation from retained versions. The
full reseed prices 530,000/2,331,000 Batch object operations, source GET
attempts, destination PUT attempts, and destination validation GET attempts;
one client-envelope KMS decrypt per destination validation; 229/1,144 GB
transferred; and a generated-manifest scan of 481,000/2,119,000 source objects.
The generated
[`S3InventoryReport_CSV_20211130`](https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_S3GeneratedManifestDescriptor.html)
set lives in a dedicated nonversioned source-region recovery-control bucket and
reserves three control objects plus at most one data object per scanned source:
481,003/2,119,003 objects and writes. Veer validation and S3 Batch Operations
consumption each read the entire conforming set, so each pass separately prices
481,003/2,119,003 Tier-2 reads. AWS documents the
[Inventory control and data objects](https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-inventory-location.html)
but publishes no shard-count quota, so this is an explicit qualification
allowance rather than a provider guarantee. Veer validates the full listed set
before replication and fails the attempt if it exceeds the cardinality or
aggregate 8 GiB allowance. S3 writes the output before that check and exposes no
pre-write control for Veer's allowance, so provider-generated excess writes,
bytes, storage, and cleanup are an explicit unbounded residual cost outside the
fixed ceilings. Veer permits one generator attempt and stops before replication
or any other non-cleanup Veer-initiated billable action on excess. Exact-prefix
cleanup LIST and DELETE calls are the sole permitted compensation and remain
part of the unbounded residual, because Veer cannot retroactively bound S3's
output. A dedicated role is assumable only by the recovery job
submitter for the signed generation. It can `s3:ListBucket` only with the exact
generated-prefix condition and can `s3:GetObject` and `s3:DeleteObject` only
beneath that prefix; it cannot write objects, create jobs, or pass roles. That
role executes pre-confirmation validation and terminal cleanup. A conforming
set is moved from `Suspended` to `Ready` only when the job submitter calls
`s3:UpdateJobStatus` on the exact created job ARN after a signed successful
validation; `Cancelled` on that ARN requires a signed rejection result, and no
other job update is permitted.
The set remains for at most 24 hours, prices 0.28
decimal GB-month, and reserves 483/2,121 cleanup LISTs plus 482/2,120 free
deletes; completion-report output is disabled. Candidate overlap is capped at the retry-inclusive
transfer envelope for 24 hours, yielding 7.39/36.91 GB-month. Each exact
destination version is read with checksum mode, its service checksum is checked,
and its body digest and embedded signature are recomputed. The
530,000/2,331,000 validation attempts use the destination Tier-2 GET rate and
one recovery-region client-envelope `Decrypt`. S3 copies the SSE-S3-wrapped
ciphertext without a KMS operation.
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
sweeper is the 24-hour hard bound and verifies an empty expired prefix;
lifecycle remains defense in depth. The sweeper checks retention and legal hold,
then deletes eligible current versions, noncurrent versions, and markers by exact
version ID. Two adjacent boundary-concentrated cohorts raise the physical cap to
555,000/2,445,000 entries per region and marker-key storage to 0.04/0.17
GB-month. The worksheet prices a deliberately pessimistic one LIST response per
eligible data version and marker plus one final empty proof for each signed
cohort prefix: 148,002/652,002 per region, 296,004/1,304,004 total. DELETE
requests remain free.
One retention and one legal-hold metadata read per eligible data version adds
148,000/652,000 Tier-2 requests per region, or 296,000/1,304,000 total.
Protected data bytes are already priced as S3 Standard storage; the default
retention path adds no separate API request row.
Qualification exercises both legal boundary states: eligible objects that remain
current while Lifecycle is delayed, and the noncurrent-version plus delete-marker
state after Lifecycle acts.

Failed candidates and retired active generations are cleaned by exact version.
The LIST budget assumes only one returned version per request plus one final
empty proof—530,001/2,331,001 requests—rather than relying on full 1,000-entry
pages. LIST uses the destination Tier-1 rate; DELETE requests are free under the
dated S3 price contract.

The exact monthly generated request schedule and winning-probe response
distribution derive 137.70/688.52 GB for response bodies and response headers.
The 49,104 duplicate and shutdown deliveries add one API write and at most 2,048
response bytes each, raising the fixed response totals to
137.800564992/688.620564992 GB, but that generator
mix is not the production bound. A durable ledger reserves the complete encoded
response before write and caps the month at 150/690 GB. The
23,485,104/117,229,104 API envelopes contain all 138,384 external-synthetic
calls: two for each intended identity and one for every duplicate and shutdown
delivery.
The ingress separately reserves 14/70 GB of server-handshake bytes while
retaining the 20/100-per-second burst limit. Adding 27.88/233.13 GB of bounded
provider-request traffic yields hard egress caps of 191.88/993.13 GB; the
worksheet prices 195/995 GB without free allowances. Request headers and request
lines contribute to ALB processing, not server-to-client internet egress.

The recovery-probe result bucket is also versioned with explicit cleanup. Current
objects expire after 30 days; a daily sweeper enumerates current versions,
noncurrent versions, and delete markers and deletes eligible entries by exact
version ID before admitting the next probe identity window. Before Lifecycle
acts, the maximum is 44,640 current data versions. After it acts, the alternate
class state is 43,200 current versions, 1,440 noncurrent versions, and 1,440
markers. The class maxima are not simultaneous; the larger physical state is
46,080 entries. Thirty-one sweeps reserve 1,488 LIST
requests including empty proofs and 93 free delete batches. Data storage is 44.64
GB-month and maximum 512-byte marker keys add 0.00073728 GB-month.
The probe role has no list or delete permission. A separate short-lived cleanup
role grants the daily sweeper only exact-prefix `s3:ListBucketVersions` and
`s3:DeleteObjectVersion`; it cannot read or write bodies, modify the bucket, or
act on another prefix.

The one-minute recovery-region probe uses 44,640 immutable schedule identities
in one dedicated accounting-window group. Each identity uses the Scheduler
universal Lambda `Invoke` target with `InvocationType=RequestResponse`, so the
probe runs synchronously without Lambda asynchronous-queue delay. Scheduler
target retries are zero and maximum event age is 60 seconds, but at-least-once
delivery is not treated as exactly once.
The worksheet reserves one duplicate per intended identity plus 4,464
non-borrowable shutdown-race attempts: 93,744 paid Scheduler/Lambda attempts.
Every attempt is allowed the full 1 GB, five-second timeout and 0.00015 GB log
envelope, producing 468,720 GB-seconds and 14.0616 GB. The identity is also the
idempotency key for the probe's no-op write; only a newly committed claim
proceeds to the read, result metric, and artifact paths. Each duplicate and
shutdown delivery still consumes that write and a bounded short response. Both
probe API clients permit one attempt with implicit SDK retries disabled; a
transient or uncertain response makes the interval unavailable. At
duplicate-reserve exhaustion an exact-group circuit breaker deletes the entire
schedule group, while the shutdown partition absorbs in-flight delivery and
eventual group deletion. The full 60-second Scheduler precision window,
five-second function, five-second EMF extraction or missing-signal recognition,
ten-second alarm, and forty-second pager budgets meet the inclusive 240-second
objective. The 44,640 artifact attempts remain winner-only; data and marker
storage plus cleanup requests are independently bounded as described above.
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
| Queues | [AWSQueueService 20250828200713 primary](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSQueueService/20250828200713/us-east-1/index.json), [recovery](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSQueueService/20250828200713/us-west-2/index.json) | Primary standard `8RN6B8U4MERHRXP3` at USD 0.40/million; recovery FIFO tier-one `YH5ZUTMAG8WSV8TJ` at USD 0.50/million |
| Load balancer | [AWSELB 20260831092255](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSELB/20260831092255/us-east-1/index.json) | `37CUWUT8GSNQEPUV` at USD 0.0225/hour; `P2XGEJ8N3KU52WA8` at USD 0.008/LCU-hour |
| NAT | [AmazonEC2 20260831181331](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/20260831181331/us-east-1/index.json) | `M2YSHUBETB3JX4M4` at USD 0.045/hour; `59S5R83GFPUAGVR5` at USD 0.045/GB |
| Public IPv4 | [AmazonVPC 20260831092232 primary](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonVPC/20260831092232/us-east-1/index.json), [recovery](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonVPC/20260831092232/us-west-2/index.json) | Primary `4GQUNXTFWVSGPUZK` and recovery `NBHXEKTE88TJDDQF` at USD 0.005/address-hour |
| Data transfer | [AWSDataTransfer 20260831121448](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSDataTransfer/20260831121448/us-east-1/index.json) | `HQEH3ZWJVT46JHRG` at USD 0.09/GB internet egress; `PNUBVW4CPC8XA46W` at USD 0.01/directional-GB cross-AZ; `XGXYRYWGNXSSEUVT` at USD 0.02/GB cross-region |
| Telemetry | [AmazonCloudWatch 20260831092148](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonCloudWatch/20260831092148/us-east-1/index.json) | `S8QGXX5R2BKKMDSJ` at USD 0.50/GB log ingest; `GF9Q9S5QWW3RHMGQ` at USD 0.50/GB OTEL ingest; `6K9ADYQAHV5KX9KZ` at USD 0.03/GB-month; `KG586CTNGQ4VRZKZ` at USD 0.30/metric-month |
| Primary alarms | [AmazonCloudWatch 20260831092148](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonCloudWatch/20260831092148/us-east-1/index.json) | Standard-resolution alarm metric `EVETVUGEN3MUTMXM` at USD 0.10/alarm-metric-month |
| Recovery scheduling | [AWSEvents 20260831092301](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSEvents/20260831092301/index.json) | us-west-2 scheduled invocation `QNGCFAB5SW8AUQEB` at USD 0.000001 after the free tier; the worksheet applies that paid rate to every dispatch |
| Recovery monitoring | [AmazonCloudWatch 20260831092148 us-west-2](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonCloudWatch/20260831092148/us-west-2/index.json) | Logs `CWY7X4MZ4F3MP5SD` at USD 0.50/GB and `MN45SJANDTCPR9QA` at USD 0.03/GB-month; metrics `CN6TP6ZEVS58RK7M` at USD 0.30/month; high-resolution alarm `JQ7VDDDHEZA9XV78` at USD 0.30/alarm-metric-month |
| Recovery Lambda compute | [AWSLambda 20260831092318 us-west-2](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSLambda/20260831092318/us-west-2/index.json) | Request `ZWHFK83WS2P4WZR6` at USD 0.0000002/request; tier-one duration `XCU6U9G4FCKZQWG9` at USD 0.0000166667/GB-second |
| Recovery validator Fargate compute | [AmazonECS 20260831092155 us-west-2](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonECS/20260831092155/us-west-2/index.json) | ARM vCPU `5UAMYEN99PSY23D6` at USD 0.03238/vCPU-hour; ARM memory `TAE28FJERF797NWS` at USD 0.00356/GB-hour |
| Recovery validation state | [AmazonDynamoDB 20260831092153 us-west-2](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonDynamoDB/20260831092153/us-west-2/index.json) | On-demand reads `K6UMRY3TVDVCBP56` at USD 0.125/million units; writes `4G4G98VBTENWGY5R` at USD 0.625/million units; storage `UNCJFSHZ2ZQGDPJV` at USD 0.25/GB-month without the free tier |
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
