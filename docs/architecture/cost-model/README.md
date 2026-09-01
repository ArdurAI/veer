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
| Month length | 730 hours | 730 hours |
| Active zones | 2 | 3 |
| EKS clusters under standard support | 1 | 1 |
| m7g.xlarge on-demand node count | 2 | 6 |
| Multi-AZ database proxy | db.t4g.medium | db.r7g.large |
| Database gp3 storage | 50 GiB | 500 GiB |
| Modeled queue requests with no free allowance | 5 million | 50 million |
| Average ALB capacity | 1 LCU | 5 LCU |
| NAT processed data | 100 GiB | 1,000 GiB |
| Total internet egress | 150 GiB | 600 GiB |
| Billable internet egress with no free allowance | 150 GiB | 600 GiB |
| CloudWatch log ingestion | 50 GiB | 500 GiB |
| Custom metrics | 50 | 500 |
| Encrypted archive/object storage | 100 GiB | 1,000 GiB |

The database and queue rows are price proxies so issue #12 can compare
alternatives on equal assumptions. They do not select the final implementation.
RDS Multi-AZ rates include the standby instance. Database storage uses the
Multi-AZ gp3 rate. Recovery storage and transfer model one provisioned database
copy and one full-dataset equivalent of monthly changed data; incremental
copies may cost less.

## Immutable rate evidence

Every billable worksheet row points to a versioned AWS Offers file. The
calculator rejects `current` aliases and ordinary mutable pricing pages.

| Category | Immutable offer evidence | SKU and captured rate |
| --- | --- | --- |
| EKS | [AmazonEKS 20260831092157](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEKS/20260831092157/us-east-1/index.json) | `ZYWMR684YSMFHWEU` at USD 0.10/cluster-hour; extended-support surcharge `M7977BSVFGDUJZ67` at USD 0.50/cluster-hour |
| EC2 compute | [AmazonEC2 20260831181331](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/20260831181331/us-east-1/index.json) | `Y7X6HJY9G859NU23` at USD 0.1632/m7g.xlarge-hour |
| RDS compute | [AmazonRDS 20260831092223](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonRDS/20260831092223/us-east-1/index.json) | `SCBZU9XX357QUA4D` at USD 0.129/db.t4g.medium Multi-AZ-hour; `QPKXCKEKNV5DW3QA` at USD 0.478/db.r7g.large Multi-AZ-hour |
| RDS primary storage | [AmazonRDS 20260831092223](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonRDS/20260831092223/us-east-1/index.json) | `J7S7KD4WFDNQWKNX` at USD 0.23/GB-month Multi-AZ gp3 |
| RDS recovery storage | [AmazonRDS 20260831092223](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonRDS/20260831092223/us-west-2/index.json) | `PAHDKG6EF4XSHYXC` at USD 0.095/GB-month |
| Queue | [AWSQueueService 20250828200713](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSQueueService/20250828200713/us-east-1/index.json) | `8RN6B8U4MERHRXP3` at USD 0.40/million standard requests |
| Load balancer | [AWSELB 20260831092255](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSELB/20260831092255/us-east-1/index.json) | `37CUWUT8GSNQEPUV` at USD 0.0225/hour; `P2XGEJ8N3KU52WA8` at USD 0.008/LCU-hour |
| NAT | [AmazonEC2 20260831181331](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/20260831181331/us-east-1/index.json) | `M2YSHUBETB3JX4M4` at USD 0.045/hour; `59S5R83GFPUAGVR5` at USD 0.045/GB |
| Public IPv4 | [AmazonVPC 20260831092232](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonVPC/20260831092232/us-east-1/index.json) | `4GQUNXTFWVSGPUZK` at USD 0.005/address-hour |
| Data transfer | [AWSDataTransfer 20260831121448](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSDataTransfer/20260831121448/us-east-1/index.json) | `HQEH3ZWJVT46JHRG` at USD 0.09/GB internet egress; `PNUBVW4CPC8XA46W` at USD 0.01/directional-GB cross-AZ; `XGXYRYWGNXSSEUVT` at USD 0.02/GB cross-region |
| Telemetry | [AmazonCloudWatch 20260831092148](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonCloudWatch/20260831092148/us-east-1/index.json) | `S8QGXX5R2BKKMDSJ` at USD 0.50/GB ingest; `6K9ADYQAHV5KX9KZ` at USD 0.03/GB-month; `KG586CTNGQ4VRZKZ` at USD 0.30/metric-month |
| Object storage | [AmazonS3 20260831092225](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonS3/20260831092225/us-east-1/index.json) | `WP9ANXZGBYYSGJEA` at USD 0.023/GB-month |
| Encryption keys | [awskms 20260831092318](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/awskms/20260831092318/index.json) | `U553K98XGDXCYHWS` and `S8HBXBVJKWKDP9AS` at USD 1/key-month |
| Managed secrets | [AWSSecretsManager 20260831092330](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSSecretsManager/20260831092330/us-east-1/index.json) | `BJ3PQ9BYGU6P632F` at USD 0.40/secret-month |

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
