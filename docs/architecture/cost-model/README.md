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
| Billable queue requests after free allowance | 4 million | 49 million |
| Average ALB capacity | 1 LCU | 5 LCU |
| NAT processed data | 100 GiB | 1,000 GiB |
| Total internet egress | 150 GiB | 600 GiB |
| Billable internet egress after 100 GiB account allowance | 50 GiB | 500 GiB |
| CloudWatch log ingestion | 50 GiB | 500 GiB |
| Custom metrics | 50 | 500 |
| Encrypted archive/object storage | 100 GiB | 1,000 GiB |

The database and queue rows are price proxies so issue #12 can compare
alternatives on equal assumptions. They do not select the final implementation.
RDS Multi-AZ rates include the standby instance. Database storage uses the
Multi-AZ gp3 rate. Recovery storage and transfer model one provisioned database
copy and one full-dataset equivalent of monthly changed data; incremental
copies may cost less.

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
