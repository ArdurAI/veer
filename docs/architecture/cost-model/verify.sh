#!/bin/sh
set -eu

script_dir=$(
  unset CDPATH
  cd -- "$(dirname -- "$0")"
  pwd
)
tmp_file=
expected_summary_file=
actual_summary_file=
expected_stack_summary_file=
actual_stack_summary_file=
negative_dir=

fail() {
  printf '%s\n' "cost model verification failed: $*" >&2
  exit 1
}

# Remove only the files allocated by mktemp for this invocation.
cleanup() {
  for allocated_file in \
    "$tmp_file" \
    "$expected_summary_file" \
    "$actual_summary_file" \
    "$expected_stack_summary_file" \
    "$actual_stack_summary_file"; do
    if [ -n "$allocated_file" ]; then
      rm -f -- "$allocated_file"
    fi
  done
  if [ -n "$negative_dir" ]; then
    rm -rf -- "$negative_dir"
  fi
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

tmp_file=$(mktemp "${TMPDIR:-/tmp}/veer-cost-model.XXXXXX")
expected_summary_file=$(mktemp \
  "${TMPDIR:-/tmp}/veer-cost-summary-expected.XXXXXX")
actual_summary_file=$(mktemp \
  "${TMPDIR:-/tmp}/veer-cost-summary-actual.XXXXXX")
expected_stack_summary_file=$(mktemp \
  "${TMPDIR:-/tmp}/veer-stack-cost-summary-expected.XXXXXX")
actual_stack_summary_file=$(mktemp \
  "${TMPDIR:-/tmp}/veer-stack-cost-summary-actual.XXXXXX")
negative_dir=$(mktemp -d "${TMPDIR:-/tmp}/veer-cost-negative.XXXXXX")

LC_ALL=C awk -f "$script_dir/calculate.awk" \
  "$script_dir/sources.tsv" \
  "$script_dir/profiles.tsv" \
  "$script_dir/inputs.tsv" >"$tmp_file"

diff -u "$script_dir/expected.tsv" "$tmp_file"

LC_ALL=C awk -f "$script_dir/verify-operational-bounds.awk" \
  "$script_dir/operational-bounds.tsv" \
  "$script_dir/inputs.tsv"

expect_bound_failure() {
  fixture_name=$1
  fixture_scope=$2
  fixture_metric=$3
  fixture_value=$4
  expected_diagnostic=$5
  fixture_file="$negative_dir/$fixture_name.tsv"
  diagnostic_file="$negative_dir/$fixture_name.err"

  LC_ALL=C awk -F '\t' -v OFS='\t' \
    -v scope="$fixture_scope" \
    -v metric="$fixture_metric" \
    -v replacement="$fixture_value" '
      NR == 1 { print; next }
      $1 == scope && $2 == metric { $3 = replacement; found = 1 }
      { print }
      END { if (!found) exit 1 }
    ' "$script_dir/operational-bounds.tsv" >"$fixture_file" ||
    fail "cannot seed $fixture_name fixture"

  if LC_ALL=C awk -f "$script_dir/verify-operational-bounds.awk" \
    "$fixture_file" "$script_dir/inputs.tsv" \
    >"$negative_dir/$fixture_name.out" 2>"$diagnostic_file"; then
    fail "$fixture_name fixture was accepted"
  fi
  grep -Fq "$expected_diagnostic" "$diagnostic_file" ||
    fail "$fixture_name fixture emitted an unexpected diagnostic"
  printf '%s\n' "operational bound negative fixture $fixture_name passed"
}

expect_input_failure() {
  fixture_name=$1
  fixture_profile=$2
  fixture_item=$3
  fixture_value=$4
  expected_diagnostic=$5
  fixture_file="$negative_dir/$fixture_name-inputs.tsv"
  diagnostic_file="$negative_dir/$fixture_name.err"

  LC_ALL=C awk -F '\t' -v OFS='\t' \
    -v profile="$fixture_profile" \
    -v item="$fixture_item" \
    -v replacement="$fixture_value" '
      NR == 1 { print; next }
      $1 == profile && $2 == item { $4 = replacement; found = 1 }
      { print }
      END { if (!found) exit 1 }
    ' "$script_dir/inputs.tsv" >"$fixture_file" ||
    fail "cannot seed $fixture_name input fixture"

  if LC_ALL=C awk -f "$script_dir/verify-operational-bounds.awk" \
    "$script_dir/operational-bounds.tsv" "$fixture_file" \
    >"$negative_dir/$fixture_name.out" 2>"$diagnostic_file"; then
    fail "$fixture_name input fixture was accepted"
  fi
  grep -Fq "$expected_diagnostic" "$diagnostic_file" ||
    fail "$fixture_name input fixture emitted an unexpected diagnostic"
  printf '%s\n' "cost input negative fixture $fixture_name passed"
}

expect_bound_failure audit-event-max-bytes shared audit_event_max_bytes 16383 \
  'audit bytes and archive packing must equal the fixed evidence envelope'
expect_bound_failure audit-average-bytes shared audit_partition_average_bytes 999 \
  'audit bytes and archive packing must equal the fixed evidence envelope'
expect_bound_failure audit-rejection-max-bytes shared audit_rejection_event_max_bytes 1001 \
  'audit bytes and archive packing must equal the fixed evidence envelope'
expect_bound_failure compact-record-max-bytes shared compact_non_audit_record_max_bytes 4095 \
  'audit bytes and archive packing must equal the fixed evidence envelope'
expect_bound_failure compact-average-bytes shared compact_non_audit_average_bytes 401 \
  'audit bytes and archive packing must equal the fixed evidence envelope'
expect_bound_failure audit-records-per-object shared archive_audit_records_per_object 501 \
  'audit bytes and archive packing must equal the fixed evidence envelope'
expect_bound_failure compact-records-per-object shared archive_compact_records_per_object 1001 \
  'audit bytes and archive packing must equal the fixed evidence envelope'
expect_bound_failure audit-reserved-object-bytes shared archive_audit_reserved_bytes_per_object 196607 \
  'audit bytes and archive packing must equal the fixed evidence envelope'
expect_bound_failure archive-timer-flush shared archive_timer_flush_seconds 601 \
  'audit bytes and archive packing must equal the fixed evidence envelope'
expect_bound_failure rejection-partition-shared shared rejection_audit_partition_shared 0 \
  'rejection audit capacity must be reserved atomically before classification'
expect_bound_failure rejection-runtime-mix-inference shared rejection_audit_capacity_inferred_from_runtime_mix 1 \
  'rejection audit capacity must be reserved atomically before classification'
expect_bound_failure rejection-before-authentication shared rejection_audit_reserve_before_authentication 0 \
  'rejection audit capacity must be reserved atomically before classification'
expect_bound_failure rejection-before-authorization shared rejection_audit_reserve_before_authorization 0 \
  'rejection audit capacity must be reserved atomically before classification'
expect_bound_failure rejection-atomic-capacity shared rejection_audit_event_byte_reservation_atomic 0 \
  'rejection audit capacity must be reserved atomically before classification'
expect_bound_failure rejection-atomic-settlement shared rejection_audit_event_settlement_atomic 0 \
  'rejection audit capacity must be reserved atomically before classification'
expect_bound_failure rejection-database-duration shared rejection_audit_database_load_seconds 86399 \
  'rejection audit database effects must be physically qualified without extra RDS performance cost'
expect_bound_failure rejection-database-runtime-adapter shared rejection_audit_database_path_uses_runtime_adapter 0 \
  'rejection audit database effects must be physically qualified without extra RDS performance cost'
expect_bound_failure rejection-database-changed-bytes shared rejection_audit_database_changed_bytes_metered 0 \
  'rejection audit database effects must be physically qualified without extra RDS performance cost'
expect_bound_failure rejection-database-extra-performance shared rejection_audit_additional_gp3_performance_allowed 1 \
  'rejection audit database effects must be physically qualified without extra RDS performance cost'
expect_bound_failure rejection-release-standard-load shared rejection_audit_authorized_release_uses_standard_load 0 \
  'rejection release and reconciliation database loads must be exact and concurrent'
expect_bound_failure rejection-reconciliation-prior-window shared rejection_audit_reconciliation_uses_prior_window 0 \
  'rejection release and reconciliation database loads must be exact and concurrent'
expect_bound_failure rejection-reconciliation-concurrent shared rejection_audit_reconciliation_concurrent_with_standard_load 0 \
  'rejection release and reconciliation database loads must be exact and concurrent'
expect_bound_failure rejection-reconciliation-final-second shared rejection_audit_reconciliation_final_second_reservations 13 \
  'small rejection release and reconciliation workloads must equal the exact profile schedule'
expect_bound_failure rejection-authorized-release shared rejection_audit_authorized_release_before_state 0 \
  'rejection audit capacity must be reserved atomically before classification'
expect_bound_failure rejection-commit-before-response shared rejection_audit_commit_before_response 0 \
  'rejection audit capacity must be reserved atomically before classification'
expect_bound_failure rejection-stale-ledger shared rejection_audit_missing_or_stale_ledger_fails_closed 0 \
  'rejection audit reservations must fail closed until exact reconciliation'
expect_bound_failure rejection-age-reclaim shared rejection_audit_uncertain_reservation_reclaimed_by_age 1 \
  'rejection audit reservations must fail closed until exact reconciliation'
expect_bound_failure rejection-exact-reconciliation shared rejection_audit_exact_reconciliation_required 0 \
  'rejection audit reservations must fail closed until exact reconciliation'
expect_bound_failure rejection-exhaustion-authentication shared rejection_audit_exhaustion_evaluates_authentication 1 \
  'rejection partition exhaustion must return a bounded generic pre-classification response'
expect_bound_failure rejection-exhaustion-authorization shared rejection_audit_exhaustion_evaluates_authorization 1 \
  'rejection partition exhaustion must return a bounded generic pre-classification response'
expect_bound_failure rejection-exhaustion-status shared rejection_audit_exhaustion_status 429 \
  'rejection partition exhaustion must return a bounded generic pre-classification response'
expect_bound_failure rejection-exhaustion-response shared rejection_audit_exhaustion_response_bytes 2049 \
  'rejection partition exhaustion must return a bounded generic pre-classification response'
expect_bound_failure rejection-classified-response shared rejection_audit_classified_response_bytes 2049 \
  'classified rejection responses must fit the bounded response envelope'
expect_bound_failure rejection-exhaustion-transition shared rejection_audit_exhaustion_transition_system_event 0 \
  'rejection exhaustion must audit its state transition without per-request event growth'
expect_bound_failure rejection-exhaustion-transition-reserve shared rejection_audit_exhaustion_transition_slot_pre_reserved 0 \
  'rejection exhaustion must audit its state transition without per-request event growth'
expect_bound_failure rejection-exhaustion-request-events shared rejection_audit_exhaustion_request_events 1 \
  'rejection exhaustion must audit its state transition without per-request event growth'
expect_bound_failure rejection-borrows-system shared rejection_audit_borrows_system_headroom 1 \
  'rejection audit capacity must not borrow another evidence partition'
expect_bound_failure rejection-borrows-other shared rejection_audit_borrows_other_partitions 1 \
  'rejection audit capacity must not borrow another evidence partition'
expect_bound_failure rejection-fixture-unauthenticated shared rejection_mix_fixture_all_unauthenticated 0 \
  'rejection qualification must shift the complete generated stream to both rejection classes'
expect_bound_failure rejection-fixture-unauthorized shared rejection_mix_fixture_all_unauthorized 0 \
  'rejection qualification must shift the complete generated stream to both rejection classes'
expect_bound_failure rejection-database-rate-small small rejection_audit_database_load_requests_per_second 19 \
  'small rejection database load must use the edge rate and included gp3 baseline'
expect_bound_failure rejection-database-iops-small small database_gp3_included_iops 2999 \
  'small rejection database load must use the edge rate and included gp3 baseline'
expect_bound_failure rejection-database-throughput-small small database_gp3_included_throughput_mib_per_second 124 \
  'small rejection database load must use the edge rate and included gp3 baseline'
expect_bound_failure rejection-release-workload-small small rejection_audit_authorized_release_fixture_requests 738057 \
  'small rejection release and reconciliation workloads must equal the exact profile schedule'
expect_bound_failure rejection-reconciliation-workload-small small rejection_audit_reconciliation_fixture_uncertain_reservations 466933 \
  'small rejection release and reconciliation workloads must equal the exact profile schedule'
expect_bound_failure rejection-reconciliation-rate-small small rejection_audit_reconciliation_requests_per_second 19 \
  'small rejection release and reconciliation workloads must equal the exact profile schedule'
expect_bound_failure rejection-reconciliation-duration-small small rejection_audit_reconciliation_duration_seconds 23346 \
  'small rejection release and reconciliation workloads must equal the exact profile schedule'
expect_bound_failure rejection-database-rate-target target rejection_audit_database_load_requests_per_second 99 \
  'target rejection database load must use the edge rate and included gp3 baseline'
expect_bound_failure rejection-database-iops-target target database_gp3_included_iops 11999 \
  'target rejection database load must use the edge rate and included gp3 baseline'
expect_bound_failure rejection-database-throughput-target target database_gp3_included_throughput_mib_per_second 499 \
  'target rejection database load must use the edge rate and included gp3 baseline'
expect_bound_failure rejection-release-workload-target target rejection_audit_authorized_release_fixture_requests 3701577 \
  'target rejection release and reconciliation workloads must equal the exact profile schedule'
expect_bound_failure rejection-reconciliation-workload-target target rejection_audit_reconciliation_fixture_uncertain_reservations 2341813 \
  'target rejection release and reconciliation workloads must equal the exact profile schedule'
expect_bound_failure rejection-reconciliation-rate-target target rejection_audit_reconciliation_requests_per_second 99 \
  'target rejection release and reconciliation workloads must equal the exact profile schedule'
expect_bound_failure rejection-reconciliation-duration-target target rejection_audit_reconciliation_duration_seconds 23418 \
  'target rejection release and reconciliation workloads must equal the exact profile schedule'
expect_bound_failure rejection-event-cap small audit_event_cap 8999999 \
  'small audit event cap differs from the published profile ceiling'
expect_bound_failure rejection-success-cancel-events target audit_success_cancel_events 17563604 \
  'target audit event partitions do not sum to the fixed cap'
expect_bound_failure rejection-partition-events target audit_rejection_partition_events 2341813 \
  'target audit event partitions do not sum to the fixed cap'
expect_bound_failure rejection-provider-events small audit_provider_attempt_events 4129199 \
  'small audit event partitions do not sum to the fixed cap'
expect_bound_failure rejection-synthetic-events target audit_synthetic_events 44639 \
  'target audit event partitions do not sum to the fixed cap'
expect_bound_failure rejection-system-events small audit_system_event_headroom 857220 \
  'small audit event partitions do not sum to the fixed cap'
expect_bound_failure rejection-general-system-events small audit_system_general_event_headroom 857221 \
  'small system headroom must pre-reserve the rejection exhaustion transition'
expect_bound_failure rejection-transition-system-events target audit_system_rejection_exhaustion_transition_events 0 \
  'target system headroom must pre-reserve the rejection exhaustion transition'
expect_bound_failure rejection-audit-byte-cap target audit_byte_cap 51999999999 \
  'target audit byte partitions do not match their event ceilings'
expect_bound_failure rejection-partition-bytes small audit_rejection_partition_bytes 466933999 \
  'small audit byte partitions do not match their event ceilings'
expect_bound_failure rejection-system-bytes target audit_system_byte_headroom 1359940999 \
  'target audit byte partitions do not match their event ceilings'
expect_bound_failure rejection-general-system-bytes target audit_system_general_byte_headroom 1359941000 \
  'target system bytes must pre-reserve the rejection exhaustion transition'
expect_bound_failure rejection-transition-system-bytes small audit_system_rejection_exhaustion_transition_bytes 999 \
  'small system bytes must pre-reserve the rejection exhaustion transition'
expect_bound_failure rejection-fixture-requests small rejection_mix_fixture_requests 23346719 \
  'small full rejection-mix fixture must fail closed without audit loss'
expect_bound_failure rejection-fixture-classified target rejection_mix_fixture_classified_events 2341813 \
  'target full rejection-mix fixture must fail closed without audit loss'
expect_bound_failure rejection-fixture-preclassification small rejection_mix_fixture_preclassification_503_requests 22879785 \
  'small full rejection-mix fixture must fail closed without audit loss'
expect_bound_failure rejection-fixture-response target rejection_mix_fixture_response_bytes 239801794559 \
  'target full rejection-mix fixture must fail closed without audit loss'
expect_bound_failure rejection-fixture-dropped target rejection_mix_fixture_dropped_required_events 1 \
  'target full rejection-mix fixture must fail closed without audit loss'
expect_bound_failure compact-record-workload small compact_non_audit_records_month 10056267 \
  'small compact non-audit record workload differs from the fixed schedule'
expect_bound_failure audit-archive-objects target audit_archive_objects_month 108463 \
  'target archive object cap omits audit compact-record or timer-flush objects'
expect_bound_failure compact-archive-objects small compact_non_audit_archive_objects_month 14520 \
  'small archive object cap omits audit compact-record or timer-flush objects'
expect_input_failure archive-s3-primary-requests small primary_archive_requests 55499 \
  'small priced archive S3 requests must reserve three tier-one calls per object across both regions'
expect_input_failure archive-s3-recovery-requests target recovery_archive_requests 244499 \
  'target priced archive S3 requests must reserve three tier-one calls per object across both regions'

expect_bound_failure probe-artifact-retention shared probe_artifact_retention_seconds 2678400 \
  'probe artifact retention must equal 30 days with cleanup inside one day'
expect_bound_failure probe-artifact-current-max shared probe_artifact_current_versions_max 44639 \
  'probe artifact class maxima must model lifecycle-dependent alternatives'
expect_bound_failure probe-artifact-noncurrent-max shared probe_artifact_noncurrent_versions_max 1439 \
  'probe artifact class maxima must model lifecycle-dependent alternatives'
expect_bound_failure probe-artifact-class-alternatives shared probe_artifact_lifecycle_class_alternatives 0 \
  'probe artifact class maxima must model lifecycle-dependent alternatives'
expect_bound_failure probe-artifact-physical shared probe_artifact_physical_entries 46079 \
  'probe artifact physical entries must include current noncurrent and marker versions'
expect_bound_failure probe-artifact-list shared probe_artifact_cleanup_list_requests_month 1487 \
  'probe artifact cleanup LIST budget must cover every physical entry and final empty proofs'
expect_bound_failure probe-artifact-exact-delete shared probe_artifact_cleanup_exact_version_delete 0 \
  'probe artifact cleanup must enumerate all version classes and delete exact versions'
expect_bound_failure probe-artifact-cleanup-role-assumable shared probe_artifact_cleanup_role_assumable 0 \
  'probe artifact cleanup requires an assumable exact-prefix least-privilege role'
expect_bound_failure probe-artifact-cleanup-role-list shared probe_artifact_cleanup_role_lists_exact_prefix 0 \
  'probe artifact cleanup requires an assumable exact-prefix least-privilege role'
expect_bound_failure probe-artifact-cleanup-role-delete shared probe_artifact_cleanup_role_deletes_exact_versions 0 \
  'probe artifact cleanup requires an assumable exact-prefix least-privilege role'
expect_bound_failure probe-artifact-cleanup-role-other shared probe_artifact_cleanup_role_other_bucket_actions 1 \
  'probe artifact cleanup requires an assumable exact-prefix least-privilege role'
expect_input_failure probe-artifact-marker-cost target external_synthetic_artifact_marker_storage 0 \
  'target probe artifact cost rows differ from the versioned cleanup contract'
expect_bound_failure archive-adjacent-overlap shared archive_lifecycle_overlap_envelopes 1 \
  'archive retention must reserve two adjacent cohorts and complete exact cleanup inside one day'
expect_bound_failure archive-current-version-sweep shared archive_sweeper_lists_current_versions 0 \
  'archive sweeper must prove Object Lock eligibility and delete every version class by exact identifier'
expect_bound_failure archive-legal-hold-read shared archive_sweeper_gets_object_legal_hold 0 \
  'archive sweeper must prove Object Lock eligibility and delete every version class by exact identifier'
expect_bound_failure archive-fixture-delayed-current shared archive_recovery_fixture_delayed_lifecycle_current_versions 0 \
  'archive recovery qualification must exercise both lifecycle-dependent version states'
expect_bound_failure archive-fixture-post-lifecycle shared archive_recovery_fixture_post_lifecycle_version_classes 0 \
  'archive recovery qualification must exercise both lifecycle-dependent version states'
expect_bound_failure archive-physical-entries target archive_physical_entries_region 2444999 \
  'target archive physical entries must include retained data and both adjacent marker cohorts'
expect_bound_failure archive-cleanup-entries target archive_retention_delete_entries_region 651999 \
  'target archive cleanup must list and delete both eligible data and marker cohorts'
expect_bound_failure archive-object-lock-reads target archive_retention_object_lock_read_requests_region 651999 \
  'target archive cleanup must read retention and legal hold for every eligible data version'
expect_bound_failure archive-marker-storage target archive_delete_marker_storage_gb 0.16 \
  'target archive marker storage must price both adjacent maximum-key cohorts'
expect_input_failure archive-list-cost target archive_lifecycle_list_requests 652001 \
  'target archive lifecycle cost rows differ from the physical-entry contract'
expect_input_failure archive-object-lock-read-cost target recovery_archive_lifecycle_object_lock_read_requests 651999 \
  'target archive lifecycle cost rows differ from the physical-entry contract'
expect_bound_failure manifest-format shared full_reseed_manifest_inventory_format 0 \
  'generated manifest must use the bounded nonversioned Inventory-format object-set contract'
expect_bound_failure manifest-nonversioned-output shared full_reseed_manifest_output_versioned 1 \
  'generated manifest must use the bounded nonversioned Inventory-format object-set contract'
expect_bound_failure manifest-prewrite-enforcement shared full_reseed_manifest_prewrite_provider_enforcement 1 \
  'generated manifest qualification must expose unbounded provider output before post-write validation'
expect_bound_failure manifest-excess-residual shared full_reseed_manifest_excess_output_residual 0 \
  'generated manifest qualification must expose unbounded provider output before post-write validation'
expect_bound_failure manifest-validator-assumable shared full_reseed_manifest_validator_assumable 0 \
  'generated manifest qualification requires an assumable exact-prefix least-privilege executor'
expect_bound_failure manifest-validator-list-prefix shared full_reseed_manifest_validator_lists_exact_prefix 0 \
  'generated manifest qualification requires an assumable exact-prefix least-privilege executor'
expect_bound_failure manifest-validator-read-prefix shared full_reseed_manifest_validator_reads_exact_prefix 0 \
  'generated manifest qualification requires an assumable exact-prefix least-privilege executor'
expect_bound_failure manifest-validator-delete-prefix shared full_reseed_manifest_validator_deletes_exact_prefix 0 \
  'generated manifest qualification requires an assumable exact-prefix least-privilege executor'
expect_bound_failure manifest-validator-create-job shared full_reseed_manifest_validator_creates_jobs 1 \
  'generated manifest qualification requires an assumable exact-prefix least-privilege executor'
expect_bound_failure manifest-validator-pass-role shared full_reseed_manifest_validator_passes_roles 1 \
  'generated manifest qualification requires an assumable exact-prefix least-privilege executor'
expect_bound_failure manifest-confirmation-required shared full_reseed_job_confirmation_required 0 \
  'generated manifest qualification requires signed evidence for exact-job status transitions'
expect_bound_failure manifest-exact-job-status shared full_reseed_job_submitter_updates_exact_job_status 0 \
  'generated manifest qualification requires signed evidence for exact-job status transitions'
expect_bound_failure manifest-other-job-status shared full_reseed_job_submitter_updates_other_job_status 1 \
  'generated manifest qualification requires signed evidence for exact-job status transitions'
expect_bound_failure manifest-ready-before-validation shared full_reseed_job_ready_requires_signed_manifest_validation 0 \
  'generated manifest qualification requires signed evidence for exact-job status transitions'
expect_bound_failure manifest-cancel-before-rejection shared full_reseed_job_cancel_requires_signed_manifest_rejection 0 \
  'generated manifest qualification requires signed evidence for exact-job status transitions'
expect_bound_failure manifest-residual-cleanup shared full_reseed_manifest_residual_cleanup_after_rejection 0 \
  'manifest rejection must permit only residual cleanup billable actions'
expect_bound_failure manifest-post-rejection-work shared full_reseed_noncleanup_billable_action_after_manifest_rejection 1 \
  'manifest rejection must permit only residual cleanup billable actions'
expect_bound_failure manifest-data-objects target full_reseed_manifest_data_objects 2118999 \
  'target generated manifest set must reserve one data object per scanned source plus three controls'
expect_bound_failure manifest-object-set target full_reseed_manifest_objects 2119002 \
  'target generated manifest set must reserve one data object per scanned source plus three controls'
expect_bound_failure manifest-write-requests target full_reseed_manifest_write_requests 2119002 \
  'target generated manifest requests must cover separate validation and consumption reads plus empty proof'
expect_bound_failure manifest-validation-read-requests target full_reseed_manifest_validation_read_requests 2119002 \
  'target generated manifest requests must cover separate validation and consumption reads plus empty proof'
expect_bound_failure manifest-consumption-read-requests target full_reseed_manifest_consumption_read_requests 2119002 \
  'target generated manifest requests must cover separate validation and consumption reads plus empty proof'
expect_bound_failure manifest-total-read-requests target full_reseed_manifest_read_requests 4238005 \
  'target generated manifest requests must cover separate validation and consumption reads plus empty proof'
expect_bound_failure manifest-cleanup-list target full_reseed_manifest_cleanup_list_requests 2120 \
  'target generated manifest requests must cover separate validation and consumption reads plus empty proof'
expect_bound_failure manifest-storage target full_reseed_manifest_storage_gb 0.27 \
  'target generated manifest storage must price eight GiB for one day'
expect_input_failure manifest-validation-read-cost target full_reseed_manifest_validation_read 1 \
  'target generated manifest cost rows differ from the bounded object-set contract'
expect_input_failure manifest-consumption-read-cost target full_reseed_manifest_consumption_read 1 \
  'target generated manifest cost rows differ from the bounded object-set contract'

expect_bound_failure network target alb_accounted_request_header_bytes 0 \
  'target ALB header accounting must equal native header bound'
expect_bound_failure network-native-header small alb_native_request_header_bytes 65535 \
  'small native ALB request-header bound must equal 65536 bytes'
expect_bound_failure network-request-line target alb_accounted_request_line_bytes 0 \
  'target ALB request-line accounting must equal native request-line bound'
expect_bound_failure network-native-request-line small alb_native_request_line_bytes 16383 \
  'small native ALB request-line bound must equal 16384 bytes'
expect_bound_failure network-lcu-over small alb_lcus 8 \
  'small ALB LCU bound must equal the processed-byte ceiling'
expect_bound_failure egress-response small response_egress_month_bytes 150000000001 \
  'small response egress ledger must equal its documented fixed cap'
expect_bound_failure egress-handshake small handshake_egress_month_bytes 14000000001 \
  'small handshake egress ledger must equal its documented fixed cap'
expect_bound_failure egress-provider target provider_egress_month_bytes 233130000001 \
  'target provider-request egress ledger must equal its documented fixed cap'
expect_bound_failure kms-retry small archive_kms_retry_requests 0 \
  'small normal archive KMS retry reserve must equal 10 percent'
expect_bound_failure kms-retry-over target archive_kms_retry_requests 32601 \
  'target normal archive KMS retry reserve must equal 10 percent'
expect_bound_failure kms-base small archive_kms_base_requests_per_object 3 \
  'small normal archive KMS base must contain exactly two application-controlled requests per object'
expect_bound_failure kms-split target live_archive_validator_retry_attempts 16301 \
  'target normal archive KMS retry reserve must split equally between writer and validator'
expect_bound_failure kms-total target archive_kms_total_requests 717201 \
  'target normal archive KMS request partitions do not sum to the total'
expect_bound_failure validator target live_archive_validator_attempts 163000 \
  'target live archive validator lacks 10 percent attempt reserve'
expect_bound_failure validator-retry target live_archive_validator_retry_attempts 1 \
  'target live archive validator retry partition is below 10 percent'
expect_bound_failure validator-queue target live_archive_validator_queue_message_requests 1 \
  'target live archive validator queue budget omits sends, validation deletes, quarantine sends, or repair-before-delete DLQ reconciliation'
expect_bound_failure validator-quarantine small live_archive_validator_queue_quarantine_requests 0 \
  'small live archive validator must reserve one quarantine send per validation attempt'
expect_bound_failure validator-dlq-repair-jobs small live_archive_validator_dlq_repair_jobs 0 \
  'small live archive validator DLQ repair jobs must equal the validation retry partition'
expect_bound_failure validator-dlq-receive-retry small live_archive_validator_dlq_receive_retry_requests 0 \
  'small live archive validator DLQ receive retry reserve must equal 10 percent of repair jobs'
expect_bound_failure validator-dlq-send-retry target live_archive_validator_dlq_redrive_send_retry_requests 0 \
  'target live archive validator DLQ redrive send retry reserve must equal 10 percent of repair jobs'
expect_bound_failure validator-dlq-reconciliation target live_archive_validator_dlq_reconciliation_requests 0 \
  'target live archive validator must reserve repair receives sends post-send deletes and explicit retries'
expect_bound_failure validator-send-retry small live_archive_validator_queue_send_retry_requests 0 \
  'small source outbox send retry reserve must equal 10 percent of archive objects'
expect_bound_failure validator-send-wire small live_archive_validator_queue_transfer_gb 0.3 \
  'small live archive validator cross-region wire omits retry-inclusive source sends'
expect_bound_failure validator-polls target live_archive_validator_queue_poll_requests 1 \
  'target live archive validator queue poll budget differs from the application-enforced maximum'
expect_bound_failure validator-poll-rate shared live_archive_validator_polls_per_second 2 \
  'live archive validator must permit exactly one poll start per second'
expect_bound_failure validator-receive-loops shared live_archive_validator_receive_loop_count 1 \
  'live archive validator must run exactly two concurrent receive loops'
expect_bound_failure validator-inter-poll shared live_archive_validator_max_inter_poll_seconds 2 \
  'live archive validator maximum inter-poll gap must equal one second'
expect_bound_failure validator-long-poll shared live_archive_validator_long_poll_seconds 19 \
  'live archive validator long-poll wait must equal 20 seconds'
expect_bound_failure validator-receive-deadline shared live_archive_validator_receive_response_seconds 20 \
  'live archive validator receive-response deadline must equal 21 seconds'
expect_bound_failure validator-state target live_archive_validator_state_write_units 1 \
  'target live archive validator state units omit receipt, heartbeat, transaction, launch, lease, or cleanup operations'
expect_bound_failure validator-lease-condition-read small live_archive_validator_final_lease_condition_read_units 0 \
  'small live archive validator final commit must reserve transactional lease-condition capacity'
expect_bound_failure validator-lease-condition-write target live_archive_validator_final_lease_condition_write_units 0 \
  'target live archive validator final commit must reserve transactional lease-condition capacity'
expect_bound_failure validator-reservation-lease-condition-read small live_archive_validator_reservation_lease_condition_read_units 0 \
  'small live archive validator pre-HEAD reservation must reserve transactional lease-condition capacity'
expect_bound_failure validator-reservation-lease-condition-write target live_archive_validator_reservation_lease_condition_write_units 0 \
  'target live archive validator pre-HEAD reservation must reserve transactional lease-condition capacity'
expect_bound_failure validator-receipt-cleanup small live_archive_validator_receipt_cleanup_writes 0 \
  'small live archive validator receipt cleanup must reserve two boundary-concentrated expiry envelopes'
expect_bound_failure validator-receipt-cleanup-enabled shared live_archive_validator_receipt_cleanup_enabled 0 \
  'live archive validator must deterministically reclaim expired receipts'
expect_bound_failure validator-receipt-cleanup-deadline shared live_archive_validator_receipt_cleanup_seconds 86401 \
  'live archive validator receipt cleanup must complete within 24 hours'
expect_bound_failure validator-receipt-storage target live_archive_validator_state_storage_gb 4.3 \
  'target live archive validator state storage omits retained receipts or cleanup overlap'
expect_bound_failure validator-receipt-overhead shared dynamodb_base_item_storage_overhead_bytes 0 \
  'DynamoDB base item storage overhead must equal 100 bytes'
expect_bound_failure validator-receipt-envelope shared live_archive_validator_receipt_storage_envelope_bytes 1124 \
  'live archive validator receipt storage must reserve a 2048-byte billed envelope'
expect_bound_failure validator-compute small live_archive_validator_fargate_vcpu_hours 1 \
  'small live archive validator compute or address hours omit bounded replacement launches'
expect_bound_failure validator-restart-guard shared live_archive_validator_restart_guard 0 \
  'live archive validator replacement and replay must use one serialized expiring lifecycle claim'
expect_bound_failure validator-launch-bucket shared live_archive_validator_launch_bucket_capacity 1 \
  'live archive validator launch reserve must use two initial tokens plus only refills strictly inside the window'
expect_bound_failure validator-launches shared live_archive_validator_launches_month 744 \
  'live archive validator launch reserve must use two initial tokens plus only refills strictly inside the window'
expect_bound_failure validator-launch-refill shared live_archive_validator_launch_token_refill_seconds 3599 \
  'live archive validator launch reserve must use two initial tokens plus only refills strictly inside the window'
expect_bound_failure validator-launch-window-end shared live_archive_validator_launch_window_end_exclusive 0 \
  'live archive validator launch reserve must use two initial tokens plus only refills strictly inside the window'
expect_bound_failure validator-control-schedule shared live_archive_validator_control_schedule_seconds 59 \
  'live archive validator topology fill must include schedule period delivery jitter and one invocation'
expect_bound_failure validator-topology-fill shared live_archive_validator_topology_fill_seconds 124 \
  'live archive validator topology fill must include schedule period delivery jitter and one invocation'
expect_bound_failure validator-restart-minimum shared live_archive_validator_restart_minimum_billing_seconds 59 \
  'live archive validator replacement must reserve the 60-second billing minimum'
expect_bound_failure validator-launch-topology shared live_archive_validator_ecs_service_scheduler 1 \
  'live archive validator must use probe-controlled standalone tasks'
expect_bound_failure validator-launch-controller shared live_archive_validator_probe_launch_controller 0 \
  'live archive validator must use probe-controlled standalone tasks'
expect_bound_failure validator-launch-drain shared live_archive_validator_stop_obsolete_before_launch 0 \
  'live archive validator must drain obsolete tasks without overlap or implicit retry'
expect_bound_failure validator-launch-stop-count shared live_archive_validator_max_stop_tasks_per_probe 2 \
  'live archive validator must drain obsolete tasks without overlap or implicit retry'
expect_bound_failure validator-launch-stop-retry shared live_archive_validator_stop_task_sdk_retries 1 \
  'live archive validator must drain obsolete tasks without overlap or implicit retry'
expect_bound_failure validator-launch-count shared live_archive_validator_run_task_count 2 \
  'live archive validator must use independent idempotent RunTask requests for each one-slot or two-slot fill'
expect_bound_failure validator-launch-two-slot-count shared live_archive_validator_two_slot_run_task_calls 1 \
  'live archive validator must use independent idempotent RunTask requests for each one-slot or two-slot fill'
expect_bound_failure validator-launch-single-slot-count shared live_archive_validator_single_slot_run_task_calls 2 \
  'live archive validator must use independent idempotent RunTask requests for each one-slot or two-slot fill'
expect_bound_failure validator-launch-idempotency shared live_archive_validator_run_task_client_token 0 \
  'live archive validator must use independent idempotent RunTask requests for each one-slot or two-slot fill'
expect_bound_failure validator-launch-started-by shared live_archive_validator_run_task_started_by 0 \
  'live archive validator must reconcile startedBy before replay and stop before the shortest client-token lifetime'
expect_bound_failure validator-launch-token-ttl shared live_archive_validator_run_task_client_token_min_ttl_seconds 3599 \
  'live archive validator must reconcile startedBy before replay and stop before the shortest client-token lifetime'
expect_bound_failure validator-launch-replay-deadline shared live_archive_validator_run_task_replay_deadline_seconds 3600 \
  'live archive validator must reconcile startedBy before replay and stop before the shortest client-token lifetime'
expect_bound_failure validator-launch-discovery shared live_archive_validator_run_task_discovery_before_replay 0 \
  'live archive validator must reconcile startedBy before replay and stop before the shortest client-token lifetime'
expect_bound_failure validator-launch-retry shared live_archive_validator_run_task_sdk_retries 1 \
  'live archive validator must retry RunTask only through its durable client token'
expect_bound_failure validator-launch-result-arn shared live_archive_validator_run_task_response_arn_persisted 0 \
  'live archive validator must concurrently launch and independently persist both reserved slots'
expect_bound_failure validator-launch-parallel shared live_archive_validator_two_slot_calls_parallel 0 \
  'live archive validator must concurrently launch and independently persist both reserved slots'
expect_bound_failure validator-launch-list-action shared live_archive_validator_probe_ecs_list_tasks 0 \
  'live archive validator probe role must have the exact guarded launch permissions'
expect_bound_failure validator-launch-extra-ecs-action shared live_archive_validator_probe_ecs_other_actions 1 \
  'live archive validator probe role must have the exact guarded launch permissions'
expect_bound_failure validator-launch-cluster-condition shared live_archive_validator_probe_ecs_cluster_condition 0 \
  'live archive validator probe role must have the exact guarded launch permissions'
expect_bound_failure validator-launch-family-condition shared live_archive_validator_probe_ecs_task_family_condition 0 \
  'live archive validator probe role must have the exact guarded launch permissions'
expect_bound_failure validator-launch-dynamodb-action shared live_archive_validator_probe_dynamodb_update_item 0 \
  'live archive validator probe role must have the exact guarded launch permissions'
expect_bound_failure validator-launch-extra-dynamodb-action shared live_archive_validator_probe_dynamodb_other_actions 1 \
  'live archive validator probe role must have the exact guarded launch permissions'
expect_bound_failure validator-launch-leading-key shared live_archive_validator_probe_launch_leading_key 0 \
  'live archive validator probe role must have the exact guarded launch permissions'
expect_bound_failure validator-launch-pass-execution-role shared live_archive_validator_probe_pass_execution_role 0 \
  'live archive validator probe role must have the exact guarded launch permissions'
expect_bound_failure validator-launch-pass-task-role shared live_archive_validator_probe_pass_task_role 0 \
  'live archive validator probe role must have the exact guarded launch permissions'
expect_bound_failure validator-launch-extra-passrole shared live_archive_validator_probe_pass_other_roles 1 \
  'live archive validator probe role must have the exact guarded launch permissions'
expect_bound_failure validator-launch-passed-service shared live_archive_validator_probe_passed_to_ecs 0 \
  'live archive validator probe role must have the exact guarded launch permissions'
expect_bound_failure validator-launch-ledger shared live_archive_validator_launch_ledger_item_bytes 2049 \
  'live archive validator launch ledger must fit two DynamoDB write request units'
expect_bound_failure validator-launch-serialization shared live_archive_validator_launch_control_serialized 0 \
  'live archive validator replacement and replay must use one serialized expiring lifecycle claim'
expect_bound_failure validator-launch-claim shared live_archive_validator_launch_control_claim_seconds 4 \
  'live archive validator replacement and replay must use one serialized expiring lifecycle claim'
expect_bound_failure validator-launch-state target live_archive_validator_launch_guard_write_units 1 \
  'target live archive validator launch guard must price every probe invocation'
expect_bound_failure validator-launch-result-state target live_archive_validator_launch_result_write_units 1 \
  'target live archive validator must price task-ARN persistence for every launch'
expect_bound_failure validator-fence shared live_archive_validator_active_leaders 2 \
  'live archive validator must have two tasks and exactly one fenced leader'
expect_bound_failure validator-order shared live_archive_validator_receipt_key_components 2 \
  'live archive validator must preserve FIFO order and use the complete object identity'
expect_bound_failure validator-receipt-digest-size shared live_archive_validator_receipt_identity_digest_bytes 31 \
  'live archive validator receipt identity digest must equal 32 bytes'
expect_bound_failure validator-receipt-digest-algorithm shared live_archive_validator_receipt_identity_sha256 0 \
  'live archive validator receipt identity must use SHA-256'
expect_bound_failure validator-signed-length shared live_archive_validator_signed_content_length 0 \
  'live archive validator job must sign the expected content length'
expect_bound_failure validator-pre-head shared live_archive_validator_pre_head_reservation 0 \
  'live archive validator must reserve billable budgets before HEAD'
expect_bound_failure validator-pending-takeover shared live_archive_validator_pending_takeover 0 \
  'live archive validator must fence takeover of expired pending receipts'
expect_bound_failure validator-final-lease-fence shared live_archive_validator_final_lease_fence 0 \
  'live archive validator final transaction must check the live lease generation'
expect_bound_failure validator-sdk-retries shared live_archive_validator_sdk_retries 1 \
  'live archive validator must disable implicit SDK retries'
expect_bound_failure validator-dlq-sdk-retries shared live_archive_validator_dlq_sdk_retries 1 \
  'live archive validator DLQ reconciliation must disable implicit SDK retries'
expect_bound_failure validator-max-receive shared live_archive_validator_max_receive_count 2 \
  'live archive validator must quarantine an unacknowledged delivery after one receive'
expect_bound_failure validator-dlq-repair-order shared live_archive_validator_dlq_repair_before_delete 0 \
  'live archive validator DLQ reconciliation must acknowledge redrive before delete'
expect_bound_failure validator-dlq-send-permission shared live_archive_validator_dlq_send_validation_permission 0 \
  'live archive validator DLQ reconciliation must acknowledge redrive before delete'
expect_bound_failure validator-fifo-dedup-window shared live_archive_validator_fifo_dedup_seconds 299 \
  'live archive validator uncertain FIFO sends must finish retry before the five-minute deduplication interval'
expect_bound_failure validator-fifo-retry-window shared live_archive_validator_uncertain_send_retry_seconds 300 \
  'live archive validator uncertain FIFO sends must finish retry before the five-minute deduplication interval'
expect_bound_failure validator-delete-ack shared live_archive_validator_attempt_includes_delete_ack 0 \
  'live archive validator attempt deadline must include DeleteMessage acknowledgement'
expect_bound_failure validator-rate target archive_objects_per_minute 30 \
  'target archive object admission rate exhausts worst-case receive-cycle capacity'
expect_bound_failure validator-fractional-rate target archive_objects_per_minute 3.7 \
  'target archive object admission rate must equal its fixed integer envelope'
expect_bound_failure validator-monthly-rate target archive_objects_per_minute 1 \
  'target monthly archive object cap exceeds its minute admission ceiling'
expect_bound_failure validator-bytes target live_archive_validator_read_gb 80 \
  'target live archive validator read budget must reserve every retry at maximum object size'
expect_bound_failure validator-max-object shared live_archive_validator_max_object_bytes 8388607 \
  'live archive validator maximum object size must equal 8 MiB'
expect_bound_failure archive-ingress target archive_ingress_gb 800 \
  'target archive ingress must equal its fixed storage and transfer envelope'
expect_bound_failure validator-logs small live_archive_validator_log_storage_gb 0.824 \
  'small live archive validator log ingestion or boundary-overlap storage is under-reserved'
expect_bound_failure validator-timing shared live_archive_validator_queue_delay_seconds 241 \
  'validator queue delay must equal 300 seconds'
expect_bound_failure managed-crr-timing shared managed_crr_stage_seconds 240 \
  'managed-CRR stage must equal 300 seconds'
expect_bound_failure validator-predecessors shared live_archive_validator_queued_predecessors 2 \
  'validator queued-predecessor budget must cover the target same-stream burst'
expect_bound_failure validator-receive-cycles shared live_archive_validator_receive_cycles 3 \
  'validator receive-cycle budget must cover every split same-stream delivery'
expect_bound_failure validator-dispatch shared live_archive_validator_outbox_dispatch_seconds 61 \
  'validator ordered outbox dispatch budget must equal 60 seconds'
expect_bound_failure validator-per-stream-interval shared live_archive_validator_per_stream_min_interval_seconds 60 \
  'validator per-stream admission interval must exceed ordered outbox dispatch time'
expect_bound_failure validator-same-stream-burst shared live_archive_validator_same_stream_burst_objects 3 \
  'validator same-stream burst must equal the modeled predecessor envelope'
expect_bound_failure validator-same-stream-refill shared live_archive_validator_same_stream_burst_blocks_refill 0 \
  'validator same-stream burst must block refill until acknowledged and checkpointed'
expect_bound_failure validator-completion shared live_archive_validator_attempt_seconds 3 \
  'validator attempt budget must equal 2 seconds'
expect_bound_failure schedule-shutdown shared probe_group_delete_coverage 1 \
  'probe group deletion does not cover every schedule identity'
expect_bound_failure schedule-cardinality shared probe_schedule_identities 44639 \
  'probe schedule must contain one identity per minute in a 744-hour month'
expect_bound_failure schedule-duplicates shared probe_duplicate_attempts 44639 \
  'probe duplicate reserve must equal one attempt per schedule identity'
expect_bound_failure schedule-propagation shared probe_shutdown_attempts 4463 \
  'probe shutdown reserve must equal 10 percent of schedule identities'
expect_bound_failure schedule-synchronous-invoke shared probe_synchronous_lambda_invoke 0 \
  'probe Scheduler target must invoke Lambda synchronously'
expect_bound_failure schedule-universal-target shared probe_scheduler_universal_invoke_target 0 \
  'probe Scheduler must use the universal Lambda Invoke target'
expect_bound_failure schedule-request-response shared probe_scheduler_invocation_type_request_response 0 \
  'probe Scheduler Lambda Invoke must use RequestResponse'
expect_bound_failure schedule-target-retries shared probe_scheduler_maximum_retry_attempts 1 \
  'probe Scheduler target retries must be disabled'
expect_bound_failure schedule-event-age shared probe_scheduler_maximum_event_age_seconds 59 \
  'probe Scheduler maximum event age must equal 60 seconds'
expect_bound_failure probe-before-launch-control shared probe_api_before_launch_control 0 \
  'probe must record the API synthetic before validator lifecycle control'
expect_bound_failure probe-api-deadline shared probe_api_deadline_seconds 2 \
  'probe must reserve one second for the API result and four seconds for lifecycle control'
expect_bound_failure probe-lifecycle-reserve shared probe_lifecycle_reserve_seconds 3 \
  'probe must reserve one second for the API result and four seconds for lifecycle control'
expect_bound_failure schedule-second-start shared probe_second_schedule_start_seconds 119 \
  'probe second schedule start must equal 120 seconds'
expect_bound_failure schedule-delivery-delay shared scheduler_delivery_delay_seconds 59 \
  'Scheduler delivery delay must reserve the full 60-second precision window'
expect_bound_failure probe-api shared probe_api_requests 89280 \
  'probe API request budget must include intended, duplicate, and shutdown writes'
expect_bound_failure probe-api-retries shared probe_api_sdk_retries 1 \
  'probe API clients must disable implicit SDK retries'
expect_bound_failure generated-api-schedule target generated_api_requests_month 117090719 \
  'target generated API workload differs from the fixed schedule'
expect_bound_failure probe-api-envelope small api_requests_month 23436000 \
  'small API envelope omits intended, duplicate, or shutdown probe calls'
expect_bound_failure probe-response shared probe_short_response_bytes 1 \
  'probe short-response envelope must equal 2048 bytes'
expect_bound_failure fixed-response-schedule small fixed_response_egress_base_bytes 137699999999 \
  'small base fixed-response workload differs from the fixed schedule'
expect_bound_failure probe-response-envelope target fixed_response_egress_bytes 688520000000 \
  'target fixed response envelope omits duplicate or shutdown probe responses'
expect_bound_failure detection-probe-timeout shared probe_timeout_seconds 6 \
  'probe timeout must equal 5 seconds'
expect_bound_failure detection shared emf_publish_extract_seconds 6 \
  'EMF publish and extraction budget must equal 5 seconds'
expect_bound_failure detection-alarm shared alarm_evaluation_seconds 11 \
  'alarm evaluation budget must equal 10 seconds'
expect_bound_failure detection-pager shared pager_receipt_seconds 41 \
  'pager receipt budget must equal 40 seconds'
expect_bound_failure detection-objective shared regional_detection_objective_seconds 241 \
  'regional detection objective must equal 240 seconds'
expect_bound_failure validator-lease-renewal shared live_archive_validator_lease_renew_seconds 11 \
  'live archive validator lease and renewal must equal 30 and 10 seconds'
expect_bound_failure validator-lease-duration shared live_archive_validator_lease_seconds 31 \
  'live archive validator lease and renewal must equal 30 and 10 seconds'

LC_ALL=C awk -F '\t' '
function money(value, formatted, parts, whole, grouped) {
    formatted = sprintf("%.2f", value + 0)
    split(formatted, parts, ".")
    whole = parts[1]
    grouped = ""
    while (length(whole) > 3) {
        grouped = "," substr(whole, length(whole) - 2) grouped
        whole = substr(whole, 1, length(whole) - 3)
    }
    return whole grouped "." parts[2]
}

NR == 1 {
    next
}

$1 == "developer" {
    label = "Developer"
    estimate = "USD " money($2) " cloud infrastructure"
}

$1 == "small" {
    label = "Small production"
    estimate = "USD " money($2)
}

$1 == "target" {
    label = "Target-scale qualification"
    estimate = "USD " money($2)
}

{
    if (label == "") {
        print "unmapped cost-summary profile " $1 > "/dev/stderr"
        exit 1
    }
    printf "| %s | %s | USD %s | USD %s |\n", \
        label, estimate, money($3), money($4)
    label = ""
    estimate = ""
}
' "$script_dir/expected.tsv" >"$expected_summary_file"

LC_ALL=C awk '
/^\| Developer \|/ ||
/^\| Small production \|/ ||
/^\| Target-scale qualification \|/
' "$script_dir/../0001-alpha-operational-bounds.md" >"$actual_summary_file"

diff -u "$expected_summary_file" "$actual_summary_file"

LC_ALL=C awk -F '\t' '
FILENAME == ARGV[1] {
    if (FNR == 1) { next }
    if ($2 == "database_compute" || $2 == "database_cpu_credits" || \
        $2 == "database_storage" || $2 == "primary_backup_storage" || \
        $2 == "recovery_backup_storage" || $2 == "recovery_backup_transfer") {
        database[$1] += $4 * $6
    }
    if ($2 == "queue_requests") {
        queue[$1] += $4 * $6
    }
    next
}
FILENAME == ARGV[2] {
    if (FNR == 1) { next }
    if ($1 == "developer") { label = "Developer" }
    if ($1 == "small") { label = "Small production" }
    if ($1 == "target") { label = "Target qualification" }
    if (label == "") {
        print "unmapped implementation-stack profile " $1 > "/dev/stderr"
        exit 1
    }
    printf "%s\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\n", \
        label, database[$1], queue[$1], database[$1] + queue[$1], $2 + 0, $4 + 0
    label = ""
}
' "$script_dir/inputs.tsv" "$script_dir/expected.tsv" >"$expected_stack_summary_file"

LC_ALL=C awk -F '|' '
function trim(value) {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
    return value
}
function money(value) {
    value = trim(value)
    sub(/^USD[[:space:]]+/, "", value)
    gsub(/,/, "", value)
    return sprintf("%.2f", value + 0)
}
/^\| Developer \|/ { label = "Developer" }
/^\| Small production \|/ { label = "Small production" }
/^\| Target qualification \|/ { label = "Target qualification" }
label != "" {
    printf "%s\t%s\t%s\t%s\t%s\t%s\n", \
        label, money($3), money($4), money($5), money($6), money($7)
    label = ""
}
' "$script_dir/../0002-alpha-implementation-stack.md" >"$actual_stack_summary_file"

diff -u "$expected_stack_summary_file" "$actual_stack_summary_file"
printf '%s\n' 'cost model verification passed'
