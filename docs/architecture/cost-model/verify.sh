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
