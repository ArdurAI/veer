BEGIN {
    FS = "\t"
    error_count = 0
}

function fail(message) {
    print "operational-bounds: " message > "/dev/stderr"
    error_count++
}

function is_amount(value) {
    return value ~ /^[0-9]+([.][0-9]+)?$/
}

function bound(scope, metric, key) {
    key = scope SUBSEP metric
    if (!(key in bounds)) {
        fail("missing " scope "/" metric)
        return 0
    }
    return bounds[key]
}

function input(profile, item, key) {
    key = profile SUBSEP item
    if (!(key in inputs)) {
        fail("missing cost input " profile "/" item)
        return 0
    }
    return inputs[key]
}

function differs(left, right) {
    return (left - right > 0.000001 || right - left > 0.000001)
}

function ceil(value) {
    return value == int(value) ? value : int(value) + 1
}

FILENAME == ARGV[1] {
    if (FNR == 1) {
        if ($0 != "scope\tmetric\tvalue\tunit\tnote") {
            fail("unexpected operational bounds header")
        }
        next
    }
    if (NF != 5) {
        fail("operational bound row must contain five tab-separated fields")
        next
    }
    key = $1 SUBSEP $2
    if (key in bounds) {
        fail("duplicate operational bound " $1 "/" $2)
    }
    if (!is_amount($3)) {
        fail("operational bound value must be a non-negative decimal")
    }
    bounds[key] = $3 + 0
    next
}

FILENAME == ARGV[2] {
    if (FNR == 1) {
        if ($0 != "profile\titem\tcategory\tquantity\tunit\tunit_rate_usd\tsource_id\tnote") {
            fail("unexpected cost inputs header")
        }
        next
    }
    if (NF != 8) {
        fail("cost input row must contain eight tab-separated fields")
        next
    }
    inputs[$1 SUBSEP $2] = $4 + 0
    next
}

{
    fail("unexpected verifier input " FILENAME)
}

END {
    profiles[1] = "small"
    profiles[2] = "target"

    intended = bound("shared", "probe_schedule_identities")
    duplicate = bound("shared", "probe_duplicate_attempts")
    shutdown = bound("shared", "probe_shutdown_attempts")
    if (intended != 744 * 60) {
        fail("probe schedule must contain one identity per minute in a 744-hour month")
    }
    if (intended != int(intended) || duplicate != int(duplicate) || shutdown != int(shutdown)) {
        fail("probe intended, duplicate, and shutdown attempt counts must be integers")
    }
    if (duplicate != intended) {
        fail("probe duplicate reserve must equal one attempt per schedule identity")
    }
    if (shutdown != intended / 10) {
        fail("probe shutdown reserve must equal 10 percent of schedule identities")
    }
    if (bound("shared", "probe_synchronous_lambda_invoke") != 1) {
        fail("probe Scheduler target must invoke Lambda synchronously")
    }
    if (bound("shared", "probe_scheduler_universal_invoke_target") != 1) {
        fail("probe Scheduler must use the universal Lambda Invoke target")
    }
    if (bound("shared", "probe_scheduler_invocation_type_request_response") != 1) {
        fail("probe Scheduler Lambda Invoke must use RequestResponse")
    }
    if (bound("shared", "probe_scheduler_maximum_retry_attempts") != 0) {
        fail("probe Scheduler target retries must be disabled")
    }
    if (bound("shared", "probe_scheduler_maximum_event_age_seconds") != 60) {
        fail("probe Scheduler maximum event age must equal 60 seconds")
    }
    if (bound("shared", "probe_api_before_launch_control") != 1) {
        fail("probe must record the API synthetic before validator lifecycle control")
    }
    probe_api_deadline_seconds = bound("shared", "probe_api_deadline_seconds")
    probe_lifecycle_reserve_seconds = bound("shared", "probe_lifecycle_reserve_seconds")
    if (probe_api_deadline_seconds != 1 || probe_lifecycle_reserve_seconds != 4 || \
        probe_api_deadline_seconds + probe_lifecycle_reserve_seconds != \
        bound("shared", "probe_timeout_seconds")) {
        fail("probe must reserve one second for the API result and four seconds for lifecycle control")
    }
    total_probe_attempts = intended + duplicate + shutdown
    probe_api_requests = intended * 2 + duplicate + shutdown
    if (bound("shared", "probe_api_requests") != probe_api_requests) {
        fail("probe API request budget must include intended, duplicate, and shutdown writes")
    }
    if (bound("shared", "probe_api_sdk_retries") != 0) {
        fail("probe API clients must disable implicit SDK retries")
    }
    if (bound("shared", "probe_short_response_bytes") != 2048) {
        fail("probe short-response envelope must equal 2048 bytes")
    }
    delete_coverage = bound("shared", "probe_group_delete_coverage")
    if (delete_coverage < intended) {
        fail("probe group deletion does not cover every schedule identity")
    }

    probe_artifact_retention_seconds = bound("shared", "probe_artifact_retention_seconds")
    probe_artifact_cleanup_seconds = bound("shared", "probe_artifact_cleanup_seconds")
    if (probe_artifact_retention_seconds != 30 * 86400 || \
        probe_artifact_cleanup_seconds != 86400) {
        fail("probe artifact retention must equal 30 days with cleanup inside one day")
    }
    probe_artifact_unexpired_current_versions = probe_artifact_retention_seconds / 60
    probe_artifact_cleanup_versions = probe_artifact_cleanup_seconds / 60
    probe_artifact_current_versions_max = \
        probe_artifact_unexpired_current_versions + probe_artifact_cleanup_versions
    if (bound("shared", "probe_artifact_unexpired_current_versions") != \
            probe_artifact_unexpired_current_versions || \
        bound("shared", "probe_artifact_cleanup_interval_data_versions") != \
            probe_artifact_cleanup_versions || \
        bound("shared", "probe_artifact_current_versions_max") != \
            probe_artifact_current_versions_max || \
        bound("shared", "probe_artifact_noncurrent_versions_max") != \
            probe_artifact_cleanup_versions || \
        bound("shared", "probe_artifact_delete_markers_max") != \
            probe_artifact_cleanup_versions || \
        bound("shared", "probe_artifact_lifecycle_class_alternatives") != 1) {
        fail("probe artifact class maxima must model lifecycle-dependent alternatives")
    }
    probe_artifact_physical_entries = probe_artifact_unexpired_current_versions + \
        2 * probe_artifact_cleanup_versions
    if (bound("shared", "probe_artifact_physical_entries") != \
        probe_artifact_physical_entries) {
        fail("probe artifact physical entries must include current noncurrent and marker versions")
    }
    probe_artifact_cleanup_sweeps = 744 * 3600 / probe_artifact_cleanup_seconds
    probe_artifact_cleanup_list_requests = probe_artifact_cleanup_sweeps * \
        (ceil(probe_artifact_physical_entries / 1000) + 1)
    if (bound("shared", "probe_artifact_cleanup_list_requests_month") != \
        probe_artifact_cleanup_list_requests) {
        fail("probe artifact cleanup LIST budget must cover every physical entry and final empty proofs")
    }
    probe_artifact_cleanup_delete_requests = probe_artifact_cleanup_sweeps * \
        ceil(2 * probe_artifact_cleanup_versions / 1000)
    if (bound("shared", "probe_artifact_cleanup_delete_requests_month") != \
        probe_artifact_cleanup_delete_requests) {
        fail("probe artifact cleanup delete budget must cover noncurrent versions and markers")
    }
    if (bound("shared", "probe_artifact_encoded_bytes") != 1000000 || \
        bound("shared", "probe_artifact_key_bytes") != 512) {
        fail("probe artifact storage must use the one-million-byte body and 512-byte key envelopes")
    }
    if (bound("shared", "probe_artifact_cleanup_lists_all_versions") != 1 || \
        bound("shared", "probe_artifact_cleanup_exact_version_delete") != 1) {
        fail("probe artifact cleanup must enumerate all version classes and delete exact versions")
    }
    if (bound("shared", "probe_artifact_cleanup_role_assumable") != 1 || \
        bound("shared", "probe_artifact_cleanup_role_lists_exact_prefix") != 1 || \
        bound("shared", "probe_artifact_cleanup_role_deletes_exact_versions") != 1 || \
        bound("shared", "probe_artifact_cleanup_role_other_bucket_actions") != 0) {
        fail("probe artifact cleanup requires an assumable exact-prefix least-privilege role")
    }

    if (bound("shared", "probe_second_schedule_start_seconds") != 120) {
        fail("probe second schedule start must equal 120 seconds")
    }
    if (bound("shared", "scheduler_delivery_delay_seconds") != 60) {
        fail("Scheduler delivery delay must reserve the full 60-second precision window")
    }
    if (bound("shared", "probe_timeout_seconds") != 5) {
        fail("probe timeout must equal 5 seconds")
    }
    if (bound("shared", "emf_publish_extract_seconds") != 5) {
        fail("EMF publish and extraction budget must equal 5 seconds")
    }
    if (bound("shared", "alarm_evaluation_seconds") != 10) {
        fail("alarm evaluation budget must equal 10 seconds")
    }
    if (bound("shared", "pager_receipt_seconds") != 40) {
        fail("pager receipt budget must equal 40 seconds")
    }
    detection_seconds = \
        bound("shared", "probe_second_schedule_start_seconds") + \
        bound("shared", "scheduler_delivery_delay_seconds") + \
        bound("shared", "probe_timeout_seconds") + \
        bound("shared", "emf_publish_extract_seconds") + \
        bound("shared", "alarm_evaluation_seconds") + \
        bound("shared", "pager_receipt_seconds")
    detection_objective = bound("shared", "regional_detection_objective_seconds")
    if (detection_objective != 240) {
        fail("regional detection objective must equal 240 seconds")
    }
    if (detection_seconds > 240) {
        fail("regional detection budget must not exceed 240 seconds")
    }

    if (bound("shared", "live_archive_validator_task_count") != 2 || \
        bound("shared", "live_archive_validator_active_leaders") != 1) {
        fail("live archive validator must have two tasks and exactly one fenced leader")
    }
    if (bound("shared", "live_archive_validator_ecs_service_scheduler") != 0 || \
        bound("shared", "live_archive_validator_probe_launch_controller") != 1) {
        fail("live archive validator must use probe-controlled standalone tasks")
    }
    if (bound("shared", "live_archive_validator_stop_obsolete_before_launch") != 1 || \
        bound("shared", "live_archive_validator_max_stop_tasks_per_probe") != 1 || \
        bound("shared", "live_archive_validator_stop_task_sdk_retries") != 0) {
        fail("live archive validator must drain obsolete tasks without overlap or implicit retry")
    }
    if (bound("shared", "live_archive_validator_run_task_count") != 1 || \
        bound("shared", "live_archive_validator_two_slot_run_task_calls") != 2 || \
        bound("shared", "live_archive_validator_single_slot_run_task_calls") != 1 || \
        bound("shared", "live_archive_validator_run_task_client_token") != 1) {
        fail("live archive validator must use independent idempotent RunTask requests for each one-slot or two-slot fill")
    }
    client_token_min_ttl_seconds = bound("shared", "live_archive_validator_run_task_client_token_min_ttl_seconds")
    replay_deadline_seconds = bound("shared", "live_archive_validator_run_task_replay_deadline_seconds")
    if (bound("shared", "live_archive_validator_run_task_started_by") != 1 || \
        bound("shared", "live_archive_validator_run_task_discovery_before_replay") != 1 || \
        client_token_min_ttl_seconds != 3600 || replay_deadline_seconds != 3000 || \
        replay_deadline_seconds >= client_token_min_ttl_seconds) {
        fail("live archive validator must reconcile startedBy before replay and stop before the shortest client-token lifetime")
    }
    if (bound("shared", "live_archive_validator_run_task_sdk_retries") != 0) {
        fail("live archive validator must retry RunTask only through its durable client token")
    }
    if (bound("shared", "live_archive_validator_run_task_response_arn_persisted") != 1 || \
        bound("shared", "live_archive_validator_two_slot_calls_parallel") != 1) {
        fail("live archive validator must concurrently launch and independently persist both reserved slots")
    }
    if (bound("shared", "live_archive_validator_probe_ecs_list_tasks") != 1 || \
        bound("shared", "live_archive_validator_probe_ecs_describe_tasks") != 1 || \
        bound("shared", "live_archive_validator_probe_ecs_stop_task") != 1 || \
        bound("shared", "live_archive_validator_probe_ecs_run_task") != 1 || \
        bound("shared", "live_archive_validator_probe_ecs_other_actions") != 0 || \
        bound("shared", "live_archive_validator_probe_ecs_cluster_condition") != 1 || \
        bound("shared", "live_archive_validator_probe_ecs_task_family_condition") != 1 || \
        bound("shared", "live_archive_validator_probe_dynamodb_update_item") != 1 || \
        bound("shared", "live_archive_validator_probe_dynamodb_other_actions") != 0 || \
        bound("shared", "live_archive_validator_probe_launch_leading_key") != 1 || \
        bound("shared", "live_archive_validator_probe_pass_execution_role") != 1 || \
        bound("shared", "live_archive_validator_probe_pass_task_role") != 1 || \
        bound("shared", "live_archive_validator_probe_pass_other_roles") != 0 || \
        bound("shared", "live_archive_validator_probe_passed_to_ecs") != 1) {
        fail("live archive validator probe role must have the exact guarded launch permissions")
    }
    launch_ledger_item_bytes = bound("shared", "live_archive_validator_launch_ledger_item_bytes")
    if (launch_ledger_item_bytes != 2048) {
        fail("live archive validator launch ledger must fit two DynamoDB write request units")
    }
    lifecycle_claim_seconds = bound("shared", "live_archive_validator_launch_control_claim_seconds")
    if (bound("shared", "live_archive_validator_restart_guard") != 1 || \
        bound("shared", "live_archive_validator_launch_control_serialized") != 1 || \
        lifecycle_claim_seconds != 5 || \
        lifecycle_claim_seconds <= probe_lifecycle_reserve_seconds) {
        fail("live archive validator replacement and replay must use one serialized expiring lifecycle claim")
    }
    launch_bucket_capacity = bound("shared", "live_archive_validator_launch_bucket_capacity")
    launch_refill_seconds = bound("shared", "live_archive_validator_launch_token_refill_seconds")
    launch_window_end_exclusive = bound("shared", "live_archive_validator_launch_window_end_exclusive")
    launches = bound("shared", "live_archive_validator_launches_month")
    topology_fill_seconds = bound("shared", "live_archive_validator_topology_fill_seconds")
    restart_minimum_seconds = bound("shared", "live_archive_validator_restart_minimum_billing_seconds")
    if (launch_bucket_capacity != 2 || launch_refill_seconds != 3600 || \
        launch_window_end_exclusive != 1 || \
        launches != launch_bucket_capacity + int((744 * 3600 - 1) / launch_refill_seconds)) {
        fail("live archive validator launch reserve must use two initial tokens plus only refills strictly inside the window")
    }
    control_schedule_seconds = bound("shared", "live_archive_validator_control_schedule_seconds")
    if (control_schedule_seconds != 60 || \
        topology_fill_seconds != control_schedule_seconds + \
        bound("shared", "scheduler_delivery_delay_seconds") + \
        bound("shared", "probe_timeout_seconds")) {
        fail("live archive validator topology fill must include schedule period delivery jitter and one invocation")
    }
    if (restart_minimum_seconds != 60) {
        fail("live archive validator replacement must reserve the 60-second billing minimum")
    }
    if (bound("shared", "live_archive_validator_fifo_enabled") != 1 || \
        bound("shared", "live_archive_validator_receipt_key_components") != 3) {
        fail("live archive validator must preserve FIFO order and use the complete object identity")
    }
    if (bound("shared", "live_archive_validator_receipt_identity_digest_bytes") != 32) {
        fail("live archive validator receipt identity digest must equal 32 bytes")
    }
    if (bound("shared", "live_archive_validator_receipt_identity_sha256") != 1) {
        fail("live archive validator receipt identity must use SHA-256")
    }
    if (bound("shared", "live_archive_validator_batch_size") != 10) {
        fail("live archive validator FIFO batch size must equal ten")
    }
    if (bound("shared", "live_archive_validator_signed_content_length") != 1) {
        fail("live archive validator job must sign the expected content length")
    }
    if (bound("shared", "live_archive_validator_pre_head_reservation") != 1) {
        fail("live archive validator must reserve billable budgets before HEAD")
    }
    if (bound("shared", "live_archive_validator_pending_takeover") != 1) {
        fail("live archive validator must fence takeover of expired pending receipts")
    }
    if (bound("shared", "live_archive_validator_final_lease_fence") != 1) {
        fail("live archive validator final transaction must check the live lease generation")
    }
    if (bound("shared", "live_archive_validator_sdk_retries") != 0) {
        fail("live archive validator must disable implicit SDK retries")
    }
    if (bound("shared", "live_archive_validator_dlq_sdk_retries") != 0) {
        fail("live archive validator DLQ reconciliation must disable implicit SDK retries")
    }
    if (bound("shared", "live_archive_validator_max_receive_count") != 1) {
        fail("live archive validator must quarantine an unacknowledged delivery after one receive")
    }
    if (bound("shared", "live_archive_validator_dlq_repair_before_delete") != 1 || \
        bound("shared", "live_archive_validator_dlq_send_validation_permission") != 1) {
        fail("live archive validator DLQ reconciliation must acknowledge redrive before delete")
    }
    fifo_dedup_seconds = bound("shared", "live_archive_validator_fifo_dedup_seconds")
    uncertain_send_retry_seconds = bound("shared", "live_archive_validator_uncertain_send_retry_seconds")
    if (fifo_dedup_seconds != 300 || uncertain_send_retry_seconds != 240 || \
        uncertain_send_retry_seconds >= fifo_dedup_seconds) {
        fail("live archive validator uncertain FIFO sends must finish retry before the five-minute deduplication interval")
    }
    if (bound("shared", "live_archive_validator_attempt_includes_delete_ack") != 1) {
        fail("live archive validator attempt deadline must include DeleteMessage acknowledgement")
    }
    if (bound("shared", "live_archive_validator_receipt_cleanup_enabled") != 1) {
        fail("live archive validator must deterministically reclaim expired receipts")
    }
    if (bound("shared", "live_archive_validator_receipt_cleanup_seconds") != 86400) {
        fail("live archive validator receipt cleanup must complete within 24 hours")
    }
    receipt_encoded_bytes = bound("shared", "live_archive_validator_receipt_encoded_bytes")
    item_storage_overhead_bytes = bound("shared", "dynamodb_base_item_storage_overhead_bytes")
    receipt_storage_envelope_bytes = bound("shared", "live_archive_validator_receipt_storage_envelope_bytes")
    if (receipt_encoded_bytes != 1024) {
        fail("live archive validator receipt encoding must remain capped at 1024 bytes")
    }
    if (item_storage_overhead_bytes != 100) {
        fail("DynamoDB base item storage overhead must equal 100 bytes")
    }
    if (receipt_storage_envelope_bytes != 2048 || \
        receipt_encoded_bytes + item_storage_overhead_bytes > receipt_storage_envelope_bytes) {
        fail("live archive validator receipt storage must reserve a 2048-byte billed envelope")
    }
    polls_per_second = bound("shared", "live_archive_validator_polls_per_second")
    if (polls_per_second != 1) {
        fail("live archive validator must permit exactly one poll start per second")
    }
    receive_loop_count = bound("shared", "live_archive_validator_receive_loop_count")
    if (receive_loop_count != 2) {
        fail("live archive validator must run exactly two concurrent receive loops")
    }
    if (bound("shared", "live_archive_validator_max_inter_poll_seconds") != 1) {
        fail("live archive validator maximum inter-poll gap must equal one second")
    }
    if (bound("shared", "live_archive_validator_long_poll_seconds") != 20) {
        fail("live archive validator long-poll wait must equal 20 seconds")
    }
    if (bound("shared", "live_archive_validator_receive_response_seconds") != 21) {
        fail("live archive validator receive-response deadline must equal 21 seconds")
    }
    if (bound("shared", "live_archive_validator_lease_renew_seconds") != 10 || \
        bound("shared", "live_archive_validator_lease_seconds") != 30) {
        fail("live archive validator lease and renewal must equal 30 and 10 seconds")
    }

    archive_overlap_envelopes = bound("shared", "archive_lifecycle_overlap_envelopes")
    archive_marker_key_bytes = bound("shared", "archive_delete_marker_key_bytes")
    if (archive_overlap_envelopes != 2 || archive_marker_key_bytes != 512 || \
        bound("shared", "archive_retention_cleanup_seconds") != 86400) {
        fail("archive retention must reserve two adjacent cohorts and complete exact cleanup inside one day")
    }
    if (bound("shared", "archive_sweeper_lists_current_versions") != 1 || \
        bound("shared", "archive_sweeper_lists_noncurrent_versions") != 1 || \
        bound("shared", "archive_sweeper_lists_delete_markers") != 1 || \
        bound("shared", "archive_sweeper_exact_version_delete") != 1 || \
        bound("shared", "archive_sweeper_checks_object_lock") != 1 || \
        bound("shared", "archive_sweeper_gets_object_retention") != 1 || \
        bound("shared", "archive_sweeper_gets_object_legal_hold") != 1) {
        fail("archive sweeper must prove Object Lock eligibility and delete every version class by exact identifier")
    }
    if (bound("shared", "archive_recovery_fixture_delayed_lifecycle_current_versions") != 1 || \
        bound("shared", "archive_recovery_fixture_post_lifecycle_version_classes") != 1) {
        fail("archive recovery qualification must exercise both lifecycle-dependent version states")
    }
    manifest_control_objects = bound("shared", "full_reseed_manifest_control_objects")
    manifest_aggregate_bytes = bound("shared", "full_reseed_manifest_aggregate_bytes")
    manifest_list_page_size = bound("shared", "full_reseed_manifest_list_page_size")
    manifest_delete_batch_size = bound("shared", "full_reseed_manifest_delete_batch_size")
    if (bound("shared", "full_reseed_manifest_inventory_format") != 1 || \
        manifest_control_objects != 3 || manifest_aggregate_bytes != 8589934592 || \
        bound("shared", "full_reseed_manifest_cleanup_seconds") != 86400 || \
        bound("shared", "full_reseed_manifest_output_versioned") != 0 || \
        manifest_list_page_size != 1000 || manifest_delete_batch_size != 1000) {
        fail("generated manifest must use the bounded nonversioned Inventory-format object-set contract")
    }
    if (bound("shared", "full_reseed_manifest_prewrite_provider_enforcement") != 0 || \
        bound("shared", "full_reseed_manifest_excess_output_residual") != 1) {
        fail("generated manifest qualification must expose unbounded provider output before post-write validation")
    }
    if (bound("shared", "full_reseed_manifest_validator_assumable") != 1 || \
        bound("shared", "full_reseed_manifest_validator_lists_exact_prefix") != 1 || \
        bound("shared", "full_reseed_manifest_validator_reads_exact_prefix") != 1 || \
        bound("shared", "full_reseed_manifest_validator_deletes_exact_prefix") != 1 || \
        bound("shared", "full_reseed_manifest_validator_creates_jobs") != 0 || \
        bound("shared", "full_reseed_manifest_validator_passes_roles") != 0) {
        fail("generated manifest qualification requires an assumable exact-prefix least-privilege executor")
    }
    if (bound("shared", "full_reseed_job_confirmation_required") != 1 || \
        bound("shared", "full_reseed_job_submitter_updates_exact_job_status") != 1 || \
        bound("shared", "full_reseed_job_submitter_updates_other_job_status") != 0 || \
        bound("shared", "full_reseed_job_ready_requires_signed_manifest_validation") != 1 || \
        bound("shared", "full_reseed_job_cancel_requires_signed_manifest_rejection") != 1) {
        fail("generated manifest qualification requires signed evidence for exact-job status transitions")
    }
    if (bound("shared", "full_reseed_manifest_residual_cleanup_after_rejection") != 1 || \
        bound("shared", "full_reseed_noncleanup_billable_action_after_manifest_rejection") != 0) {
        fail("manifest rejection must permit only residual cleanup billable actions")
    }

    audit_event_max_bytes = bound("shared", "audit_event_max_bytes")
    audit_average_bytes = bound("shared", "audit_partition_average_bytes")
    rejection_event_max_bytes = bound("shared", "audit_rejection_event_max_bytes")
    compact_record_max_bytes = bound("shared", "compact_non_audit_record_max_bytes")
    compact_average_bytes = bound("shared", "compact_non_audit_average_bytes")
    audit_records_per_object = bound("shared", "archive_audit_records_per_object")
    compact_records_per_object = bound("shared", "archive_compact_records_per_object")
    audit_reserved_bytes = bound("shared", "archive_audit_reserved_bytes_per_object")
    archive_flush_seconds = bound("shared", "archive_timer_flush_seconds")
    if (audit_event_max_bytes != 16384 || audit_average_bytes != 1000 || \
        rejection_event_max_bytes != 1000 || compact_record_max_bytes != 4096 || \
        compact_average_bytes != 400 || audit_reserved_bytes != 196608 || \
        audit_records_per_object != 500 || compact_records_per_object != 1000 || \
        archive_flush_seconds != 600) {
        fail("audit bytes and archive packing must equal the fixed evidence envelope")
    }
    if (bound("shared", "rejection_audit_partition_shared") != 1 || \
        bound("shared", "rejection_audit_capacity_inferred_from_runtime_mix") != 0 || \
        bound("shared", "rejection_audit_reserve_before_authentication") != 1 || \
        bound("shared", "rejection_audit_reserve_before_authorization") != 1 || \
        bound("shared", "rejection_audit_event_byte_reservation_atomic") != 1 || \
        bound("shared", "rejection_audit_event_settlement_atomic") != 1 || \
        bound("shared", "rejection_audit_authorized_release_before_state") != 1 || \
        bound("shared", "rejection_audit_commit_before_response") != 1) {
        fail("rejection audit capacity must be reserved atomically before classification")
    }
    if (bound("shared", "rejection_audit_database_load_seconds") != 86400 || \
        bound("shared", "rejection_audit_database_path_uses_runtime_adapter") != 1 || \
        bound("shared", "rejection_audit_database_changed_bytes_metered") != 1 || \
        bound("shared", "rejection_audit_additional_gp3_performance_allowed") != 0) {
        fail("rejection audit database effects must be physically qualified without extra RDS performance cost")
    }
    if (bound("shared", "rejection_audit_authorized_release_uses_standard_load") != 1 || \
        bound("shared", "rejection_audit_reconciliation_uses_prior_window") != 1 || \
        bound("shared", "rejection_audit_reconciliation_concurrent_with_standard_load") != 1) {
        fail("rejection release and reconciliation database loads must be exact and concurrent")
    }
    if (bound("shared", "rejection_audit_missing_or_stale_ledger_fails_closed") != 1 || \
        bound("shared", "rejection_audit_uncertain_reservation_reclaimed_by_age") != 0 || \
        bound("shared", "rejection_audit_exact_reconciliation_required") != 1) {
        fail("rejection audit reservations must fail closed until exact reconciliation")
    }
    if (bound("shared", "rejection_audit_exhaustion_evaluates_authentication") != 0 || \
        bound("shared", "rejection_audit_exhaustion_evaluates_authorization") != 0 || \
        bound("shared", "rejection_audit_exhaustion_status") != 503 || \
        bound("shared", "rejection_audit_exhaustion_response_bytes") != 2048) {
        fail("rejection partition exhaustion must return a bounded generic pre-classification response")
    }
    if (bound("shared", "rejection_audit_classified_response_bytes") != 2048) {
        fail("classified rejection responses must fit the bounded response envelope")
    }
    if (bound("shared", "rejection_audit_exhaustion_transition_system_event") != 1 || \
        bound("shared", "rejection_audit_exhaustion_transition_slot_pre_reserved") != 1 || \
        bound("shared", "rejection_audit_exhaustion_request_events") != 0) {
        fail("rejection exhaustion must audit its state transition without per-request event growth")
    }
    if (bound("shared", "rejection_audit_borrows_system_headroom") != 0 || \
        bound("shared", "rejection_audit_borrows_other_partitions") != 0) {
        fail("rejection audit capacity must not borrow another evidence partition")
    }
    if (bound("shared", "rejection_mix_fixture_all_unauthenticated") != 1 || \
        bound("shared", "rejection_mix_fixture_all_unauthorized") != 1) {
        fail("rejection qualification must shift the complete generated stream to both rejection classes")
    }

    for (profile_index = 1; profile_index <= 2; profile_index++) {
        profile = profiles[profile_index]
        generated_api_requests = bound(profile, "generated_api_requests_month")
        expected_generated_api_requests = profile == "small" ? 23346720 : 117090720
        if (generated_api_requests != expected_generated_api_requests) {
            fail(profile " generated API workload differs from the fixed schedule")
        }
        if (bound(profile, "api_requests_month") != generated_api_requests + probe_api_requests) {
            fail(profile " API envelope omits intended, duplicate, or shutdown probe calls")
        }
        complete_request_cycles = int(generated_api_requests / 100)
        if (generated_api_requests != complete_request_cycles * 100 + 20) {
            fail(profile " generated API workload must contain complete cycles plus twenty final reads")
        }
        audit_event_cap = bound(profile, "audit_event_cap")
        expected_audit_event_cap = profile == "small" ? 9000000 : 52000000
        if (audit_event_cap != expected_audit_event_cap) {
            fail(profile " audit event cap differs from the published profile ceiling")
        }
        success_cancel_events = complete_request_cycles * 15
        rejection_events = complete_request_cycles * 2
        provider_attempt_events = profile == "small" ? 4129200 : 30690000
        synthetic_events = intended
        system_event_headroom = audit_event_cap - success_cancel_events - \
            rejection_events - provider_attempt_events - synthetic_events
        rejection_exhaustion_transition_events = \
            bound("shared", "rejection_audit_exhaustion_transition_system_event")
        general_system_event_headroom = \
            system_event_headroom - rejection_exhaustion_transition_events
        if (bound(profile, "audit_success_cancel_events") != success_cancel_events || \
            bound(profile, "audit_rejection_partition_events") != rejection_events || \
            bound(profile, "audit_provider_attempt_events") != provider_attempt_events || \
            bound(profile, "audit_synthetic_events") != synthetic_events || \
            bound(profile, "audit_system_event_headroom") != system_event_headroom) {
            fail(profile " audit event partitions do not sum to the fixed cap")
        }
        if (bound(profile, "audit_system_general_event_headroom") != \
                general_system_event_headroom || \
            bound(profile, "audit_system_rejection_exhaustion_transition_events") != \
                rejection_exhaustion_transition_events) {
            fail(profile " system headroom must pre-reserve the rejection exhaustion transition")
        }
        audit_byte_cap = bound(profile, "audit_byte_cap")
        if (audit_byte_cap != audit_event_cap * audit_average_bytes || \
            bound(profile, "audit_rejection_partition_bytes") != \
                rejection_events * rejection_event_max_bytes || \
            bound(profile, "audit_system_byte_headroom") != \
                system_event_headroom * audit_average_bytes) {
            fail(profile " audit byte partitions do not match their event ceilings")
        }
        if (bound(profile, "audit_system_general_byte_headroom") != \
                general_system_event_headroom * audit_average_bytes || \
            bound(profile, "audit_system_rejection_exhaustion_transition_bytes") != \
                rejection_exhaustion_transition_events * audit_average_bytes || \
            bound(profile, "audit_system_general_byte_headroom") + \
                bound(profile, "audit_system_rejection_exhaustion_transition_bytes") != \
                bound(profile, "audit_system_byte_headroom")) {
            fail(profile " system bytes must pre-reserve the rejection exhaustion transition")
        }
        rejection_fixture_requests = bound(profile, "rejection_mix_fixture_requests")
        rejection_fixture_classified = bound(profile, "rejection_mix_fixture_classified_events")
        rejection_fixture_preclassification = \
            bound(profile, "rejection_mix_fixture_preclassification_503_requests")
        rejection_fixture_response_bytes = \
            rejection_fixture_classified * \
                bound("shared", "rejection_audit_classified_response_bytes") + \
            rejection_fixture_preclassification * \
                bound("shared", "rejection_audit_exhaustion_response_bytes")
        if (rejection_fixture_requests != generated_api_requests || \
            rejection_fixture_classified != rejection_events || \
            rejection_fixture_preclassification != \
                rejection_fixture_requests - rejection_fixture_classified || \
            bound(profile, "rejection_mix_fixture_response_bytes") != \
                rejection_fixture_response_bytes || \
            bound(profile, "rejection_mix_fixture_dropped_required_events") != 0) {
            fail(profile " full rejection-mix fixture must fail closed without audit loss")
        }
        compact_non_audit_records = bound(profile, "compact_non_audit_records_month")
        expected_compact_non_audit_records = \
            profile == "small" ? 10056268 : 49897468
        if (compact_non_audit_records != expected_compact_non_audit_records) {
            fail(profile " compact non-audit record workload differs from the fixed schedule")
        }
        request_rate = bound(profile, "api_requests_per_second")
        rejection_database_rate = \
            bound(profile, "rejection_audit_database_load_requests_per_second")
        database_storage = input(profile, "database_storage")
        database_gp3_iops = bound(profile, "database_gp3_included_iops")
        database_gp3_throughput = \
            bound(profile, "database_gp3_included_throughput_mib_per_second")
        expected_database_gp3_iops = database_storage < 400 ? 3000 : 12000
        expected_database_gp3_throughput = database_storage < 400 ? 125 : 500
        if (rejection_database_rate != request_rate || \
            database_gp3_iops != expected_database_gp3_iops || \
            database_gp3_throughput != expected_database_gp3_throughput) {
            fail(profile " rejection database load must use the edge rate and included gp3 baseline")
        }
        daily_generated_api_requests = generated_api_requests / 31
        daily_complete_request_cycles = int(daily_generated_api_requests / 100)
        expected_authorized_release_requests = daily_generated_api_requests - \
            daily_complete_request_cycles * 2
        reconciliation_reservations = \
            bound(profile, "rejection_audit_reconciliation_fixture_uncertain_reservations")
        reconciliation_rate = \
            bound(profile, "rejection_audit_reconciliation_requests_per_second")
        if (daily_generated_api_requests != int(daily_generated_api_requests) || \
            bound(profile, "rejection_audit_authorized_release_fixture_requests") != \
                expected_authorized_release_requests || \
            reconciliation_reservations != rejection_events || \
            reconciliation_rate != request_rate || \
            bound(profile, "rejection_audit_reconciliation_duration_seconds") != \
                ceil(reconciliation_reservations / reconciliation_rate) || \
            reconciliation_reservations % reconciliation_rate != \
                bound("shared", "rejection_audit_reconciliation_final_second_reservations")) {
            fail(profile " rejection release and reconciliation workloads must equal the exact profile schedule")
        }
        native_headers = bound(profile, "alb_native_request_header_bytes")
        accounted_headers = bound(profile, "alb_accounted_request_header_bytes")
        native_request_line = bound(profile, "alb_native_request_line_bytes")
        accounted_request_line = bound(profile, "alb_accounted_request_line_bytes")
        if (native_headers != 65536) {
            fail(profile " native ALB request-header bound must equal 65536 bytes")
        }
        if (accounted_headers != native_headers) {
            fail(profile " ALB header accounting must equal native header bound")
        }
        if (native_request_line != 16384) {
            fail(profile " native ALB request-line bound must equal 16384 bytes")
        }
        if (accounted_request_line != native_request_line) {
            fail(profile " ALB request-line accounting must equal native request-line bound")
        }
        non_header_processed = bound(profile, "alb_non_request_header_processed_bytes_hour")
        processed = non_header_processed + \
            (accounted_headers + accounted_request_line) * request_rate * 3600
        if (differs(processed, bound(profile, "alb_processed_bytes_hour"))) {
            fail(profile " ALB processed-byte cap omits native-limit request headers or request lines")
        }
        lcus = bound(profile, "alb_lcus")
        if (lcus != ceil(processed / 1000000000)) {
            fail(profile " ALB LCU bound must equal the processed-byte ceiling")
        }
        if (input(profile, "load_balancer_capacity") != lcus * 744) {
            fail(profile " ALB LCU-hour quantity is inconsistent with the operational cap")
        }

        fixed_response_base = bound(profile, "fixed_response_egress_base_bytes")
        expected_fixed_response_base = profile == "small" ? 137700000000 : 688520000000
        if (fixed_response_base != expected_fixed_response_base) {
            fail(profile " base fixed-response workload differs from the fixed schedule")
        }
        fixed_response = bound(profile, "fixed_response_egress_bytes")
        if (fixed_response != fixed_response_base + \
            (duplicate + shutdown) * bound("shared", "probe_short_response_bytes")) {
            fail(profile " fixed response envelope omits duplicate or shutdown probe responses")
        }
        response = bound(profile, "response_egress_month_bytes")
        handshake = bound(profile, "handshake_egress_month_bytes")
        provider = bound(profile, "provider_egress_month_bytes")
        internet = bound(profile, "internet_egress_month_bytes")
        expected_response = profile == "small" ? 150000000000 : 690000000000
        expected_handshake = profile == "small" ? 14000000000 : 70000000000
        expected_provider = profile == "small" ? 27880000000 : 233130000000
        if (response != expected_response) {
            fail(profile " response egress ledger must equal its documented fixed cap")
        }
        if (handshake != expected_handshake) {
            fail(profile " handshake egress ledger must equal its documented fixed cap")
        }
        if (provider != expected_provider) {
            fail(profile " provider-request egress ledger must equal its documented fixed cap")
        }
        if (fixed_response > response) {
            fail(profile " fixed response workload exceeds its durable egress ledger")
        }
        if (rejection_fixture_response_bytes > response) {
            fail(profile " full rejection-mix responses exceed the durable egress ledger")
        }
        if (response + handshake + provider > internet) {
            fail(profile " response, handshake, and provider egress exceed internet egress")
        }
        if (differs(input(profile, "internet_egress") * 1000000000, internet)) {
            fail(profile " billable internet egress row is inconsistent with the operational cap")
        }

        objects = bound(profile, "archive_objects_month")
        archive_flush_objects = ceil(744 * 3600 / archive_flush_seconds)
        audit_archive_objects = ceil(audit_event_cap / audit_records_per_object) + \
            archive_flush_objects
        compact_archive_objects = \
            ceil(compact_non_audit_records / compact_records_per_object) + \
            archive_flush_objects
        if (bound(profile, "audit_archive_objects_month") != audit_archive_objects || \
            bound(profile, "compact_non_audit_archive_objects_month") != \
                compact_archive_objects || \
            audit_archive_objects + compact_archive_objects > objects) {
            fail(profile " archive object cap omits audit compact-record or timer-flush objects")
        }
        if (input(profile, "primary_archive_requests") * 2 != objects * 3 || \
            input(profile, "recovery_archive_requests") * 2 != objects * 3) {
            fail(profile " priced archive S3 requests must reserve three tier-one calls per object across both regions")
        }
        kms_per_object = bound(profile, "archive_kms_base_requests_per_object")
        if (kms_per_object != 2) {
            fail(profile " normal archive KMS base must contain exactly two application-controlled requests per object")
        }
        kms_base = objects * kms_per_object
        kms_retry = bound(profile, "archive_kms_retry_requests")
        kms_total = bound(profile, "archive_kms_total_requests")
        if (kms_retry != kms_base / 10) {
            fail(profile " normal archive KMS retry reserve must equal 10 percent")
        }
        if (kms_total != kms_base + kms_retry) {
            fail(profile " normal archive KMS request partitions do not sum to the total")
        }
        if (input(profile, "archive_kms_requests") != kms_total) {
            fail(profile " priced archive KMS requests differ from the operational total")
        }

        validator_attempts = bound(profile, "live_archive_validator_attempts")
        validator_retries = bound(profile, "live_archive_validator_retry_attempts")
        if (validator_attempts < objects + objects / 10) {
            fail(profile " live archive validator lacks 10 percent attempt reserve")
        }
        if (validator_retries < objects / 10) {
            fail(profile " live archive validator retry partition is below 10 percent")
        }
        if (kms_retry != validator_retries * 2) {
            fail(profile " normal archive KMS retry reserve must split equally between writer and validator")
        }
        if (validator_attempts != objects + validator_retries) {
            fail(profile " live archive validator attempt partitions do not sum to the total")
        }
        if (bound(profile, "live_archive_validator_get_requests") != validator_attempts * 2) {
            fail(profile " live archive validator GET budget omits HEAD or body reads")
        }
        queue_send_retries = bound(profile, "live_archive_validator_queue_send_retry_requests")
        if (queue_send_retries != objects / 10) {
            fail(profile " source outbox send retry reserve must equal 10 percent of archive objects")
        }
        queue_send_attempts = objects + queue_send_retries
        queue_quarantine_requests = bound(profile, "live_archive_validator_queue_quarantine_requests")
        if (queue_quarantine_requests != validator_attempts) {
            fail(profile " live archive validator must reserve one quarantine send per validation attempt")
        }
        dlq_repair_jobs = bound(profile, "live_archive_validator_dlq_repair_jobs")
        if (dlq_repair_jobs != validator_retries) {
            fail(profile " live archive validator DLQ repair jobs must equal the validation retry partition")
        }
        dlq_receive_retries = bound(profile, "live_archive_validator_dlq_receive_retry_requests")
        if (dlq_receive_retries != dlq_repair_jobs / 10) {
            fail(profile " live archive validator DLQ receive retry reserve must equal 10 percent of repair jobs")
        }
        dlq_redrive_send_retries = bound(profile, "live_archive_validator_dlq_redrive_send_retry_requests")
        if (dlq_redrive_send_retries != dlq_repair_jobs / 10) {
            fail(profile " live archive validator DLQ redrive send retry reserve must equal 10 percent of repair jobs")
        }
        dlq_reconciliation_requests = bound(profile, "live_archive_validator_dlq_reconciliation_requests")
        if (dlq_reconciliation_requests != dlq_repair_jobs * 3 + \
            dlq_receive_retries + dlq_redrive_send_retries) {
            fail(profile " live archive validator must reserve repair receives sends post-send deletes and explicit retries")
        }
        queue_message_requests = bound(profile, "live_archive_validator_queue_message_requests")
        if (queue_message_requests != queue_send_attempts + validator_attempts + \
            queue_quarantine_requests + dlq_reconciliation_requests) {
            fail(profile " live archive validator queue budget omits sends, validation deletes, quarantine sends, or repair-before-delete DLQ reconciliation")
        }
        queue_poll_requests = polls_per_second * 744 * 3600
        if (bound(profile, "live_archive_validator_queue_poll_requests") != queue_poll_requests) {
            fail(profile " live archive validator queue poll budget differs from the application-enforced maximum")
        }
        queue_requests = bound(profile, "live_archive_validator_queue_requests")
        if (queue_requests != queue_message_requests + queue_poll_requests) {
            fail(profile " live archive validator queue total omits message or poll requests")
        }
        send_wire_bytes = bound("shared", "live_archive_validator_send_wire_bytes")
        if (send_wire_bytes != 8192 || differs(bound(profile, "live_archive_validator_queue_transfer_gb") * 1000000000, \
            queue_send_attempts * send_wire_bytes)) {
            fail(profile " live archive validator cross-region wire omits retry-inclusive source sends")
        }
        task_count = bound("shared", "live_archive_validator_task_count")
        task_vcpu = bound("shared", "live_archive_validator_task_vcpu")
        task_memory = bound("shared", "live_archive_validator_task_memory_gb")
        restart_hours = launches * restart_minimum_seconds / 3600
        if (differs(bound(profile, "live_archive_validator_fargate_vcpu_hours"), \
                task_count * task_vcpu * 744 + restart_hours * task_vcpu) || \
            differs(bound(profile, "live_archive_validator_fargate_memory_hours"), \
                task_count * task_memory * 744 + restart_hours * task_memory) || \
            differs(bound(profile, "live_archive_validator_public_ipv4_hours"), \
                task_count * 744 + restart_hours)) {
            fail(profile " live archive validator compute or address hours omit bounded replacement launches")
        }
        attempt_seconds = bound("shared", "live_archive_validator_attempt_seconds")
        receive_cycle_seconds = \
            bound("shared", "live_archive_validator_max_inter_poll_seconds") + \
            bound("shared", "live_archive_validator_receive_response_seconds") + \
            attempt_seconds
        object_rate = bound(profile, "archive_objects_per_minute")
        expected_object_rate = profile == "small" ? 1 : 4
        if (object_rate * 1.1 >= receive_loop_count * 60 / receive_cycle_seconds) {
            fail(profile " archive object admission rate exhausts worst-case receive-cycle capacity")
        }
        if (objects > object_rate * 744 * 60) {
            fail(profile " monthly archive object cap exceeds its minute admission ceiling")
        }
        if (object_rate != expected_object_rate) {
            fail(profile " archive object admission rate must equal its fixed integer envelope")
        }
        state_reads = bound(profile, "live_archive_validator_state_read_units")
        state_writes = bound(profile, "live_archive_validator_state_write_units")
        reservation_lease_condition_reads = bound(profile, "live_archive_validator_reservation_lease_condition_read_units")
        reservation_lease_condition_writes = bound(profile, "live_archive_validator_reservation_lease_condition_write_units")
        final_lease_condition_reads = bound(profile, "live_archive_validator_final_lease_condition_read_units")
        final_lease_condition_writes = bound(profile, "live_archive_validator_final_lease_condition_write_units")
        if (reservation_lease_condition_reads != validator_attempts * 2 || \
            reservation_lease_condition_writes != validator_attempts * 2) {
            fail(profile " live archive validator pre-HEAD reservation must reserve transactional lease-condition capacity")
        }
        if (final_lease_condition_reads != validator_attempts * 2 || \
            final_lease_condition_writes != validator_attempts * 2) {
            fail(profile " live archive validator final commit must reserve transactional lease-condition capacity")
        }
        receipt_cleanup_writes = bound(profile, "live_archive_validator_receipt_cleanup_writes")
        if (receipt_cleanup_writes != objects * 2) {
            fail(profile " live archive validator receipt cleanup must reserve two boundary-concentrated expiry envelopes")
        }
        launch_guard_writes = bound(profile, "live_archive_validator_launch_guard_write_units")
        launch_item_write_units = ceil(launch_ledger_item_bytes / 1024)
        if (launch_guard_writes != total_probe_attempts * launch_item_write_units) {
            fail(profile " live archive validator launch guard must price every probe invocation")
        }
        launch_result_writes = bound(profile, "live_archive_validator_launch_result_write_units")
        if (launch_result_writes != launches * launch_item_write_units) {
            fail(profile " live archive validator must price task-ARN persistence for every launch")
        }
        heartbeat_reads = 744 * 3600 / bound("shared", "live_archive_validator_heartbeat_read_seconds")
        lease_writes = task_count * 744 * 3600 / bound("shared", "live_archive_validator_lease_renew_seconds")
        if (state_reads != validator_attempts + reservation_lease_condition_reads + \
            final_lease_condition_reads + heartbeat_reads || \
            state_writes != validator_attempts * 8 + reservation_lease_condition_writes + \
            final_lease_condition_writes + \
            launch_guard_writes + launch_result_writes + lease_writes + receipt_cleanup_writes) {
            fail(profile " live archive validator state units omit receipt, heartbeat, transaction, launch, lease, or cleanup operations")
        }
        retained_receipts = objects * 13
        cleanup_overlap_receipts = objects * 2 / 31
        state_storage_bytes = bound(profile, "live_archive_validator_state_storage_gb") * 1000000000
        if (state_storage_bytes < \
            (retained_receipts + cleanup_overlap_receipts) * receipt_storage_envelope_bytes) {
            fail(profile " live archive validator state storage omits retained receipts or cleanup overlap")
        }
        max_object_bytes = bound("shared", "live_archive_validator_max_object_bytes")
        if (max_object_bytes != 8388608) {
            fail("live archive validator maximum object size must equal 8 MiB")
        }
        if (audit_records_per_object * audit_event_max_bytes + audit_reserved_bytes != \
                max_object_bytes || \
            compact_records_per_object * compact_record_max_bytes + \
                audit_reserved_bytes > max_object_bytes) {
            fail(profile " archive packing must fit maximum-size records and reserved framing")
        }
        archive_ingress_gb = bound(profile, "archive_ingress_gb")
        expected_archive_ingress_gb = profile == "small" ? 16 : 80
        if (archive_ingress_gb != expected_archive_ingress_gb) {
            fail(profile " archive ingress must equal its fixed storage and transfer envelope")
        }
        if (input(profile, "object_archive") != archive_ingress_gb * 13 || \
            input(profile, "recovery_object_archive") != archive_ingress_gb * 13 || \
            input(profile, "normal_recovery_object_transfer") != archive_ingress_gb) {
            fail(profile " archive storage or normal replication transfer differs from ingress")
        }
        if (audit_byte_cap + compact_non_audit_records * compact_average_bytes > \
            archive_ingress_gb * 1000000000) {
            fail(profile " audit and compact-record bytes exceed archive ingress")
        }
        archive_retained_data_versions = objects * 13
        archive_physical_entries = archive_retained_data_versions + \
            archive_overlap_envelopes * objects
        archive_eligible_entries = 2 * archive_overlap_envelopes * objects
        archive_object_lock_read_requests = \
            2 * archive_overlap_envelopes * objects
        archive_list_requests = archive_eligible_entries + archive_overlap_envelopes
        archive_marker_storage_gb = \
            ceil(archive_overlap_envelopes * objects * archive_marker_key_bytes / 10000000) / 100
        if (bound(profile, "archive_retained_data_versions_region") != \
                archive_retained_data_versions || \
            bound(profile, "archive_physical_entries_region") != \
                archive_physical_entries) {
            fail(profile " archive physical entries must include retained data and both adjacent marker cohorts")
        }
        if (bound(profile, "archive_retention_list_requests_region") != \
                archive_list_requests || \
            bound(profile, "archive_retention_delete_entries_region") != \
                archive_eligible_entries) {
            fail(profile " archive cleanup must list and delete both eligible data and marker cohorts")
        }
        if (bound(profile, "archive_retention_object_lock_read_requests_region") != \
            archive_object_lock_read_requests) {
            fail(profile " archive cleanup must read retention and legal hold for every eligible data version")
        }
        if (differs(bound(profile, "archive_delete_marker_storage_gb"), \
            archive_marker_storage_gb)) {
            fail(profile " archive marker storage must price both adjacent maximum-key cohorts")
        }
        if (input(profile, "archive_lifecycle_list_requests") != archive_list_requests || \
            input(profile, "recovery_archive_lifecycle_list_requests") != \
                archive_list_requests || \
            input(profile, "archive_lifecycle_object_lock_read_requests") != \
                archive_object_lock_read_requests || \
            input(profile, "recovery_archive_lifecycle_object_lock_read_requests") != \
                archive_object_lock_read_requests || \
            differs(input(profile, "archive_delete_marker_overlap"), \
                archive_marker_storage_gb) || \
            differs(input(profile, "recovery_archive_delete_marker_overlap"), \
                archive_marker_storage_gb)) {
            fail(profile " archive lifecycle cost rows differ from the physical-entry contract")
        }

        manifest_source_objects = input(profile, "full_reseed_generated_manifest_scan")
        manifest_data_objects = bound(profile, "full_reseed_manifest_data_objects")
        manifest_objects = manifest_data_objects + manifest_control_objects
        manifest_write_requests = bound(profile, "full_reseed_manifest_write_requests")
        manifest_validation_read_requests = \
            bound(profile, "full_reseed_manifest_validation_read_requests")
        manifest_consumption_read_requests = \
            bound(profile, "full_reseed_manifest_consumption_read_requests")
        manifest_read_requests = bound(profile, "full_reseed_manifest_read_requests")
        manifest_cleanup_list_requests = \
            ceil(manifest_objects / manifest_list_page_size) + 1
        manifest_cleanup_delete_requests = \
            ceil(manifest_objects / manifest_delete_batch_size)
        manifest_storage_gb = \
            ceil(manifest_aggregate_bytes / 1000000000 / 31 * 100) / 100
        if (manifest_source_objects != archive_retained_data_versions || \
            manifest_data_objects != manifest_source_objects || \
            bound(profile, "full_reseed_manifest_objects") != manifest_objects) {
            fail(profile " generated manifest set must reserve one data object per scanned source plus three controls")
        }
        if (manifest_write_requests != manifest_objects || \
            manifest_validation_read_requests != manifest_objects || \
            manifest_consumption_read_requests != manifest_objects || \
            manifest_read_requests != 2 * manifest_objects || \
            bound(profile, "full_reseed_manifest_cleanup_list_requests") != \
                manifest_cleanup_list_requests || \
            bound(profile, "full_reseed_manifest_cleanup_delete_requests") != \
                manifest_cleanup_delete_requests) {
            fail(profile " generated manifest requests must cover separate validation and consumption reads plus empty proof")
        }
        if (differs(bound(profile, "full_reseed_manifest_storage_gb"), \
            manifest_storage_gb)) {
            fail(profile " generated manifest storage must price eight GiB for one day")
        }
        if (input(profile, "full_reseed_manifest_write") != manifest_write_requests || \
            input(profile, "full_reseed_manifest_validation_read") != \
                manifest_validation_read_requests || \
            input(profile, "full_reseed_manifest_consumption_read") != \
                manifest_consumption_read_requests || \
            input(profile, "full_reseed_manifest_cleanup_list_requests") != \
                manifest_cleanup_list_requests || \
            differs(input(profile, "full_reseed_manifest_storage"), \
                manifest_storage_gb)) {
            fail(profile " generated manifest cost rows differ from the bounded object-set contract")
        }
        validator_read_bytes = archive_ingress_gb * 1000000000 + \
            validator_retries * max_object_bytes
        if (differs(bound(profile, "live_archive_validator_read_gb") * 1000000000, \
            validator_read_bytes)) {
            fail(profile " live archive validator read budget must reserve every retry at maximum object size")
        }
        log_gb = bound(profile, "live_archive_validator_log_gb")
        log_storage_gb = bound(profile, "live_archive_validator_log_storage_gb")
        if (differs(log_gb, validator_attempts * 0.00002 + 0.01) || \
            differs(log_storage_gb, log_gb * 2)) {
            fail(profile " live archive validator log ingestion or boundary-overlap storage is under-reserved")
        }
        if (input(profile, "live_archive_validator_get_requests") != bound(profile, "live_archive_validator_get_requests") || \
            differs(input(profile, "live_archive_validator_queue_requests") * 1000000, queue_requests) || \
            input(profile, "live_archive_validator_fargate_vcpu") != bound(profile, "live_archive_validator_fargate_vcpu_hours") || \
            input(profile, "live_archive_validator_fargate_memory") != bound(profile, "live_archive_validator_fargate_memory_hours") || \
            input(profile, "live_archive_validator_public_ipv4") != bound(profile, "live_archive_validator_public_ipv4_hours") || \
            input(profile, "live_archive_validator_state_reads") != state_reads || \
            input(profile, "live_archive_validator_state_writes") != state_writes || \
            input(profile, "live_archive_validator_state_storage") != bound(profile, "live_archive_validator_state_storage_gb") || \
            differs(input(profile, "live_archive_validator_queue_transfer"), bound(profile, "live_archive_validator_queue_transfer_gb")) || \
            input(profile, "live_archive_validator_log_ingestion") != log_gb || \
            input(profile, "live_archive_validator_log_storage") != log_storage_gb) {
            fail(profile " live archive validator cost rows differ from the operational contract")
        }

        if (input(profile, "external_synthetic_schedule_invocations") != total_probe_attempts || \
            input(profile, "external_synthetic_lambda_requests") != total_probe_attempts) {
            fail(profile " probe request rows omit intended, duplicate, or shutdown attempts")
        }
        if (input(profile, "external_synthetic_lambda_duration") != \
            total_probe_attempts * bound("shared", "probe_timeout_seconds")) {
            fail(profile " probe duration row is inconsistent with the hard timeout")
        }
        probe_artifact_storage_gb = probe_artifact_current_versions_max * \
            bound("shared", "probe_artifact_encoded_bytes") / 1000000000
        probe_artifact_marker_storage_gb = probe_artifact_cleanup_versions * \
            bound("shared", "probe_artifact_key_bytes") / 1000000000
        if (input(profile, "external_synthetic_artifact_requests") != intended || \
            differs(input(profile, "external_synthetic_artifact_storage"), \
                probe_artifact_storage_gb) || \
            differs(input(profile, "external_synthetic_artifact_marker_storage"), \
                probe_artifact_marker_storage_gb) || \
            input(profile, "external_synthetic_artifact_cleanup_list_requests") != \
                probe_artifact_cleanup_list_requests) {
            fail(profile " probe artifact cost rows differ from the versioned cleanup contract")
        }
    }

    if (bound("shared", "live_archive_validator_queue_delay_seconds") != 300) {
        fail("validator queue delay must equal 300 seconds")
    }
    if (bound("shared", "managed_crr_stage_seconds") != 300) {
        fail("managed-CRR stage must equal 300 seconds")
    }
    if (bound("shared", "live_archive_validator_queue_delay_seconds") != \
        bound("shared", "managed_crr_stage_seconds")) {
        fail("validator queue delay must start after and equal the managed-CRR stage")
    }
    receive_cycles = bound("shared", "live_archive_validator_receive_cycles")
    queued_predecessors = bound("shared", "live_archive_validator_queued_predecessors")
    same_stream_burst = bound("shared", "live_archive_validator_same_stream_burst_objects")
    if (queued_predecessors != int(queued_predecessors) || \
        receive_cycles != int(receive_cycles) || \
        same_stream_burst != int(same_stream_burst)) {
        fail("validator predecessor, receive-cycle, and burst bounds must be integers")
    }
    if (queued_predecessors != \
        bound("target", "archive_objects_per_minute") - 1) {
        fail("validator queued-predecessor budget must cover the target same-stream burst")
    }
    if (receive_cycles != queued_predecessors + 1) {
        fail("validator receive-cycle budget must cover every split same-stream delivery")
    }
    outbox_dispatch_seconds = bound("shared", "live_archive_validator_outbox_dispatch_seconds")
    if (outbox_dispatch_seconds != 60) {
        fail("validator ordered outbox dispatch budget must equal 60 seconds")
    }
    if (bound("shared", "live_archive_validator_attempt_seconds") != 2) {
        fail("validator attempt budget must equal 2 seconds")
    }
    per_stream_min_interval = bound("shared", "live_archive_validator_per_stream_min_interval_seconds")
    if (per_stream_min_interval <= outbox_dispatch_seconds) {
        fail("validator per-stream admission interval must exceed ordered outbox dispatch time")
    }
    if (same_stream_burst != queued_predecessors + 1) {
        fail("validator same-stream burst must equal the modeled predecessor envelope")
    }
    if (bound("shared", "live_archive_validator_same_stream_burst_blocks_refill") != 1) {
        fail("validator same-stream burst must block refill until acknowledged and checkpointed")
    }
    source_to_complete = \
        (queued_predecessors + 1) * \
            outbox_dispatch_seconds + \
        bound("shared", "live_archive_validator_queue_delay_seconds") + \
        receive_cycles * ( \
            bound("shared", "live_archive_validator_max_inter_poll_seconds") + \
            bound("shared", "live_archive_validator_receive_response_seconds") + \
            bound("shared", "live_archive_validator_attempt_seconds"))
    if (source_to_complete > 636) {
        fail("validator source-to-completion timing budget exceeds 636 seconds")
    }
    if (source_to_complete != bound("shared", "live_archive_validator_source_to_complete_seconds")) {
        fail("validator source-to-completion timing budget is inconsistent")
    }

    if (error_count > 0) {
        exit 1
    }
    printf "veer-operational-bounds status=passed profiles=2 detection_seconds=%d\n", detection_seconds
}
