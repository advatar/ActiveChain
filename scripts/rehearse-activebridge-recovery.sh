#!/usr/bin/env bash
set -euo pipefail

run_exact() {
  local package="$1"
  local test_name="$2"
  cargo test --offline -p "$package" "$test_name" -- --exact --test-threads=1
}

run_exact activechain-payment-connector-ntzs \
  attempt::tests::exact_prepare_is_idempotent_but_changed_request_conflicts
run_exact activechain-payment-connector-ntzs \
  attempt::tests::dispatch_boundary_survives_restart_and_forces_reconciliation

run_exact activechain-payment-connector-host \
  tests::intent_binding_and_created_lifecycle_persist_atomically_and_retry_exactly
run_exact activechain-payment-connector-host \
  tests::joined_lifecycle_advance_survives_restart_and_replay_fails_closed
run_exact activechain-payment-connector-host \
  tests::settlement_state_persists_full_evidence_request_and_refund_accounting_together
run_exact activechain-payment-connector-host \
  tests::atomic_refund_rejects_substitution_over_refund_and_failed_write
run_exact activechain-payment-connector-host \
  tests::atomic_dispute_state_survives_restart_and_exact_successor
run_exact activechain-payment-connector-host \
  tests::atomic_treasury_failed_write_does_not_advance_budget_or_nonce
run_exact activechain-payment-connector-host \
  tests::atomic_api_failed_write_does_not_consume_authorization
run_exact activechain-payment-connector-host \
  tests::atomic_webhook_cursor_requires_retained_intent_and_survives_restart
run_exact activechain-payment-connector-host \
  tests::bounded_multi_intent_restart_soak_preserves_complete_aggregate
run_exact activechain-payment-connector-host \
  tests::atomic_fee_sponsorship_failed_write_does_not_charge_sponsor
run_exact activechain-payment-connector-host \
  tests::finalized_refund_requires_complete_accounting_and_survives_restart

echo '{"schema":"activechain-activebridge-recovery-drill-v1","scenarios":13,"result":"passed"}'
