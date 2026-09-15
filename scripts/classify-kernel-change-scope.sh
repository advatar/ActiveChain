#!/usr/bin/env bash
set -euo pipefail

full=${1:?usage: classify-kernel-change-scope.sh true-or-false}
if [[ "$full" != true && "$full" != false ]]; then
  echo "qualification scope must be true or false" >&2
  exit 1
fi
changed=$(cat)
kernel_changed=$(printf '%s\n' "$changed" |
  grep -Ev '^(AGENTS\.md$|STATUS\.md$|\.github/workflows/kernel\.yml$|mobile/ios/|vendor/AnyIdentity/|scripts/(build-anyidentity\.sh|finalize-anyidentity-archive\.sh|check-ios-wallet-archive\.py|classify-kernel-change-scope\.sh|check-kernel-workflow-policy\.py|test_check_kernel_workflow_policy\.py)$)' || true)

source='^(Cargo\.(toml|lock)|rust-toolchain.*|crates/|tools/|examples/|scripts/.*\.(rs|sh|py)|\.cargo/)'
protocol='^(Cargo\.(toml|lock)|crates/|formal/|testing/|scripts/check-(proof|formal|kani|type-tag|independent-client))'
distribution='^(Cargo\.(toml|lock)|crates/(verifier|wallet|apple|protocol|canonical)|distribution/apple/|mobile/ios/|vendor/AnyIdentity/|scripts/(build|check)-apple|scripts/(build-anyidentity|finalize-anyidentity-archive|check-ios-wallet-archive)|tools/apple-distribution/)'
runtime='^(Cargo\.(toml|lock)|crates/(consensus|validator|rpc|cash|storage|testnet|application)|deploy/|scripts/(rehearse|test-kanalen|test-qualify-kanalen|test_probe_kanalen))'
vectors='^(Cargo\.(toml|lock)|crates/(vector|semantic|application|protocol|canonical)|formal/lean/|testing/vectors/)'
ci_core='^\.github/actions/kernel-setup/'

matches() {
  local expression=$1
  [[ "$full" == true ]] || grep -Eq "$expression" <<<"$kernel_changed"
}
matches_distribution() {
  [[ "$full" == true ]] || grep -Eq "$distribution|$ci_core" <<<"$changed"
}
emit() {
  local name=$1
  local value=$2
  printf '%s=%s\n' "$name" "$value"
}

emit full "$full"
matches "$source|$ci_core" && emit static true || emit static false
matches "$protocol|$ci_core" && emit formal true || emit formal false
matches "$protocol|$ci_core" && emit kani true || emit kani false
matches "$source|$ci_core" && emit tests true || emit tests false
matches_distribution && emit apple true || emit apple false
matches "$runtime|$ci_core" && emit runtime true || emit runtime false
matches "$vectors|$ci_core" && emit vectors true || emit vectors false
