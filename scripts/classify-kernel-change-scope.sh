#!/usr/bin/env bash
set -euo pipefail

full=${1:?usage: classify-kernel-change-scope.sh true-or-false}
if [[ "$full" != true && "$full" != false ]]; then
  echo "qualification scope must be true or false" >&2
  exit 1
fi
changed=$(cat)

source='^(Cargo\.(toml|lock)|rust-toolchain.*|crates/|tools/|examples/|scripts/.*\.(rs|sh|py)|\.cargo/)'
protocol='^(Cargo\.(toml|lock)|crates/|formal/|testing/|scripts/check-(proof|formal|kani|type-tag|independent-client))'
distribution='^(Cargo\.(toml|lock)|crates/(verifier|wallet|apple|protocol|canonical)|distribution/apple/|scripts/(build|check)-apple|tools/apple-distribution/)'
runtime='^(Cargo\.(toml|lock)|crates/(consensus|validator|rpc|cash|storage|testnet|application)|deploy/|scripts/(rehearse|test-kanalen|test-qualify-kanalen))'
vectors='^(Cargo\.(toml|lock)|crates/(vector|semantic|application|protocol|canonical)|formal/lean/|testing/vectors/)'
ci_core='^\.github/(workflows/kernel.yml|actions/kernel-setup/)'

matches() {
  local expression=$1
  [[ "$full" == true ]] || grep -Eq "$expression" <<<"$changed"
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
matches "$distribution|$ci_core" && emit apple true || emit apple false
matches "$runtime|$ci_core" && emit runtime true || emit runtime false
matches "$vectors|$ci_core" && emit vectors true || emit vectors false
