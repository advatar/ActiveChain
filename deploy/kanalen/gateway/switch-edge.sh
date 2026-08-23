#!/usr/bin/env bash
set -euo pipefail

gateway_dir=${1:-"$HOME/activechain-deploy/kanalen/gateway"}
existing_dir=${2:-"$HOME/providehr"}
docker_bin=${ACTIVECHAIN_DOCKER:-docker}
docker_context=${ACTIVECHAIN_DOCKER_CONTEXT:-colima-coolify}
existing_compose="$existing_dir/compose.yml"
backup="$existing_compose.activechain-backup.$(date -u +%Y%m%dT%H%M%SZ)"
switched=false

rollback() {
  status=$?
  if (( status != 0 )) && [[ "$switched" == true ]]; then
    "$docker_bin" --context "$docker_context" compose -f "$gateway_dir/compose.yml" \
      down >/dev/null 2>&1 || true
    cp "$backup" "$existing_compose"
    "$docker_bin" --context "$docker_context" compose --project-directory "$existing_dir" \
      --profile standalone-caddy up -d --no-deps --pull never caddy >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap rollback EXIT

if ! grep -q -- '- "443:443"' "$existing_compose"; then
  if grep -q -- '- "8443:443"' "$existing_compose"; then
    echo "existing Caddy is already assigned to rollback port 8443"
  else
    echo "expected existing Caddy 443:443 mapping was not found" >&2
    exit 1
  fi
else
  cp "$existing_compose" "$backup"
  perl -0pi -e 's/- "443:443"/- "8443:443"/' "$existing_compose"
  switched=true
fi

"$docker_bin" --context "$docker_context" compose --project-directory "$existing_dir" \
  --profile standalone-caddy config >/dev/null
"$docker_bin" --context "$docker_context" compose --project-directory "$existing_dir" \
  --profile standalone-caddy up -d --no-deps --pull never caddy

"$docker_bin" --context "$docker_context" compose -f "$gateway_dir/compose.yml" config >/dev/null
"$docker_bin" --context "$docker_context" compose -f "$gateway_dir/compose.yml" up -d --pull never
"$docker_bin" --context "$docker_context" compose -f "$gateway_dir/compose.yml" ps

trap - EXIT
echo "edge switch completed; rollback backup: $backup"
