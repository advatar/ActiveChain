#!/usr/bin/env bash
set -euo pipefail

fragment="${1:?usage: install-caddy-fragment.sh <fragment>}"
caddy_dir="${ACTIVECHAIN_CADDY_DIR:-$HOME/providehr}"
caddyfile="${ACTIVECHAIN_CADDYFILE:-$caddy_dir/Caddyfile}"
docker_bin="${ACTIVECHAIN_DOCKER:-docker}"
docker_context="${ACTIVECHAIN_DOCKER_CONTEXT:-colima-coolify}"
begin='# BEGIN activechain-kanalen'
end='# END activechain-kanalen'
temporary=''
backup="$caddyfile.activechain-backup"
installed=false

cleanup() {
  status=$?
  if [[ -n "$temporary" && -e "$temporary" ]]; then
    rm -f "$temporary"
  fi
  if (( status != 0 )) && [[ "$installed" == true && -f "$backup" ]]; then
    cp -p "$backup" "$caddyfile"
    "$docker_bin" --context "$docker_context" compose --project-directory "$caddy_dir" \
      --profile standalone-caddy up -d --no-deps --pull never --force-recreate caddy \
      >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT

for input in "$fragment" "$caddyfile"; do
  if [[ -L "$input" || ! -f "$input" ]]; then
    echo "Caddy input must be a regular, non-symlink file: $input" >&2
    exit 1
  fi
done
if [[ "$(grep -Fxc "$begin" "$fragment")" -ne 1 ||
  "$(grep -Fxc "$end" "$fragment")" -ne 1 ]]; then
  echo "Caddy fragment must contain exactly one managed marker pair" >&2
  exit 1
fi

temporary="$(mktemp "$(dirname "$caddyfile")/.Caddyfile.activechain.XXXXXX")"
awk -v begin="$begin" -v end="$end" '
  FNR == NR { fragment = fragment $0 ORS; next }
  $0 == begin { if (inside || seen) exit 20; inside = 1; seen = 1; next }
  $0 == end { if (!inside) exit 21; inside = 0; next }
  !inside { print }
  END {
    if (inside) exit 22
    if (NR > 0) print ""
    printf "%s", fragment
  }
' "$fragment" "$caddyfile" >"$temporary"

cp -p "$caddyfile" "$backup"
chmod "$(stat -f '%Lp' "$caddyfile")" "$temporary"
mv "$temporary" "$caddyfile"
temporary=''
installed=true

"$docker_bin" --context "$docker_context" compose --project-directory "$caddy_dir" \
  --profile standalone-caddy run --rm --no-deps --entrypoint caddy caddy \
  validate --config /etc/caddy/Caddyfile >/dev/null
"$docker_bin" --context "$docker_context" compose --project-directory "$caddy_dir" \
  --profile standalone-caddy up -d --no-deps --pull never --force-recreate caddy >/dev/null

trap - EXIT
echo "installed managed Kanalen Caddy fragment"
