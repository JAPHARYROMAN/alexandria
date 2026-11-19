#!/usr/bin/env bash
# Run from platform/. Intended for an isolated Linux CI runner.
set -euo pipefail
work=$(mktemp -d)
origin_pid=""
a_pid=""
b_pid=""
cleanup() {
  for pid in "$origin_pid" "$a_pid" "$b_pid"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
  rm -rf -- "$work"
}
trap cleanup EXIT
exe="$work/repo"
go build -o "$exe" ./cmd/alexandria-repo
openssl genpkey -algorithm Ed25519 -out "$work/key"
openssl pkey -in "$work/key" -pubout -out "$work/pub"
origin=http://127.0.0.1:18700
node_a=http://127.0.0.1:18701
node_b=http://127.0.0.1:18702
publish() { "$exe" publish -store "$work/catalogue" -signing-key "$work/key" "$@"; }
start_a() { "$exe" node -store "$work/a" -public-key "$work/pub" -upstream "$origin/v1/head" -listen 127.0.0.1:18701 & a_pid=$!; }
wait_status() {
  local code
  for _ in {1..50}; do
    code=$(curl -s --max-time 2 -o "$work/body" -w '%{http_code}' "$1") || code=000
    if [[ "$code" == "$2" ]]; then return; fi
    sleep 0.1
  done
  echo "Expected $2 from $1, received $code" >&2
  return 1
}
publish
"$exe" origin -store "$work/catalogue" -public-key "$work/pub" -listen 127.0.0.1:18700 & origin_pid=$!
start_a
"$exe" node -store "$work/b" -public-key "$work/pub" -upstream "$origin/v1/head" -listen 127.0.0.1:18702 & b_pid=$!
wait_status "$node_a/v1/records/moon-identity" 200
version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$work/body")
citation="/v1/records/moon-identity/versions/$version/lines/1"
wait_status "$node_a$citation" 200
cp "$work/body" "$work/expected"
kill "$a_pid"; wait "$a_pid" || true; a_pid=""
wait_status "$node_b$citation" 200
cmp "$work/expected" "$work/body"
publish -withdraw moon-identity
wait_status "$node_b$citation" 410
start_a
wait_status "$node_a$citation" 410
wait_status "$node_a/v1/records/sky-log" 404
echo "Two readers served the same citation; withdrawal enforced on the surviving and returning reader."
