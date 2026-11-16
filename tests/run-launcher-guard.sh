#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
tmp_dir="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

# run.sh по умолчанию зовёт node по прод-пути VPS; в тесте — тот node, что есть в PATH.
node_bin="$(command -v node)" || { echo "FAIL: node не найден в PATH"; exit 1; }

prepare_case() {
  local name="$1" case_dir="$tmp_dir/$1"
  mkdir -p "$case_dir/.next/standalone"
  cp "$repo_dir/run.sh" "$case_dir/run.sh"
  printf '%s\n' '// sentinel: valid launcher configuration reaches Node and exits 0' \
    > "$case_dir/.next/standalone/server.js"
  cat > "$case_dir/.env" <<'ENV'
JWT_SECRET='jwt-test'
CLERK_SECRET_KEY='clerk-test'
VPS_SSO_DB_URL='postgres://test.invalid/vps_sso'
COOKIE_DOMAIN='example.test'
SSO_HOST='sso.example.test'
ALLOWED_REDIRECT_HOSTS='example.test,reader.example.test'
SSO_ACCESS='{"user@example.test":["reader.example.test"]}'
SSO_INTERNAL_SECRETS='{"reader.example.test":"internal-test"}'
ENV
}

invoke() {
  local case_dir="$1"
  shift
  set +e
  output="$(
    env -i \
      HOME="$tmp_dir" \
      PATH="$PATH" \
      SSO_NODE_BIN="$node_bin" \
      "$@" \
      timeout 20 bash "$case_dir/run.sh" 2>&1
  )"
  rc=$?
  set -e
}

expect_failure() {
  local label="$1" expected="$2"
  if [ "$rc" -eq 0 ]; then
    echo "FAIL: $label unexpectedly reached Node"
    exit 1
  fi
  if ! grep -q "$expected" <<<"$output"; then
    echo "FAIL: $label failed for an unrelated reason"
    printf '%s\n' "$output"
    exit 1
  fi
}

required=(
  JWT_SECRET
  CLERK_SECRET_KEY
  VPS_SSO_DB_URL
  COOKIE_DOMAIN
  SSO_HOST
  ALLOWED_REDIRECT_HOSTS
)
for name in "${required[@]}"; do
  case_name="missing-$name"
  prepare_case "$case_name"
  grep -v "^${name}=" "$tmp_dir/$case_name/.env" > "$tmp_dir/$case_name/.env.new"
  mv "$tmp_dir/$case_name/.env.new" "$tmp_dir/$case_name/.env"
  invoke "$tmp_dir/$case_name"
  expect_failure "$case_name" "$name missing"
done

for name in SSO_ACCESS SSO_INTERNAL_SECRETS; do
  case_name="missing-$name"
  prepare_case "$case_name"
  grep -v "^${name}=" "$tmp_dir/$case_name/.env" > "$tmp_dir/$case_name/.env.new"
  mv "$tmp_dir/$case_name/.env.new" "$tmp_dir/$case_name/.env"
  invoke "$tmp_dir/$case_name"
  expect_failure "$case_name" "$name"
done

declare -A bad_redirects=(
  [redirect-trailing-comma]='example.test,'
  [redirect-double-comma]='example.test,,reader.example.test'
)
for case_name in "${!bad_redirects[@]}"; do
  prepare_case "$case_name"
  printf "ALLOWED_REDIRECT_HOSTS='%s'\n" "${bad_redirects[$case_name]}" >> "$tmp_dir/$case_name/.env"
  invoke "$tmp_dir/$case_name"
  expect_failure "$case_name" "ALLOWED_REDIRECT_HOSTS contains an empty host"
done

declare -A invalid_values=(
  [access-empty]="SSO_ACCESS='{}'"
  [access-malformed]="SSO_ACCESS='{not-json'"
  [access-wrong-shape]="SSO_ACCESS='{\"user@example.test\":[]}'"
  [internal-empty]="SSO_INTERNAL_SECRETS='{}'"
  [internal-malformed]="SSO_INTERNAL_SECRETS='{not-json'"
  [internal-wrong-shape]="SSO_INTERNAL_SECRETS='{\"reader.example.test\":\"\"}'"
)
for case_name in "${!invalid_values[@]}"; do
  prepare_case "$case_name"
  printf '%s\n' "${invalid_values[$case_name]}" >> "$tmp_dir/$case_name/.env"
  invoke "$tmp_dir/$case_name"
  if [[ "$case_name" == access-* ]]; then
    expect_failure "$case_name" "SSO_ACCESS"
  else
    expect_failure "$case_name" "SSO_INTERNAL_SECRETS"
  fi
done

prepare_case valid-fallback
invoke "$tmp_dir/valid-fallback"
if [ "$rc" -ne 0 ]; then
  echo "FAIL: valid fallback configuration did not reach Node"
  printf '%s\n' "$output"
  exit 1
fi

# Нет node по заданному пути — явный отказ лаунчера, а не «No such file» от exec.
prepare_case missing-node
set +e
output="$(env -i HOME="$tmp_dir" PATH="$PATH" SSO_NODE_BIN="$tmp_dir/no-such-node" \
  timeout 20 bash "$tmp_dir/missing-node/run.sh" 2>&1)"
rc=$?
set -e
expect_failure missing-node "FATAL: node не найден"

fake_bin="$tmp_dir/fake-bin"
credentials="$tmp_dir/credentials"
mkdir -p "$fake_bin" "$credentials"
printf '%s\n' 'test-token' > "$credentials/secgw-token"
cat > "$fake_bin/curl" <<'CURL'
#!/usr/bin/env bash
set -euo pipefail
url="${!#}"
if [[ "$url" == */health ]]; then
  kind=secrets
  fails="${FAKE_SECRET_FAILS:-0}"
  if [[ "$url" == *config.test* ]]; then
    kind=config
    fails="${FAKE_CONFIG_FAILS:-0}"
  fi
  state="$FAKE_CURL_STATE.$kind"
  count=0
  [ ! -f "$state" ] || count="$(cat "$state")"
  count=$((count + 1))
  printf '%s\n' "$count" > "$state"
  [ "$count" -gt "$fails" ]
  exit
fi
if [[ "$url" == */secrets/CONFIG_STORE_TOKEN_VPS_SSO ]] && [ "${FAKE_CONFIG_TOKEN:-0}" -eq 1 ]; then
  printf '%s\n' '{"value":"config-token"}'
elif [[ "$url" == */config/defaults/sso_access ]] && [ "${FAKE_OBJECT_ACCESS:-0}" -eq 1 ]; then
  printf '%s\n' '{"value":{"user@example.test":["reader.example.test"]}}'
else
  printf '%s\n' '{"value":""}'
fi
CURL
chmod +x "$fake_bin/curl"

prepare_case retry-success
retry_state="$tmp_dir/retry-success.count"
invoke "$tmp_dir/retry-success" \
  PATH="$fake_bin:$PATH" \
  CREDENTIALS_DIRECTORY="$credentials" \
  FAKE_CURL_STATE="$retry_state" \
  FAKE_SECRET_FAILS=2 \
  SSO_BOOT_ATTEMPTS=4 \
  SSO_BOOT_RETRY_DELAY=0
if [ "$rc" -ne 0 ] || ! grep -q "secrets-gateway готов (попытка 3)" <<<"$output"; then
  echo "FAIL: gateway retry did not recover after transient failures"
  printf '%s\n' "$output"
  exit 1
fi

prepare_case config-retry-success
retry_state="$tmp_dir/config-retry-success.count"
invoke "$tmp_dir/config-retry-success" \
  PATH="$fake_bin:$PATH" \
  CREDENTIALS_DIRECTORY="$credentials" \
  FAKE_CURL_STATE="$retry_state" \
  FAKE_CONFIG_TOKEN=1 \
  FAKE_OBJECT_ACCESS=1 \
  FAKE_SECRET_FAILS=0 \
  FAKE_CONFIG_FAILS=2 \
  SECGW_URL=http://secrets.test \
  CFGW_URL=http://config.test \
  SSO_BOOT_ATTEMPTS=4 \
  SSO_BOOT_RETRY_DELAY=0
if [ "$rc" -ne 0 ] || ! grep -q "config-store готов (попытка 3)" <<<"$output"; then
  echo "FAIL: config-store retry did not recover after transient failures"
  printf '%s\n' "$output"
  exit 1
fi

prepare_case retry-exhausted
retry_state="$tmp_dir/retry-exhausted.count"
invoke "$tmp_dir/retry-exhausted" \
  PATH="$fake_bin:$PATH" \
  CREDENTIALS_DIRECTORY="$credentials" \
  FAKE_CURL_STATE="$retry_state" \
  FAKE_SECRET_FAILS=99 \
  SSO_BOOT_ATTEMPTS=3 \
  SSO_BOOT_RETRY_DELAY=0
expect_failure retry-exhausted "FATAL: secrets-gateway не готов после 3 попыток"

cat > "$tmp_dir/partial-server.py" <<'PY'
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        values = {
            "/secrets/CONFIG_STORE_TOKEN_VPS_SSO": "config-token",
            "/secrets/SECRET_ONE": "value-one",
            "/config/defaults/sso_access": {"user@example.test": ["reader.example.test"]},
            "/config/defaults/sso_internal_secrets": {
                "one.example.test": "SECRET_ONE",
                "two.example.test": "SECRET_TWO",
            },
        }
        if self.path == "/health":
            payload = {}
            status = 200
        elif self.path in values:
            payload = {"value": values[self.path]}
            status = 200
        else:
            payload = {"value": ""}
            status = 503 if self.path == "/secrets/SECRET_TWO" else 200
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *args):
        pass

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write(str(server.server_port))
server.serve_forever()
PY
port_file="$tmp_dir/partial-server.port"
python3 "$tmp_dir/partial-server.py" "$port_file" &
server_pid=$!
for _ in {1..50}; do
  [ ! -s "$port_file" ] || break
  sleep 0.1
done
if [ ! -s "$port_file" ]; then
  echo "FAIL: partial-map fixture server did not start"
  exit 1
fi
port="$(cat "$port_file")"
prepare_case partial-internal-map
invoke "$tmp_dir/partial-internal-map" \
  CREDENTIALS_DIRECTORY="$credentials" \
  SECGW_URL="http://127.0.0.1:$port" \
  CFGW_URL="http://127.0.0.1:$port" \
  SSO_BOOT_ATTEMPTS=2 \
  SSO_BOOT_RETRY_DELAY=0
expect_failure partial-internal-map "FATAL: SSO_INTERNAL_SECRETS собран не полностью"
kill "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=""

echo "PASS: launcher validates required fields, JSON/maps, complete secret resolution, and both gateway retries"
