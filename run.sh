#!/usr/bin/env bash
# vps-sso launcher: секреты из secrets-gateway, конфиг из config-store, .env — фолбэк.
# Паттерн как alice-relay/run.sh. Bootstrap-bearer = MESH_TOKEN (единственный секрет
# в .env). Источник каждого ключа логируется по ИМЕНИ (никогда не значение).
set -euo pipefail
cd "$(dirname "$0")"

# База/фолбэк: .env (в т.ч. MESH_TOKEN, NEXT_PUBLIC_* build-time, и текущие значения)
set -a; . ./.env 2>/dev/null || true; set +a

SECGW="${SECGW_URL:-http://100.66.108.118:8783}"
CFGW="${CFGW_URL:-http://100.66.108.118:8782}"
BOOT_ATTEMPTS="${SSO_BOOT_ATTEMPTS:-15}"
BOOT_RETRY_DELAY="${SSO_BOOT_RETRY_DELAY:-2}"

wait_for_gateway() {  # $1=label $2=health URL
  local label="$1" url="$2" attempt=1
  while [ "$attempt" -le "$BOOT_ATTEMPTS" ]; do
    if curl -fsS -m 2 "$url" >/dev/null 2>&1; then
      [ "$attempt" -eq 1 ] || echo "sso-cfg: $label готов (попытка $attempt)" >&2
      return 0
    fi
    if [ "$attempt" -lt "$BOOT_ATTEMPTS" ]; then
      echo "sso-cfg: ждём $label ($attempt/$BOOT_ATTEMPTS)" >&2
      sleep "$BOOT_RETRY_DELAY"
    fi
    attempt=$((attempt + 1))
  done
  echo "FATAL: $label не готов после $BOOT_ATTEMPTS попыток" >&2
  return 1
}

# serg/tasks#1108: bearer шлюза — ЛИЧНЫЙ токен vps-sso (LoadCredential=secgw-token; scope VPS_SSO_*,
# INFGW_ASSERT_KEY, CONFIG_STORE_TOKEN). Раньше здесь был root-шим Bitwarden (bws + bitwarden-sm.env)
# ради общего MESH_TOKEN с доступом ко всему хранилищу. Отката на него нет намеренно.
MT=""
if [ -n "${CREDENTIALS_DIRECTORY:-}" ] && [ -r "$CREDENTIALS_DIRECTORY/secgw-token" ]; then
  MT="$(tr -d '\r\n ' < "$CREDENTIALS_DIRECTORY/secgw-token")"
  echo "sso-cfg: личный токен secgw получен (LoadCredential)" >&2
else
  echo "sso-cfg: личный токен secgw недоступен — только .env-фолбэк" >&2
fi

if [ -n "$MT" ]; then
  wait_for_gateway secrets-gateway "$SECGW/health"
fi

_val() {
  python3 -c 'import sys,json; v=json.load(sys.stdin).get("value"); print(json.dumps(v,separators=(",",":")) if isinstance(v,(dict,list)) else (v or ""))'
}

fetch_secret() {  # $1=key → эхо значение или пусто
  [ -n "$MT" ] || return 0
  curl -fsS -m 8 -H "Authorization: Bearer $MT" "$SECGW/secrets/$1" 2>/dev/null | _val 2>/dev/null || true
}
fetch_config() {  # $1=key (defaults/<key>) → эхо значение или пусто
  [ -n "${CONFIG_STORE_TOKEN:-}" ] || return 0
  curl -fsS -m 8 -H "Authorization: Bearer ${CONFIG_STORE_TOKEN}" \
    "$CFGW/config/defaults/$1" 2>/dev/null | _val 2>/dev/null || true
}

set_from() {  # $1=VAR $2=value $3=source — не перезаписываем пустым (фолбэк на .env)
  if [ -n "$2" ]; then export "$1=$2"; echo "sso-cfg: $1 <- $3" >&2
  elif [ -n "${!1:-}" ]; then echo "sso-cfg: $1 <- .env fallback" >&2
  else echo "sso-cfg: $1 MISSING" >&2; fi
}

# 1) токен config-store — из secrets-gateway (бутстрап по MESH_TOKEN)
CST=$(fetch_secret CONFIG_STORE_TOKEN_VPS_SSO); [ -n "$CST" ] && export CONFIG_STORE_TOKEN="$CST"
export CONFIG_STORE_URL="$CFGW"
if [ -n "${CONFIG_STORE_TOKEN:-}" ]; then
  wait_for_gateway config-store "$CFGW/health"
fi

# 2) секреты приложения — из secrets-gateway (в security store — токены приложений)
set_from JWT_SECRET       "$(fetch_secret VPS_SSO_JWT_SECRET)"       secrets-gateway
set_from CLERK_SECRET_KEY "$(fetch_secret VPS_SSO_CLERK_SECRET_KEY)" secrets-gateway
set_from INTERNAL_SECRET  "$(fetch_secret VPS_SSO_INTERNAL_SECRET)"  secrets-gateway
# Plan B: реестр opaque service-token'ов в mesh-postgres (схема vps_sso).
set_from VPS_SSO_DB_URL   "$(fetch_secret VPS_SSO_DB_URL)"           secrets-gateway

# 3) несекретный конфиг + карта доступов — из config-store
set_from SSO_ACCESS             "$(fetch_config sso_access)"             config-store
set_from ALLOWED_REDIRECT_HOSTS "$(fetch_config sso_allowed_redirects)" config-store
set_from COOKIE_DOMAIN          "$(fetch_config sso_cookie_domain)"     config-store
set_from SSO_HOST               "$(fetch_config sso_host)"              config-store

# 3.5) Plan B фаза 3: per-consumer ключи подписи assertion'ов.
# config-store defaults/sso_assertion_consumers = { "<host>": "<secretName>" };
# значения ключей лежат в secrets-gateway под этими именами. Собираем
# SSO_ASSERT_KEYS = { "<host>": "<keyValue>" }. Хост без ключа → assertion не
# чеканится (сервисы, не потребляющие assertion, не затрагиваются).
CONSUMERS="$(fetch_config sso_assertion_consumers)"
if [ -n "$CONSUMERS" ] && [ -n "$MT" ]; then
  ASSERT_KEYS="$(SECGW="$SECGW" MT="$MT" python3 - "$CONSUMERS" <<'PY' 2>/dev/null || true
import sys, json, os, urllib.request
try:
    consumers = json.loads(sys.argv[1])
except Exception:
    consumers = {}
secgw = os.environ["SECGW"]; mt = os.environ["MT"]
out = {}
for host, secname in (consumers.items() if isinstance(consumers, dict) else []):
    try:
        req = urllib.request.Request(
            f"{secgw}/secrets/{secname}",
            headers={"Authorization": f"Bearer {mt}"},
        )
        val = json.load(urllib.request.urlopen(req, timeout=8)).get("value")
        if val:
            out[str(host).strip().lower()] = val
    except Exception:
        pass
print(json.dumps(out))
PY
)"
  # Экспортируем только если реально собрали хотя бы один ключ ({} = пусто-эквивалент).
  if [ -n "$ASSERT_KEYS" ] && [ "$ASSERT_KEYS" != "{}" ]; then
    export SSO_ASSERT_KEYS="$ASSERT_KEYS"
    echo "sso-cfg: SSO_ASSERT_KEYS <- secrets-gateway×config-store" >&2
  else
    echo "sso-cfg: SSO_ASSERT_KEYS пуст (нет потребителей/ключей)" >&2
  fi
fi

# 3.6) Пер-сервисные X-Internal-Secret. config-store defaults/sso_internal_secrets
# = { "<host>": "<secretName>" }; значения — в secrets-gateway под этими именами.
# Собираем SSO_INTERNAL_SECRETS = { "<host>": "<value>" }: у каждого сайта свой
# секрет, годный только для него. Форма намеренно та же, что у SSO_ASSERT_KEYS.
# Частичную или пустую сборку не экспортируем и завершаем bootstrap:
# активный SSO обязан знать каждый host из конфигурационной карты.
INTERNAL_MAP="$(fetch_config sso_internal_secrets)"
if [ -n "$INTERNAL_MAP" ] && [ -n "$MT" ]; then
  INTERNAL_SECRETS="$(SECGW="$SECGW" MT="$MT" python3 - "$INTERNAL_MAP" <<'PY' 2>/dev/null || true
import sys, json, os, urllib.request
raw = sys.argv[1]
try:
    mapping = json.loads(raw)
except Exception:
    mapping = {}
secgw = os.environ["SECGW"]; mt = os.environ["MT"]
out = {}
for host, secname in (mapping.items() if isinstance(mapping, dict) else []):
    try:
        req = urllib.request.Request(
            f"{secgw}/secrets/{secname}",
            headers={"Authorization": f"Bearer {mt}"},
        )
        val = json.load(urllib.request.urlopen(req, timeout=8)).get("value")
        if val:
            out[str(host).strip().lower()] = val
    except Exception:
        pass
print(json.dumps(out))
PY
)"
  if [ -n "$INTERNAL_SECRETS" ] && [ "$INTERNAL_SECRETS" != "{}" ] && \
    INTERNAL_MAP="$INTERNAL_MAP" INTERNAL_SECRETS="$INTERNAL_SECRETS" python3 - <<'PY'
import json
import os
import sys

try:
    expected_raw = json.loads(os.environ["INTERNAL_MAP"])
    actual_raw = json.loads(os.environ["INTERNAL_SECRETS"])
except Exception:
    raise SystemExit(1)

def normalized_keys(mapping):
    if not isinstance(mapping, dict) or not mapping:
        raise SystemExit(1)
    keys = []
    for host, value in mapping.items():
        if (
            not isinstance(host, str)
            or not host.strip()
            or not isinstance(value, str)
            or not value
        ):
            raise SystemExit(1)
        keys.append(host.strip().lower())
    if len(keys) != len(set(keys)):
        raise SystemExit(1)
    return set(keys)

if normalized_keys(expected_raw) != normalized_keys(actual_raw):
    raise SystemExit(1)
PY
  then
    export SSO_INTERNAL_SECRETS="$INTERNAL_SECRETS"
    echo "sso-cfg: SSO_INTERNAL_SECRETS <- secrets-gateway×config-store ($(printf %s "$INTERNAL_SECRETS" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))') хостов)" >&2
  else
    echo "FATAL: SSO_INTERNAL_SECRETS собран не полностью" >&2
    exit 1
  fi
fi

# Не запускаем живой SSO в частично сконфигурированном состоянии. systemd
# перезапустит unit после восстановления gateway; до этого nginx останется
# fail-closed, но не получит ложный active с 500 от Clerk. Проверяем не только
# наличие, но и форму access/internal maps: "{}" и malformed JSON здесь равны
# отсутствию, иначе auth/check либо даст 500, либо свалится в небезопасный fallback.
python3 - <<'PY'
import json
import os
import sys

errors = []
required = (
    "JWT_SECRET",
    "CLERK_SECRET_KEY",
    "VPS_SSO_DB_URL",
    "COOKIE_DOMAIN",
    "SSO_HOST",
    "ALLOWED_REDIRECT_HOSTS",
)
for name in required:
    if not os.environ.get(name, "").strip():
        errors.append(f"{name} missing")

redirect_raw = os.environ.get("ALLOWED_REDIRECT_HOSTS", "")
redirect_hosts = [host.strip() for host in redirect_raw.split(",")]
if redirect_raw.strip() and any(not host for host in redirect_hosts):
    errors.append("ALLOWED_REDIRECT_HOSTS contains an empty host")

def load_object(name):
    raw = os.environ.get(name, "")
    try:
        value = json.loads(raw)
    except Exception:
        errors.append(f"{name} malformed JSON")
        return None
    if not isinstance(value, dict) or not value:
        errors.append(f"{name} must be a non-empty object")
        return None
    return value

access = load_object("SSO_ACCESS")
if access is not None:
    for email, hosts in access.items():
        if not isinstance(email, str) or not email.strip():
            errors.append("SSO_ACCESS has an empty/non-string email")
            break
        if (
            not isinstance(hosts, list)
            or not hosts
            or any(not isinstance(host, str) or not host.strip() for host in hosts)
        ):
            errors.append(f"SSO_ACCESS[{email!r}] must be a non-empty string array")
            break

internal = load_object("SSO_INTERNAL_SECRETS")
if internal is not None:
    for host, secret in internal.items():
        if (
            not isinstance(host, str)
            or not host.strip()
            or not isinstance(secret, str)
            or not secret
        ):
            errors.append("SSO_INTERNAL_SECRETS must map non-empty hosts to non-empty strings")
            break

if errors:
    print("FATAL: invalid required boot configuration: " + "; ".join(errors), file=sys.stderr)
    raise SystemExit(1)
PY

# 4) Next standalone НЕ кладёт .next/static (и public) в свою папку, а сервер
# отдаёт /_next/static/* из своего CWD (.next/standalone). Без линка все чанки =
# 404 → клиентские компоненты не гидратируются (кнопки мертвы). Self-heal: линк
# всегда указывает на статику ТЕКУЩЕЙ сборки, переживает любой ребилд.
# Симлинки .next/standalone/{.next/static,public} делает deploy/prepare.sh (ExecStartPre=+, root):
# под непривилегированным пользователем дерево только для чтения.
cd .next/standalone
# Путь к node — прод-значение по умолчанию; SSO_NODE_BIN переопределяет его там, где node
# стоит иначе (CI-раннер, машина разработчика). Раньше путь был зашит, и тест лаунчера
# проходил только на VPS: CI главной ветки был красным с 18.10 (serg/tasks#3045).
NODE_BIN="${SSO_NODE_BIN:-/usr/local/lib/nodejs/v22.22.3/bin/node}"
if [ ! -x "$NODE_BIN" ]; then
  echo "FATAL: node не найден: $NODE_BIN (задай SSO_NODE_BIN)" >&2
  exit 1
fi
exec "$NODE_BIN" server.js
