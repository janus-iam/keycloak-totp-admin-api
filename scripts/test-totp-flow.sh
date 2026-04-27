#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
REALM="${REALM:-master}"
USERNAME="${USERNAME:-admin}"
PASSWORD="${PASSWORD:-admin}"
TARGET_USERNAME="${TARGET_USERNAME:-admin}"
TARGET_USER_ID="${TARGET_USER_ID:-}"
DEVICE_NAME="${DEVICE_NAME:-totp-test-$(date +%s)}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd curl
require_cmd jq

fetch_realm_otp_policy() {
  local realm_json
  realm_json="$(curl -sS -H "Authorization: Bearer $ACCESS_TOKEN" "$BASE_URL/admin/realms/$REALM")"

  OTP_TYPE="$(echo "$realm_json" | jq -r '.otpPolicyType // "totp"')"
  OTP_ALGORITHM="$(echo "$realm_json" | jq -r '.otpPolicyAlgorithm // "HmacSHA1"')"
  OTP_DIGITS="$(echo "$realm_json" | jq -r '.otpPolicyDigits // 6')"
  OTP_PERIOD="$(echo "$realm_json" | jq -r '.otpPolicyPeriod // 30')"
}

generate_totp_code() {
  local secret="$1"
  local algorithm="$2"
  local digits="$3"
  local period="$4"

  python3 - "$secret" "$algorithm" "$digits" "$period" <<'PY'
import base64
import hashlib
import hmac
import struct
import time
import sys

secret = sys.argv[1].strip().replace(" ", "").upper()
algorithm = sys.argv[2].strip().lower()
digits = int(sys.argv[3])
period = int(sys.argv[4])

padding = "=" * ((8 - len(secret) % 8) % 8)
key = base64.b32decode(secret + padding, casefold=True)

counter = int(time.time()) // period
msg = struct.pack(">Q", counter)
h = hmac.new(key, msg, getattr(hashlib, "sha1")).digest()
offset = h[-1] & 0x0F
code_int = ((h[offset] & 0x7F) << 24) | ((h[offset + 1] & 0xFF) << 16) | ((h[offset + 2] & 0xFF) << 8) | (h[offset + 3] & 0xFF)
print(f"{code_int % (10 ** digits):0{digits}d}")
PY
}

http_json() {
  local method="$1"
  local url="$2"
  local auth_token="${3:-}"
  local body="${4:-}"

  local tmp_body
  tmp_body="$(mktemp)"
  local code

  if [[ -n "$auth_token" && -n "$body" ]]; then
    code="$(curl -sS -o "$tmp_body" -w "%{http_code}" -X "$method" "$url" \
      -H "Authorization: Bearer $auth_token" \
      -H "Content-Type: application/json" \
      -d "$body")"
  elif [[ -n "$auth_token" ]]; then
    code="$(curl -sS -o "$tmp_body" -w "%{http_code}" -X "$method" "$url" \
      -H "Authorization: Bearer $auth_token")"
  elif [[ -n "$body" ]]; then
    code="$(curl -sS -o "$tmp_body" -w "%{http_code}" -X "$method" "$url" \
      -H "Content-Type: application/json" \
      -d "$body")"
  else
    code="$(curl -sS -o "$tmp_body" -w "%{http_code}" -X "$method" "$url")"
  fi

  local resp
  resp="$(cat "$tmp_body")"
  rm -f "$tmp_body"

  echo "$code"
  echo "$resp"
}

echo "Step 1/8: requesting admin token"
TOKEN_RESPONSE="$(curl -sS -X POST "$BASE_URL/realms/$REALM/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=admin-cli" \
  --data-urlencode "username=$USERNAME" \
  --data-urlencode "password=$PASSWORD")"
ACCESS_TOKEN="$(echo "$TOKEN_RESPONSE" | jq -r '.access_token // empty')"
if [[ -z "$ACCESS_TOKEN" ]]; then
  echo "Failed to obtain access token (check credentials and Keycloak server)" >&2
  exit 1
fi

echo "Step 2/8: resolving target user"
if [[ -z "$TARGET_USER_ID" ]]; then
  USERS_RESPONSE="$(curl -sS -X GET "$BASE_URL/admin/realms/$REALM/users?username=$TARGET_USERNAME&exact=true" \
    -H "Authorization: Bearer $ACCESS_TOKEN")"
  TARGET_USER_ID="$(echo "$USERS_RESPONSE" | jq -r '.[0].id // empty')"
fi

if [[ -z "$TARGET_USER_ID" ]]; then
  echo "Could not resolve target user id for username: $TARGET_USERNAME" >&2
  exit 1
fi

echo "Using target user id: $TARGET_USER_ID"

echo "Step 2b/8: reading realm OTP policy"
fetch_realm_otp_policy
if [[ "$OTP_TYPE" != "totp" ]]; then
  echo "Realm OTP policy type is '$OTP_TYPE', but this flow expects TOTP" >&2
  exit 1
fi
echo "Using OTP policy: algorithm=$OTP_ALGORITHM digits=$OTP_DIGITS period=$OTP_PERIOD"

echo "Step 3/8: generating TOTP secret"
readarray -t GENERATE_RESULT < <(http_json GET "$BASE_URL/admin/realms/$REALM/totp-admin-api/totp/generate/$TARGET_USER_ID" "$ACCESS_TOKEN")
GEN_CODE="${GENERATE_RESULT[0]}"
GEN_BODY="${GENERATE_RESULT[1]}"
if [[ "$GEN_CODE" != "200" ]]; then
  echo "Generate endpoint failed with status $GEN_CODE" >&2
  echo "$GEN_BODY" >&2
  exit 1
fi
ENCODED_SECRET="$(echo "$GEN_BODY" | jq -r '.encodedSecret // empty')"
if [[ -z "$ENCODED_SECRET" ]]; then
  echo "Generate response did not include encodedSecret" >&2
  echo "$GEN_BODY" >&2
  exit 1
fi

echo "Step 4/8: computing initial TOTP code"
INITIAL_CODE="$(generate_totp_code "$ENCODED_SECRET" "$OTP_ALGORITHM" "$OTP_DIGITS" "$OTP_PERIOD")"

echo "Step 5/8: registering TOTP credential"
REGISTER_BODY="{\"deviceName\":\"$DEVICE_NAME\",\"encodedSecret\":\"$ENCODED_SECRET\",\"initialCode\":\"$INITIAL_CODE\",\"overwrite\":true}"
readarray -t REGISTER_RESULT < <(http_json POST "$BASE_URL/admin/realms/$REALM/totp-admin-api/totp/register/$TARGET_USER_ID" "$ACCESS_TOKEN" "$REGISTER_BODY")
REG_CODE="${REGISTER_RESULT[0]}"
REG_BODY="${REGISTER_RESULT[1]}"
if [[ "$REG_CODE" != "200" ]]; then
  echo "Register endpoint failed with status $REG_CODE" >&2
  echo "$REG_BODY" >&2
  exit 1
fi

echo "Step 6/8: verifying credential appears in list"
readarray -t LIST_RESULT < <(http_json GET "$BASE_URL/admin/realms/$REALM/totp-admin-api/totp/get-totp-credentials/$TARGET_USER_ID" "$ACCESS_TOKEN")
LIST_CODE="${LIST_RESULT[0]}"
LIST_BODY="${LIST_RESULT[1]}"
if [[ "$LIST_CODE" != "200" ]]; then
  echo "List endpoint failed with status $LIST_CODE" >&2
  echo "$LIST_BODY" >&2
  exit 1
fi
HAS_DEVICE="$(echo "$LIST_BODY" | jq --arg device "$DEVICE_NAME" '.deviceName | index($device) != null')"
if [[ "$HAS_DEVICE" != "true" ]]; then
  echo "Registered device was not found in list" >&2
  echo "$LIST_BODY" >&2
  exit 1
fi

echo "Step 7/8: removing TOTP credential"
REMOVE_BODY="{\"deviceName\":\"$DEVICE_NAME\"}"
readarray -t REMOVE_RESULT < <(http_json POST "$BASE_URL/admin/realms/$REALM/totp-admin-api/totp/remove-totp/$TARGET_USER_ID" "$ACCESS_TOKEN" "$REMOVE_BODY")
REM_CODE="${REMOVE_RESULT[0]}"
REM_BODY="${REMOVE_RESULT[1]}"
if [[ "$REM_CODE" != "200" ]]; then
  echo "Remove endpoint failed with status $REM_CODE" >&2
  echo "$REM_BODY" >&2
  exit 1
fi

echo "Step 8/8: verifying credential removal"
readarray -t LIST_AFTER_RESULT < <(http_json GET "$BASE_URL/admin/realms/$REALM/totp-admin-api/totp/get-totp-credentials/$TARGET_USER_ID" "$ACCESS_TOKEN")
LIST_AFTER_CODE="${LIST_AFTER_RESULT[0]}"
LIST_AFTER_BODY="${LIST_AFTER_RESULT[1]}"
if [[ "$LIST_AFTER_CODE" != "200" ]]; then
  echo "Post-remove list endpoint failed with status $LIST_AFTER_CODE" >&2
  echo "$LIST_AFTER_BODY" >&2
  exit 1
fi
HAS_DEVICE_AFTER="$(echo "$LIST_AFTER_BODY" | jq --arg device "$DEVICE_NAME" '.deviceName | index($device) != null')"
if [[ "$HAS_DEVICE_AFTER" == "true" ]]; then
  echo "Device still present after remove" >&2
  echo "$LIST_AFTER_BODY" >&2
  exit 1
fi

echo "Success: TOTP register/remove flow passed for user $TARGET_USER_ID with device $DEVICE_NAME"
