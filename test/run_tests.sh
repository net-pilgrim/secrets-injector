#!/usr/bin/env bash
set -euo pipefail

VAULT_PORT=8899
VAULT_KEY="test-secret-vault-key-42"
LIB_PATH="${LIB_PATH:-$(pwd)/bin/libsecrets_injector.so}"
TEST_APP="${TEST_APP:-$(pwd)/bin/test_app}"

echo "=================================================="
echo "Testing Library: ${LIB_PATH}"
echo "Test App:        ${TEST_APP}"
echo "Starting Mock Web Vault on port ${VAULT_PORT}..."
echo "=================================================="
python3 test/vault_server.py ${VAULT_PORT} "${VAULT_KEY}" &
VAULT_PID=$!

cleanup() {
    echo "Stopping Vault Server (PID ${VAULT_PID})..."
    kill "${VAULT_PID}" 2>/dev/null || true
    wait "${VAULT_PID}" 2>/dev/null || true
}
trap cleanup EXIT

echo "Waiting for vault to be ready..."
for i in {1..30}; do
    if curl -s "http://127.0.0.1:${VAULT_PORT}/health" > /dev/null 2>&1; then
        echo "Vault server is UP!"
        break
    fi
    sleep 0.1
done

echo ""
echo "=================================================="
echo "TEST 1: Binary getenv & secure_getenv"
echo "=================================================="
SECRETS_VAULT_URL="http://127.0.0.1:${VAULT_PORT}/secrets" \
SECRETS_FETCH_KEY="${VAULT_KEY}" \
SECRETS_INJECTOR_DEBUG=1 \
LD_PRELOAD="${LIB_PATH}" \
"${TEST_APP}"
echo ">>> TEST 1 PASSED!"

echo ""
echo "=================================================="
echo "TEST 2: Python os.getenv and os.environ"
echo "=================================================="
SECRETS_VAULT_URL="http://127.0.0.1:${VAULT_PORT}/secrets" \
SECRETS_FETCH_KEY="${VAULT_KEY}" \
LD_PRELOAD="${LIB_PATH}" \
python3 -c '
import os
assert os.getenv("DATABASE_URL") == "postgresql://dbuser:supersecretpass@db.internal:5432/production"
assert os.environ["API_KEY"] == "sk_live_9876543210abcdef"
assert os.getenv("JWT_SECRET") == "my-ultra-secure-jwt-signing-key"
assert os.getenv("SECRETS_FETCH_KEY") is None, "SECRETS_FETCH_KEY should have been scrubbed!"
print("[python] Injected secrets successfully verified in os.getenv and os.environ!")
'
echo ">>> TEST 2 PASSED!"

echo ""
echo "=================================================="
echo "TEST 3: HashiCorp Vault KV v2 structure"
echo "=================================================="
SECRETS_VAULT_URL="http://127.0.0.1:${VAULT_PORT}/vault_kv2" \
SECRETS_FETCH_KEY="${VAULT_KEY}" \
LD_PRELOAD="${LIB_PATH}" \
"${TEST_APP}" "KV2_SECRET" "hashicorp_vault_v2_value"
echo ">>> TEST 3 PASSED!"

echo ""
echo "=================================================="
echo "TEST 4: Plain text / Dotenv format"
echo "=================================================="
SECRETS_VAULT_URL="http://127.0.0.1:${VAULT_PORT}/dotenv" \
SECRETS_FETCH_KEY="${VAULT_KEY}" \
LD_PRELOAD="${LIB_PATH}" \
"${TEST_APP}" "DOTENV_SECRET" "secret_from_dotenv_format"
echo ">>> TEST 4 PASSED!"

echo ""
echo "=================================================="
echo "TEST 5: Missing SECRETS_FETCH_KEY (Passthrough mode)"
echo "=================================================="
LD_PRELOAD="${LIB_PATH}" \
"${TEST_APP}" "PATH" "${PATH}"
echo ">>> TEST 5 PASSED!"

echo ""
echo "=================================================="
echo "TEST 6: Invalid SECRETS_FETCH_KEY (Graceful error handling)"
echo "=================================================="
SECRETS_VAULT_URL="http://127.0.0.1:${VAULT_PORT}/secrets" \
SECRETS_FETCH_KEY="wrong-key" \
SECRETS_INJECTOR_DEBUG=1 \
LD_PRELOAD="${LIB_PATH}" \
"${TEST_APP}" "DATABASE_URL" "__NULL__"
echo ">>> TEST 6 PASSED!"

echo ""
echo "=================================================="
echo "TEST 7: FAIL_FAST mode on invalid key"
echo "=================================================="
set +e
SECRETS_VAULT_URL="http://127.0.0.1:${VAULT_PORT}/secrets" \
SECRETS_FETCH_KEY="wrong-key" \
SECRETS_INJECTOR_FAIL_FAST=1 \
LD_PRELOAD="${LIB_PATH}" \
"${TEST_APP}" > /dev/null 2>&1
EXIT_CODE=$?
set -e
if [ "${EXIT_CODE}" -ne 0 ]; then
    echo "Correctly failed fast with exit code ${EXIT_CODE}"
    echo ">>> TEST 7 PASSED!"
else
    echo "Expected failure with FAIL_FAST=1, but got exit code 0"
    exit 1
fi

echo ""
echo "=================================================="
echo "TEST 8: Bitwarden Secrets Manager Adapter"
echo "=================================================="
SECRETS_VAULT_URL="http://127.0.0.1:${VAULT_PORT}/bitwarden/secrets" \
SECRETS_FETCH_KEY="${VAULT_KEY}" \
SECRETS_INJECTOR_DEBUG=1 \
LD_PRELOAD="${LIB_PATH}" \
"${TEST_APP}" "BW_DATABASE_URL" "postgres://bwuser:secret@localhost:5432/bwdb"
echo ">>> TEST 8 PASSED (Bitwarden)!"

echo ""
echo "=================================================="
echo "TEST 9: 1Password Connect Adapter"
echo "=================================================="
SECRETS_VAULT_URL="http://127.0.0.1:${VAULT_PORT}/1password/v1/vaults/v123/items/i456" \
SECRETS_FETCH_KEY="${VAULT_KEY}" \
SECRETS_INJECTOR_DEBUG=1 \
LD_PRELOAD="${LIB_PATH}" \
"${TEST_APP}" "OP_API_TOKEN" "ops_token_abc123"
echo ">>> TEST 9 PASSED (1Password)!"

echo ""
echo "=================================================="
echo "ALL TESTS PASSED SUCCESSFULLY!"
echo "=================================================="
