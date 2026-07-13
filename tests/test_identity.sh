#!/bin/bash

source tests/common.sh

set -e

function test_identity_without_forwarded() {
    echo "Testing identity handling without Forwarded header..."

    identity=$(curl -s -4 --key "$CERT_DIR/client.key" --cert "$CERT_DIR/client.crt" --cacert "$CERT_DIR/ca.crt" "$GATEWAY_URL/_identity" | base64 -d)

    # test that the identity type is User
    if [[ $(jq -e -r '.identity.type' <<< "$identity") != "User" ]]; then
        echo "$identity"
        echo "[${FUNCNAME[0]}][FAIL] Identity type is not User"
        exit 1
    fi

    # test that the identity has the correct org_id
    if [[ $(jq -e -r '.identity.org_id' <<< "$identity") != "1" ]]; then
        echo "$identity"
        echo "[${FUNCNAME[0]}] FAIL: Identity org_id is not 1"
        exit 1
    fi

    echo "[${FUNCNAME[0]}] PASS"
}

function test_identity_with_forwarded() {
    echo "Testing identity handling with Forwarded header..."

    identity=$(curl -s -4 -H "Forwarded: for=\"_00000000-0000-0000-0000-000000000000\"" --key "$CERT_DIR/client.key" --cert "$CERT_DIR/client.crt" --cacert "$CERT_DIR/ca.crt" "$GATEWAY_URL/_identity" | base64 -d)

    # test that the identity type is System
    if [[ $(jq -e -r '.identity.type' <<< "$identity") != "System" ]]; then
        echo "$identity"
        echo "[${FUNCNAME[0]}][FAIL] Identity type is not System"
        exit 1
    fi

    # test that the identity has the correct auth_type
    if [[ $(jq -e -r '.identity.auth_type' <<< "$identity") != "cert-auth" ]]; then
        echo "$identity"
        echo "[${FUNCNAME[0]}] FAIL: Identity auth_type is not cert-auth"
        exit 1
    fi

    # test that the identity has the correct org_id
    if [[ $(jq -e -r '.identity.org_id' <<< "$identity") != "1" ]]; then
        echo "$identity"
        echo "[${FUNCNAME[0]}] FAIL: Identity org_id is not 1"
        exit 1
    fi

    # test that the identity has the correct system cn
    if [[ $(jq -e -r '.identity.system.cn' <<< "$identity") != "00000000-0000-0000-0000-000000000000" ]]; then
        echo "$identity"
        echo "[${FUNCNAME[0]}] FAIL: Identity system cn is not as per Forwarded header (for=_CN)"
        exit 1
    fi

    echo "[${FUNCNAME[0]}] PASS"
}

function test_identity_entitlements() {
    echo "Testing identity includes entitlements..."

    identity=$(curl -s -4 --key "$CERT_DIR/client.key" --cert "$CERT_DIR/client.crt" --cacert "$CERT_DIR/ca.crt" "$GATEWAY_URL/_identity" | base64 -d)

    if [[ $(jq -e -r '.entitlements.insights.is_entitled' <<< "$identity") != "true" ]]; then
        echo "$identity"
        echo "[${FUNCNAME[0]}][FAIL] entitlements.insights.is_entitled is not true"
        exit 1
    fi

    echo "[${FUNCNAME[0]}] PASS"
}

function test_identity_no_cert_with_forwarded() {
    echo "Testing identity without client cert but with Forwarded + X-Org-Id..."

    identity=$(curl -s -4 -k -H "Forwarded: for=\"_test-uuid-1234\"" -H "X-Org-Id: 42" "$GATEWAY_URL/_identity" | base64 -d)

    if [[ $(jq -e -r '.identity.type' <<< "$identity") != "System" ]]; then
        echo "$identity"
        echo "[${FUNCNAME[0]}][FAIL] Identity type is not System"
        exit 1
    fi

    if [[ $(jq -e -r '.identity.system.cn' <<< "$identity") != "test-uuid-1234" ]]; then
        echo "$identity"
        echo "[${FUNCNAME[0]}][FAIL] Identity system cn does not match Forwarded header"
        exit 1
    fi

    if [[ $(jq -e -r '.identity.org_id' <<< "$identity") != "42" ]]; then
        echo "$identity"
        echo "[${FUNCNAME[0]}][FAIL] Identity org_id does not match X-Org-Id header"
        exit 1
    fi

    echo "[${FUNCNAME[0]}] PASS"
}

function test_identity_no_cert_no_forwarded() {
    echo "Testing identity without client cert and without Forwarded header is rejected..."

    identity=$(curl -s -4 -k "$GATEWAY_URL/_identity")

    if [[ -n "$identity" ]]; then
        decoded=$(echo "$identity" | base64 -d 2>/dev/null)
        if [[ -n "$decoded" ]]; then
            echo "$decoded"
            echo "[${FUNCNAME[0]}][FAIL] Expected no identity but got one"
            exit 1
        fi
    fi

    echo "[${FUNCNAME[0]}] PASS"
}

test_identity_without_forwarded
test_identity_with_forwarded
test_identity_entitlements
test_identity_no_cert_with_forwarded
test_identity_no_cert_no_forwarded
