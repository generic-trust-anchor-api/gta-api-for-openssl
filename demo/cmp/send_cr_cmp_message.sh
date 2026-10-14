#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025-2026 Siemens
#
# SPDX-License-Identifier: Apache-2.0

readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1

set -euo pipefail

gta_cli_fail() {
    echo "gta-cli failed" >&2
    exit "$EXIT_FAILURE"
}

export _WD="${WORK_DIR:-.}"
echo "Working directory: $_WD"

export GTA_STATE_DIRECTORY="$_WD/tmp/gta_api_state"
export DEMO_CREDENTIAL_DIR="$_WD/tmp/cmp_example"
export CLOUD_PKI_CREDENTIAL_DIR="./cloud-pki"
export OPENSSL_CONF=../openssl_config/openssl_provider_gta_and_default.cnf

# If running locally and the env var isn't set, read it from the local file into the variable
if [[ -z "${CMP_CLIENT_KEY:-}" && -f "${CLOUD_PKI_CREDENTIAL_DIR}/cmp_client_key.pem" ]]; then
    CMP_CLIENT_KEY=$(<"${CLOUD_PKI_CREDENTIAL_DIR}/cmp_client_key.pem")
    export CMP_CLIENT_KEY
fi
if [[ -z "${CMP_CLIENT_KEY:-}" ]]; then
    echo "Missing CMP client key"
    exit 1
fi

if openssl list -provider gta -providers; then
    echo "The gta provider installed... OK"
else
    echo "Missing gta provider"
    exit "$EXIT_FAILURE"
fi

if gta-cli personality_attributes_enumerate --pers=test >/dev/null; then
    echo "The gta-cli installed... OK"
else
    echo "Missing gta-cli"
    exit "$EXIT_FAILURE"
fi

echo "Send CMP cr"
# Note: The CMP client credentials could also be managed by GTA API as soon as we have a profile allowing the import of private keys
openssl cmp -cmd cr -server https://broker.sdo.siemens.cloud:443 -path "/.well-known/cmp" -recipient "/CN=CloudPKI-Integration-Test" -trusted "$DEMO_CREDENTIAL_DIR/gta-trusted-cert.pem" -cert "${CLOUD_PKI_CREDENTIAL_DIR}/cmp_client_cert.pem" -key <(printf '%s\n' "${CMP_CLIENT_KEY}") -subject "/CN=CloudPKI-Integration-Test-User/OU=PPKI Playground/OU=Corporate Technology/OU=For internal test purposes only/O=Siemens/C=DE" -newkey "$DEMO_CREDENTIAL_DIR/gta-key.pem" -certout "$DEMO_CREDENTIAL_DIR/test.cert.pem" -verbosity 8 -total_timeout 20

export OPENSSL_CONF=../openssl_config/openssl.cnf

echo "Store issued cert"
gta-cli personality_add_attribute --pers=CMP --prof=com.github.generic-trust-anchor-api.basic.signature --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name="Test Cert" --attr_val="$DEMO_CREDENTIAL_DIR/test.cert.pem" || gta_cli_fail

echo "List the stored attributes"
gta-cli personality_attributes_enumerate --pers=CMP || gta_cli_fail

exit "$EXIT_SUCCESS"