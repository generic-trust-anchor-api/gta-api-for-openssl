#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025-2026 Siemens
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

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

echo "Provider config..."
cat $OPENSSL_CONF | head -79 | tail -30 | grep -v '#'

echo "Show all active provider..."
openssl list -providers
if openssl list -provider gta -providers; then
    echo "The gta provider installed... OK"
else
    echo "Missing gta provider"
    exit 1
fi

if gta-cli personality_attributes_enumerate --pers=test >/dev/null; then
    echo "The gta-cli installed... OK"
else
    echo "Missing gta-cli"
    exit 1
fi

echo "Send CMP kur"
# Note: The CMP client credentials could also be managed by GTA API as soon as we have a profile allowing the import of private keys
openssl cmp -cmd kur -server https://broker.sdo.siemens.cloud:443 -path "/.well-known/cmp" -recipient "/CN=CloudPKI-Integration-Test" -trusted "$DEMO_CREDENTIAL_DIR/gta-trusted-cert.pem" -cert "${CLOUD_PKI_CREDENTIAL_DIR}/cmp_client_cert.pem" -key <(printf '%s\n' "${CMP_CLIENT_KEY}") -oldcert "$DEMO_CREDENTIAL_DIR/test.cert.pem" -newkey "$DEMO_CREDENTIAL_DIR/gta-key.pem" -certout "$DEMO_CREDENTIAL_DIR/test.cert-updated.pem" -verbosity 8 -total_timeout 20

export OPENSSL_CONF=../openssl_config/openssl.cnf

echo "List the stored attributes (before remove)"
gta-cli personality_attributes_enumerate --pers=CMP

echo "Remove old certificate"
gta-cli personality_remove_attribute --pers=CMP --prof=com.github.generic-trust-anchor-api.basic.signature --attr_name="Test Cert"

echo "List the stored attributes (after remove)"
gta-cli personality_attributes_enumerate --pers=CMP

echo "Add new certificate to personality"
gta-cli personality_add_attribute --pers=CMP --prof=com.github.generic-trust-anchor-api.basic.signature --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name="Test Cert" --attr_val="$DEMO_CREDENTIAL_DIR/test.cert.pem"

echo "List the stored attributes (new)"
gta-cli personality_attributes_enumerate --pers=CMP
