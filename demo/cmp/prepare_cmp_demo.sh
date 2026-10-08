#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025-2026 Siemens
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

export _WD="${WORK_DIR:-.}"
echo "Working directory: $_WD"

export GTA_API_STATE_DIR="$_WD/tmp/gta_api_state"
export GTA_STATE_DIRECTORY="$GTA_API_STATE_DIR"
export DEMO_CREDENTIAL_DIR="$_WD/tmp/cmp_example"
export CLOUD_PKI_CREDENTIAL_DIR="./cloud-pki"
export OPENSSL_CONF=../openssl_config/openssl.cnf

if [[ -d "$_WD/cmp" ]]; then
    echo "CMP (in $_WD) directory exists."
else
    echo "Create $_WD/cmp directory."
    mkdir -p "$_WD/cmp"
fi

if [[ -d "$GTA_STATE_DIRECTORY" ]]; then
    echo "$GTA_STATE_DIRECTORY directory exists."
else
    echo "Create $GTA_STATE_DIRECTORY directory."
    mkdir -p "$GTA_STATE_DIRECTORY"
fi

if [[ -d "$DEMO_CREDENTIAL_DIR" ]]; then
    echo "$DEMO_CREDENTIAL_DIR directory exists."
else
    echo "Create $DEMO_CREDENTIAL_DIR directory."
    mkdir -p "$DEMO_CREDENTIAL_DIR"
fi

rm -f "$GTA_STATE_DIRECTORY/"*
rm -f "$DEMO_CREDENTIAL_DIR/"*

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

echo "Create reference to GTA API private key for OpenSSL provider (personality_name,profile_name)"
echo "-----BEGIN GTA PRIVATE KEY-----" > "$DEMO_CREDENTIAL_DIR/gta-key.pem"
echo -n "CMP,com.github.generic-trust-anchor-api.basic.signature" | base64 >> "$DEMO_CREDENTIAL_DIR/gta-key.pem"
echo "-----END GTA PRIVATE KEY-----" >> "$DEMO_CREDENTIAL_DIR/gta-key.pem"
cat "$DEMO_CREDENTIAL_DIR/gta-key.pem"
echo ""

echo "Create reference to GTA API personality (holding the CMP trust list) for OpenSSL provider (personality_name,profile_name)"
echo "-----BEGIN GTA TRUSTED KEY-----" > "$DEMO_CREDENTIAL_DIR/gta-trusted-cert.pem"
echo -n "CMP,com.github.generic-trust-anchor-api.basic.signature" | base64 >> "$DEMO_CREDENTIAL_DIR/gta-trusted-cert.pem"
echo "-----END GTA TRUSTED KEY-----" >> "$DEMO_CREDENTIAL_DIR/gta-trusted-cert.pem"
cat "$DEMO_CREDENTIAL_DIR/gta-trusted-cert.pem"
echo ""

echo "Create identifier"
gta-cli identifier_assign --id_type=ch.iec.30168.identifier.mac_addr --id_val=DE-AD-BE-EF-FE-ED

echo "Create key GTA API personality for CMP"
gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=CMP --app_name=cmp --prof=com.github.generic-trust-anchor-api.basic.ec

# Note that the certs need to be DER encoded
echo "Add trusted certificates to personality"
gta-cli personality_add_trusted_attribute --pers=CMP --prof=com.github.generic-trust-anchor-api.basic.signature --attr_type=ch.iec.30168.trustlist.certificate.trusted.x509v3 --attr_name="Root CA" --attr_val="${CLOUD_PKI_CREDENTIAL_DIR}/cmp_root_ca.crt"
gta-cli personality_add_trusted_attribute --pers=CMP --prof=com.github.generic-trust-anchor-api.basic.signature --attr_type=ch.iec.30168.trustlist.certificate.trusted.x509v3 --attr_name="ECC Root CA" --attr_val="${CLOUD_PKI_CREDENTIAL_DIR}/cmp_ecc_root_ca.crt"

echo "List the stored attributes of the personality"
gta-cli personality_attributes_enumerate --pers=CMP