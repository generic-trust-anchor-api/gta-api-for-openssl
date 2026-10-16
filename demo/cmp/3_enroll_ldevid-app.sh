#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2026 Siemens
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
export GTA_API_STATE_DIR="$_WD/tmp/gta_api_state"
export GTA_STATE_DIRECTORY="$GTA_API_STATE_DIR"
export DEMO_CREDENTIAL_DIR="$_WD/tmp/cmp_example"
export OPENSSL_CONF=../openssl_config/openssl_provider_gta_and_default.cnf

if [[ "${1:-}" = "ec" ]]; then
  echo "Use EC keys..."
  PROFILE="ec"
elif [[ "${1:-}" = "rsa" ]]; then
  echo "Use RSA keys..."
  PROFILE="rsa"
else
  echo "Use EC keys..."
  PROFILE="ec"
fi

echo "Create reference to GTA API private key (LDevID-App) for OpenSSL provider (personality_name,profile_name)"
echo "-----BEGIN GTA PRIVATE KEY-----" > "$DEMO_CREDENTIAL_DIR/gta_ldevid-app.pem"
echo -n "LDevID-App,com.github.generic-trust-anchor-api.basic.signature" | base64 >> "$DEMO_CREDENTIAL_DIR/gta_ldevid-app.pem"
echo "-----END GTA PRIVATE KEY-----" >> "$DEMO_CREDENTIAL_DIR/gta_ldevid-app.pem"
cat "$DEMO_CREDENTIAL_DIR/gta_ldevid-app.pem"
echo ""

if [[ "$PROFILE" = "ec" ]]; then
    echo "Create EC GTA API personality for LDevID-App"
    gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=LDevID-App --app_name=LDevID-App --prof=com.github.generic-trust-anchor-api.basic.ec || gta_cli_fail
fi

if [[ "$PROFILE" = "rsa" ]]; then
    echo "Create RSA GTA API personality for LDevID-App"
    gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=LDevID-App --app_name=LDevID-App --prof=com.github.generic-trust-anchor-api.basic.rsa || gta_cli_fail
fi

echo "Send CMP cr"
openssl cmp -cmd cr -server http://localhost:6080 -path "/ejbca/publicweb/cmp/cmp_operation_RA" -recipient "/CN=CUSTOMER_ISSUING_CA" -trusted "$DEMO_CREDENTIAL_DIR/gta_ldevid-generic_ta.pem" -cert "$DEMO_CREDENTIAL_DIR/ldevid-generic_ee.pem" -key "$DEMO_CREDENTIAL_DIR/gta_ldevid-generic.pem" -subject "/CN=test-ldevid-app/OU=For testing purposes only/O=Siemens/C=DE/OU=LDevID" -newkey "$DEMO_CREDENTIAL_DIR/gta_ldevid-app.pem" -certout "$DEMO_CREDENTIAL_DIR/ldevid-app_ee.pem" -verbosity 8 -total_timeout 20
echo ""
cat "$DEMO_CREDENTIAL_DIR/ldevid-app_ee.pem"
echo ""

echo "Store issued cert"
gta-cli personality_add_attribute --pers=LDevID-App --prof=com.github.generic-trust-anchor-api.basic.signature --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name="LDevID-App_EE" --attr_val="$DEMO_CREDENTIAL_DIR/ldevid-app_ee.pem" || gta_cli_fail

echo "List the stored attributes"
gta-cli personality_attributes_enumerate --pers=LDevID-App || gta_cli_fail

exit "$EXIT_SUCCESS"