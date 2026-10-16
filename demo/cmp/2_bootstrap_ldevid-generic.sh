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

echo "Create reference to GTA API private key (LDevID-Generic) for OpenSSL provider (personality_name,profile_name)"
echo "-----BEGIN GTA PRIVATE KEY-----" > "$DEMO_CREDENTIAL_DIR/gta_ldevid-generic.pem"
echo -n "LDevID-Generic,com.github.generic-trust-anchor-api.basic.signature" | base64 >> "$DEMO_CREDENTIAL_DIR/gta_ldevid-generic.pem"
echo "-----END GTA PRIVATE KEY-----" >> "$DEMO_CREDENTIAL_DIR/gta_ldevid-generic.pem"
cat "$DEMO_CREDENTIAL_DIR/gta_ldevid-generic.pem"
echo ""

echo "Create reference to GTA API trusted certificate (LDevID-Generic) for OpenSSL provider (personality_name,profile_name)"
echo "-----BEGIN GTA TRUSTED CERTIFICATE-----" > "$DEMO_CREDENTIAL_DIR/gta_ldevid-generic_ta.pem"
echo -n "LDevID-Generic,com.github.generic-trust-anchor-api.basic.signature" | base64 >> "$DEMO_CREDENTIAL_DIR/gta_ldevid-generic_ta.pem"
echo "-----END GTA TRUSTED CERTIFICATE-----" >> "$DEMO_CREDENTIAL_DIR/gta_ldevid-generic_ta.pem"
cat "$DEMO_CREDENTIAL_DIR/gta_ldevid-generic_ta.pem"
echo ""

if [[ "$PROFILE" = "ec" ]]; then
    echo "Create EC GTA API personality for LDevID-Generic"
    gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=LDevID-Generic --app_name=LDevID-Generic --prof=com.github.generic-trust-anchor-api.basic.ec || gta_cli_fail
fi

if [[ "$PROFILE" = "rsa" ]]; then
    echo "Create RSA GTA API personality for LDevID-Generic"
    gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=LDevID-Generic --app_name=LDevID-Generic --prof=com.github.generic-trust-anchor-api.basic.rsa || gta_cli_fail
fi

echo "Fetch Trusted Domain Certificate and store it in GTA API LDevID-Generic personality"
wget -q --no-check-certificate "https://localhost:6443/ejbca/ra/cert?caid=-23062321&chain=false&format=der" -O "$DEMO_CREDENTIAL_DIR/customer_root_ca.crt"
gta-cli personality_add_trusted_attribute --pers=LDevID-Generic --prof=com.github.generic-trust-anchor-api.basic.signature --attr_type=ch.iec.30168.trustlist.certificate.trusted.x509v3 --attr_name="LDevID-Generic_TA" --attr_val="$DEMO_CREDENTIAL_DIR/customer_root_ca.crt" || gta_cli_fail

echo "Send CMP cr"
openssl cmp -cmd cr -server http://localhost:6080 -path "/ejbca/publicweb/cmp/cmp_bootstrap_RA" -recipient "/CN=CUSTOMER_ISSUING_CA" -trusted "$DEMO_CREDENTIAL_DIR/gta_ldevid-generic_ta.pem" -cert "$DEMO_CREDENTIAL_DIR/idevid_ee.pem" -key "$DEMO_CREDENTIAL_DIR/gta_idevid.pem" -subject "/CN=test-ldevid-gen/OU=For testing purposes only/O=Siemens/C=DE/OU=LDevID-Generic" -newkey "$DEMO_CREDENTIAL_DIR/gta_ldevid-generic.pem" -certout "$DEMO_CREDENTIAL_DIR/ldevid-generic_ee.pem" -verbosity 8 -total_timeout 20
echo ""
cat "$DEMO_CREDENTIAL_DIR/ldevid-generic_ee.pem"
echo ""

echo "Store issued cert"
gta-cli personality_add_attribute --pers=LDevID-Generic --prof=com.github.generic-trust-anchor-api.basic.signature --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name="LDevID-Generic_EE" --attr_val="$DEMO_CREDENTIAL_DIR/ldevid-generic_ee.pem" || gta_cli_fail

echo "List the stored attributes"
gta-cli personality_attributes_enumerate --pers=LDevID-Generic || gta_cli_fail

exit "$EXIT_SUCCESS"