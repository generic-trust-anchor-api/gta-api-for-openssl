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

echo "Send CMP kur"
openssl cmp -cmd kur -server http://localhost:6080 -path "/ejbca/publicweb/cmp/cmp_operation_RA" -recipient "/CN=CUSTOMER_ISSUING_CA" -trusted "$DEMO_CREDENTIAL_DIR/gta_ldevid-generic_ta.pem" -cert "$DEMO_CREDENTIAL_DIR/ldevid-app_ee.pem" -key "$DEMO_CREDENTIAL_DIR/gta_ldevid-app.pem" -oldcert "$DEMO_CREDENTIAL_DIR/ldevid-app_ee.pem" -newkey "$DEMO_CREDENTIAL_DIR/gta_ldevid-app.pem" -certout "$DEMO_CREDENTIAL_DIR/ldevid-app_new_ee.pem" -verbosity 8 -total_timeout 20
echo ""
cat "$DEMO_CREDENTIAL_DIR/ldevid-app_new_ee.pem"
echo ""

echo "Remove old cert"
gta-cli personality_remove_attribute --pers=LDevID-App --prof=com.github.generic-trust-anchor-api.basic.signature --attr_name="LDevID-App_EE" || gta_cli_fail

echo "Store new issued cert"
gta-cli personality_add_attribute --pers=LDevID-App --prof=com.github.generic-trust-anchor-api.basic.signature --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name="LDevID-App_EE" --attr_val="$DEMO_CREDENTIAL_DIR/ldevid-app_new_ee.pem" || gta_cli_fail

echo "List the stored attributes"
gta-cli personality_attributes_enumerate --pers=LDevID-App || gta_cli_fail

exit "$EXIT_SUCCESS"