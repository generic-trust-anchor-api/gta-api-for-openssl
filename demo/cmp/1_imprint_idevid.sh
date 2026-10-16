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

echo "Create reference to GTA API private key (IDevID) for OpenSSL provider (personality_name,profile_name)"
echo "-----BEGIN GTA PRIVATE KEY-----" > "$DEMO_CREDENTIAL_DIR/gta_idevid.pem"
echo -n "IDevID,com.github.generic-trust-anchor-api.basic.signature" | base64 >> "$DEMO_CREDENTIAL_DIR/gta_idevid.pem"
echo "-----END GTA PRIVATE KEY-----" >> "$DEMO_CREDENTIAL_DIR/gta_idevid.pem"
cat "$DEMO_CREDENTIAL_DIR/gta_idevid.pem"
echo ""

echo "Create identifier"
gta-cli identifier_assign --id_type=ch.iec.30168.identifier.mac_addr --id_val=DE-AD-BE-EF-FE-ED || gta_cli_fail

if [[ "$PROFILE" = "ec" ]]; then
    echo "Create EC GTA API personality for IDevID"
    gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=IDevID --app_name=IDevID --prof=com.github.generic-trust-anchor-api.basic.ec || gta_cli_fail
fi

if [[ "$PROFILE" = "rsa" ]]; then
    echo "Create RSA GTA API personality for IDevID"
    gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=IDevID --app_name=IDevID --prof=com.github.generic-trust-anchor-api.basic.rsa || gta_cli_fail
fi

echo "Send CMP ir"
openssl cmp -cmd ir -server http://localhost:6080 -path "/ejbca/publicweb/cmp/cmp_imprint_RA" -recipient "/CN=CMP_ISSUING_CA" -secret pass:SecretCmp -ref 3078 -subject "/CN=test-idevid/OU=For testing purposes only/O=Siemens/C=DE/OU=IDevID" -newkey "$DEMO_CREDENTIAL_DIR/gta_idevid.pem" -certout "$DEMO_CREDENTIAL_DIR/idevid_ee.pem" -verbosity 8 -total_timeout 20
echo ""
cat "$DEMO_CREDENTIAL_DIR/idevid_ee.pem"
echo ""

echo "Store issued cert"
gta-cli personality_add_attribute --pers=IDevID --prof=com.github.generic-trust-anchor-api.basic.signature --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name="IDevID_EE" --attr_val="$DEMO_CREDENTIAL_DIR/idevid_ee.pem" || gta_cli_fail

echo "List the stored attributes"
gta-cli personality_attributes_enumerate --pers=IDevID || gta_cli_fail

echo "Transition device state"
h_pol_physical="$(gta-cli access_policy_simple --descr_type=PHYSICAL_PRESENCE)"
gta-cli devicestate_transition --acc_pol_recede="$h_pol_physical" --owner_lock_count=2 || gta_cli_fail

exit "$EXIT_SUCCESS"