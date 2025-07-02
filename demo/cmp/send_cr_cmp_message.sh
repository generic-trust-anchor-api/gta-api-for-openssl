#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

export OPENSSL_CONF=../openssl_config/openssl_provider_gta_and_default.cnf
export CMP_CREDENTIAL_DIR=./cmp_example
export GTA_STATE_DIRECTORY="../client/serialized_data"

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

echo "Send cmp"
openssl cmp -server pki.certificate.fi:8700/pkix/ -secret pass:insta -recipient "/C=FI/O=Insta Demo/CN=Insta Demo CA" -ref 3078 -subject "/CN=openssl-cmp-provider-test" -cmd cr -certout "$CMP_CREDENTIAL_DIR/test.cert.pem" -newkey "$CMP_CREDENTIAL_DIR/gta-key.pem" -verbosity 8

export OPENSSL_CONF=../openssl_config/openssl.cnf

echo "Store issued cert"
gta-cli personality_add_attribute --pers=CMP --prof=com.github.generic-trust-anchor-api.basic.tls --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name="Test Cert" --attr_val="$CMP_CREDENTIAL_DIR/test.cert.pem"

echo "List the stored attributes"
gta-cli personality_attributes_enumerate --pers=CMP