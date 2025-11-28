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

echo "Create reference to GTA API public key for OpenSSL provider (personality_name,profile_name)"
echo "-----BEGIN GTA TRUSTED KEY-----" > "$CMP_CREDENTIAL_DIR/gta-trusted-cert.pem"
echo -n "CMP,com.github.generic-trust-anchor-api.basic.signature" | base64 >> "$CMP_CREDENTIAL_DIR/gta-trusted-cert.pem"
echo "-----END GTA TRUSTED KEY-----" >> "$CMP_CREDENTIAL_DIR/gta-trusted-cert.pem"
cat "$CMP_CREDENTIAL_DIR/gta-trusted-cert.pem"
echo ""

export OPENSSL_CONF=../openssl_config/openssl.cnf

echo "Remove old trusted certificate"
gta-cli personality_remove_attribute --pers=CMP --prof=com.github.generic-trust-anchor-api.basic.signature --attr_name="Trusted"

echo "Get Insta CA certificate"
wget 'http://pki.certificate.fi:8081/install-ca-cert.html/ca-certificate.crt?ca-id=632&download-certificate=1' -O "$CMP_CREDENTIAL_DIR/insta.ca.crt"

echo "Add trusted certificate to personality"
gta-cli personality_add_trusted_attribute --pers=CMP --prof=com.github.generic-trust-anchor-api.basic.signature --attr_type=ch.iec.30168.trustlist.certificate.trusted.x509v3 --attr_name="Insta CA cert" --attr_val="$CMP_CREDENTIAL_DIR/insta.ca.crt"

echo "List the stored attributes (after the root CA install)"
gta-cli personality_attributes_enumerate --pers=CMP

export OPENSSL_CONF=../openssl_config/openssl_provider_gta_and_default.cnf

echo "Send cmp"
openssl cmp -server pki.certificate.fi:8700/pkix/ -recipient "/C=FI/O=Insta Demo/CN=Insta Demo CA" -trusted "$CMP_CREDENTIAL_DIR/gta-trusted-cert.pem" -ignore_keyusage -cert "$CMP_CREDENTIAL_DIR/test.cert.pem" -key "$CMP_CREDENTIAL_DIR/gta-key.pem" -subject "/CN=openssl-cmp-provider-test" -newkey "$CMP_CREDENTIAL_DIR/gta-key.pem" -cmd kur -certout "$CMP_CREDENTIAL_DIR/test.cert-updated.pem" -verbosity 8

export OPENSSL_CONF=../openssl_config/openssl.cnf

echo "List the stored attributes (before remove)"
gta-cli personality_attributes_enumerate --pers=CMP

echo "Remove old certificate"
gta-cli personality_remove_attribute --pers=CMP --prof=com.github.generic-trust-anchor-api.basic.signature --attr_name="Test Cert"

echo "List the stored attributes (after remove)"
gta-cli personality_attributes_enumerate --pers=CMP

echo "Add new certificate to personality"
gta-cli personality_add_attribute --pers=CMP --prof=com.github.generic-trust-anchor-api.basic.signature --attr_type=ch.iec.30168.trustlist.certificate.self.x509 --attr_name="Test Cert" --attr_val="$CMP_CREDENTIAL_DIR/test.cert.pem"

echo "List the stored attributes (new)"
gta-cli personality_attributes_enumerate --pers=CMP
