#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

export GTA_API_STATE_DIR="./client/serialized_data"
export GTA_STATE_DIRECTORY=$GTA_API_STATE_DIR
export CMP_CREDENTIAL_DIR=./cmp/cmp_example
export OPENSSL_CONF=/src/openssl.cnf

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

if [ -d "$GTA_STATE_DIRECTORY" ]; then
    echo "$GTA_STATE_DIRECTORY directory exists."
else
    echo "Create $GTA_STATE_DIRECTORY directory."
    mkdir -p "$GTA_STATE_DIRECTORY"
fi

if [ -d "$CMP_CREDENTIAL_DIR" ]; then
    echo "$CMP_CREDENTIAL_DIR directory exists."
else
    echo "Create $CMP_CREDENTIAL_DIR directory."
    mkdir -p "$CMP_CREDENTIAL_DIR"
fi

rm -f "$GTA_STATE_DIRECTORY/"*
rm -f "$CMP_CREDENTIAL_DIR/"*

echo "Create reference to GTA API private key for OpenSSL provider (personality_name,profile_name)"
echo "-----BEGIN GTA PRIVATE KEY-----" > "$CMP_CREDENTIAL_DIR/gta-key.pem"
echo -n "CMP,com.github.generic-trust-anchor-api.basic.signature" | base64 >> "$CMP_CREDENTIAL_DIR/gta-key.pem"
echo "-----END GTA PRIVATE KEY-----" >> "$CMP_CREDENTIAL_DIR/gta-key.pem"
cat "$CMP_CREDENTIAL_DIR/gta-key.pem"
echo ""

echo "Create identifier"
gta-cli identifier_assign --id_type=ch.iec.30168.identifier.mac_addr --id_val=DE-AD-BE-EF-FE-ED

echo "Create key GTA API personality for CMP"
gta-cli personality_create --id_val=DE-AD-BE-EF-FE-ED --pers=CMP --app_name=gta-cli --prof=com.github.generic-trust-anchor-api.basic.ec
