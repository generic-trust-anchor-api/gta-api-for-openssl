#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

if [ "${WORK_DIR}" == "" ]; then
    export _WD="."
else
    export _WD="${WORK_DIR}"
fi

echo "Working directory: $_WD"

echo "Configure working directory"
if [[ -d "$_WD" ]]; then
    echo "$_WD directory exists."
else
    echo "Create $_WD directory."
    mkdir -p "$_WD"
fi

if [[ -d "$_WD/server" ]]; then
    echo "Server (in $_WD) directory exists."
else
    echo "Create $_WD/server directory."
    mkdir -p "$_WD/server"
fi

if [[ -d "$_WD/client" ]]; then
    echo "Client (in $_WD) directory exists."
else
    echo "Create $_WD/client directory."
    mkdir -p "$_WD/client"
fi

if [[ "$1" = "ec" ]]; then
  echo "Generate EC key materials..."
  PROFILE="ec"
elif [[ "$1" = "dilithium" ]]; then
  echo "Generate PQ key materials..."
  PROFILE="dilithium2"
else
  echo "Set EC key materials as default..."
  PROFILE="ec"
fi

export GTA_STATE_DIRECTORY="$_WD/client/serialized_data"

if [[ -d "$GTA_STATE_DIRECTORY" ]]; then
    echo "$GTA_STATE_DIRECTORY directory exists."
else
    echo "Create $GTA_STATE_DIRECTORY directory."
    mkdir -p "$GTA_STATE_DIRECTORY"
fi

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

if [[ "$PROFILE" = "dilithium2" ]]; then
    if openssl list -provider oqsprovider -providers; then
        echo "The oqsprovider installed... OK"
    else
        echo "Missing oqsprovider provider"
        echo "Copy oqsprovider objeect from the ./demo/openssl_config to the /usr/lib/x86_64-linux-gnu/ossl-modules and/or /usr/local/lib64/ossl-modules"
        echo "or define path property of the oqsprovider.so file in the ../../openssl_config/openssl_provider_oqs.cnf".
        echo "For example: module = <path of so file>"
        exit 1
    fi
fi

rm -rf "$_WD/CA"
rm -f "$GTA_STATE_DIRECTORY/"*
rm -rf "$_WD/client/"*.pem
rm -rf "$_WD/server/"*.pem

mkdir "$_WD/CA"

if [[ "$PROFILE" = "ec" ]]; then
    echo "Create CA credentials"
    openssl req -x509 -new -newkey ec:<(openssl genpkey -genparam -algorithm ec -pkeyopt ec_paramgen_curve:P-256) -keyout "$_WD/CA/CAkey.pem" -out "$_WD/CA/CAcert.pem" -nodes -subj "/CN=Demo CA" -days 365

    echo "Create server credentials"
    openssl req -newkey ec:<(openssl genpkey -genparam -algorithm ec -pkeyopt ec_paramgen_curve:P-256) -keyout "$_WD/server/key.pem" -out "$_WD/server/csr.pem" -nodes -subj "/CN=Demo Server"
    openssl x509 -req -CAkey "$_WD/CA/CAkey.pem" -CA "$_WD/CA/CAcert.pem" -days 365 -CAcreateserial -in "$_WD/server/csr.pem" -out "$_WD/server/cert.pem"
fi 


if [[ "$PROFILE" = "dilithium2" ]]; then
    SIG_ALG="dilithium2"
    export OPENSSL_CONF=../openssl_config/openssl.cnf
    OPENSSL_CONF_CA=../openssl_config/openssl_ca.cnf
    echo "Signature ALGORITHM: $SIG_ALG"

    echo "Create CA credentials"
    openssl req -provider oqsprovider -provider default -x509 -new -newkey ${SIG_ALG} -keyout "$_WD/CA/CAkey.pem" -out "$_WD/CA/CAcert.pem" -nodes -subj "/CN=Demo CA" -days 365 -config ${OPENSSL_CONF_CA}

    echo "Create server credentials"
    openssl req -provider oqsprovider -provider default -newkey ${SIG_ALG} -keyout "$_WD/server/key.pem" -out "$_WD/server/csr.pem" -pubkey -nodes -subj "/CN=Demo Server" -config ${OPENSSL_CONF}
    openssl x509 -provider oqsprovider -provider default -req -CAkey "$_WD/CA/CAkey.pem" -CA "$_WD/CA/CAcert.pem" -days 365 -CAcreateserial -in "$_WD/server/csr.pem" -out "$_WD/server/cert.pem"
fi

echo "Update GTA personality for client in the gta-key.pem"
echo "-----BEGIN GTA PRIVATE KEY-----" >"$_WD/client/gta-key.pem"
# b64(pers_dilithium2_default,com.github.generic-trust-anchor-api.basic.signature)
# or
# b64(pers_ec_default,com.github.generic-trust-anchor-api.basic.signature)
echo -n "pers_${PROFILE}_default,com.github.generic-trust-anchor-api.basic.signature" | base64 >>"$_WD/client/gta-key.pem"
echo "-----END GTA PRIVATE KEY-----" >>"$_WD/client/gta-key.pem"

echo "gta_identifier_assign"
gta-cli identifier_assign --id_type=identifier1 --id_val=identifier1

echo "Create GTA personality for client"
if [[ "$PROFILE" = "ec" ]]; then
    echo "gta_personality_create ec"
    gta-cli personality_create --id_val=identifier1 --pers=pers_${PROFILE}_default --app_name=Application --prof=com.github.generic-trust-anchor-api.basic.ec   
fi

if [[ "$PROFILE" = "dilithium2" ]]; then
    echo "gta_personality_create dilitihium"
    gta-cli personality_create --id_val=identifier1 --pers=pers_${PROFILE}_default --app_name=Application --prof=com.github.generic-trust-anchor-api.basic.dilithium
fi

echo "gta_personality_enroll"
gta-cli personality_enroll --pers=pers_${PROFILE}_default --prof=com.github.generic-trust-anchor-api.basic.enroll --ctx_attr com.github.generic-trust-anchor-api.enroll.subject_rdn="CN=Client Cert">"$_WD/client/csr.pem"

cat "$_WD/client/csr.pem"

echo "Create client certificate from public key"

if [[ "$PROFILE" = "dilithium2" ]]; then
    openssl x509 -provider oqsprovider -provider default -req -in "$_WD/client/csr.pem" -CAkey "$_WD/CA/CAkey.pem" -CA "$_WD/CA/CAcert.pem" -days 365
else
    openssl x509 -req -in "$_WD/client/csr.pem" -out "$_WD/client/cert.pem" -CAkey "$_WD/CA/CAkey.pem" -CA "$_WD/CA/CAcert.pem" -CAcreateserial -days 365
fi

cat "$_WD/client/cert.pem"