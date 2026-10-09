#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025-2026 Siemens
#
# SPDX-License-Identifier: Apache-2.0

if [[ "${WORK_DIR}" == "" ]]; then
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
elif [[ "$1" = "rsa" ]]; then
  echo "Generate RSA key materials..."
  PROFILE="rsa"
elif [[ "$1" = "mldsa" ]]; then
  echo "Generate PQ key materials..."
  PROFILE="ml-dsa"
else
  echo "Set EC key materials as default..."
  PROFILE="ec"
fi

export GTA_STATE_DIRECTORY="$_WD/client/gta_api_state"

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

if [[ "$PROFILE" = "rsa" ]]; then
    echo "Create CA credentials"
    openssl req -x509 -new -newkey rsa:2048 -keyout "$_WD/CA/CAkey.pem" -out "$_WD/CA/CAcert.pem" -nodes -subj "/CN=Demo CA" -days 365

    echo "Create server credentials"
    openssl req -newkey rsa:2048 -keyout "$_WD/server/key.pem" -out "$_WD/server/csr.pem" -nodes -subj "/CN=Demo Server"
    openssl x509 -req -CAkey "$_WD/CA/CAkey.pem" -CA "$_WD/CA/CAcert.pem" -days 365 -CAcreateserial -in "$_WD/server/csr.pem" -out "$_WD/server/cert.pem"
fi

if [[ "$PROFILE" = "ml-dsa" ]]; then
    echo "Create CA credentials"
    openssl req -x509 -new -newkey ML-DSA-65 -keyout "$_WD/CA/CAkey.pem" -out "$_WD/CA/CAcert.pem" -nodes -subj "/CN=Demo CA" -days 365

    echo "Create server credentials"
    openssl req -newkey ML-DSA-65 -keyout "$_WD/server/key.pem" -out "$_WD/server/csr.pem" -nodes -subj "/CN=Demo Server"
    openssl x509 -req -CAkey "$_WD/CA/CAkey.pem" -CA "$_WD/CA/CAcert.pem" -days 365 -CAcreateserial -in "$_WD/server/csr.pem" -out "$_WD/server/cert.pem"
fi

echo "Update GTA personality for client in the gta-key.pem"
echo "-----BEGIN GTA PRIVATE KEY-----" >"$_WD/client/gta-key.pem"
echo -n "pers_basic_${PROFILE},com.github.generic-trust-anchor-api.basic.tls" | base64 >>"$_WD/client/gta-key.pem"
echo "-----END GTA PRIVATE KEY-----" >>"$_WD/client/gta-key.pem"

echo "gta_identifier_assign"
gta-cli identifier_assign --id_type=identifier1 --id_val=identifier1

echo "Create GTA personality for client"
gta-cli personality_create --id_val=identifier1 --pers=pers_basic_${PROFILE} --app_name=Application --prof=com.github.generic-trust-anchor-api.basic.${PROFILE}

echo "gta_personality_enroll"
gta-cli personality_enroll --pers=pers_basic_${PROFILE} --prof=com.github.generic-trust-anchor-api.basic.enroll --ctx_attr com.github.generic-trust-anchor-api.enroll.subject_rdn="CN=Client Cert">"$_WD/client/csr.pem"

cat "$_WD/client/csr.pem"

echo "Create client certificate from public key"
openssl x509 -req -in "$_WD/client/csr.pem" -out "$_WD/client/cert.pem" -CAkey "$_WD/CA/CAkey.pem" -CA "$_WD/CA/CAcert.pem" -CAcreateserial -days 365

cat "$_WD/client/cert.pem"