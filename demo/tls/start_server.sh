#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

if [[ "${WORK_DIR}" == "" ]]; then
    export _WD="."
else
    export _WD="${WORK_DIR}"
fi

echo "Working directory: $_WD"

# OPENSSL_CONF=../openssl_config/openssl_provider_oqs.cnf

# KEM_ALG=kyber768

#if openssl list -provider oqsprovider -providers; then
#    echo "The oqsprovider installed... OK"
#else
#    echo "Missing oqsprovider provider"
#    echo "Copy oqsprovider objeect from the ./demo/openssl_config to the /usr/lib/x86_64-linux-gnu/ossl-modules and/or /usr/local/lib64/ossl-modules"
#    echo "or define path property of the oqsprovider.so file in the ../openssl_config/openssl_provider_oqs.cnf".
#    echo "For example: module = <path of so file>"
#    exit 1
#fi

# Start command with Dilithium base key materials 
#openssl s_server -provider default -provider oqsprovider -cert "$_WD/server/cert.pem" -key "$_WD/server/key.pem" -www -tls1_3 -accept 44330 -CAfile "$_WD/server/../CA/CAcert.pem" -Verify 1
openssl s_server -cert "$_WD/server/cert.pem" -key "$_WD/server/key.pem" -www -tls1_3 -accept 44330 -CAfile "$_WD/server/../CA/CAcert.pem" -Verify 1

# Debug options:
# -debug
# -security_debug
# -security_debug_verbose
# -verify_return_error
