#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

if [ "${WORK_DIR}" == "" ]; then
    export _WD=".."
else
    export _WD="${WORK_DIR}"
fi

echo "Working directory: $_WD"

export OPENSSL_CONF=../../openssl_config/openssl_provider_gta_and_default.cnf

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

echo "Start s_client..."
openssl s_client -key "$_WD/client/gta-key.pem" -cert "$_WD/client/cert.pem" -CAfile "$_WD/client/../CA/CAcert.pem" -connect localhost:44330
