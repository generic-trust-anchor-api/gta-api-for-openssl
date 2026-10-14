#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025-2026 Siemens
#
# SPDX-License-Identifier: Apache-2.0

readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1

set -euo pipefail

export _WD="${WORK_DIR:-.}"

echo "Working directory: $_WD"

export OPENSSL_CONF=../openssl_config/openssl_provider_gta_and_default.cnf
export GTA_STATE_DIRECTORY="$_WD/client/gta_api_state"

if openssl list -provider gta -providers; then
    echo "The gta provider installed... OK"
else
    echo "Missing gta provider"
    exit "$EXIT_FAILURE"
fi

echo "Start s_client..."
printf 'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n' | timeout 30s openssl s_client -quiet -key "$_WD/client/gta-key.pem" -cert "$_WD/client/cert.pem" -CAfile "$_WD/client/../CA/CAcert.pem" -connect localhost:44330
exit "$EXIT_SUCCESS"
