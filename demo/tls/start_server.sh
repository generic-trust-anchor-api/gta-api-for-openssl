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

openssl s_server -cert "$_WD/server/cert.pem" -key "$_WD/server/key.pem" -www -tls1_3 -accept 44330 -CAfile "$_WD/server/../CA/CAcert.pem" -Verify 1

# Debug options:
# -debug
# -security_debug
# -security_debug_verbose
# -verify_return_error
