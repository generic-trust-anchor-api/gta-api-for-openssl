#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025-2026 Siemens
#
# SPDX-License-Identifier: Apache-2.0

readonly EXIT_SUCCESS=0

set -euo pipefail

export _WD="${WORK_DIR:-.}"

echo "Working directory: $_WD"

echo "Server configuration: using default OpenSSL provider only"

openssl s_server -cert "$_WD/server/cert.pem" -key "$_WD/server/key.pem" -www -tls1_3 -accept 44330 -CAfile "$_WD/server/../CA/CAcert.pem" -Verify 1
exit "$EXIT_SUCCESS"

# Debug options:
# -debug
# -security_debug
# -security_debug_verbose
# -verify_return_error
