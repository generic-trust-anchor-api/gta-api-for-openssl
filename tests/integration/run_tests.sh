#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025-2026 Siemens
#
# SPDX-License-Identifier: Apache-2.0

DIR="$PWD";

if [[ "${WORK_DIR}" == "" ]]; then
    export _WD=".."
else
    export _WD="${WORK_DIR}"
fi

echo "Working directory: $_WD"

if [[ -n "${BASH_TEST_TOOLS}" ]]; then
    TEST_TOOLS_SCRIPT="${BASH_TEST_TOOLS}"
else
    TEST_TOOLS_SCRIPT="$DIR/../../subprojects/bash_test_tools/bash_test_tools"
fi

if [[ ! -f "${TEST_TOOLS_SCRIPT}" ]]; then
    echo "Missing bash_test_tools helper: ${TEST_TOOLS_SCRIPT}" >&2
    echo "Run Meson setup first or export BASH_TEST_TOOLS to the helper path." >&2
    exit 1
fi

# shellcheck source=/dev/null
source "$TEST_TOOLS_SCRIPT"

if [[ ! -t 1 ]]; then
    function move_cursor_right
    {
        :
        return 0
    }
fi

function setup
{
    echo "Setup test env..."
    cd "$DIR/../.." || exit
    echo "Working directory: $_WD"
    echo -n "Current dir:"
    pwd
    echo "Test source dir: $DIR"
    return 0
}

function teardown
{
    echo "Teardown test..."
    killall -s 9 openssl &>/dev/null
    return 0
}

# Test definitions
# shellcheck source=/dev/null
source "$DIR/test_tls_ec.sh"
# shellcheck source=/dev/null
source "$DIR/test_tls_rsa.sh"

if [[ "${ENABLE_PQC:-false}" == "true" ]]; then
    # shellcheck source=/dev/null
    source "$DIR/test_tls_mldsa.sh"
fi

# shellcheck source=/dev/null
source "$DIR/test_cmp_ec.sh"

# OpenSSL 3.0/3.1 CMP does not use the provider's signature algorithm
# identifier for message protection, mislabeling RSA-PSS as PKCS#1 v1.5.
# Run the tests only with OpenSSL >= 3.2.0.
if openssl version 2>/dev/null | grep -Eq 'OpenSSL 3\.[01]\.'; then
    echo "Skipping CMP RSA test on OpenSSL 3.0.x/3.1.x"
else
    # shellcheck source=/dev/null
    source "$DIR/test_cmp_rsa.sh"
fi
if [[ "${ENABLE_PQC:-false}" == "true" ]]; then
    # shellcheck source=/dev/null
    source "$DIR/test_cmp_mldsa.sh"
fi

# Run all test functions
testrunner
