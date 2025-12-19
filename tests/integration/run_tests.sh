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
    killall -s 9 openssl
    return 0
}

# Test definitions
# shellcheck source=/dev/null
source "$DIR/test_tls_default.sh"
# shellcheck source=/dev/null
source "$DIR/test_tls_ec.sh"
# shellcheck source=/dev/null
source "$DIR/test_tls_rsa.sh"
# Post quantum support is deactivated
# shellcheck source=/dev/null
# source "$DIR/test_tls_dilithium.sh"
# shellcheck source=/dev/null
source "$DIR/test_cmp_ec.sh"

# Run all test functions
testrunner
