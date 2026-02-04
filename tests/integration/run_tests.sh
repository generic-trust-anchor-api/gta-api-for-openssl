#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

DIR="$PWD"; 

if [ "${WORK_DIR}" == "" ]; then
    export _WD=".."
else
    export _WD="${WORK_DIR}"
fi

echo "Working directory: $_WD"

# shellcheck source=/dev/null
source "$DIR/tools/bash_test_tools"

function setup
{
    echo "Setup test env..."
    cd "$DIR/../.."
    echo "Working directory: $_WD"
    pwd
    echo "Test source dir: $DIR"
    return 0
}

function teardown
{
    echo "Teardown test..."
    killall -s 9 openssl
    
    pwd   
    
    echo "Clean up test folder..."
    rm -rf "$_WD/CA"
    echo "The CA dir removed"
    rm -rf "$_WD/client/serialized_data/"*
    echo "The client/serialized_data dir removed"
    rm -rf "$_WD/client/cert.pem"
    echo "The client/cert.pem file removed"
    rm -rf "$_WD/client/csr.pem"
    echo "The client/csr.pem file removed"
    rm -rf "$_WD/server/"*.pem
    echo "The pem file in server dir removed"
    rm -rf "$_WD/cmp/cmp_example/"*
    echo "The cmp/cmp_example dir removed"
    return 0
}

# Test definitions
# shellcheck source=/dev/null
source "$DIR/test_tls_default.sh"
# shellcheck source=/dev/null
source "$DIR/test_tls_ec.sh"
# Post quantum support is deactivated
# shellcheck source=/dev/null
# source "$DIR/test_tls_dilithium.sh"
# shellcheck source=/dev/null
source "$DIR/test_cmp_cr.sh"
# shellcheck source=/dev/null
source "$DIR/test_cmp_kur.sh"

# Run all test functions
testrunner