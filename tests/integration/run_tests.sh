#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

DIR="$PWD"; 

# shellcheck source=/dev/null
source "$DIR/tools/bash_test_tools"

function setup
{
    echo "Setup test env..."
    cd ../..    
    return 0
}

function teardown
{
    echo "Teardown test..."
    killall -s 9 openssl
    
    pwd   
    
    echo "Clean up test folder..."
    rm -rf ../CA
    echo "The CA dir removed"
    rm -rf ../client/serialized_data/*
    echo "The client/serialized_data dir removed"
    rm -rf ../client/cert.pem
    echo "The client/cert.pem file removed"
    rm -rf ../client/csr.pem
    echo "The client/csr.pem file removed"
    rm -rf ../server/*.pem
    echo "The pem file in server dir removed"
    rm -rf ../cmp/cmp_example/*
    echo "The cmp/cmp_example dir removed"
    return 0
}

# Test definitions
# shellcheck source=/dev/null
source "$DIR/test_no_parameter_during_the_init.sh"
# shellcheck source=/dev/null
source "$DIR/test_ec_parameter_during_the_init.sh"
# source "$DIR/test_dilithium_parameter_during_the_init.sh"
# shellcheck source=/dev/null
source "$DIR/test_send_cmp_to_demo_ca.sh"
# shellcheck source=/dev/null
source "$DIR/test_send_kur_cmp_to_demo_ca.sh"

# Run all test functions
testrunner