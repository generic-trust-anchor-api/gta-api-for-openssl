#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

function test_send_cmp_to_fake_ca
{
    echo "Test sending a cmp massege to CA server"
    echo "Prepare test"
    (cd demo && ./prepare_cmp_demo.sh &>/dev/null)
    sleep 2
    
    cd demo/cmp || exit 
    echo "Create and send cmp message"
    run ./send_cr_cmp_message.sh
    sleep 1
 
    assert_output_contains "CMP info: sending CR" 
    assert_output_contains "CMP DEBUG: finished reading response from CMP server"
    assert_output_contains "CMP info: received CP"
    assert_output_contains "CMP DEBUG: successfully validated PBM-based CMP message protection"
    assert_output_contains "CMP DEBUG: validating CMP message"
    assert_output_contains "Attribute Name:   Test Cert"
    return 0
}