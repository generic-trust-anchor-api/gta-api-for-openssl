#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

function test_send_kur_cmp_to_fake_ca
{
    echo "Test sending a cmp massege to CA server"
    echo "Prepare test"
    (cd demo && ./prepare_cmp_demo.sh &>/dev/null)
    sleep 2

    echo "Create and send cr cmp message"
    (cd demo/cmp && ./send_cr_cmp_message.sh &>/dev/null)    
    sleep 2

    cd demo/cmp || exit 
    echo "Create and send kur cmp message"
    run ./send_kur_cmp_message.sh
    sleep 1
 
    assert_output_contains "CMP DEBUG: success building chain for own CMP signer cert"
    assert_output_contains "CMP DEBUG: Starting new transaction"
    assert_output_contains "CMP info: sending KUR"
    assert_output_contains "CMP info: received KUP"
    assert_output_contains "CMP DEBUG: successfully validated signature-based CMP message protection using trust store"
    assert_output_contains "CMP DEBUG: validating CMP message"
    assert_output_contains "Attribute Name:   Insta CA cert"
    assert_output_contains "Attribute Name:   Test Cert"
    return 0
}