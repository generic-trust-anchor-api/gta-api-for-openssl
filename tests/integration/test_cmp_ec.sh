#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025-2026 Siemens
#
# SPDX-License-Identifier: Apache-2.0

function test_cmp_ec
{
    echo "Test CMP with EC"
    echo "Prepare test"
    (cd demo/cmp && ./prepare_cmp_demo.sh &>/dev/null)
    sleep 2

    echo "Create and send CMP cr"
    cd demo/cmp || exit 
    run ./send_cr_cmp_message.sh 
    sleep 2

    assert_output_contains "CMP info: sending CR" 
    assert_output_contains "CMP DEBUG: finished reading response from CMP server"
    assert_output_contains "CMP info: received CP"
    assert_output_contains "CMP DEBUG: successfully validated signature-based CMP message protection using trust store"
    assert_output_contains "CMP DEBUG: validating CMP message"
    assert_output_contains "Attribute Name:   Test Cert"
    assert_output_contains "Attribute Name:   ECC Root CA"
    assert_output_contains "Attribute Name:   Root CA"

    echo "Create and send CMP kur"
    run ./send_kur_cmp_message.sh
    sleep 1
 
    assert_output_contains "CMP DEBUG: successfully validated signature-based CMP message protection using trust store"
    assert_output_contains "CMP DEBUG: success building chain for own CMP signer cert"
    assert_output_contains "CMP DEBUG: Starting new transaction"
    assert_output_contains "CMP info: sending KUR"
    assert_output_contains "CMP info: received KUP"
    assert_output_contains "CMP DEBUG: successfully validated signature-based CMP message protection using trust store"
    assert_output_contains "CMP DEBUG: validating CMP message"
    assert_output_contains "Attribute Name:   Test Cert"
    assert_output_contains "Attribute Name:   ECC Root CA"
    assert_output_contains "Attribute Name:   Root CA"
    return 0
}