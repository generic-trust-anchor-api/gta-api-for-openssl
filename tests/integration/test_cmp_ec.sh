#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025-2026 Siemens
#
# SPDX-License-Identifier: Apache-2.0

function test_cmp_ec
{
    echo "Test CMP with EC"
    cd demo/cmp || exit

    echo "Prepare test"
    run ./prepare_cmp_demo.sh ec
    assert_success

    echo "Create and send CMP cr"
    run ./send_cr_cmp_message.sh 
    assert_success
    assert_output_contains "CMP info: sending CR" 
    assert_output_contains "CMP info: received CP"
    assert_output_contains "CMP DEBUG: successfully validated signature-based CMP message protection using trust store"

    echo "Create and send CMP kur"
    run ./send_kur_cmp_message.sh
    assert_success
    assert_output_contains "CMP info: sending KUR"
    assert_output_contains "CMP info: received KUP"
    assert_output_contains "CMP DEBUG: successfully validated signature-based CMP message protection using trust store"

    return 0
}