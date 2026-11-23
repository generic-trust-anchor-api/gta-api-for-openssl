#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2026 Siemens
#
# SPDX-License-Identifier: Apache-2.0

function test_tls_mldsa
{
    echo "Test TLS with ML-DSA"
    echo "Prepare test"
    (cd demo/tls && ./prepare_tls_demo.sh mldsa &>/dev/null)
    echo "Start server"
    (cd demo/tls && timeout 10s ./start_server.sh &>/dev/null)&
    sleep 2
    
    cd demo/tls || exit 
    echo "Start client"
    run ./start_client.sh
    sleep 1
    
    assert_output_contains "Verification: OK"
    assert_output_contains "CONNECTED(00000003)"
    assert_output_contains "sigalg: ML-DSA-65"
    assert_output_contains "Tear down provider instance"
    assert_output_contains "Verify return code: 0 (ok)"
    # assert_output_contains "read R BLOCK"
    assert_output_contains "base_signature_sign_impl : b64_enc(data)="
    assert_error_contains "depth=1 CN=Demo CA"
    assert_error_contains "verify return:1"
    assert_error_contains "depth=0"
    assert_error_contains "verify return:1"
    return 0
}