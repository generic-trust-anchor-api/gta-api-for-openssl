#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025 Siemens
#
# SPDX-License-Identifier: Apache-2.0

function test_dilithium_parameter_during_the_init
{
    echo "Test the dilithium value"
    echo "Prepare test"
    (cd demo && ./prepare_demo.sh dilithium &>/dev/null)
    echo "Start server"
    (cd demo/server && timeout 10s ./start_server.sh &>/dev/null)&
    sleep 2

    cd demo/client || exit 
    echo "Start client"
    run ./start_client.sh
    sleep 1
    
    assert_output_contains "Verification: OK"
    assert_output_contains "Peer signature type: dilithium2"
    # assert_output_contains "Connecting to 127.0.0.1"
    assert_output_contains "Tear down provider instance"
    assert_output_contains "Verify return code: 0 (ok)"
    assert_output_contains "read R BLOCK"
    assert_output_contains "gtaossl_provider_base_signature_digest_sign : b64_enc(data)="
    assert_error_contains "depth=1 CN=Demo CA"
    assert_error_contains "verify return:1"
    assert_error_contains "depth=0"
    assert_error_contains "verify return:1"
}