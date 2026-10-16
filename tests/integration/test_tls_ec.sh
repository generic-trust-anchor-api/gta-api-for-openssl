#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025-2026 Siemens
#
# SPDX-License-Identifier: Apache-2.0

function test_tls_ec
{
    echo "Test the TLS with EC"
    cd demo/tls || exit

    echo "Prepare test"
    run ./prepare_tls_demo.sh ec
    assert_exit_success
    assert_terminated_normally

    echo "Start server"
    timeout 10s ./start_server.sh &>/dev/null &
    sleep 2
    
    echo "Start client"
    run ./start_client.sh
    assert_exit_success
    assert_terminated_normally
    assert_output_contains "HTTP/1.0 200 ok"

    pkill openssl
    return 0
}