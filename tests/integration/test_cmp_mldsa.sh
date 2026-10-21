#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2026 Siemens
#
# SPDX-License-Identifier: Apache-2.0

function test_cmp_mldsa
{
    echo "Test CMP with ML-DSA"
    cd demo/cmp || exit

    run "./0_prepare_cmp_demo.sh"
    assert_exit_success
    assert_terminated_normally

    run "./1_imprint_idevid.sh mldsa"
    assert_success
    assert_output_contains "CMP info: sending IR" 
    assert_output_contains "CMP info: received IP"
    assert_output_contains "Attribute Type:   ch.iec.30168.trustlist.certificate.self.x509"
    assert_output_contains "Attribute Name:   IDevID_EE"


    run "./2_bootstrap_ldevid-generic.sh mldsa"
    assert_success
    assert_output_contains "CMP info: sending CR"
    assert_output_contains "CMP info: received CP"
    assert_output_contains "Attribute Type:   ch.iec.30168.trustlist.certificate.self.x509"
    assert_output_contains "Attribute Name:   LDevID-Generic_EE"
    assert_output_contains "Attribute Type:   ch.iec.30168.trustlist.certificate.trusted.x509v3"
    assert_output_contains "Attribute Name:   LDevID-Generic_TA"

    run "./3_enroll_ldevid-app.sh mldsa"
    assert_success
    assert_output_contains "CMP info: sending CR"
    assert_output_contains "CMP info: received CP"
    assert_output_contains "Attribute Type:   ch.iec.30168.trustlist.certificate.self.x509"
    assert_output_contains "Attribute Name:   LDevID-App_EE"

    run "./4_update_ldevid-app.sh"
    assert_success
    assert_output_contains "CMP info: sending KUR"
    assert_output_contains "CMP info: received KUP"
    assert_output_contains "Attribute Type:   ch.iec.30168.trustlist.certificate.self.x509"
    assert_output_contains "Attribute Name:   LDevID-App_EE"

    return 0
}