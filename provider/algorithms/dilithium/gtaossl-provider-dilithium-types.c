/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtaossl-provider-dilithium-types.h"

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/types.h>

ASN1_SEQUENCE(AlgorithmIdentifierDilithium) =
    {
        ASN1_SIMPLE(AlgorithmIdentifierDilithium, algorithm, ASN1_OBJECT),
} ASN1_SEQUENCE_END(AlgorithmIdentifierDilithium)

        IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifierDilithium)

            ASN1_SEQUENCE(SubjectPublicKeyInfoDilithium) =
                {
                    ASN1_SIMPLE(SubjectPublicKeyInfoDilithium, algorithm, AlgorithmIdentifierDilithium),
                    ASN1_SIMPLE(SubjectPublicKeyInfoDilithium, public_key_data, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(SubjectPublicKeyInfoDilithium)

                    IMPLEMENT_ASN1_FUNCTIONS(SubjectPublicKeyInfoDilithium)
