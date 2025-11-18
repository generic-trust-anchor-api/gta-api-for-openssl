/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtaossl-provider-ecdsa-types.h"

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

ASN1_SEQUENCE(AlgorithmIdentifier) =
    {
        ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
        ASN1_SIMPLE(AlgorithmIdentifier, parameters, ASN1_OBJECT),
} ASN1_SEQUENCE_END(AlgorithmIdentifier)

        IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier)

            ASN1_SEQUENCE(SubjectPublicKeyInfo) =
                {
                    ASN1_SIMPLE(SubjectPublicKeyInfo, algorithm, AlgorithmIdentifier),
                    ASN1_SIMPLE(SubjectPublicKeyInfo, subjectPublicKey, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(SubjectPublicKeyInfo)

                    IMPLEMENT_ASN1_FUNCTIONS(SubjectPublicKeyInfo)
