/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GTAOSSL_PROVIDER_EC_TYPES_H_
#define _GTAOSSL_PROVIDER_EC_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

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

/*
 * Example Structure for EC public key:
 *
 * SubjectPublicKeyInfo SEQUENCE (2 elem)
 *   algorithm AlgorithmIdentifier SEQUENCE (2 elem)
 *          algorithm OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
 *          parameters ANY OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named elliptic curve)
 *   subjectPublicKey BIT STRING (520 bit) 0000010001001001001000110010011101000101101010101111110001010100110001…
 *
 * Reverted structure:
 * https://lapo.it/asn1js/#MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESSMnRar8VMTuqBfayu085FuJb5L7PANK8dkIKJfSpltPFkOeg6dtgD4dGJYfczDL1YmkQhmvTQ1dvoUSaZVeHQ
 */
typedef struct AlgorithmIdentifier_st {
    ASN1_OBJECT * algorithm;
    ASN1_OBJECT * parameters;
} AlgorithmIdentifier;
DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier)

typedef struct PublicKeyInfo_st {
    AlgorithmIdentifier * algorithm;
    ASN1_BIT_STRING * subjectPublicKey;
} SubjectPublicKeyInfo;
DECLARE_ASN1_FUNCTIONS(SubjectPublicKeyInfo)

#ifdef __cplusplus
}
#endif

#endif /* _GTAOSSL_PROVIDER_EC_TYPES_H_ */
