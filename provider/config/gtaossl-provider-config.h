/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GTAOSSL_PROVIDER_CONFIG_H_
#define _GTAOSSL_PROVIDER_CONFIG_H_

#include <openssl/rsa.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NOK 0
#define OK 1

#define NO_SIZE_INFO -1

#define PREQS_EC "EC"
#define PREQS_RSA "RSA"

#define GTA_DATA_STRUCTURE_PARAM "GTA"

#define DER_DATA_STRUCTURE_PARAM "DER"

#define OQS_DILITHIUM_2 "dilithium2"
#define OQS_DILITHIUM_2_OID "1.3.6.1.4.1.2.267.7.4.4"

/* Some defines which depend on the profile */
#define SUPPORTED_DIGEST NID_sha256
#define SUPPORTED_PAD_MODE RSA_PKCS1_PSS_PADDING
#define SUPPORTED_PSS_SALTLEN "digest"

#define GTA_READ_BUFFER 2048
#define GTA_READ_BUFFER_FOR_CA_CERT 4096
#define MAXLEN_ATTRIBUTE_NAME 1000
#define SIZE_OF_GTA_O_BUFFER 1000
#define SIZE_OF_GTA_O_BUFFER_FOR_DILITHIUM 4000

#define GTA_KEY_TYPE_ATTRIBUTE "com.github.generic-trust-anchor-api.keytype.openssl"
#define GTA_TRUSTED_CERTIFICATE_TYPE "ch.iec.30168.trustlist.certificate.trusted.x509v3"

#define PUB_KEY_BEGIN_TAG "-----BEGIN PUBLIC KEY-----\n"
#define PUB_KEY_END_TAG "\n-----END PUBLIC KEY-----\n"

#ifdef __cplusplus
}
#endif

#endif /* _GTAOSSL_PROVIDER_CONFIG_H_ */
