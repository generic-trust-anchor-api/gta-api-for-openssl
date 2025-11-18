/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GTAOSSL_PROVIDER_CONFIG_H_
#define _GTAOSSL_PROVIDER_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

#define NOK 0
#define OK 1

#define NO_SIZE_INFO -1

#define PREQS_EC "EC"

#define GTA_DATA_STRUCTURE_PARAM "GTA"

#define DER_DATA_STRUCTURE_PARAM "DER"

#define OQS_DILITHIUM_2 "dilithium2"
#define OQS_DILITHIUM_2_OID "1.3.6.1.4.1.2.267.7.4.4"

#define OQS_ESTIMATED_SIG_SIZE 2420
#define OQS_SIG_BUFFER 4000

#define EC_ESTIMATED_SIG_SIZE 72
#define EC_SIG_BUFFER 1000

#define GTA_READ_BUFFER 2048
#define GTA_READ_BUFFER_FOR_CA_CERT 4096
#define SIZE_OF_GTA_O_BUFFER 1000
#define SIZE_OF_GTA_O_BUFFER_FOR_DILITHIUM 4000

#define GTA_KEY_TYPE_ATTRIBUTE "com.github.generic-trust-anchor-api.keytype.openssl"

#define PUB_KEY_BEGIN_TAG "-----BEGIN PUBLIC KEY-----\n"
#define PUB_KEY_END_TAG "\n-----END PUBLIC KEY-----\n";

#ifdef __cplusplus
}
#endif

#endif /* _GTAOSSL_PROVIDER_CONFIG_H_ */
