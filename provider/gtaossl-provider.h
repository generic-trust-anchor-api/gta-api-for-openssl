/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GTAOSSL_PROVIDER_
#define _GTAOSSL_PROVIDER_

/*
 * The GTA-OpenSSL provider is a proof-of-concept project to demonstrate
 * establishing a TLS connection (and sending Certificate Request [CR] and
 * Key Update Request [KUR] CMP [RFC 4210] messages)
 * with OpenSSL and using the GTA API Software Provider
 * that implements GTA API core standard interfaces.
 *
 * More details about the GTA (Generic Trust Anchor) API can be found
 * in the ISO/IEC TS 30168 standard: https://www.iso.org/standard/53288.html
 *
 * The general approach is the following:
 *
 * 1. The GTA API is called in a custom OpenSSL provider for client authentication
 *    during the TLS handshake. Only the private key operation (signature generation) is
 *    performed by this provider. For the signature verification, the default provider is
 *    used.
 *
 * 2. Initialization and contexts: The decoder (GTA_DER_DECODER_CTX | GTA_DECODER_CTX),
 *    key manager (GTA_KEYMANAGER_CTX), and signature (GTA_SIGNATURE_CTX) contexts shall
 *    contain a GTA provider context (GTA_PROVIDER_CTX), which is initialized by the
 *    OSSL_provider_init function. In most cases, the asymmetric key object (GTA_PKEY)
 *    is also required to be initialized (allocate memory), but the following
 *    design decisions must be taken into consideration:
 *    a) Private and public keys are generated and stored with the GTA API CLI tool,
 *       and the GTA API SW provider shall open them based on the profile and personality.
 *    b) The public key can be exported from the GTA API data structure, but
 *       the private key must be non-exportable protected information.
 *
 * 3. Signing operation: The GTA-OpenSSL provider delegate the signing operation
 *    to the GTA API Software provider. The GTA API has a interface function
 *    (gta_authenticate_data_detached) to sign a data with a private key that is
 *    stored in the GTA context.
 *
 * 4. Key management, decoder and encoder functions need to adopt the GTA key handling
 *    during the loading, export, import and conversion of a key data:
 *    a) If necessary, retrieve the public key from the GTA API and parse the EC
 *       or Dilithium key data from different structures.
 *    b) The provider needs to support reading the ASN1 public key and X509 structures if
 *       the key type is of Elliptic Curve or Dilithium 2.
 *       @note: PublicKeyInfo_st (EC public key) is declared in provider\algorithms\ecdsa\gtaossl-provider-ecdsa-types.h
 *       implemented in provider\algorithms\ecdsa\gtaossl-provider-ecdsa-types.c
 *       @note: PublicKeyInfo_Dilithium_st (Dilithium public key) is declared in
 * provider\algorithms\dilithium\gtaossl-provider-dilithium-types.h implemented in
 * provider\algorithms\dilithium\gtaossl-provider-dilithium-types.c
 *
 * @note The proof-of-concept provider realizes only the client-side TLS connection.
 *       The certificate preparation script and server side use the open-quantum-safe/oqs-provider.
 *
 * @note The default setup of the GTA API software provider does not contain a post-quantum
 *       solution. It needs to be activated during the build of the SW provider.
 *
 * @note The proof-of-concept provider is implemented and tested with OpenSSL 3.2.0
 *
 * OpenSSL provider basics: https://docs.openssl.org/3.2/man7/provider/
 *
 * OQS Provider: https://github.com/open-quantum-safe/oqs-provider
 *
 * GTA API Core: https://github.com/generic-trust-anchor-api/gta-api-core
 *
 * GTA API Software Provider: https://github.com/generic-trust-anchor-api/gta-api-sw-provider
 *
 * RFC 4210: https://datatracker.ietf.org/doc/html/rfc4210
 */

#include <gta_api/gta_api.h>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/ec.h>

#define GTA_PROVIDER_NAME "GTA"
#define GTA_PROVIDER_VERSION "0.1"

#ifndef GTA_PROVIDER_BUILDINFO
#define GTA_PROVIDER_BUILDINFO "dev"
#endif

/**
 * Context structure of the GTA provider that combines
 * the OpenSSL descriptors and the GTA instance.
 */
typedef struct {
    const OSSL_CORE_HANDLE * core; /** Link to OSSL core. */
    OSSL_LIB_CTX * libctx;         /** Link to libcrypto context. */
    int status;                    /** Provider state flag: 1 if provider is active, 0 otherwise */
    gta_instance_handle_t h_inst;  /** GTA instance handle */
} GTA_PROVIDER_CTX;

/*
 * GTA_PKEY is a structure used to store
 * and manage the operations of asymmetric keys.
 */
typedef struct {
    char * string;
    gta_profile_name_t profile_name;
    gta_personality_name_t personality_name;
    char * pub_key;
    size_t pub_key_size;
    GTA_PROVIDER_CTX * provctx;
} GTA_PKEY;

/**
 * Provider initialization function, called by OSSL's
 * OSSL_provider_init(), which is the entry point of the provider.
 *
 * More details can be found at the following URLs:
 * - https://docs.openssl.org/3.0/man7/provider/#general
 * - https://docs.openssl.org/3.0/man7/provider-base/#synopsis
 *
 * @param[in] handle
 * @param[in] in
 *
 * @param[out] out
 * @param[out] provctx
 *
 * @return 1 on success
 * @return 0 on failure
 */
OPENSSL_EXPORT int OSSL_provider_init(
    const OSSL_CORE_HANDLE * handle,
    const OSSL_DISPATCH * in,
    const OSSL_DISPATCH ** out,
    void ** provctx);

#endif
