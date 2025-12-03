/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GTAOSSL_PROVIDER_BASE_SIGNATURE_H_
#define _GTAOSSL_PROVIDER_BASE_SIGNATURE_H_

#include "../gtaossl-provider.h"
#include <openssl/core_dispatch.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Extended signature context
 * (with GTA context)
 */
typedef struct {
    GTA_PROVIDER_CTX * provider_ctx;
    size_t max_sig_size;
    gta_context_handle_t h_ctx;
} GTA_SIGNATURE_CTX;

/**
 * The signature new context function should create and return a pointer
 * to a structure that is extended with a GTA provider context.
 * This structure holds the signature context during the signature operation.
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-signature/#description
 *
 * @param[in] propq: a property query string (optional),
 *                   currently, this parameter is not used.
 * @param[in/out] provctx: the parameter is a provider context
 *                generated during the provider initialization.
 * @return a new context.
 *
 * The preprocessor-generated function signature:
 *
 * void *gtaossl_provider_base_signature_newctx(void *provctx, const char *propq)
 */
OSSL_FUNC_signature_newctx_fn gtaossl_provider_base_signature_newctx;

/**
 * The function should free the signature context.
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-signature/#description
 *
 * @param[in] ctx pointer of the signing context
 *
 * The preprocessor-generated function signature:
 *
 * void gtaossl_provider_base_signature_freectx(void *ctx)
 */
OSSL_FUNC_signature_freectx_fn gtaossl_provider_base_signature_freectx;

/**
 * Initialization of the signing context:
 *
 * 1. The init function reads the personality and profile name from the provider key
 *    input parameter.
 *
 * 2. This function tries to open the GTA context
 *    from the personality and profile names.
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-signature/#description
 *
 * @param[in] ctx: signature context
 * @param[in] mdname: name of the digest
 * @param[in] provkey: provider key object that can be converted to GTA_PKEY
 * @param[in] params[]: OSSL parameter collection to extend the context (optional),
 *                  currently, this parameter is not used.
 * @return OK = 1
 * @return NOK = 0
 *
 * The preprocessor-generated function signature:
 *
 * int gtaossl_provider_base_signature_digest_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM
 * params[])
 */
OSSL_FUNC_signature_digest_sign_init_fn gtaossl_provider_base_signature_digest_init;

/**
 * The function does the actual signing.
 *
 * @param[in] ctx: signature context
 * @param[in] sigsize: expected signature size in bytes (from OpenSSL)
 * @param[in] data: input byte array
 * @param[in] datalen: length of input byte array
 * @param[out] sig: signature value byte array
 * @param[out] siglen: length of the newly generated signature
 *
 * @return OK = 1
 * @return NOK = 0
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-signature/#description
 */
OSSL_FUNC_signature_digest_sign_fn gtaossl_provider_base_signature_digest_sign;

/**
 * Configure the gettable OSSL parameters:
 *
 * In this case, the ID of the signature algorithm will be provided.
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-signature/#description
 *
 * @param[in] ctx: signature context (not used)
 * @param[in] provctx: provider context (not used)
 * @return array of OSSL_PARAM
 *
 * The preprocessor-generated function signature:
 *
 * const OSSL_PARAM *gtaossl_provider_base_signature_gettable_ctx_params(void *ctx, void *provctx)
 */
OSSL_FUNC_signature_gettable_ctx_params_fn gtaossl_provider_base_signature_gettable_ctx_params;

/**
 * Set ctx parameters.
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-signature/#description
 *
 * @param[in] ctx: signature context (not used)
 * @return array of OSSL_PARAM
 */
OSSL_FUNC_signature_set_ctx_params_fn gtaossl_provider_base_signature_set_ctx_params;

#ifdef __cplusplus
}
#endif

#endif /* _GTAOSSL_PROVIDER_BASE_SIGNATURE_H_ */
