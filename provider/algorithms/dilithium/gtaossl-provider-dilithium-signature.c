/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../../config/gtaossl-provider-config.h"
#include "../../gtaossl-provider.h"
#include "../../logger/gtaossl-provider-logger.h"
#include "../gtaossl-provider-base-signature.h"
#include <gta_api/gta_api.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <string.h>

static OSSL_FUNC_signature_digest_sign_fn gtaossl_provider_dilithium_signature_digest_sign;
#if 0
static OSSL_FUNC_signature_digest_verify_init_fn gtaossl_provider_dilithium_signature_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn gtaossl_provider_dilithium_signature_digest_verify_update;
static OSSL_FUNC_signature_digest_verify_final_fn gtaossl_provider_dilithium_signature_digest_verify_final;
#endif

/**
 * The function extends the base signature digest verify init.
 *
 * @param[in] ctx: signature context
 * @param[in] mdname: name of the digest
 * @param[in] provkey: provider key object, that can be converted to GTA_PKEY
 * @param[in] params: OSSL parameter collection to extend the context (optional),
 *                  currently, this parameter is not used
 *
 * @return OK = 1
 * @return NOK = 0
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-signature/#description
 */
#if 0
static int gtaossl_provider_dilithium_signature_digest_verify_init(
    void * ctx,
    const char * mdname,
    void * provkey,
    const OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    return gtaossl_provider_base_signature_digest_verify_init(ctx, mdname, provkey, params);
}
#endif

/**
 * This function updates a signature operation but does not contain any implementation.
 * It is used only for debugging purposes.
 *
 * @param[in] ctx: signature context (not used)
 * @param[in] data: input byte array
 * @param[in] datalen: length of input byte array
 * @return OK = 1
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-signature/#description
 */
#if 0
static int
gtaossl_provider_dilithium_signature_digest_verify_update(void * ctx, const unsigned char * data, size_t datalen)
{
    LOG_INFO("Update signature digest");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)ctx;

#ifdef LOG_B64_ON
    char * dataBase64;
    base_64_encode(data, datalen, &dataBase64);

    LOG_TRACE_ARG("Input of %s : b64_enc(data)= %s", __func__, dataBase64);
#endif

    LOG_TRACE_ARG("Input of %s : datalen= %zu", __func__, datalen);

    LOG_TRACE_KEY_DATA(LOG__EOM);
    for (int i = 0; i < datalen; i++) {
        LOG_TRACE_KEY_DATA_ARG("%02X ", (unsigned int)(data[i] & 0xFF));
    }
    LOG_TRACE_KEY_DATA(LOG__EOM);

    return OK;
}
#endif

/**
 * The function extends the base signature digest sign.
 * Estimated signature size (OQS_ESTIMATED_SIG_SIZE) 2420.
 *
 * @param[in] ctx: signature context
 * @param[in] sigsize: expected signature size in bytes (from OpenSSL)
 * @param[in] data: input byte array
 * @param[in] datalen: length of input byte array
 * @param[in] estimated_sig_size: expected signature size of a specific algorithm
 * @param[out] sig: signature value byte array
 * @param[out] siglen: length of the newly generated signature
 *
 * @return OK = 1
 * @return NOK = 0
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-signature/#description
 */
static int gtaossl_provider_dilithium_signature_digest_sign(
    void * ctx,
    unsigned char * sig,
    size_t * siglen,
    size_t sigsize,
    const unsigned char * data,
    size_t datalen)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    return gtaossl_provider_base_signature_digest_sign(
        ctx, sig, siglen, sigsize, data, datalen, OQS_ESTIMATED_SIG_SIZE);
}

/**
 * This function verify a signature but does not contain any implementation.
 * It is used only for debugging purposes.
 *
 *
 * @param[in] ctx: signature context (not used)
 * @param[in] sig: input byte array
 * @param[in] siglen: length of input byte array
 * @return OK = 1
 */
#if 0
static int
gtaossl_provider_dilithium_signature_digest_verify_final(void * ctx, const unsigned char * sig, size_t siglen)
{
    LOG_INFO("Finalize signature digest");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)ctx;

#ifdef LOG_B64_ON
    char * signBase64;
    base_64_encode(sig, siglen, &signBase64);

    LOG_TRACE_ARG("Input of %s : b64_enc(sig)= %s", __func__, signBase64);
#endif
    LOG_TRACE_ARG("Input of %s : siglen= %zu", __func__, siglen);

    return OK;
}
#endif

static int gtaossl_provider_dilithium_signature_get_ctx_params(void * ctx, OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)ctx;
    (void)params;

    return NOK;
}

static int gtaossl_provider_dilithium_signature_set_ctx_params(void * ctx, const OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)ctx;
    (void)params;

    return OK;
}

const OSSL_DISPATCH dilithium_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))gtaossl_provider_base_signature_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))gtaossl_provider_base_signature_freectx},
#if 0
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, NULL},
    {OSSL_FUNC_SIGNATURE_SIGN, NULL},
#endif
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))gtaossl_provider_base_signature_digest_init},
#if 0
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, NULL},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, NULL},
#endif
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))gtaossl_provider_dilithium_signature_digest_sign},
#if 0
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, NULL},
    {OSSL_FUNC_SIGNATURE_VERIFY, NULL},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, NULL},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, NULL},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, NULL},
#endif
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))gtaossl_provider_dilithium_signature_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))gtaossl_provider_base_signature_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))gtaossl_provider_dilithium_signature_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))gtaossl_provider_base_signature_settable_ctx_params},
    {0, NULL}};
