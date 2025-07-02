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
#include <openssl/x509.h>
#include <string.h>

#ifdef CUSTOM_EC_VERIFIER
static OSSL_FUNC_signature_digest_verify_init_fn gtaossl_provider_ecdsa_signature_digest_verify_init;
#endif

static OSSL_FUNC_signature_digest_sign_fn gtaossl_provider_ecdsa_signature_digest_sign;

#ifdef CUSTOM_EC_VERIFIER
static OSSL_FUNC_signature_digest_verify_update_fn gtaossl_provider_ecdsa_signature_digest_verify_update;
#endif

#ifdef CUSTOM_EC_VERIFIER
static OSSL_FUNC_signature_digest_verify_final_fn gtaossl_provider_ecdsa_signature_digest_verify_final;
#endif

#ifdef CUSTOM_EC_VERIFIER

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
static int gtaossl_provider_ecdsa_signature_digest_verify_init(
    void * ctx,
    const char * mdname,
    void * provkey,
    const OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    return gtaossl_provider_base_signature_digest_verify_init(ctx, mdname, provkey, params);
}
#endif

#ifdef CUSTOM_EC_VERIFIER

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
static int gtaossl_provider_ecdsa_signature_digest_verify_update(void * ctx, const unsigned char * data, size_t datalen)
{
    LOG_INFO("Update signature digest");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
#ifdef LOG_B64_ON
    char * dataBase64;
    base_64_encode(data, datalen, &dataBase64);

    LOG_TRACE_ARG("Input of %s : b64_enc(data)= %s", __func__, dataBase64);
#endif
    LOG_TRACE_ARG("Input of %s : datalen= %zu", __func__, datalen);
    return OK;
}
#endif

/**
 * The function extends the base signature digest sign.
 * Estimated signature size (EC_ESTIMATED_SIG_SIZE) 72.
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
static int gtaossl_provider_ecdsa_signature_digest_sign(
    void * ctx,
    unsigned char * sig,
    size_t * siglen,
    size_t sigsize,
    const unsigned char * data,
    size_t datalen)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    return gtaossl_provider_base_signature_digest_sign(ctx, sig, siglen, sigsize, data, datalen, EC_ESTIMATED_SIG_SIZE);
}

#ifdef CUSTOM_EC_VERIFIER

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
static int gtaossl_provider_ecdsa_signature_digest_verify_final(void * ctx, const unsigned char * sig, size_t siglen)
{
    LOG_INFO("Finalize signature digest");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    return OK;
}
#endif

/**
 * Get context parameter.
 *
 * @param[in] ctx: signature context
 * @param[in] params: OSSL parameter collection to extend the context (optional),
 *                  currently, this parameter is not used.
 *
 * @return OK = 1
 * @return NOK = 0
 */
static int gtaossl_provider_ecdsa_signature_get_ctx_params(void * ctx, OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    OSSL_PARAM * p;

    if (params == NULL) {
        LOG_DEBUG("There are no parameters");
        return OK;
    }

    LOG_DEBUG("Locate algorithm ID parameter");
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL) {
        unsigned char * aid = NULL;
        int aid_len;
        int r;

        ASN1_OBJECT * oid = OBJ_nid2obj(NID_ecdsa_with_SHA256);
        X509_ALGOR * x509_algor;
        if ((x509_algor = X509_ALGOR_new()) == NULL) {
            LOG_DEBUG("X509 Algorithm Object creation failed");
            return NOK;
        }

        X509_ALGOR_set0(x509_algor, oid, V_ASN1_NULL, NULL);

        aid_len = i2d_X509_ALGOR(x509_algor, &aid);

        LOG_DEBUG_ARG("Length of algorithm ID: %d", aid_len);
        r = OSSL_PARAM_set_octet_string(p, aid, aid_len);

        OPENSSL_free(aid);
        X509_ALGOR_free(x509_algor);
        LOG_DEBUG_ARG("Return %d", r);
        return r;
    }

    LOG_TRACE("Return OK");
    return OK;
}

static int gtaossl_provider_ecdsa_signature_set_ctx_params(void * ctx, const OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    return OK;
}

const OSSL_DISPATCH ecdsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))gtaossl_provider_base_signature_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))gtaossl_provider_base_signature_freectx},
#if 0
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, NULL},
    {OSSL_FUNC_SIGNATURE_SIGN, NULL},
#endif
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))gtaossl_provider_base_signature_digest_init},
#if 0
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, NULL},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))gtaossl_provider_base_signature_digest_sign_final},
#endif
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))gtaossl_provider_ecdsa_signature_digest_sign},
#ifdef CUSTOM_EC_VERIFIER
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))gtaossl_provider_ecdsa_signature_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))gtaossl_provider_ecdsa_signature_digest_verify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))gtaossl_provider_ecdsa_signature_digest_verify_final},
#endif
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))gtaossl_provider_ecdsa_signature_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))gtaossl_provider_base_signature_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))gtaossl_provider_ecdsa_signature_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))gtaossl_provider_base_signature_settable_ctx_params},
    {0, NULL}};
