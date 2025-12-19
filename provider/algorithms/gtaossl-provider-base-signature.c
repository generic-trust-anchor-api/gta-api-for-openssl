/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtaossl-provider-base-signature.h"

#include "../config/gtaossl-provider-config.h"
#include "../gtaossl-provider.h"
#include "../logger/gtaossl-provider-logger.h"
#include "../stream/streams.h"
#include "gtaossl-provider-base-keymgmt.h"
#include <gta_api/gta_api.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <string.h>

/**
 * The signature new context function should create and return a pointer
 * to a structure that is extended with a GTA provider context.
 */
void * gtaossl_provider_base_signature_newctx(void * provctx, const char * propq)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("Input of %s : %s", __func__, propq);

    GTA_PROVIDER_CTX * cprov = provctx;
    GTA_SIGNATURE_CTX * sctx = OPENSSL_zalloc(sizeof(GTA_SIGNATURE_CTX));

    sctx->provider_ctx = cprov;
    if (sctx == NULL) {
        LOG_WARN("sctx null");
        return NULL;
    }

    return sctx;
}

/**
 * The function should free the signature context.
 */
void gtaossl_provider_base_signature_freectx(void * ctx)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    GTA_SIGNATURE_CTX * sctx = ctx;

    if (sctx == NULL) {
        LOG_WARN("sctx null");
        return;
    }

    OPENSSL_clear_free(sctx, sizeof(GTA_SIGNATURE_CTX));
}

/**
 * This helper functions checks if the context params are supported
 * by the provider. It should work for all algorithms.
 */
static int base_signature_check_ctx_params(const OSSL_PARAM params[], const char * mdname)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    const OSSL_PARAM * p = NULL;

    /* Check mdname if there */
    if ((NULL != mdname) && (SUPPORTED_DIGEST != EVP_MD_get_type(EVP_get_digestbyname(mdname)))) {
        LOG_ERROR_ARG("Digest %s unsupported", mdname);
        return NOK;
    }

    if (NULL == params) {
        LOG_ERROR("params is NULL -> nothing more to check");
        return OK;
    }

    LOG_DEBUG("Locate OSSL_SIGNATURE_PARAM_PAD_MODE");
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {
        if (p->data_type == OSSL_PARAM_INTEGER) {
            int pad_mode;

            if (!OSSL_PARAM_get_int(p, &pad_mode)) {
                LOG_ERROR("OSSL_PARAM_get_int failed");
                return NOK;
            }
            if (SUPPORTED_PAD_MODE != pad_mode) {
                LOG_ERROR_ARG("OSSL_SIGNATURE_PARAM_PAD_MODE %i unsupported", pad_mode);
                return NOK;
            }
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            /* This case is currently unsupported */
            LOG_ERROR("This case is currently unsupported");
            return NOK;
        } else {
            return NOK;
        }
    }

    LOG_DEBUG("Locate OSSL_SIGNATURE_PARAM_DIGEST");
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if ((p != NULL) && ((p->data_type != OSSL_PARAM_UTF8_STRING) ||
                        (SUPPORTED_DIGEST != EVP_MD_get_type(EVP_get_digestbyname((char *)p->data))))) {
        LOG_ERROR_ARG("OSSL_SIGNATURE_PARAM_DIGEST %s not supported", (char *)p->data);
        return NOK;
    }

    LOG_DEBUG("Locate OSSL_SIGNATURE_PARAM_PSS_SALTLEN");
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if ((p != NULL) && ((p->data_type != OSSL_PARAM_UTF8_STRING) && (0 != strcmp(SUPPORTED_PSS_SALTLEN, p->data)))) {
        LOG_ERROR_ARG("OSSL_SIGNATURE_PARAM_PSS_SALTLEN %s not supported", (char *)p->data);
        return NOK;
    }

    return OK;
}

/**
 * Initialization of the signing context.
 */
int gtaossl_provider_base_signature_digest_init(
    void * ctx,
    const char * mdname,
    void * provkey,
    const OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("Input parameter mdname: %s", mdname);

    /* Check if params are supported */
    if (!base_signature_check_ctx_params(params, mdname)) {
        return NOK;
    }

    GTA_SIGNATURE_CTX * sctx = ctx;
    GTA_PKEY * pkey = provkey;

    if (NULL == pkey) {
        LOG_ERROR("No pkey!");
        return NOK;
    }

    LOG_TRACE_ARG("pkey->string: %s", pkey->string);
    LOG_TRACE_ARG("pkey->profile_name: %s", pkey->profile_name);
    LOG_TRACE_ARG("pkey->personality_name: %s", pkey->personality_name);

    /* Get may signature size: this may be optimized in the future*/
    EVP_PKEY * key = NULL;
    if (!base_get_public_key(pkey, &key)) {
        LOG_ERROR("Converting GTA_PKEY to EVP_PKEY failed");
        return NOK;
    }
    sctx->max_sig_size = EVP_PKEY_get_size(key);
    EVP_PKEY_free(key);

    /* Open a GTA API context with the given personality name and profile name */
    if ((NULL != pkey->profile_name) && (NULL != pkey->personality_name)) {
        gta_errinfo_t errinfo = 0;
        sctx->h_ctx =
            gta_context_open(sctx->provider_ctx->h_inst, pkey->personality_name, pkey->profile_name, &errinfo);
        if (NULL == sctx->h_ctx) {
            LOG_ERROR_ARG("GTA context open failed: %lu", errinfo);
            return NOK;
        }
    }
    return OK;
}

int gtaossl_provider_base_signature_digest_sign(
    void * ctx,
    unsigned char * sig,
    size_t * siglen,
    size_t sigsize,
    const unsigned char * data,
    size_t datalen)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    GTA_SIGNATURE_CTX * sctx = ctx;

    if (sig == NULL) {
        LOG_TRACE_ARG("Return max signature size: %zu", sctx->max_sig_size);
        *siglen = sctx->max_sig_size;
        return *siglen > 0;
    }

    /* GTA API */
    gta_errinfo_t errinfo = 0;

    istream_from_buf_t istream_data_to_seal = {0};
    ostream_to_buf_t ostream_seal = {0};

    istream_from_buf_init(&istream_data_to_seal, (const char *)data, datalen);
    ostream_to_buf_init(&ostream_seal, (char *)sig, sigsize);

    if (OK != gta_authenticate_data_detached(
                  sctx->h_ctx, (gtaio_istream_t *)&istream_data_to_seal, (gtaio_ostream_t *)&ostream_seal, &errinfo)) {
        LOG_ERROR("gta_authenticate_data_detached failed");
        return NOK;
    }

    LOG_TRACE_ARG("Sigsize: %zu", ostream_seal.buf_pos);
    *siglen = ostream_seal.buf_pos;

    if (OK != gta_context_close(sctx->h_ctx, &errinfo)) {
        LOG_ERROR("gta_context_close failed");
        return NOK;
    }
#ifdef LOG_B64_ON
    char * signBase64;
    base_64_encode(sig, *siglen, &signBase64);

    LOG_TRACE_ARG("Input of %s : b64_enc(sig)= %s", __func__, signBase64);
#endif
    LOG_TRACE_ARG("Input of %s : siglen= %zu", __func__, *siglen);
    LOG_TRACE_ARG("Input of %s : sigsize= %zu", __func__, sigsize);
#ifdef LOG_B64_ON
    char * dataBase64;
    base_64_encode(data, datalen, &dataBase64);

    LOG_TRACE_ARG("Input of %s : b64_enc(data)= %s", __func__, dataBase64);
#endif
    LOG_TRACE_ARG("Input of %s : datalen= %zu", __func__, datalen);

    return OK;
}

/**
 * Configure the gettable OSSL parameters.
 */
const OSSL_PARAM * gtaossl_provider_base_signature_gettable_ctx_params(void * ctx, void * provctx)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)ctx;
    (void)provctx;

    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0), OSSL_PARAM_END};
    return gettable;
}

/**
 * Set ctx parameters.
 */
int gtaossl_provider_base_signature_set_ctx_params(void * ctx, const OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)ctx;

    /* Check if context parameters are supported */
    return base_signature_check_ctx_params(params, NULL);
}