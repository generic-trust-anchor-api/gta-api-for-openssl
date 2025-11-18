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
#include <gta_api/gta_api.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
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

#if LOG_LEVEL == LOG_LEVEL_TRACE
    if (sctx->provider_ctx->libctx != NULL) {
        int is_default_active = OSSL_PROVIDER_available(sctx->provider_ctx->libctx, "default");
        LOG_DEBUG_ARG("DAFAULT: active = %d", is_default_active);

        int is_oqsprovider_active = OSSL_PROVIDER_available(sctx->provider_ctx->libctx, "oqsprovider");
        LOG_DEBUG_ARG("OQSPROVIDER: active = %d", is_oqsprovider_active);

        int is_gta_active = OSSL_PROVIDER_available(sctx->provider_ctx->libctx, "gta");
        LOG_DEBUG_ARG("GTA: active = %d", is_gta_active);
    } else {
        LOG_WARN(" libctx null");
    }
#endif

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
 * Initialization of the signing context.
 */
int gtaossl_provider_base_signature_digest_init(
    void * ctx,
    const char * mdname,
    void * provkey,
    const OSSL_PARAM params[])
{

    LOG_INFO("Initialize a context for digest signing");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("Input parameter mdname: %s", mdname);

    GTA_SIGNATURE_CTX * sctx = ctx;
    GTA_PKEY * pkey = provkey;

    if (NULL != pkey) {
        LOG_TRACE_ARG("pkey->string: %s", pkey->string);
        LOG_TRACE_ARG("pkey->profile_name: %s", pkey->profile_name);
        LOG_TRACE_ARG("pkey->personality_name: %s", pkey->personality_name);
    } else {
        LOG_WARN("No pkey!");
        return NOK;
    }

    /* We currently only do the signature calculation */
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

/**
 * The function finalizes a signature operation but does not contain any implementation.
 */
int gtaossl_provider_base_signature_digest_sign_final(void * ctx, unsigned char * sig, size_t * siglen, size_t sigsize)
{
    LOG_INFO("Finalize signature digest");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("Input of %s : sig= %s", __func__, sig);
    LOG_TRACE_ARG("Input of %s : siglen= %zu", __func__, *siglen);
    LOG_TRACE_ARG("Input of %s : sigsize= %zu", __func__, sigsize);
    return NOK;
}

/**
 * Configure the gettable OSSL parameters.
 */
const OSSL_PARAM * gtaossl_provider_base_signature_gettable_ctx_params(void * ctx, void * provctx)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0), OSSL_PARAM_END};

    return gettable;
}

/**
 * Configure the settable OSSL parameters.
 */
const OSSL_PARAM * gtaossl_provider_base_signature_settable_ctx_params(void * ctx, void * provctx)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    static OSSL_PARAM settable[] = {OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0), OSSL_PARAM_END};

    return settable;
}

/**
 * Initialization of the signature verification context.
 */
int gtaossl_provider_base_signature_digest_verify_init(
    void * ctx,
    const char * mdname,
    void * provkey,
    const OSSL_PARAM params[])
{
    LOG_INFO("Initialize a context for digest signing");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("Input parameter mdname: %s", mdname);

    GTA_SIGNATURE_CTX * sctx = ctx;
    GTA_PKEY * pkey = provkey;

    if (NULL != pkey) {
        LOG_TRACE_ARG("pkey->string: %s", pkey->string);
        LOG_TRACE_ARG("pkey->profile_name: %s", pkey->profile_name);
        LOG_TRACE_ARG("pkey->personality_name: %s", pkey->personality_name);
    } else {
        LOG_WARN("No pkey!");
        return NOK;
    }

    /* We currently only do the signature calculation */
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

/**
 * The function implements a "one-shot" digest sign operation,
 * calling the GTA API functions to delegate the signing operation.
 */
int gtaossl_provider_base_signature_digest_sign(
    void * ctx,
    unsigned char * sig,
    size_t * siglen,
    size_t sigsize,
    const unsigned char * data,
    size_t datalen,
    size_t estimated_sig_size)
{
    LOG_INFO("Dilithium digest sign (call GTA API)");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    GTA_SIGNATURE_CTX * sctx = ctx;

    if (sig == NULL) {
        LOG_TRACE("SIGN DIGEST_SIGN estimate");
        *siglen = estimated_sig_size;
        return *siglen > 0;
    }

    LOG_TRACE_KEY_DATA(LOG__EOM);
    for (int i = 0; i < datalen; i++) {
        LOG_TRACE_KEY_DATA_ARG("%#x ", data[i]);
    }
    LOG_TRACE_KEY_DATA(LOG__EOM);

    /* GTA API */
    gta_errinfo_t errinfo = 0;

    istream_from_buf_t istream_data_to_seal = {0};
    ostream_to_buf_t ostream_seal = {0};

    unsigned char gta_sig[OQS_SIG_BUFFER] = {0};
    if (OK != istream_from_buf_init(&istream_data_to_seal, (const char *)data, datalen, &errinfo)) {
        LOG_ERROR("istream_from_buf_init failed");
        return NOK;
    }
    if (OK != ostream_to_buf_init(&ostream_seal, (char *)gta_sig, sizeof(gta_sig), &errinfo)) {
        LOG_ERROR("ostream_to_buf_init failed");
        return NOK;
    }

    if (OK != gta_authenticate_data_detached(
                  sctx->h_ctx, (gtaio_istream_t *)&istream_data_to_seal, (gtaio_ostream_t *)&ostream_seal, &errinfo)) {
        LOG_ERROR("gta_authenticate_data_detached failed");
        return NOK;
    }

    LOG_TRACE("Test: Seal HEX:");
    for (size_t i = 0; i < ostream_seal.buf_pos; i++) {
        LOG_TRACE_KEY_DATA_ARG("%02x ", (unsigned char)gta_sig[i]);
    }
    LOG_TRACE_KEY_DATA(LOG__EOM);

    LOG_TRACE_ARG("Sigsize: %zu", ostream_seal.buf_pos);
    memcpy(sig, gta_sig, ostream_seal.buf_pos);
    *siglen = ostream_seal.buf_pos;

    if (OK != istream_from_buf_close(&istream_data_to_seal, &errinfo)) {
        LOG_ERROR("istream_from_buf_close failed");
        return NOK;
    }
    if (OK != ostream_to_buf_close(&ostream_seal, &errinfo)) {
        LOG_ERROR("ostream_to_buf_close failed");
        return NOK;
    }
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