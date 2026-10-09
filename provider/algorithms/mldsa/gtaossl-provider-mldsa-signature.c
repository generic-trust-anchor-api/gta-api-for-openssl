/*
 * SPDX-FileCopyrightText: Copyright 2025-2026 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../../config/gtaossl-provider-config.h"
#include "../../gtaossl-provider.h"
#include "../../logger/gtaossl-provider-logger.h"
#include "../../stream/streams.h"
#include "../gtaossl-provider-base-keymgmt.h"
#include "../gtaossl-provider-base-signature.h"
#include <gta_api/gta_api.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <string.h>

static OSSL_FUNC_signature_get_ctx_params_fn gtaossl_provider_mldsa_signature_get_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn gtaossl_provider_mldsa_signature_settable_ctx_params;
static OSSL_FUNC_signature_digest_sign_init_fn gtaossl_provider_mldsa_signature_digest_sign_init;

static int gtaossl_provider_mldsa_signature_get_ctx_params(void * ctx, OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)ctx;

    OSSL_PARAM * p = NULL;

    if (params == NULL) {
        LOG_DEBUG("There are no parameters");
        return OK;
    }

    LOG_DEBUG("Locate algorithm ID parameter");
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL) {
        unsigned char * aid = NULL;
        int aid_len = 0;
        int ret = 0;
        ASN1_OBJECT * oid = OBJ_nid2obj(NID_ML_DSA_65);
        X509_ALGOR * x509_algor = NULL;

        if (NULL == oid) {
            LOG_ERROR("OBJ lookup failed");
            return NOK;
        }

        x509_algor = X509_ALGOR_new();
        if (NULL == x509_algor) {
            LOG_ERROR("X509 Algorithm Object creation failed");
            return NOK;
        }

        X509_ALGOR_set0(x509_algor, oid, V_ASN1_UNDEF, NULL);
        aid_len = i2d_X509_ALGOR(x509_algor, &aid);
        ret = OSSL_PARAM_set_octet_string(p, aid, aid_len);

        OPENSSL_free(aid);
        X509_ALGOR_free(x509_algor);
        return ret;
    }

    return OK;
}

/**
 * Configure the settable OSSL parameters:
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-signature/#description
 *
 * @param[in] ctx: signature context (not used)
 * @param[in] provctx: provider context (not used)
 * @return array of OSSL_PARAMs
 */
static const OSSL_PARAM * gtaossl_provider_mldsa_signature_settable_ctx_params(void * ctx, void * provctx)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)ctx;
    (void)provctx;

    static OSSL_PARAM settable[] = {OSSL_PARAM_END};
    return settable;
}

/* Check mdname before forwarding to base provider */
static int gtaossl_provider_mldsa_signature_digest_sign_init(
    void * ctx,
    const char * mdname,
    void * provkey,
    const OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("Input parameter mdname: %s", (NULL == mdname) ? "(null)" : mdname);

    if ((NULL != mdname) && ('\0' != mdname[0])) {
        LOG_ERROR_ARG("Digest %s unsupported for ML-DSA", mdname);
        return NOK;
    }

    return gtaossl_provider_base_signature_sign_init(ctx, provkey, params);
}

const OSSL_DISPATCH mldsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))gtaossl_provider_base_signature_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))gtaossl_provider_base_signature_freectx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))gtaossl_provider_base_signature_sign_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))gtaossl_provider_base_signature_sign},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))gtaossl_provider_mldsa_signature_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))gtaossl_provider_base_signature_digest_sign},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))gtaossl_provider_mldsa_signature_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))gtaossl_provider_base_signature_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))gtaossl_provider_base_signature_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))gtaossl_provider_mldsa_signature_settable_ctx_params},
    {0, NULL}};
