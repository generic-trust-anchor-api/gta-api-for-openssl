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

static OSSL_FUNC_signature_get_ctx_params_fn gtaossl_provider_ecdsa_signature_get_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn gtaossl_provider_ecdsa_signature_settable_ctx_params;

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
        int r = 0;
        ASN1_OBJECT * oid = NULL;

#if SUPPORTED_DIGEST == NID_sha256
        oid = OBJ_nid2obj(NID_ecdsa_with_SHA256);
#else
#error Algorithm identifier for selected hash algorithm not implemented.
#endif
        X509_ALGOR * x509_algor = X509_ALGOR_new();
        if (NULL == x509_algor) {
            LOG_ERROR("X509 Algorithm Object creation failed");
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
static const OSSL_PARAM * gtaossl_provider_ecdsa_signature_settable_ctx_params(void * ctx, void * provctx)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)ctx;
    (void)provctx;

    static OSSL_PARAM settable[] = {OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0), OSSL_PARAM_END};
    return settable;
}

const OSSL_DISPATCH ecdsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))gtaossl_provider_base_signature_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))gtaossl_provider_base_signature_freectx},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))gtaossl_provider_base_signature_digest_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))gtaossl_provider_base_signature_digest_sign},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))gtaossl_provider_ecdsa_signature_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))gtaossl_provider_base_signature_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))gtaossl_provider_base_signature_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))gtaossl_provider_ecdsa_signature_settable_ctx_params},
    {0, NULL}};
