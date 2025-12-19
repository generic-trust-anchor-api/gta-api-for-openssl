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

static OSSL_FUNC_signature_get_ctx_params_fn gtaossl_provider_rsa_signature_get_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn gtaossl_provider_rsa_signature_settable_ctx_params;

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
static int gtaossl_provider_rsa_signature_get_ctx_params(void * ctx, OSSL_PARAM params[])
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
        ASN1_STRING * parstr = NULL;
        X509_ALGOR * x509_algor = X509_ALGOR_new();
        X509_ALGOR * hash = X509_ALGOR_new();
        ASN1_INTEGER * pss_salt_length = ASN1_INTEGER_new();
        X509_ALGOR * mfg1 = X509_ALGOR_new();
        RSA_PSS_PARAMS * pss = RSA_PSS_PARAMS_new();

        if ((NULL == x509_algor) || (NULL == hash) || (NULL == pss_salt_length) || (NULL == mfg1) || (NULL == pss)) {
            LOG_ERROR("Object creation failed");
            return NOK;
        }

        /* Set hash algorithm */
        if (!X509_ALGOR_set0(hash, OBJ_nid2obj(SUPPORTED_DIGEST), V_ASN1_NULL, NULL)) {
            LOG_ERROR("X509_ALGOR_set0 for hash failed");
            return NOK;
        }
        pss->hashAlgorithm = hash;

        /* Set mgf1 */
        X509_ALGOR * hash_tmp = X509_ALGOR_dup(hash);
        const ASN1_STRING * sres = NULL;
        ASN1_STRING * stmp = NULL;

        sres = ASN1_item_pack(hash_tmp, ASN1_ITEM_rptr(X509_ALGOR), &stmp);
        X509_ALGOR_free(hash_tmp);
        if (NULL == sres) {
            LOG_ERROR("ASN1_item_pack for hash_tmp failed");
            return NOK;
        }

        if (!X509_ALGOR_set0(mfg1, OBJ_nid2obj(NID_mgf1), V_ASN1_SEQUENCE, stmp)) {
            LOG_ERROR("X509_ALGOR_set0 for mfg1 failed");
            return NOK;
        }
        pss->maskGenAlgorithm = mfg1;

        /* Set PSS salt length */
        const EVP_MD * md = EVP_get_digestbynid(SUPPORTED_DIGEST);
        if (NULL == md) {
            LOG_ERROR("EVP_get_digestbynid failed");
            return NOK;
        }

        if (!ASN1_INTEGER_set(pss_salt_length, EVP_MD_size(md))) {
            LOG_ERROR("ASN1_INTEGER_set for pss_salt_length failed");
            return NOK;
        }
        pss->saltLength = pss_salt_length;
        EVP_MD_free(md);

        if (!ASN1_item_pack(pss, ASN1_ITEM_rptr(RSA_PSS_PARAMS), &parstr)) {
            LOG_ERROR("ASN1_item_pack failed");
            return NOK;
        }

        RSA_PSS_PARAMS_free(pss);

        if (!X509_ALGOR_set0(x509_algor, OBJ_nid2obj(NID_rsassaPss), V_ASN1_SEQUENCE, parstr)) {
            LOG_ERROR("X509_ALGOR_set0 for x509_algor failed");
            return NOK;
        }

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
static const OSSL_PARAM * gtaossl_provider_rsa_signature_settable_ctx_params(void * ctx, void * provctx)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)ctx;
    (void)provctx;

    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END};
    return settable;
}

const OSSL_DISPATCH rsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))gtaossl_provider_base_signature_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))gtaossl_provider_base_signature_freectx},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))gtaossl_provider_base_signature_digest_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))gtaossl_provider_base_signature_digest_sign},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))gtaossl_provider_rsa_signature_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))gtaossl_provider_base_signature_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))gtaossl_provider_base_signature_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))gtaossl_provider_rsa_signature_settable_ctx_params},
    {0, NULL}};
