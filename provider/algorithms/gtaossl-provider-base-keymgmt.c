/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtaossl-provider-base-keymgmt.h"

#include "../config/gtaossl-provider-config.h"
#include "../gtaossl-provider.h"
#include "../logger/gtaossl-provider-logger.h"
#include <gta_api/gta_api.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/types.h>

/**
 * The key management new function should create and return a pointer
 * to a structure, that is GTA PKEY object extended with the OpenSSL
 * and GTA provider context.
 */
void * gtaossl_provider_base_keymgmt_new(void * provctx)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    GTA_PROVIDER_CTX * cprov = provctx;

    GTA_PKEY * pkey = NULL;

    if ((pkey = OPENSSL_zalloc(sizeof(GTA_PKEY))) == NULL) {
        LOG_ERROR_ARG("%s -> allocation failed", __func__);
        return NULL;
    }

    GTA_KEYMANGER_CTX * kctx = OPENSSL_zalloc(sizeof(GTA_KEYMANGER_CTX));

    kctx->core = cprov->core;
    kctx->libctx = cprov->libctx;
    kctx->provider_ctx = cprov;

    pkey->provctx = (GTA_PROVIDER_CTX *)kctx;

    LOG_TRACE_ARG("%s return pkey", __func__);
    return pkey;
}

/**
 * Creates a provider-side GTA_PKEY object that initialized with NULL pointer.
 */
void * gtaossl_provider_base_keymgmt_load(const void * reference, size_t reference_sz)
{
    LOG_INFO("Key manager loads object");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("reference_sz: %zu", reference_sz);

    GTA_PKEY * pkey = *(GTA_PKEY **)reference;

    LOG_TRACE_ARG("Function(%s) GTA pkey->string = %s", __func__, pkey->string);
    LOG_TRACE_ARG("Function(%s) GTA pkey->personality_name = %s", __func__, pkey->personality_name);
    LOG_TRACE_ARG("Function(%s) GTA pkey->profile_name = %s", __func__, pkey->profile_name);

    /* detach it */
    *(GTA_PKEY **)reference = NULL;

    LOG_TRACE_ARG("%s return pkey", __func__);
    return pkey;
}

/**
 * The function should free the passed keydata.
 */
void gtaossl_provider_base_keymgmt_free(void * keydata)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    GTA_PKEY * pkey = keydata;

    if (pkey == NULL) {
        LOG_ERROR_ARG("%s -> pkey null", __func__);
        return;
    }

    if (NULL != pkey->string) {
        OPENSSL_free(pkey->string);
        pkey->personality_name = NULL;
        pkey->profile_name = NULL;
    }

    /* todo: free internal memory too */
    OPENSSL_clear_free(pkey, sizeof(GTA_PKEY));
    LOG_TRACE_ARG("End of %s", __func__);
    return;
}

/**
 * The function updates information data associated with the given keydata.
 */
int gtaossl_provider_base_keymgmt_set_params(void * keydata, const OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    const OSSL_PARAM * p;

    if (params == NULL) {
        LOG_WARN_ARG("%s -> return 1", __func__);
        return OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        LOG_TRACE_ARG("%s -> pub key located", __func__);
        return NOK;
    }

    LOG_TRACE_ARG("%s -> return 1", __func__);
    return OK;
}

/**
 * The function returns a descriptor of OSSL parameters.
 */
const OSSL_PARAM * gtaossl_provider_base_keymgmt_settable_params(void * provctx)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0), OSSL_PARAM_END};

    LOG_ERROR_ARG("Stop %s", __func__);
    return settable;
}

/**
 * The OSSL_FUNC_keymgmt_has() function checks whether the given keydata
 * contains the subsets of data indicated by the selector.
 */
int gtaossl_provider_base_keymgmt_has(const void * keydata, int selection)
{
    LOG_INFO("Key manager tries to read key data from store");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("Selection = %d", selection);

    if (keydata == NULL) {
        LOG_TRACE("Key data is null");
    } else {
        LOG_TRACE("Key data is not null");
#if LOG_LEVEL == LOG_LEVEL_TRACE
        GTA_PKEY * pkey = (GTA_PKEY *)keydata;

        LOG_TRACE_ARG("Function(%s) GTA pkey->string = %s", __func__, pkey->string);
        LOG_TRACE_ARG("Function(%s) GTA pkey->personality_name = %s", __func__, pkey->personality_name);
        LOG_TRACE_ARG("Function(%s) GTA pkey->profile_name = %s", __func__, pkey->profile_name);
#endif
    }

    LOG_DEBUG_ARG("Do nothing method [%s], only return with true value", __func__);
    return OK;
}

/**
 * The base key management import function imports data indicated
 * by selection into keydata with values taken from the OSSL_PARAM(3) array params
 */
int gtaossl_provider_base_keymgmt_import(void * keydata, int selection, const OSSL_PARAM params[])
{
    LOG_INFO("Key manager imports key object");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("%s selection: %d", __func__, selection);
    const OSSL_PARAM * p;

    GTA_PKEY * pkey = (GTA_PKEY *)keydata;

    if (pkey == NULL) {
        LOG_ERROR_ARG("%s pkey null", __func__);
        return NOK;
    }

    LOG_TRACE_ARG("Function(%s) GTA pkey->string = %s", __func__, pkey->string);
    LOG_TRACE_ARG("Function(%s) GTA pkey->personality_name = %s", __func__, pkey->personality_name);
    LOG_TRACE_ARG("Function(%s) GTA pkey->profile_name = %s", __func__, pkey->profile_name);

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        LOG_TRACE_ARG("%s OSSL Param locate in pub key", __func__);
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {

            if ((pkey->pub_key = OPENSSL_zalloc(p->data_size)) == NULL) {
                LOG_ERROR("Allocation error of pub key");
                return NOK;
            }

            pkey->pub_key_size = p->data_size;
            memcpy(pkey->pub_key, p->data, p->data_size);

            LOG_TRACE_ARG("p->data_size: %zu", p->data_size);
            for (int i = 0; i < p->data_size; i++) {
                LOG_TRACE_KEY_DATA_ARG("%#x ", ((unsigned char *)p->data)[i]);
            }
            LOG_TRACE_KEY_DATA(LOG__EOM);

        } else {
            LOG_TRACE_ARG("%s p null", __func__);
        }
    }

    if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) {
        LOG_TRACE_ARG("%s OSSL Param locate all", __func__);
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
        if (p != NULL) {
            LOG_TRACE_ARG("p->data = %s", (char *)p->data);
        } else {
            LOG_TRACE_ARG("%s p2 null", __func__);
        }
    }

    LOG_TRACE_ARG("%s return 1", __func__);
    return OK;
}

/**
 * The helper function should convert and copy a key data
 * form an ASN1 (BIT STRING) structure.
 */
void base_parse_key_data_1(
    const void * keydata1,
    unsigned char ** pub_key_from_data_1,
    size_t * size_of_pub_key_from_data_1)
{

    GTA_PKEY * pkey1 = (GTA_PKEY *)keydata1;

    LOG_TRACE_ARG("Function(%s) GTA pkey1->string = %s", __func__, pkey1->string);
    LOG_TRACE_ARG("Function(%s) GTA pkey1->personality_name = %s", __func__, pkey1->personality_name);
    LOG_TRACE_ARG("Function(%s) GTA pkey1->profile_name = %s", __func__, pkey1->profile_name);

#ifdef LOG_B64_ON
    char * pubKeyBase64;
    base_64_encode((const unsigned char *)(pkey1->pub_key), pkey1->pub_key_size, &pubKeyBase64);

    LOG_TRACE_ARG("%s : b64_enc(pkey1->pub_key)= %s", __func__, pubKeyBase64);
#endif
    LOG_TRACE_ARG("Function(%s) GTA pkey1->pub_key_size = %zu", __func__, pkey1->pub_key_size);

    ASN1_BIT_STRING * pub_part = ASN1_BIT_STRING_new();
    ASN1_BIT_STRING_set(pub_part, (unsigned char *)(pkey1->pub_key), pkey1->pub_key_size);

    LOG_TRACE_ARG("pub_part->length: %d", pub_part->length);
#ifdef LOG_BYTE_ARRARY_ON
    for (int i = 0; i < (pub_part->length); i++) {
        LOG_TRACE_KEY_DATA_ARG("%#x ", pub_part->data[i]);
    }
#endif

    (*pub_key_from_data_1) = (unsigned char *)mem_dup(pub_part->data, (size_t)(pub_part->length));
    (*size_of_pub_key_from_data_1) = (size_t)(pub_part->length);
}