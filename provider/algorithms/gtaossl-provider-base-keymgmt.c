/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtaossl-provider-base-keymgmt.h"

#include "../config/gtaossl-provider-config.h"
#include "../gtaossl-provider.h"
#include "../logger/gtaossl-provider-logger.h"
#include "../stream/streams.h"
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
#include <openssl/pem.h>
#include <openssl/types.h>
#include <openssl/x509.h>

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
    const OSSL_PARAM * p = NULL;

    /* Currently unused */
    (void)keydata;

    if (params == NULL) {
        LOG_WARN_ARG("%s -> return 1", __func__);
        return OK;
    }

    /* This needs to be implemented more generic, or moved to the algorithm specific part */
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

    /* Currently unused */
    (void)provctx;

    /* This needs to be moved to the algorithm specific part */
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
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("Selection = %d", selection);

    /* Currently unused */
    (void)keydata;
    (void)selection;

    LOG_DEBUG("We don't do any checks here and just return OK");
    return OK;
}

/**
 * Helper function to get the public key from given GTA API personality.
 */
int base_get_public_key(const GTA_PKEY * pkey, EVP_PKEY ** key)
{
    if (pkey->provctx == NULL) {
        LOG_ERROR("No context in pkey2");
        return NOK;
    }

    gta_errinfo_t errinfo = 0;
    gta_context_handle_t h_ctx = GTA_HANDLE_INVALID;

    LOG_TRACE("GTA context open");
    h_ctx = gta_context_open(pkey->provctx->h_inst, pkey->personality_name, pkey->profile_name, &errinfo);
    if (NULL == h_ctx) {
        LOG_ERROR_ARG("GTA context open problem: %lu", errinfo);
        return NOK;
    }

    ostream_to_buf_t ostream_data = {0};
    unsigned char obuf[SIZE_OF_GTA_O_BUFFER] = {0};
    size_t obuf_size = sizeof(obuf) - 1;

    LOG_TRACE("Init output stream");
    ostream_to_buf_init(&ostream_data, (char *)obuf, obuf_size);

    LOG_TRACE("gta_personality_enroll(...)");
    if (!gta_personality_enroll(h_ctx, (gtaio_ostream_t *)&ostream_data, &errinfo)) {
        LOG_ERROR_ARG("gta_personality_enroll failed: %lu", errinfo);
        return NOK;
    }

    gta_context_close(h_ctx, &errinfo);

    LOG_TRACE_ARG("ostream_data.pos=%ld", (long)ostream_data.buf_pos);
#ifdef LOG_B64_ON
    LOG_TRACE_ARG("ostream_data.buf=%s", ostream_data.buf);
#endif

    /* Range check */
    if (INT_MAX < ostream_data.buf_pos) {
        LOG_ERROR("Range check failed");
        return NOK;
    }

    /* Convert PEM public key to EVP_PKEY */
    BIO * bio = BIO_new_mem_buf(obuf, (int)ostream_data.buf_pos);
    EVP_PKEY * key_tmp = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (NULL == key_tmp) {
        LOG_ERROR("PEM_read_bio_PUBKEY failed");
        return NOK;
    }
    *key = key_tmp;
    return OK;
}

/**
 * The function checks if the data subset indicated by selection
 * in keydata1 and keydata2 match.
 */
int gtaossl_provider_base_keymgmt_match(const void * keydata1, const void * keydata2, int selection)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("Selection = %d", selection);

    if ((NULL == keydata1) || (NULL == keydata2)) {
        LOG_ERROR("keydata1 and/or keydata2 is null");
        return NOK;
    }

    const GTA_PKEY * pkey1 = (const GTA_PKEY *)keydata1;
    const GTA_PKEY * pkey2 = (const GTA_PKEY *)keydata2;

    /* We need a temporary copy of the key */
    const unsigned char * pub_key_tmp = OPENSSL_memdup(pkey1->pub_key, pkey1->pub_key_size);
    if (NULL == pub_key_tmp) {
        LOG_ERROR("Memory allocation failed!");
        return NOK;
    }

    /* Convert SubjectPublicKeyInfo to EVP_PKEY */
    EVP_PKEY * key1 = d2i_PUBKEY(NULL, &pub_key_tmp, pkey1->pub_key_size);
    if (NULL == key1) {
        LOG_ERROR("Converting pkey1 to EVP_PKEY failed!");
        return NOK;
    }

    LOG_TRACE_ARG("Function (%s) GTA pkey2->string = %s", __func__, pkey2->string);
    LOG_TRACE_ARG("Function (%s) GTA pkey2->personality_name = %s", __func__, pkey2->personality_name);
    LOG_TRACE_ARG("Function (%s) GTA pkey2->profile_name = %s", __func__, pkey2->profile_name);

    EVP_PKEY * key2 = NULL;
    if (!base_get_public_key(pkey2, &key2)) {
        return NOK;
    }
    int result = EVP_PKEY_eq(key1, key2);
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);

    LOG_TRACE_ARG("Comparison result: %i", result);

    if (OK != result) {
        result = NOK;
        LOG_ERROR("Comparison failed!");
    }

    return result;
}

/**
 * The base key management import function imports data indicated
 * by selection into keydata with values taken from the OSSL_PARAM(3) array params
 */
int base_keymgmt_import(void * keydata, int selection, const OSSL_PARAM params[], const char * name)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    int ret = NOK;

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

        EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
        EVP_PKEY * key = NULL;
        int len = 0;

        if (EVP_PKEY_fromdata_init(ctx) <= 0) {
            LOG_ERROR("EVP_PKEY_fromdata_init failed");
            return NOK;
        }

        if (EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
            LOG_ERROR("EVP_PKEY_fromdata failed");
            return NOK;
        }

        /* Convert to SubjectPublicKeyInfo */
        len = i2d_PUBKEY(key, (unsigned char **)&pkey->pub_key);
        if (0 >= len) {
            LOG_ERROR("i2d_PUBKEY failed");
            return NOK;
        }
        pkey->pub_key_size = len;
        LOG_TRACE_ARG("len: %i", len);

        EVP_PKEY_free(key);
        ret = OK;
    }

    LOG_TRACE_ARG("%s return %i", __func__, ret);
    return ret;
}

/**
 * The function reads requested params from keydata by converting the GTA_PKEY
 * to an EVP_PKEY and use OpenSSL functions.
 */
int gtaossl_provider_base_keymgmt_get_params(void * keydata, OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    OSSL_PARAM * p = NULL;
    EVP_PKEY * key = NULL;
    const GTA_PKEY * pkey = (const GTA_PKEY *)keydata;

    if (params == NULL) {
        LOG_ERROR_ARG("%s -> params array is null", __func__);
        return OK;
    }

    /* Convert GTA_PKEY to EVP_PKEY */
    if (!base_get_public_key(pkey, &key)) {
        LOG_ERROR("base_get_public_key failed");
        return NOK;
    }

    /* This needs to be declared here */
    size_t group_name_len = 0;
    char * group_name = NULL;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        /* Get group name */
        if (!EVP_PKEY_get_group_name(key, NULL, 0, &group_name_len)) {
            LOG_ERROR("EVP_PKEY_get_group_name failed");
            return NOK;
        }
        LOG_TRACE_ARG("group_name_len: %zu", group_name_len);

        group_name = OPENSSL_zalloc(group_name_len + 1);
        if (NULL == group_name) {
            LOG_ERROR("mamory allocation failed");
            return NOK;
        }

        if (!EVP_PKEY_get_group_name(key, group_name, group_name_len + 1, NULL)) {
            LOG_ERROR("EVP_PKEY_get_group_name failed");
            return NOK;
        }
        LOG_TRACE_ARG("group_name: %s", group_name);

        if (!OSSL_PARAM_set_utf8_string(p, group_name)) {
            LOG_ERROR_ARG("%s -> error set parameter group name", __func__);
            goto error;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL) {
        int bits = EVP_PKEY_get_bits(key);
        LOG_TRACE_ARG("bits: %i", bits);

        if (!OSSL_PARAM_set_int(p, bits)) {
            LOG_ERROR_ARG("%s -> error set int parameter", __func__);
            goto error;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL) {
        int security_bits = EVP_PKEY_get_security_bits(key);
        LOG_TRACE_ARG("security_bits: %i", security_bits);
        if (!OSSL_PARAM_set_int(p, security_bits)) {
            LOG_ERROR_ARG("%s -> error set sec bit", __func__);
            goto error;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL) {
        int max_size = EVP_PKEY_get_size(key);
        LOG_TRACE_ARG("max_size: %i", max_size);
        if (!OSSL_PARAM_set_int(p, max_size)) {
            LOG_ERROR_ARG("%s -> error  max size", __func__);
            goto error;
        }
    }

    OPENSSL_free(group_name);
    return OK;
error:
    OPENSSL_free(group_name);
    return NOK;
}