/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../../config/gtaossl-provider-config.h"
#include "../../gtaossl-provider.h"
#include "../../logger/gtaossl-provider-logger.h"
#include "../../stream/streams.h"
#include "../gtaossl-provider-base-keymgmt.h"
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

static OSSL_FUNC_keymgmt_get_params_fn gtaossl_provider_dilithium_keymgmt_get_params;

static OSSL_FUNC_keymgmt_gettable_params_fn gtaossl_provider_dilithium_keymgmt_gettable_params;

static OSSL_FUNC_keymgmt_match_fn gtaossl_provider_dilithium_keymgmt_match;

static OSSL_FUNC_keymgmt_import_types_fn gtaossl_provider_dilithium_keymgmt_eximport_types;

/**
 * The function should extract information data associated with the given keydata.
 *
 * @param[in] keydata: pointer of a key structure
 * @param[out] params: array of OSSL_PARAMs
 * @return OK = 1
 * @return NOK = 0
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/master/man7/provider-keymgmt/#key-object-information-functions
 */
static int gtaossl_provider_dilithium_keymgmt_get_params(void * keydata, OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    OSSL_PARAM * p = NULL;

    /* Currently unused */
    (void)keydata;

    if (params == NULL) {
        LOG_ERROR_ARG("%s -> params array is null", __func__);
        return OK;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p == NULL) {
        LOG_WARN("bits ossl parameter is null");
    }

    if (p != NULL && !OSSL_PARAM_set_int(p, 128)) {
        LOG_ERROR_ARG("%s -> error set int parameter", __func__);
        goto error;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL) {
        int sec_bits;

        /* We apply the same logic as OpenSSL does */
        sec_bits = 128;

        if (!OSSL_PARAM_set_int(p, sec_bits)) {
            LOG_ERROR_ARG("%s -> error set sec bit", __func__);
            goto error;
        }
    }

    return OK;
error:
    return NOK;
}

/**
 * The function returns a descriptor of OSSL parameters.
 *
 * @param[in] provctx: provider context (not used)
 * @return array of OSSL_PARAM
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/master/man7/provider-keymgmt/#key-object-information-functions
 */
static const OSSL_PARAM * gtaossl_provider_dilithium_keymgmt_gettable_params(void * provctx)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)provctx;

    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END};

    return gettable;
}

/**
 * The function checks if the data subset indicated by selection
 * in keydata1 and keydata2 match.
 *
 * 1. The `keydata1` parameter is represented in Diltihium public key format,
 * which needs to be converted to a byte array.
 *
 * 2. The `keydata2` parameter is stored in the GTA context, which needs to be exported
 * and converted to a byte array.
 *
 * 3. In case of key pair selection, `keydata1` and `keydata2` need to be compared.
 * If they are equal, then return true.
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/master/man7/provider-keymgmt/#key-object-information-functions
 *
 * @param[in] keydata1: pointer to a key structure 1
 * @param[in] keydata2: pointer to a key structure 2
 * @param[in] selection: type of the selection
 * @return OK = 1
 * @return NOK = 0
 */
static int gtaossl_provider_dilithium_keymgmt_match(const void * keydata1, const void * keydata2, int selection)
{
    LOG_INFO("Dilithium key manager tries to compare the stored key with the input object");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("Selection = %d", selection);

    if ((NULL == keydata1) || (NULL == keydata2)) {
        LOG_ERROR("keydata1 and/or keydata2 is null");
        return NOK;
    }

    const GTA_PKEY * pkey1 = (const GTA_PKEY *)keydata1;
    const GTA_PKEY * pkey2 = (const GTA_PKEY *)keydata2;

    /* pkey1 needs to be converted to an EVP_PKEY */
    /* We need a temporary copy of the key */
    const unsigned char * pub_key_tmp = OPENSSL_memdup(pkey1->pub_key, pkey1->pub_key_size);
    if (NULL == pub_key_tmp) {
        LOG_ERROR("Memory allocation failed!");
        return NOK;
    }

    /* todo: check key type e.g., EVP_PKEY_ML_DSA_44*/
    EVP_PKEY * key1 = d2i_PublicKey(0, NULL, &pub_key_tmp, pkey1->pub_key_size);
    if (NULL == key1) {
        LOG_ERROR("Converting pkey1 to EVP_PKEY failed!");
        return NOK;
    }

    /* Call the helper function to compare the keys */
    int res = base_keymgmt_match(key1, pkey2);

    EVP_PKEY_free(key1);
    return res;
}

/**
 * This function configures the types of import and export.
 * (OSSL_PKEY_PARAM_PUB_KEY)
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/master/man7/provider-keymgmt/#key-object-information-functions
 *
 * @param[in] selection: type of selection
 * @return array of OSSL parameters
 */
static const OSSL_PARAM * gtaossl_provider_dilithium_keymgmt_eximport_types(int selection)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    static const OSSL_PARAM dilithium_public_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0), OSSL_PARAM_END};

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0) {
        LOG_TRACE("return dilithium_public_key_types");
        return dilithium_public_key_types;
    } else {
        LOG_TRACE_ARG("%s return null", __func__);
        return NULL;
    }
}

const OSSL_DISPATCH dilithium_keymgmt_functions[] = {

    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))gtaossl_provider_base_keymgmt_new},
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))gtaossl_provider_base_keymgmt_load},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))gtaossl_provider_base_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))gtaossl_provider_dilithium_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))gtaossl_provider_dilithium_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))gtaossl_provider_base_keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))gtaossl_provider_base_keymgmt_settable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))gtaossl_provider_base_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))gtaossl_provider_dilithium_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))gtaossl_provider_base_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))gtaossl_provider_dilithium_keymgmt_eximport_types},
    {OSSL_FUNC_KEYMGMT_EXPORT, NULL},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))gtaossl_provider_dilithium_keymgmt_eximport_types},
    {0, NULL}};
