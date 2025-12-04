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
#include <openssl/pem.h>
#include <openssl/types.h>

static OSSL_FUNC_keymgmt_gettable_params_fn gtaossl_provider_ecdsa_keymgmt_gettable_params;
static OSSL_FUNC_keymgmt_import_fn gtaossl_provider_ecdsa_keymgmt_import;
static OSSL_FUNC_keymgmt_export_fn gtaossl_provider_ecdsa_keymgmt_export;
static OSSL_FUNC_keymgmt_import_types_fn gtaossl_provider_ecdsa_keymgmt_eximport_types;
static OSSL_FUNC_keymgmt_query_operation_name_fn gtaossl_provider_ecdsa_keymgmt_query_operation_name;

/**
 * The function returns a descriptor of OSSL parameters.
 *
 * @param[in] provctx: provider context (not used)
 * @return array of OSSL_PARAM
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/master/man7/provider-keymgmt/#key-object-information-functions
 */
static const OSSL_PARAM * gtaossl_provider_ecdsa_keymgmt_gettable_params(void * provctx)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)provctx;

    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
#if 0
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
        /* static curve parameters */
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, NULL),
#endif
        /* public key */
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
#if 0
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
#endif
        OSSL_PARAM_END};

    return gettable;
}

/**
 * This method should return a pointer to a string matching
 * the requested operation, or NULL if the same name used
 * to fetch the keymgmt applies.
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/master/man7/provider-keymgmt/#key-object-information-functions
 *
 * @param[in] operation_id: ID of operation
 * @return algorithm string
 */
static const char * gtaossl_provider_ecdsa_keymgmt_query_operation_name(int operation_id)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        LOG_INFO("Signature");
        return "ECDSA";
    default:
        break;
    }
    return NULL;
}

/**
 * The key management import function imports data indicated
 * by selection into keydata with values taken from the OSSL_PARAM(3) array params:
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/master/man7/provider-keymgmt/#key-object-information-functions
 *
 * @param[in] selection: type of the selection
 * @param[in] params: array of the OSSL parameters
 * @param[out] keydata: pointer of a key structure
 * @return OK = 1
 * @return NOK = 0
 *
 */
static int gtaossl_provider_ecdsa_keymgmt_import(void * keydata, int selection, const OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    return (base_keymgmt_import(keydata, selection, params, PREQS_EC));
}

/**
 * This function configures the types of import and export.
 * (OSSL_PKEY_PARAM_EC_PUB_X and OSSL_PKEY_PARAM_EC_PUB_Y =
 * coordinates of the circle)
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/master/man7/provider-keymgmt/#key-object-information-functions
 *
 * @param[in] selection: type of selection
 * @return array of OSSL parameters
 */
static const OSSL_PARAM * gtaossl_provider_ecdsa_keymgmt_eximport_types(int selection)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    static const OSSL_PARAM ecc_public_key_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
        OSSL_PARAM_END};

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0) {
        LOG_TRACE("return ecc_public_key_types");
        return ecc_public_key_types;
    } else {
        LOG_TRACE_ARG("%s return null", __func__);
        return NULL;
    }
}

/**
 * Export key in case EC
 *
 * @param[in] keydata: pointer to a key structure
 * @param[in] selection: type of the selection
 * @param[in] param_cb: parameters of callback function
 * @param[in] cbarg: callback function
 *
 * @return OK = 1
 * @return NOK = 0
 */
static int gtaossl_provider_ecdsa_keymgmt_export(void * keydata, int selection, OSSL_CALLBACK * param_cb, void * cbarg)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("Selection = %d", selection);

    int result = NOK;
    GTA_PKEY * pkey = (GTA_PKEY *)keydata;

#if LOG_LEVEL == LOG_LEVEL_TRACE
    LOG_TRACE_ARG("Function(%s) GTA pkey->string = %s", __func__, pkey->string);
    LOG_TRACE_ARG("Function(%s) GTA pkey->personality_name = %s", __func__, pkey->personality_name);
    LOG_TRACE_ARG("Function(%s) GTA pkey->profile_name = %s", __func__, pkey->profile_name);

    LOG_TRACE_ARG("Function(%s) GTA pkey->pub_key = %s", __func__, pkey->pub_key);
    LOG_TRACE_ARG("Function(%s)  GTA pkey->pub_key_size = %zu", __func__, pkey->pub_key_size);
#endif

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        LOG_TRACE("OSSL_KEYMGMT_SELECT_PRIVATE_KEY");
        return NOK;
    }

    EVP_PKEY * key = NULL;
    if (!base_get_public_key(pkey, &key)) {
        return NOK;
    }

    size_t public_key_len = 0;
    char * public_key = NULL;
    size_t group_name_len = 0;
    char * group_name = NULL;
    OSSL_PARAM params[3] = {0};
    OSSL_PARAM * p = params;
    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0) {
        LOG_TRACE("OSSL_KEYMGMT_SELECT_ALL_PARAMETERS");
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
        /* Return the group name */
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        LOG_TRACE("OSSL_KEYMGMT_SELECT_PUBLIC_KEY");
        /* Get raw public key */
        if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &public_key_len)) {
            LOG_ERROR("EVP_PKEY_get_octet_string_param failed");
            return NOK;
        }
        LOG_TRACE_ARG("public_key_len: %zu", public_key_len);

        public_key = OPENSSL_zalloc(public_key_len);
        if (NULL == public_key) {
            LOG_ERROR("mamory allocation failed");
            return NOK;
        }

        if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, public_key, public_key_len, NULL)) {
            LOG_ERROR("EVP_PKEY_get_group_name failed");
            return NOK;
        }
        /* Return the raw public key */
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, public_key, public_key_len);
    }
    *p = OSSL_PARAM_construct_end();

    LOG_TRACE("Call param_cb");
    result = param_cb(params, cbarg);
    OPENSSL_free(group_name);
    OPENSSL_free(public_key);
    return result;
}

const OSSL_DISPATCH ecdsa_keymgmt_functions[] = {

    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))gtaossl_provider_base_keymgmt_new},
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))gtaossl_provider_base_keymgmt_load},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))gtaossl_provider_base_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))gtaossl_provider_base_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))gtaossl_provider_ecdsa_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))gtaossl_provider_base_keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))gtaossl_provider_base_keymgmt_settable_params},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))gtaossl_provider_ecdsa_keymgmt_query_operation_name},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))gtaossl_provider_base_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))gtaossl_provider_base_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))gtaossl_provider_ecdsa_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))gtaossl_provider_ecdsa_keymgmt_eximport_types},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))gtaossl_provider_ecdsa_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))gtaossl_provider_ecdsa_keymgmt_eximport_types},
    {0, NULL}};
