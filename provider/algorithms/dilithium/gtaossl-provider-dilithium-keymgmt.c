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

static OSSL_FUNC_keymgmt_gettable_params_fn gtaossl_provider_dilithium_keymgmt_gettable_params;
static OSSL_FUNC_keymgmt_import_fn gtaossl_provider_dilithium_keymgmt_import;
static OSSL_FUNC_keymgmt_export_fn gtaossl_provider_dilithium_keymgmt_export;
static OSSL_FUNC_keymgmt_import_types_fn gtaossl_provider_dilithium_keymgmt_eximport_types;

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
static int gtaossl_provider_dilithium_keymgmt_import(void * keydata, int selection, const OSSL_PARAM params[])
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    return (base_keymgmt_import(keydata, selection, params, "todo"));
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

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0) {
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
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))gtaossl_provider_base_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))gtaossl_provider_dilithium_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))gtaossl_provider_base_keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))gtaossl_provider_base_keymgmt_settable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))gtaossl_provider_base_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))gtaossl_provider_base_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))gtaossl_provider_dilithium_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))gtaossl_provider_dilithium_keymgmt_eximport_types},
    {OSSL_FUNC_KEYMGMT_EXPORT, NULL},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))gtaossl_provider_dilithium_keymgmt_eximport_types},
    {0, NULL}};
