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
#include "gtaossl-provider-dilithium-types.h"
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
    OSSL_PARAM * p;

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
    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END};

    return gettable;
}

/**
 * The helper function should convert and copy a key data
 * form an ASN1 (BIT STRING) structure.
 */
static void parse_dilithium_key_data_1(
    const void * keydata1,
    unsigned char ** pub_key_from_data_1,
    size_t * size_of_pub_key_from_data_1,
    GTA_PROVIDER_CTX ** kctx)
{

    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    GTA_PKEY * pkey1 = (GTA_PKEY *)keydata1;

    base_parse_key_data_1(keydata1, pub_key_from_data_1, size_of_pub_key_from_data_1);

    if (pkey1->provctx == NULL) {
        LOG_WARN("No context in keydata1");
    } else {
        LOG_TRACE("We have a context in keydata1");
        (*kctx) = (GTA_PROVIDER_CTX *)(pkey1->provctx);
    }
}

/**
 * Parse Dilithium ASN1 structure from a base64 string.
 *
 * @param[in] onlyTheB64Part: base64 string
 * @param[out] pub_key: public key in SubjectPublicKeyInfoDilithium structure
 */
static void parse_dilithium_pem_object(char * onlyTheB64Part, SubjectPublicKeyInfoDilithium ** pub_key)
{

    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    unsigned char * pub_bytes_buffer = 0;
    size_t pub_bytes_length = sizeof(pub_bytes_buffer);

    LOG_TRACE("Convert to raw");
    base_64_decode(onlyTheB64Part, &pub_bytes_buffer, &pub_bytes_length);

    LOG_TRACE_ARG("pub_bytes_length: %zu", pub_bytes_length);
#ifdef LOG_BYTE_ARRARY_ON
    for (int i = 0; i < pub_bytes_length; i++) {
        LOG_TRACE_KEY_DATA_ARG("index: %d -> %#x |", i, pub_bytes_buffer[i]);
    }
#endif

    const unsigned char * const_pub_bytes_buffer = pub_bytes_buffer;

    LOG_TRACE("Parse input");
    (*pub_key) = d2i_SubjectPublicKeyInfoDilithium(pub_key, &const_pub_bytes_buffer, pub_bytes_length);
}

/**
 * Compare two public key data.
 *
 * @param[in] selection: type of the selection
 * @param[in] pub_key_from_data_1: key data 1
 * @param[in] size_of_pub_key_from_data_1: size of key data 1
 * @param[in] pub_key_from_data_2_with_gta_api: key data 2
 * @param[in] size_of_pub_key_from_data_2_with_gta_api: size of key data 2
 * @param[out] ret: OK = 1 or NOK = 0
 */
void compare_dilithium_keydata(
    int selection,
    unsigned char * pub_key_from_data_1,
    size_t size_of_pub_key_from_data_1,
    unsigned char * pub_key_from_data_2_with_gta_api,
    size_t size_of_pub_key_from_data_2_with_gta_api,
    int * ret)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s) compare keys", __func__);
    int key_checked = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        LOG_TRACE("CASE PUBLIC KEY: Compare dilithium raw key");

        if ((size_of_pub_key_from_data_1 == size_of_pub_key_from_data_2_with_gta_api) &&
            (0 == memcmp(pub_key_from_data_1, pub_key_from_data_2_with_gta_api, size_of_pub_key_from_data_1))) {

            LOG_TRACE("Match");
            (*ret) = OK;
        } else {
            LOG_TRACE("Not match");
            (*ret) = NOK;
        }

        key_checked = 1;
    }

    if (!key_checked && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        LOG_TRACE("CASE PRIVATE KEY: Compare dilithium raw key");

        LOG_WARN("Unhandled CASE");
        (*ret) = NOK;
    }
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

    unsigned char * pub_key_from_data_1 = NULL;
    size_t size_of_pub_key_from_data_1 = 0;
    unsigned char * pub_key_from_data_2_with_gta_api = NULL;
    size_t size_of_pub_key_from_data_2_with_gta_api = 0;

    GTA_PROVIDER_CTX * kctx = NULL;

    if (keydata1 == NULL) {
        LOG_TRACE("Key data 1 is null");
        return NOK;
    } else {
        LOG_TRACE("Key data 1 is not null");
        parse_dilithium_key_data_1(keydata1, &pub_key_from_data_1, &size_of_pub_key_from_data_1, &kctx);
    }

    if (keydata2 == NULL) {
        LOG_TRACE("Key data 2 is null");
        return NOK;
    } else {
        LOG_TRACE("Key data 2 is not null");

        GTA_PKEY * pkey2 = (GTA_PKEY *)keydata2;

        LOG_TRACE_ARG("Function (%s) GTA pkey2->string = %s", __func__, pkey2->string);
        LOG_TRACE_ARG("Function (%s) GTA pkey2->personality_name = %s", __func__, pkey2->personality_name);
        LOG_TRACE_ARG("Function (%s) GTA pkey2->profile_name = %s", __func__, pkey2->profile_name);

        LOG_TRACE_ARG("Function (%s) GTA pkey2->pub_key = %s", __func__, pkey2->pub_key);
        LOG_TRACE_ARG("Function (%s) GTA pkey2->pub_key_size = %zu", __func__, pkey2->pub_key_size);

        if (pkey2->provctx == NULL) {
            LOG_WARN("No context in keydata2");
        } else {
            LOG_TRACE("We have a context in keydata2");
            kctx = (GTA_PROVIDER_CTX *)(pkey2->provctx);
        }

        gta_errinfo_t errinfo = 0;

        LOG_TRACE("GTA context open");
        LOG_TRACE("Check input parameters");
        if (kctx == NULL) {
            LOG_WARN("kctx is NULL");
            return NOK;
        }

        LOG_TRACE_ARG("kctx->status = %d", kctx->status);

        if (kctx->h_inst == NULL) {
            LOG_WARN("kctx->h_inst is NULL");
            return NOK;
        }

        LOG_TRACE("Call gta_context_open");
        gta_context_handle_t h_ctx =
            gta_context_open(kctx->h_inst, pkey2->personality_name, pkey2->profile_name, &errinfo);
        LOG_TRACE("After call gta_context_open");

        if (NULL == h_ctx) {
            LOG_WARN_ARG("GTA context open problem: %lu", errinfo);
            return NOK;
        } else {
            LOG_TRACE("We have a GTA context");

            ostream_to_buf_t ostream_data = {0};
            unsigned char obuf[SIZE_OF_GTA_O_BUFFER_FOR_DILITHIUM] = {0};
            size_t obuf_size = sizeof(obuf) - 1;

            LOG_TRACE("Open output stream");
            if (!ostream_to_buf_init(&ostream_data, (char *)obuf, obuf_size, &errinfo)) {
                LOG_ERROR_ARG("ostream_to_buf_init failed: %lu", errinfo);
                return NOK;
            }

            LOG_TRACE("gta_personality_enroll(...)");
            if (!gta_personality_enroll(h_ctx, (gtaio_ostream_t *)&ostream_data, &errinfo)) {
                LOG_ERROR_ARG("gta_personality_enroll failed: %lu", errinfo);
                return NOK;
            }

            LOG_TRACE_ARG("ostream_data.pos=%ld", (long)ostream_data.buf_pos);
#ifdef LOG_B64_ON
            LOG_TRACE_ARG("ostream_data.buf=%s", ostream_data.buf);
#endif

            LOG_TRACE("Convert");

            char * pub_key_begin = PUB_KEY_BEGIN_TAG;
            char * pub_key_end = PUB_KEY_END_TAG;

            char * onlyTheB64Part = str_remove((char *)ostream_data.buf, pub_key_begin);
            onlyTheB64Part = str_remove(onlyTheB64Part, pub_key_end);
            onlyTheB64Part = str_remove(onlyTheB64Part, "\n");

#ifdef LOG_B64_ON
            LOG_TRACE_ARG("B64 part: %s", onlyTheB64Part);
#endif

            SubjectPublicKeyInfoDilithium * pub_key = NULL;
            parse_dilithium_pem_object(onlyTheB64Part, &pub_key);

            if (NULL == pub_key) {
                LOG_ERROR("Key component is null");
                return NOK;
            } else {
                LOG_TRACE("Key component OK");
            }

            LOG_TRACE_ARG("pub_key->subjectPublicKey length: %d", pub_key->public_key_data->length);
            for (int i = 0; i < (pub_key->public_key_data->length); i++) {
                LOG_TRACE_KEY_DATA_ARG("%#x ", pub_key->public_key_data->data[i]);
            }

            pub_key_from_data_2_with_gta_api =
                mem_dup(pub_key->public_key_data->data, (size_t)(pub_key->public_key_data->length));
            size_of_pub_key_from_data_2_with_gta_api = (size_t)(pub_key->public_key_data->length);

            if (OK != ostream_to_buf_close(&ostream_data, &errinfo)) {
                LOG_ERROR_ARG("ostream_to_buf_close failed: %lu", errinfo);
                return NOK;
            }
        }

        if (OK != gta_context_close(h_ctx, &errinfo)) {
            LOG_ERROR_ARG("GTA context close failed: %lu", errinfo);
            return NOK;
        }
    }

    LOG_TRACE("Match - compare pub keys");

    int ret = NOK;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        LOG_TRACE("CASE DOMAIN_PARAMETERS: Compare dilithium group");
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        compare_dilithium_keydata(
            selection,
            pub_key_from_data_1,
            size_of_pub_key_from_data_1,
            pub_key_from_data_2_with_gta_api,
            size_of_pub_key_from_data_2_with_gta_api,
            &ret);
    }

    OPENSSL_clear_free(pub_key_from_data_1, size_of_pub_key_from_data_1);
    OPENSSL_clear_free(pub_key_from_data_2_with_gta_api, size_of_pub_key_from_data_2_with_gta_api);

    LOG_WARN_ARG("Method [%s], return with %d value", __func__, ret);
    return ret;
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
