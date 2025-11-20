/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtaossl-provider-base-gta-decoder.h"

#include "../config/gtaossl-provider-config.h"
#include "../gtaossl-provider.h"
#include "../logger/gtaossl-provider-logger.h"
#include "../stream/streams.h"
#include <ctype.h>
#include <gta_api/gta_api.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <string.h>

extern int gtaossl_provider_base_keymgmt_export(void * keydata, int selection, OSSL_CALLBACK * param_cb, void * cbarg);

/**
 * The GTA decoder new context function should create and return a pointer
 * to a structure that is extended with a GTA provider and GTA_DECODER context.
 * This structure holds the decoder context during the decoding operation.
 */
void * gtaossl_provider_base_gta_decoder_newctx(void * provctx)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    GTA_PROVIDER_CTX * cprov = provctx;
    GTA_DECODER_CTX * dctx = OPENSSL_zalloc(sizeof(GTA_DECODER_CTX));

    if (dctx == NULL) {
        LOG_WARN_ARG("%s -> dctx is null", __func__);
        return NULL;
    }

    dctx->core = cprov->core;
    dctx->libctx = cprov->libctx;
    dctx->provider_ctx = cprov;
    LOG_DEBUG_ARG("End of %s", __func__);
    return dctx;
}

/**
 * The function should free the GTA decoder context.
 */
void gtaossl_provider_base_gta_decoder_freectx(void * ctx)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    GTA_DECODER_CTX * dctx = ctx;

    OPENSSL_clear_free(dctx, sizeof(GTA_DECODER_CTX));
}

char * strlwr(char * str)
{
    unsigned char * p = (unsigned char *)str;

    while (*p) {
        *p = (unsigned char)tolower(*p);
        p++;
    }

    return str;
}

int str_equals_ignore_case(const char * str1, const char * str2)
{

    char * lower_str1 = strdup(str1);
    lower_str1 = strlwr(lower_str1);

    LOG_TRACE_ARG("str1: lower(%s) = %s ", str1, lower_str1);

    char * lower_str2 = strdup(str2);
    lower_str2 = strlwr(lower_str2);

    LOG_TRACE_ARG("str2: lower(%s) = %s ", str2, lower_str2);

    if (0 == strcmp(str1, str2)) {
        return OK;
    }

    return NOK;
}

int str_contains_ignore_case(const char * str1, const char * str2)
{

    char * lower_str1 = strdup(str1);
    lower_str1 = strlwr(lower_str1);

    LOG_TRACE_ARG("str1: lower(%s) = %s ", str1, lower_str1);

    char * lower_str2 = strdup(str2);
    lower_str2 = strlwr(lower_str2);

    LOG_TRACE_ARG("str2: lower(%s) = %s ", str2, lower_str2);

    if (NULL == strstr(str1, str2)) {
        return NOK;
    }

    return OK;
}

/**
 * Thew function should decode the data as read from the OSSL_CORE_BIO
 * (the key BIO objects are replaced with GTA API references,
 * because the GTA Provider must manage the public and private key pair.)
 * to produce decoded data or an object to be passed as reference in an OSSL_PARAM(3)
 * array along with possible other metadata that was decoded from the input.
 * (only the public key can be exported from the GTA context)
 */
int gtaossl_provider_base_gta_decoder_decode(
    void * ctx,
    OSSL_CORE_BIO * cin,
    int selection,
    OSSL_CALLBACK * object_cb,
    void * object_cbarg,
    OSSL_PASSPHRASE_CALLBACK * pw_cb,
    void * pw_cbarg,
    const char * expected_keytype)
{
    LOG_INFO("Decode GTA object");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    GTA_DECODER_CTX * dctx = ctx;
    BIO * bin = NULL;

    /* Currently unused */
    (void)pw_cb;
    (void)pw_cbarg;

    LOG_TRACE_ARG("%s - selection=%d", __func__, selection);

    OSSL_PARAM params[4] = {0};
    int object_type = 0;
    int res = NOK;

    if ((bin = BIO_new_from_core_bio(dctx->libctx, cin)) == NULL) {
        LOG_ERROR("BIO_new_from_core_bio failed!");
        goto error1;
    }

    if (BIO_tell(bin) == -1) {
        LOG_ERROR("BIO position problem");
        goto error2;
    }

    char buf[GTA_READ_BUFFER] = {0};
    size_t read = 0;

    BIO_read_ex(bin, buf, sizeof(buf), &read);
    LOG_TRACE_ARG("Read (bytes): %zu", read);
    LOG_TRACE_ARG("Buffer: %s", buf);

    read += 1;

    GTA_PKEY * pkey = OPENSSL_zalloc(sizeof(GTA_PKEY));
    if (pkey == NULL) {
        LOG_ERROR("Allocation problem of GTA_PKEY");
        return NOK;
    }

    pkey->string = OPENSSL_zalloc(read * sizeof(char));
    if (pkey->string == NULL) {
        LOG_ERROR("Allocation problem of pkey->string");
        return NOK;
    }

    memcpy(pkey->string, buf, read);
    LOG_TRACE_ARG("pkey->string: %s", pkey->string);

    char * saveptr = NULL;
    char * personality = strtok_r(pkey->string, ",", &saveptr);
    if (NULL == personality) {
        LOG_DEBUG("strtok failed - no personalty info in the string");
        return NOK;
    }

    char * profile = strtok_r(NULL, ",", &saveptr);
    if (NULL == profile) {
        LOG_DEBUG("strtok failed - no profile info in the string");
        return NOK;
    }

    LOG_TRACE_ARG("Profile: %s", profile);

    pkey->personality_name = personality;
    pkey->profile_name = profile;

    gta_errinfo_t errinfo = 0;

    LOG_TRACE("GTA context open");

    dctx->h_ctx = gta_context_open(dctx->provider_ctx->h_inst, pkey->personality_name, pkey->profile_name, &errinfo);

    if (NULL == dctx->h_ctx) {
        LOG_WARN_ARG("Skip decoder, because of the GTA context open problem: %lu", errinfo);
        return NOK;
    } else {

        ostream_to_buf_t ostream_data = {0};
        unsigned char obuf[SIZE_OF_GTA_O_BUFFER] = {0};
        size_t obuf_size = sizeof(obuf) - 1;

        LOG_TRACE("Open output stream");
        if (!ostream_to_buf_init(&ostream_data, (char *)obuf, obuf_size, &errinfo)) {
            LOG_ERROR_ARG("ostream_to_buf_init failed: %lu", errinfo);
            return NOK;
        }

        LOG_TRACE("Get attribute");
        if (!gta_personality_get_attribute(
                dctx->h_ctx, GTA_KEY_TYPE_ATTRIBUTE, (gtaio_ostream_t *)&ostream_data, &errinfo)) {
            LOG_ERROR_ARG("GTA personality get attribute failed: %lu", errinfo);
            return NOK;
        } else {

            LOG_TRACE_ARG("Keytype from GTA personality: %s", ostream_data.buf);
            LOG_TRACE_ARG("Expected keytype: %s", expected_keytype);

            if (str_equals_ignore_case(expected_keytype, ostream_data.buf)) {
                LOG_DEBUG("Decoder selected");
            } else {
                LOG_DEBUG("Skip decoder");
                return OK;
            }
        }

        if (OK != ostream_to_buf_close(&ostream_data, &errinfo)) {
            LOG_ERROR_ARG("ostream_to_buf_close failed: %lu", errinfo);
            return NOK;
        }

        if (OK != gta_context_close(dctx->h_ctx, &errinfo)) {
            LOG_ERROR_ARG("GTA context close failed: %lu", errinfo);
            return NOK;
        }
    }

    pkey->provctx = dctx->provider_ctx;

    if (NULL != expected_keytype) {
        LOG_TRACE_ARG("GTA DECODER DECODE found %s", expected_keytype);

        object_type = OSSL_OBJECT_PKEY;
        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);

        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)expected_keytype, 0);
        /* The address of the key becomes the octet string */
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &pkey, sizeof(GTA_PKEY));
        params[3] = OSSL_PARAM_construct_end();

        if (object_cb(params, object_cbarg)) {
            BIO_free(bin);
            return OK;
        }
    } else {
        LOG_WARN("We return \"empty handed\". This is not an error.");
        res = OK;
    }
error2:
    BIO_free(bin);
error1:
    return res;
}

/**
 * The function exports the GTA object but does not contain any implementation.
 * It is defined because of avoiding an error.
 */
int gtaossl_provider_base_gta_decoder_export_object(
    void * ctx,
    const void * objref,
    size_t objref_sz,
    OSSL_CALLBACK * export_cb,
    void * export_cbarg)
{
    LOG_INFO("GTA decoder tries to export object");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)ctx;
    (void)objref;
    (void)objref_sz;
    (void)export_cb;
    (void)export_cbarg;

    LOG_DEBUG_ARG("(%s) return NOK", __func__);
    return NOK;
}

/**
 * OSSL_FUNC_decoder_does_selection() should indicate if a particular
 * implementation supports any of the combinations given by selection.
 *
 * 1. In the current demo,
 * - If the selection is a private key, then the function will return with true.
 * - In case of public key and parameter selection, return false.
 * - If the selection is 0, the function will return true.
 *
 * 2. In case of GTA API usage, the private key must be handled by the GTA provider.
 * All private key-related functions must be overwrite in the gtaossl provider.
 *
 * @param[in] provctx: provider context
 * @param[in] selection: type of the selection
 * @return OK = 1
 * @return NOK = 0
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-decoder/#description
 */
int gtaossl_provider_base_gta_does_selection(void * provctx, int selection)
{

    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("Selection: %d", selection);

    /* Currently unused */
    (void)provctx;

    int checks[] = {
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS};

    /* The decoder implementations made here support guessing */
    if (selection == 0) {
        LOG_TRACE_ARG("%s - The decoder implementations made here support guessing.", __func__);
        return OK;
    }

    for (size_t i = 0; i < OSSL_NELEM(checks); i++) {
        int check1 = (selection & checks[i]) != 0;
        int check2 = (OSSL_KEYMGMT_SELECT_PRIVATE_KEY & checks[i]) != 0;

#ifdef LOG_FOR_CYCLE_ON
        LOG_TRACE_ARG("Check 1: %d", check1);

        LOG_TRACE_ARG("Check 2: %d", check2);
#endif

        /*
         * If the caller asked for the currently checked bit(s), return
         * whether the decoder description says it's supported.
         */
        if (check1) {
            LOG_TRACE_ARG("Return %d", check2);
            return check2;
        }
    }

    LOG_TRACE("Return false");
    return NOK;
}