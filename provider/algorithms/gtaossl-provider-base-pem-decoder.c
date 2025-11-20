/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../config/gtaossl-provider-config.h"
#include "../gtaossl-provider.h"
#include "../logger/gtaossl-provider-logger.h"
#include "../stream/streams.h"
#include "gtaossl-provider-base-decoder.h"
#include "gtaossl-provider-base-gta-decoder.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <string.h>

/*-------------------------------PEM------------------------------------------*/
static OSSL_FUNC_decoder_newctx_fn gtaossl_provider_base_pem_decoder_newctx;
static OSSL_FUNC_decoder_freectx_fn gtaossl_provider_base_pem_decoder_freectx;
static OSSL_FUNC_decoder_decode_fn gtaossl_provider_base_pem_decoder_decode;

/**
 * The PEM decoder new context function should create and return a pointer
 * to a structure, that is extended with a GTA provider and GTA_DER_DECODER_CTX context.
 * This structure holds the decoder context during the decoding operation.
 *
 * @param[in/out] provctx: the parameter is a provider context
 *                         generated during the provider initialization.
 * @return a new context.
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-decoder/#description
 */
static void * gtaossl_provider_base_pem_decoder_newctx(void * provctx)
{

    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    GTA_PROVIDER_CTX * cprov = provctx;
    GTA_DER_DECODER_CTX * dctx = OPENSSL_zalloc(sizeof(GTA_DER_DECODER_CTX));

    if (dctx == NULL) {
        LOG_WARN_ARG("%s -> dctx is null", __func__);
        return NULL;
    }

    dctx->core = cprov->core;
    dctx->libctx = cprov->libctx;
    dctx->provctx = cprov;
    LOG_DEBUG_ARG("End of %s", __func__);
    return dctx;
}

/**
 * The function should free the PEM decoder context.
 *
 * @param[in] ctx pointer of the PEM decoder context
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-decoder/#description
 */
static void gtaossl_provider_base_pem_decoder_freectx(void * ctx)
{

    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    GTA_DER_DECODER_CTX * dctx = ctx;

    OPENSSL_clear_free(dctx, sizeof(GTA_DER_DECODER_CTX));
}

/**
 * Thew function should decode the data as read from the OSSL_CORE_BIO (PEM encoded input)
 * to produce decoded data (result is a DER object) or an object
 * to be passed as a reference in an OSSL_PARAM(3)
 * array along with possible other metadata that was decoded from the input.
 * (OSSL_OBJECT_PARAM_DATA_STRUCTURE is GTA
 *  OSSL_OBJECT_PARAM_DATA = data)
 *
 * @param[in] ctx: pointer of the PEM decoder context
 * @param[in] cin: input BIO object
 * @param[in] selection: type of the selection
 * @param[in] object_cb: object callback function
 * @param[in] object_cbarg: arguments of the object callback function
 * @param[in] pw_cb: password callback function
 * @param[in] pw_cbarg: arguments of password callback function
 * @return OK = 1
 * @return NOK = 0
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-decoder/#export-function
 */
static int gtaossl_provider_base_pem_decoder_decode(
    void * ctx,
    OSSL_CORE_BIO * cin,
    int selection,
    OSSL_CALLBACK * object_cb,
    void * object_cbarg,
    OSSL_PASSPHRASE_CALLBACK * pw_cb,
    void * pw_cbarg)
{

    LOG_INFO("Decode pem object");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("%s -> input (selection = %d)", __func__, selection);
    GTA_DER_DECODER_CTX * dctx = ctx;

    /* Currently unused */
    (void)pw_cb;
    (void)pw_cbarg;

    BIO * bin = NULL;
    char * pem_name = NULL;
    char * pem_header = NULL;
    unsigned char * der_data = NULL;
    long der_len = 0;
    OSSL_PARAM params[3] = {0};
    int res = 0;

    if ((bin = BIO_new_from_core_bio(dctx->libctx, cin)) == NULL) {
        LOG_ERROR("BIO_new_from_core_bio failed!");
        return NOK;
    }

    /* Note: der_data is not NULL-terminated */
    if (PEM_read_bio(bin, &pem_name, &pem_header, &der_data, &der_len) > 0) {

        if (strcmp(pem_name, "GTA PRIVATE KEY") == 0) {

            LOG_TRACE_ARG("%s -> submit the loaded key", __func__);
            LOG_TRACE_ARG("%s -> pem_name: %s", __func__, pem_name);
            LOG_TRACE_ARG("%s -> pem_header: %s", __func__, pem_header);
            LOG_TRACE_ARG("Full data in %s = %s", __func__, (char *)der_data);

            params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, der_data, der_len);
            params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE, GTA_DATA_STRUCTURE_PARAM, 0);
            params[2] = OSSL_PARAM_construct_end();

            res = object_cb(params, object_cbarg);
        } else if (strcmp(pem_name, "GTA TRUSTED KEY") == 0) {

            LOG_TRACE_ARG("%s -> submit the trusted key", __func__);
            LOG_TRACE_ARG("%s -> pem_name: %s", __func__, pem_name);
            LOG_TRACE_ARG("%s -> pem_header: %s", __func__, pem_header);
            LOG_TRACE_ARG("Full data in %s = %s", __func__, (char *)der_data);
            LOG_TRACE_ARG("%s -> der len: %li", __func__, der_len);

            /* Copy der_data into temporary buffer in order to NULL-terminate it */
            char * buf = OPENSSL_zalloc(der_len + 1);
            if (NULL == buf) {
                LOG_ERROR("Allocation problem of buf");
                return NOK;
            }
            memcpy(buf, der_data, der_len);

            char * saveptr = NULL;
            char * personality = strtok_r(buf, ",", &saveptr);
            if (NULL == personality) {
                LOG_ERROR("strtok failed - no personalty info in the string");
                return NOK;
            }

            char * profile = strtok_r(NULL, ",", &saveptr);
            if (NULL == profile) {
                LOG_ERROR("strtok failed - no profile info in the string");
                return NOK;
            }

            gta_context_handle_t h_ctx = GTA_HANDLE_INVALID;
            gta_errinfo_t errinfo = 0;

            LOG_INFO_ARG("GTA personality: %s", personality);
            LOG_INFO_ARG("GTA profile: %s", profile);
            h_ctx = gta_context_open(dctx->provctx->h_inst, personality, profile, &errinfo);
            if (GTA_HANDLE_INVALID == h_ctx) {
                LOG_ERROR_ARG("Skip decoder, because of the GTA context open problem: %lu", errinfo);
                return NOK;
            }

            char buffer[GTA_READ_BUFFER_FOR_CA_CERT] = {0};
            ostream_to_buf_t ostream = {0};

            LOG_TRACE("Open output stream");
            if (OK != ostream_to_buf_init(&ostream, (char *)buffer, sizeof(buffer), &errinfo)) {
                LOG_ERROR_ARG("ostream_to_buf_init failed: %lu", errinfo);
                return NOK;
            }

            LOG_TRACE("Get attribute");
            if (!gta_personality_get_attribute(h_ctx, "Trusted", (gtaio_ostream_t *)&ostream, &errinfo)) {
                LOG_ERROR_ARG("GTA personality get attribute failed: %lu", errinfo);
                return NOK;
            }

            params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, buffer, ostream.buf_pos);
            params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE, DER_DATA_STRUCTURE_PARAM, 0);
            params[2] = OSSL_PARAM_construct_end();

            res = object_cb(params, object_cbarg);
            gta_context_close(h_ctx, &errinfo);
            OPENSSL_free(buf);
        } else {
            /* We return "empty handed". This is not an error. */
            LOG_TRACE_ARG("%s -> We return \"empty handed\" (1). This is not an error.", __func__);
            res = OK;
        }
    } else {

        /* We return "empty handed". This is not an error. */
        LOG_TRACE_ARG("%s -> We return \"empty handed\" (2). This is not an error.", __func__);
        res = OK;
    }

    OPENSSL_free(pem_name);
    OPENSSL_free(pem_header);
    OPENSSL_free(der_data);
    BIO_free(bin);
    LOG_TRACE_ARG("End of %s", __func__);
    return res;
}

const OSSL_DISPATCH base_decoder_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))gtaossl_provider_base_pem_decoder_newctx},
    {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))gtaossl_provider_base_pem_decoder_freectx},
    {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))gtaossl_provider_base_gta_does_selection},
    {OSSL_FUNC_DECODER_DECODE, (void (*)(void))gtaossl_provider_base_pem_decoder_decode},
    {0, NULL}};
