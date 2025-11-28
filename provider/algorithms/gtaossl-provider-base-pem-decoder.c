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
    dctx->h_persenum = GTA_HANDLE_ENUM_FIRST;
    dctx->next_attribute = NULL;
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

    OPENSSL_free(dctx->next_attribute);
    OPENSSL_clear_free(dctx, sizeof(GTA_DER_DECODER_CTX));
}

static bool get_next_trusted_attribute_name(
    GTA_DER_DECODER_CTX * dctx,
    gta_personality_name_t personality,
    gta_personality_attribute_name_t * attribute_name)
{
    /* Enumerate trusted attributes of a personality */
    gta_errinfo_t errinfo = 0;
    char attr_name[MAXLEN_ATTRIBUTE_NAME] = {0};
    ostream_to_buf_t ostream = {0};
    ocmpstream_t attr_type = {0};
    bool b_loop = true;

    LOG_TRACE("Enumerate personality attributes");
    while (b_loop) {
        ocmpstream_init(&attr_type, GTA_TRUSTED_CERTIFICATE_TYPE);
        ostream_to_buf_init(&ostream, attr_name, sizeof(attr_name));
        if (gta_personality_attributes_enumerate(
                dctx->provctx->h_inst,
                personality,
                &dctx->h_persenum,
                (gtaio_ostream_t *)&attr_type,
                (gtaio_ostream_t *)&ostream,
                &errinfo)) {
            if (CMP_EQUAL == attr_type.cmp_result) {
                b_loop = false;
                LOG_TRACE("Found a trusted attribute");
                *attribute_name = OPENSSL_zalloc(ostream.buf_pos);
                if (NULL == *attribute_name) {
                    LOG_ERROR("Error in memory allocation");
                    return false;
                }
                memcpy(*attribute_name, attr_name, ostream.buf_pos);
                LOG_TRACE_ARG("Attribute name: %s", *attribute_name);
            }
        } else {
            b_loop = false;
            if (GTA_ERROR_ENUM_NO_MORE_ITEMS != errinfo) {
                /* Error in enumeration */
                LOG_ERROR_ARG("Error in enumeration of personality attributes: %lu", errinfo);
                return false;
            }
            LOG_TRACE("Enumerate personality attributes done");
            dctx->h_persenum = GTA_HANDLE_ENUM_FIRST;
        }
    }
    return true;
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
    OSSL_PARAM params[4] = {0};
    int res = 0;
    int bio_pos = 0;

    if ((bin = BIO_new_from_core_bio(dctx->libctx, cin)) == NULL) {
        LOG_ERROR("BIO_new_from_core_bio failed!");
        return NOK;
    }

    /* Save current file position */
    bio_pos = BIO_tell(bin);

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

            LOG_INFO_ARG("GTA personality: %s", personality);
            LOG_INFO_ARG("GTA profile: %s", profile);

            /* Get the next attribute name if we don't have one yet */
            if ((NULL == dctx->next_attribute) &&
                (!get_next_trusted_attribute_name(dctx, personality, &dctx->next_attribute))) {
                return NOK;
            }

            /* Get personality attribute */
            gta_context_handle_t h_ctx = GTA_HANDLE_INVALID;
            gta_errinfo_t errinfo = 0;
            char buffer[GTA_READ_BUFFER_FOR_CA_CERT] = {0};
            ostream_to_buf_t ostream = {0};

            LOG_TRACE("Open GTA API context");
            h_ctx = gta_context_open(dctx->provctx->h_inst, personality, profile, &errinfo);
            if (GTA_HANDLE_INVALID == h_ctx) {
                LOG_ERROR_ARG("Error in GTA API context open: %lu", errinfo);
                return NOK;
            }
            LOG_TRACE("Init output stream");
            ostream_to_buf_init(&ostream, (char *)buffer, sizeof(buffer));
            LOG_TRACE("Get attribute");
            if (!gta_personality_get_attribute(h_ctx, dctx->next_attribute, (gtaio_ostream_t *)&ostream, &errinfo)) {
                LOG_ERROR_ARG("GTA personality get attribute failed: %lu", errinfo);
                return NOK;
            }
            LOG_TRACE("Close GTA API context");
            gta_context_close(h_ctx, &errinfo);

            int objtype = OSSL_OBJECT_CERT;
            params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, buffer, ostream.buf_pos);
            params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE, "Certificate", 0);
            params[2] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &objtype);
            params[3] = OSSL_PARAM_construct_end();
            res = object_cb(params, object_cbarg);
            LOG_TRACE_ARG("result: %i", res);

            OPENSSL_free(dctx->next_attribute);
            dctx->next_attribute = NULL;

            /* Retrieve the next attribute name */
            if (!get_next_trusted_attribute_name(dctx, personality, &dctx->next_attribute)) {
                return NOK;
            }
            /* Restore BIO position, if we found another attribute */
            if (NULL != dctx->next_attribute) {
                BIO_seek(bin, bio_pos);
            }

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
