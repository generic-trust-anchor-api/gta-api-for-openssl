/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../../config/gtaossl-provider-config.h"
#include "../../gtaossl-provider.h"
#include "../../logger/gtaossl-provider-logger.h"
#include "../gtaossl-provider-base-decoder.h"
#include "../gtaossl-provider-base-gta-decoder.h"
#include "gtaossl-provider-dilithium-types.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <string.h>

/*--------------------------------DER-----------------------------------------*/
static OSSL_FUNC_decoder_freectx_fn gtaossl_provider_dilithium_der2key_freectx;
static OSSL_FUNC_decoder_decode_fn gtaossl_provider_dilithium_der2key_decode;
static OSSL_FUNC_decoder_newctx_fn gtaossl_provider_dilithium_subject_pub_key_info_newctx;

int asn1_d2i_read_bio(BIO * in, BUF_MEM ** pb);

int ossl_read_der(GTA_PROVIDER_CTX * provctx, OSSL_CORE_BIO * cin, unsigned char ** data, long * len);

static void create_key_object_from_der_data(GTA_PKEY * pKey, unsigned char * der_data, long der_len);

static void generate_ossl_parameters(void ** key, OSSL_PARAM * params);

/**
 * The DER to key decoder new context function should create and return a pointer
 * to a structure, that is extended with GTA_DER_DECODER_CTX context.
 * This structure holds the decoder context during the decoding operation.
 *
 * @param[in/out] vctx: the parameter is a provider context
 *                      generated during the provider initialization.
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-decoder/#description
 */
static void gtaossl_provider_dilithium_der2key_freectx(void * vctx)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    GTA_DER_DECODER_CTX * dctx = vctx;
    OPENSSL_clear_free(dctx, sizeof(GTA_DER_DECODER_CTX));
}

/**
 * Thew function should decode the data as read from the OSSL_CORE_BIO (DER encoded input)
 * to produce decoded data (result is a GTA_PKEY object) or an object
 * to be passed as a reference in an OSSL_PARAM(3)
 * array along with possible other metadata that was decoded from the input.
 * (OSSL_OBJECT_PARAM_DATA_STRUCTURE is GTA
 *  OSSL_OBJECT_PARAM_DATA = data)
 *
 * 1. Open the BIO object to read the DER data into a buffer.
 *
 * 2. Based on the type, the function tries
 * to prepare the value of private, public key and OSSL paramters:
 * - In case of PRIVATE KEY, an empty structure wil be created.
 * - In case of PUBLIC KEY, binary key data and size paremates will be created.
 * - In case of the OSSL PARAMETERs, data type parameter will be created.
 *
 * 3. Convert and copy key data form an ASN1 Dilithium structure.
 *
 * 4. The data type parameter is dilithium2.
 *
 * @param[in] vctx: pointer of the DER to key decoder context
 * @param[in] cin: input BIO object
 * @param[in] selection: type of the selection
 * @param[in] data_cb: object callback function
 * @param[in] data_cbarg: arguments of the object callback function
 * @param[in] pw_cb: password callback function
 * @param[in] pw_cbarg: arguments of password callback function
 * @return OK = 1
 * @return NOK = 0
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-decoder/#export-function
 */
static int gtaossl_provider_dilithium_der2key_decode(
    void * vctx,
    OSSL_CORE_BIO * cin,
    int selection,
    OSSL_CALLBACK * data_cb,
    void * data_cbarg,
    OSSL_PASSPHRASE_CALLBACK * pw_cb,
    void * pw_cbarg)
{
    void * key = NULL;
    int ok = NOK;
    GTA_PKEY * pKey = NULL;

    /* Currently unused */
    (void)pw_cb;
    (void)pw_cbarg;

    LOG_INFO("Decode dilithium der object");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("%s -> input (selection = %d)", __func__, selection);

    char * pem_name = NULL;
    char * pem_header = NULL;
    unsigned char * der_data = NULL;
    long der_len = 0;

    GTA_DER_DECODER_CTX * dctx = (GTA_DER_DECODER_CTX *)vctx;

    LOG_TRACE_ARG("CUSTOM PROVIDER(%s) ossl_read_der", __func__);
    ok = ossl_read_der(dctx->provctx, cin, &der_data, &der_len);
    if (!ok) {
        LOG_TRACE_ARG("Custom provider(%s) IT WOULD BE THE go to next\n", __func__);
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        LOG_TRACE("OSSL_KEYMGMT_SELECT_PRIVATE_KEY");
        key = malloc(sizeof(GTA_PKEY));
        pKey = (GTA_PKEY *)key;
        pKey->string = NULL;
        pKey->profile_name = NULL;
        pKey->personality_name = NULL;
    }
    if (key == NULL && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        LOG_TRACE("OSSL_KEYMGMT_SELECT_PUBLIC_KEY");
        key = malloc(sizeof(GTA_PKEY));
        pKey = (GTA_PKEY *)key;
        pKey->string = NULL;
        pKey->profile_name = NULL;
        pKey->personality_name = NULL;
        pKey->provctx = dctx->provctx;

        create_key_object_from_der_data(pKey, der_data, der_len);
    }
    if (key == NULL && (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0) {
        LOG_TRACE("OSSL_KEYMGMT_SELECT_ALL_PARAMETERS");
    }

    if (key != NULL) {
        LOG_TRACE("Create OSSL parameters for the callback function");
        OSSL_PARAM params[4];
        generate_ossl_parameters(&key, params);
        ok = data_cb(params, data_cbarg);
    }

    OPENSSL_free(pem_name);
    OPENSSL_free(pem_header);
    OPENSSL_free(der_data);
    LOG_TRACE_ARG("Return decoder: %d", ok);
    return ok;
}

/**
 * The (subject) public key info new context function should create and return a pointer
 * to a structure, that is extended with GTA_DER_DECODER_CTX context.
 * This structure holds the decoder context during the decoding operation.
 *
 * @param[in/out] provctx: the parameter is a provider context
 *                      generated during the provider initialization.
 * @return a new context.
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-decoder/#description
 */
static void * gtaossl_provider_dilithium_subject_pub_key_info_newctx(void * provctx)
{

    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    GTA_PROVIDER_CTX * cprov = provctx;
    GTA_DER_DECODER_CTX * dctx = OPENSSL_zalloc(sizeof(GTA_DER_DECODER_CTX));

    if (dctx == NULL) {
        LOG_ERROR("Decoder context allocation error");
        return NULL;
    }

    dctx->core = cprov->core;
    dctx->libctx = cprov->libctx;
    dctx->provctx = cprov;
    return dctx;
}

/**
 * Create GTA key object from DER data
 *
 * @param[in] der_data: input byte array
 * @param[in] der_len: length of the input data
 * @param[out] pKey: GTA_PKEY object
 */
static void create_key_object_from_der_data(GTA_PKEY * pKey, unsigned char * der_data, long der_len)
{

    SubjectPublicKeyInfoDilithium * pub_key = NULL;
    const unsigned char * const_der_data = der_data;

    LOG_TRACE_ARG("Length of der object: %ld", der_len);

    pub_key = d2i_SubjectPublicKeyInfoDilithium(&pub_key, &const_der_data, der_len);

    if (pub_key != NULL) {
        LOG_TRACE("Push content to the public key data");
        pKey->pub_key = (char *)mem_dup(pub_key->public_key_data->data, (size_t)(pub_key->public_key_data->length));
        pKey->pub_key_size = (size_t)(pub_key->public_key_data->length);
    } else {
        LOG_WARN("Der object parsing problem");
    }
}

/*
 * The address of the key becomes the octet string
 */
static void generate_ossl_parameters(void ** key, OSSL_PARAM * params)
{

    int object_type = OSSL_OBJECT_PKEY;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, OQS_DILITHIUM_2, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, key, sizeof(*key));
    params[3] = OSSL_PARAM_construct_end();
}

/*
 * Private source code from OpenSSL 3.2.0
 * Original source code:
 * https://github.com/openssl/openssl/blob/openssl-3.2.0/providers/implementations/encode_decode/endecoder_common.c#L87
 */
int ossl_read_der(GTA_PROVIDER_CTX * provctx, OSSL_CORE_BIO * cin, unsigned char ** data, long * len)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    BUF_MEM * mem = NULL;
    BIO * in = BIO_new_from_core_bio(provctx->libctx, cin);
    int ok = NOK;

    if (in == NULL)
        return 0;
    ok = (asn1_d2i_read_bio(in, &mem) >= 0);
    if (ok) {
        *data = (unsigned char *)mem->data;
        *len = (long)mem->length;
        OPENSSL_free(mem);
    }
    BIO_free(in);
    return ok;
}

#define HEADER_SIZE 8
#define ASN1_CHUNK_INITIAL_SIZE (16 * 1024)

/*
 * Private source code from OpenSSL 3.2.0
 * Original source code: https://github.com/openssl/openssl/blob/openssl-3.2.0/crypto/asn1/a_d2i_fp.c#L109
 */
int asn1_d2i_read_bio(BIO * in, BUF_MEM ** pb)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    BUF_MEM * b = NULL;
    const unsigned char * p = NULL;
    long i = 0;
    size_t want = HEADER_SIZE;
    uint32_t eos = 0;
    size_t off = 0;
    size_t len = 0;
    size_t diff = 0;

    const unsigned char * q = NULL;
    long slen = 0;
    int inf = 0;
    int tag = 0;
    int xclass = 0;

    b = BUF_MEM_new();
    if (b == NULL) {
        LOG_ERROR("Buffer new problem");
        return -1;
    }

    ERR_set_mark();
    for (;;) {
        diff = len - off;
        if (want >= diff) {
            want -= diff;

            if (len + want < len || !BUF_MEM_grow_clean(b, len + want)) {
                LOG_ERROR("Problem 1");
                goto err;
            }
            /* range check */
            if (INT_MAX < want) {
                goto err;
            }
            i = BIO_read(in, &(b->data[len]), (int)want);
            if (i < 0 && diff == 0) {
                LOG_ERROR("Problem 2");
                goto err;
            }
            if (i > 0) {
                if (len + i < len) {
                    LOG_ERROR("Problem 3");
                    goto err;
                }
                len += i;
            }
        }
        /* else data already loaded */

        p = (unsigned char *)&(b->data[off]);
        q = p;
        diff = len - off;
        if (diff == 0)
            goto err;
        inf = ASN1_get_object(&q, &slen, &tag, &xclass, diff);
        if (inf & 0x80) {
            unsigned long e;

            e = ERR_GET_REASON(ERR_peek_last_error());
            if (e != ASN1_R_TOO_LONG)
                goto err;
            ERR_pop_to_mark();
        }
        i = q - p; /* header length */
        off += i;  /* end of data */

        if (inf & 1) {
            /* no data body so go round again */
            if (eos == UINT32_MAX) {
                LOG_ERROR("Header too long");
                goto err;
            }
            eos++;
            want = HEADER_SIZE;
        } else if (eos && (slen == 0) && (tag == V_ASN1_EOC)) {
            /* eos value, so go back and read another header */
            eos--;
            if (eos == 0)
                break;
            else
                want = HEADER_SIZE;
        } else {
            /* suck in slen bytes of data */
            want = slen;
            if (want > (len - off)) {
                size_t chunk_max = ASN1_CHUNK_INITIAL_SIZE;

                want -= (len - off);
                if (want > INT_MAX /* BIO_read takes an int length */ || len + want < len) {
                    LOG_ERROR("ASN1 R too long");
                    goto err;
                }
                while (want > 0) {
                    /*
                     * Read content in chunks of increasing size
                     * so we can return an error for EOF without
                     * having to allocate the entire content length
                     * in one go.
                     */
                    size_t chunk = want > chunk_max ? chunk_max : want;

                    if (!BUF_MEM_grow_clean(b, len + chunk)) {
                        LOG_ERROR("Buffer clean problem");
                        // ERR_raise(ERR_LIB_ASN1, ERR_R_BUF_LIB);
                        goto err;
                    }
                    want -= chunk;
                    while (chunk > 0) {
                        /* range check */
                        if (INT_MAX < chunk) {
                            goto err;
                        }
                        i = BIO_read(in, &(b->data[len]), (int)chunk);
                        if (i <= 0) {
                            LOG_ERROR("ASN1 R not enough data");
                            goto err;
                        }
                        /*
                         * This can't overflow because |len+want| didn't
                         * overflow.
                         */
                        len += i;
                        chunk -= i;
                    }
                    if (chunk_max < INT_MAX / 2)
                        chunk_max *= 2;
                }
            }
            if (off + slen < off) {
                LOG_ERROR("ASN1 R too long 1");
                goto err;
            }
            off += slen;
            if (eos == 0) {
                break;
            } else
                want = HEADER_SIZE;
        }
    }

    if (off > INT_MAX) {
        LOG_ERROR("ASN1 R too long 2");
        goto err;
    }

    *pb = b;
    /* range check */
    if (INT_MAX < off) {
        goto err;
    }
    return off;
err:
    ERR_clear_last_mark();
    BUF_MEM_free(b);
    return -1;
}

const OSSL_DISPATCH dilithium_der_decoder_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))gtaossl_provider_dilithium_subject_pub_key_info_newctx},
    {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))gtaossl_provider_dilithium_der2key_freectx},
    {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))gtaossl_provider_base_gta_does_selection},
    {OSSL_FUNC_DECODER_DECODE, (void (*)(void))gtaossl_provider_dilithium_der2key_decode},
    {0, NULL}};
