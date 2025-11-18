/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtaossl-provider.h"

#include "algorithms/gtaossl-provider-base-signature.h"
#include "config/gtaossl-provider-config.h"
#include "logger/gtaossl-provider-logger.h"
#include "stream/streams.h"
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/prov_ssl.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

#if !defined(SERIALIZATION_FOLDER)
#error "SERIALIZATION_FOLDER not defined!"
#endif

extern const struct gta_function_list_t * gta_sw_provider_init(
    gta_context_handle_t,
    gtaio_istream_t *,
    gtaio_ostream_t *,
    void **,
    void (**)(void *),
    gta_errinfo_t *);

/*----------------Function collections for TLS Handshake-----------------*/

extern const OSSL_DISPATCH base_decoder_functions[];

/*---------------------------Dilithium-----------------------------------*/

extern const OSSL_DISPATCH dilithium_signature_functions[];

extern const OSSL_DISPATCH dilithium_keymgmt_functions[];

extern const OSSL_DISPATCH gta_to_dilithium_decoder_functions[];

extern const OSSL_DISPATCH dilithium_der_decoder_functions[];

/*---------------------------ECDSA---------------------------------------*/

extern const OSSL_DISPATCH ecdsa_signature_functions[];

extern const OSSL_DISPATCH ecdsa_keymgmt_functions[];

extern const OSSL_DISPATCH gta_to_ecdsa_decoder_functions[];

/*------------------Required OSSL provider functions----------------------*/

static OSSL_FUNC_core_gettable_params_fn * core_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn * core_get_params = NULL;
static OSSL_FUNC_core_new_error_fn * core_new_error = NULL;
static OSSL_FUNC_core_set_error_debug_fn * core_set_error_debug = NULL;
static OSSL_FUNC_core_vset_error_fn * core_vset_error = NULL;

/*-------------------------------------------------------------------------*/

/**
 * Sets the function pointers of some functions provided
 * by the OSSL core to the provider.
 *
 * @param[in] disp: dispatchable function table
 * @return OK = 1
 */
static int gtaossl_provider_init_openssl_core(const OSSL_DISPATCH * disp)
{

    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    for (; disp->function_id != 0; disp++) {

        switch (disp->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            if (core_gettable_params == NULL) {
                core_gettable_params = OSSL_FUNC_core_gettable_params(disp);
            }
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            if (core_get_params == NULL) {
                core_get_params = OSSL_FUNC_core_get_params(disp);
            }
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            if (core_new_error == NULL) {
                core_new_error = OSSL_FUNC_core_new_error(disp);
            }
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            if (core_set_error_debug == NULL) {
                core_set_error_debug = OSSL_FUNC_core_set_error_debug(disp);
            }
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            if (core_vset_error == NULL) {
                core_vset_error = OSSL_FUNC_core_vset_error(disp);
            }
            break;
        }
    }

    return OK;
}

/**
 * Retrieves provider parameters.
 *
 * @param prov: provider context
 * @param params: array of OSSL_PARAMs
 * @return OK = 1
 * @return NOK = 0
 */
int gtaossl_provider_core_get_params(const OSSL_CORE_HANDLE * prov, OSSL_PARAM params[])
{

    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    if (core_get_params == NULL) {
        return NOK;
    }

    return core_get_params(prov, params);
}

/**
 * All provider-related parameters that we can provide to OSSL.
 *
 * @param[in] provctx: provider context
 * @return array of OSSL_PARAMs
 */
static const OSSL_PARAM * gtaossl_provider_gettable_params(void * provctx)
{

    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)provctx;

    static const OSSL_PARAM param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_END};

    return param_types;
}

/**
 * Returns the values of requested provider-related parameters to OSSL.
 *
 * @param[in] provctx: provider context
 * @param[in] params: array of OSSL_PARAMs
 * @return OK = 1
 * @return NOK = 0
 */
static int gtaossl_provider_get_params(void * provctx, OSSL_PARAM params[])
{

    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    OSSL_PARAM * p = NULL;
    GTA_PROVIDER_CTX * prov = provctx;

    if (prov == NULL) {
        LOG_ERROR("Provider null");
        return NOK;
    }

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, GTA_PROVIDER_NAME)) {
        LOG_ERROR("Provider name null");
        return NOK;
    }

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, GTA_PROVIDER_VERSION)) {
        LOG_ERROR("Provider version null");
        return NOK;
    }

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, GTA_PROVIDER_BUILDINFO)) {
        LOG_ERROR("Provider build info null");
        return NOK;
    }

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, prov->status)) {
        LOG_ERROR("Provider status null");
        return NOK;
    }

    return OK;
}

/**
 * Specification of the digest schemes that the provider offers to OSSL.
 */

/**
 * Signature functions mapping to algorithm identifiers.
 */
static const OSSL_ALGORITHM gtaossl_provider_signatures[] = {
    {"ECDSA", "provider=gta,gta.signature", ecdsa_signature_functions},
#ifdef DILITHIUM_ON
    {OQS_DILITHIUM_2, "provider=gta", dilithium_signature_functions},
#endif
    {NULL, NULL, NULL}};

/**
 * Key management functions mapping to algorithm identifiers.
 */
static const OSSL_ALGORITHM gtaossl_provider_keymgmts[] = {
#ifdef EC_ON
    {"EC:id-ecPublicKey:1.2.840.10045.2.1", "provider=gta", ecdsa_keymgmt_functions},
#endif
#ifdef DILITHIUM_ON
    {OQS_DILITHIUM_2, "provider=gta", dilithium_keymgmt_functions},
#endif
    {NULL, NULL, NULL}};

/**
 * Key encoder/decoder functions mapping to algorithm identifiers.
 */
static const OSSL_ALGORITHM gtaossl_provider_decoders[] = {
    {"DER", "provider=gta,input=pem", base_decoder_functions},
#ifdef EC_ON
    {"EC:id-ecPublicKey:1.2.840.10045.2.1", "provider=gta,input=der,structure=GTA", gta_to_ecdsa_decoder_functions},
    //{ "EC:1.2.840.10045.2.1", "provider=gta,input=der,structure=PrivateKeyInfo", gta_to_ec_decoder_functions},
    {"EC", "provider=gta,input=der,structure=PrivateKeyInfo", gta_to_ecdsa_decoder_functions},
#endif
#ifdef DILITHIUM_ON
    {OQS_DILITHIUM_2, "provider=gta,input=der,structure=PrivateKeyInfo", gta_to_dilithium_decoder_functions},
    {OQS_DILITHIUM_2, "provider=gta,input=der,structure=SubjectPublicKeyInfo", dilithium_der_decoder_functions},
#endif
    {NULL, NULL, NULL}};

/**
 * OSSL queries the provider for supported operations with a specific operation ID.
 *
 * @param[in] provctx: provider context
 * @param[in] id: operation ID
 * @param[in] no_cache: cache handling option
 * @return collection of operations
 */
static const OSSL_ALGORITHM * gtaossl_provider_query_operation(void * provctx, int id, int * no_cache)
{

    LOG_DEBUG("Select methods for the operation");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("id=%d", id);
    GTA_PROVIDER_CTX * cprov = provctx;

    (void)cprov;

    LOG_TRACE("Set no_cache variable to 0 but value of the variable not used by the next functions.");

    if (no_cache != NULL) {
        LOG_TRACE("no Forcing the non-caching of queries.");
        *no_cache = 0;
    }

    switch (id) {

    case OSSL_OP_KEYMGMT:
        LOG_INFO("Key management");
        LOG_TRACE("Return list of all supported digest algorithms");
        return gtaossl_provider_keymgmts;

    case OSSL_OP_SIGNATURE:
        LOG_INFO("Signatures");
        LOG_TRACE("Return list of all supported digest algorithms");
        return gtaossl_provider_signatures;

    case OSSL_OP_DECODER:
        LOG_INFO("Decoder");
        return gtaossl_provider_decoders;
    }

    LOG_TRACE("Currently the provider only supports digest functions");
    return NULL;
}

/**
 * Finalization work for the query operation.
 *
 * @param[in] provctx: provider context
 * @param[in] id: operation ID
 * @param[in] alg: algorithm
 */
static void gtaossl_provider_unquery_operation(void * provctx, int id, const OSSL_ALGORITHM * alg)
{

    LOG_DEBUG("Finalization work for the query operation");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);

    /* Currently unused */
    (void)provctx;

    if (alg != NULL) {
        for (int i = 0; alg[i].algorithm_names != NULL; i++) {
            LOG_TRACE_ARG("algorithm_names = %s", alg[i].algorithm_names);
            LOG_TRACE_ARG("algorithm_description = %s", alg[i].algorithm_description);
            LOG_TRACE_ARG("property_definition = %s", alg[i].property_definition);
            LOG_TRACE_ARG("Function id = %d", alg[i].implementation->function_id);
        }
    }

    LOG_TRACE_ARG("%s - operation id = %d", __func__, id);

    switch (id) {
    case OSSL_OP_KEYMGMT:
        LOG_DEBUG("Key management of an algorithm");
        LOG_TRACE_ARG("%s - Key management", __func__);
        break;
    case OSSL_OP_SIGNATURE:
        LOG_DEBUG("Signatures of an algorithm");
        LOG_TRACE_ARG("%s - Signatures", __func__);
        break;
    case OSSL_OP_DECODER:
        LOG_DEBUG("Decoder of an algorithm");
        LOG_TRACE_ARG("%s - Decoder", __func__);
        break;
    default:
        break;
    }

    LOG_TRACE("Nothing to do here");
    return;
}

typedef struct oqs_sigalg_constants_st {
    unsigned int code_point; /* Code point */
    unsigned int secbits;    /* Bits of security */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
} OQS_SIGALG_CONSTANTS;

static OQS_SIGALG_CONSTANTS oqs_sigalg_list[] = {
    // Ad-hoc assignments - take from OQS generate data structures.
    // OQS_TEMPLATE_FRAGMENT_SIGALG_ASSIGNMENTS_START
    {0xfea0, 128, TLS1_3_VERSION, 0}, {0xfea1, 128, TLS1_3_VERSION, 0}, {0xfea2, 128, TLS1_3_VERSION, 0},
    {0xfea3, 192, TLS1_3_VERSION, 0}, {0xfea4, 192, TLS1_3_VERSION, 0}, {0xfea5, 256, TLS1_3_VERSION, 0},
    {0xfea6, 256, TLS1_3_VERSION, 0}, {0xfeae, 128, TLS1_3_VERSION, 0}, {0xfeaf, 128, TLS1_3_VERSION, 0},
    {0xfeb0, 128, TLS1_3_VERSION, 0}, {0xfeb1, 256, TLS1_3_VERSION, 0}, {0xfeb2, 256, TLS1_3_VERSION, 0},
    {0xfeb3, 128, TLS1_3_VERSION, 0}, {0xfeb4, 128, TLS1_3_VERSION, 0}, {0xfeb5, 128, TLS1_3_VERSION, 0},
    {0xfeb6, 128, TLS1_3_VERSION, 0}, {0xfeb7, 128, TLS1_3_VERSION, 0}, {0xfeb8, 128, TLS1_3_VERSION, 0},
    {0xfeb9, 192, TLS1_3_VERSION, 0}, {0xfeba, 192, TLS1_3_VERSION, 0}, {0xfec2, 128, TLS1_3_VERSION, 0},
    {0xfec3, 128, TLS1_3_VERSION, 0}, {0xfec4, 128, TLS1_3_VERSION, 0},
    // OQS_TEMPLATE_FRAGMENT_SIGALG_ASSIGNMENTS_END
};

#define OQS_SIGALG_ENTRY(tlsname, realname, algorithm, oid, idx)                                                       \
    {                                                                                                                  \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME, #tlsname, sizeof(#tlsname)),                      \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME, #tlsname, sizeof(#tlsname)),                       \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_OID, #oid, sizeof(#oid)),                                \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT, (unsigned int *)&oqs_sigalg_list[idx].code_point),  \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS, (unsigned int *)&oqs_sigalg_list[idx].secbits),  \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS, (unsigned int *)&oqs_sigalg_list[idx].mintls),          \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS, (unsigned int *)&oqs_sigalg_list[idx].maxtls),          \
            OSSL_PARAM_END                                                                                             \
    }

static const OSSL_PARAM oqs_param_sigalg_list[][12] = {
    OQS_SIGALG_ENTRY(dilithium2, dilithium2, dilithium2, OQS_DILITHIUM_2_OID, 0),
};

#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

/**
 * The following for loop can fix the error:
 *
 * error setting certificate
 * 807B68E7D37F0000:error:0A0000F7:SSL routines:ssl_set_cert:unknown certificate type:ssl/ssl_rsa.c:257:
 *
 * @param[in] cb: callback function
 * @param[in] arg: arguments of the callback function
 * @return OK = 1
 * @return NOK = 0
 */
static int oqs_sigalg_capability(OSSL_CALLBACK * cb, void * arg)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    size_t i;

    // Relaxed assertion for the case that not all algorithms are enabled in liboqs:
    // assert(OSSL_NELEM(oqs_param_sigalg_list) <= OSSL_NELEM(oqs_sigalg_list));
    for (i = 0; i < OSSL_NELEM(oqs_param_sigalg_list); i++) {
        if (!cb(oqs_param_sigalg_list[i], arg)) {
            LOG_ERROR("Error during the configuration of the callback function for sigalg capability");
            return NOK;
        }
    }

    return OK;
}

/**
 * Get provider capabilities.
 *
 * @param[in] provctx: provider context
 * @param[in] capability: capability string ("TLS-GROUP" and "TLS-SIGALG")
 * @param[in] cb: callback function
 * @param[in] arg: arguments of the callback function
 * @return OK = 1
 * @return NOK = 0
 */
int gtaossl_provider_get_capabilities(void * provctx, const char * capability, OSSL_CALLBACK * cb, void * arg)
{
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    LOG_TRACE_ARG("Capability: %s", capability);

    /* Currently unused */
    (void)provctx;

    if (strcasecmp(capability, "TLS-GROUP") == 0) {
        LOG_TRACE("In case of TLS-GROUP capability");
        LOG_WARN("Ignore to set callback function for TLS-GROUP capability");
        return OK;
    }

    if (strcasecmp(capability, "TLS-SIGALG") == 0) {
        LOG_TRACE("In case of TLS-SIGALG capability");
        return oqs_sigalg_capability(cb, arg);
    }

    LOG_ERROR_ARG("We don't support this capability [%s]", capability);
    return NOK;
}

/**
 * Perform provider internal self test.
 *
 * @param[in] provctx: provider context
 * @return OK = 1
 * @return NOK = 0
 */
static int gtaossl_provider_self_test(void * provctx)
{

    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    GTA_PROVIDER_CTX * cprov = provctx;
    int ret = 0;

    (void)cprov;

#if defined(FLAG_SELFTEST)
    /*   SHA 256 Test disabled
     *
     *   ret = sha256_test();
     */
#endif

    return ret == 0 ? OK : NOK;
}

/**
 * Tear down function of the provider.
 *
 * @param[in] provctx: provider context
 */
static void gtaossl_provider_teardown(void * provctx)
{
    LOG_INFO("Tear down provider instance");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    GTA_PROVIDER_CTX * prov = provctx;
    gta_errinfo_t errinfo = 0;

    if (prov == NULL) {
        LOG_ERROR("Provider context is NULL.");
        return;
    }

    LOG_TRACE("Here tear down work in my personal provider context");
    if (prov->h_inst != NULL) {
        gta_instance_final(prov->h_inst, &errinfo);
    }

    LOG_TRACE("OSSL Context free");
    if (prov->libctx != NULL) {
        OSSL_LIB_CTX_free(prov->libctx);
    }

    LOG_TRACE("OSSL free");
    OPENSSL_clear_free(prov, sizeof(GTA_PROVIDER_CTX));
    return;
}

/*-------------------------------------------------------------------------*/

static OSSL_FUNC_provider_gettable_params_fn gtaossl_provider_gettable_params;
static OSSL_FUNC_provider_get_params_fn gtaossl_provider_get_params;
static OSSL_FUNC_provider_query_operation_fn gtaossl_provider_query_operation;
static OSSL_FUNC_provider_unquery_operation_fn gtaossl_provider_unquery_operation;
static OSSL_FUNC_provider_self_test_fn gtaossl_provider_self_test;
static OSSL_FUNC_provider_teardown_fn gtaossl_provider_teardown;
OSSL_FUNC_provider_get_capabilities_fn gtaossl_provider_get_capabilities;

/** General provider dispatch table */
static const OSSL_DISPATCH gta_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))gtaossl_provider_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))gtaossl_provider_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))gtaossl_provider_query_operation},
    {OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, (void (*)(void))gtaossl_provider_unquery_operation},
    {OSSL_FUNC_PROVIDER_SELF_TEST, (void (*)(void))gtaossl_provider_self_test},
    {OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))gtaossl_provider_get_capabilities},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))gtaossl_provider_teardown},
    {0, NULL}};

/**
 * Clean-up function to dispose of the GTA instance and OpenSSL context.
 *
 * @param[in] prov: provider context
 * @param[in/out] ret: return code
 * @param[out] errinfo: object to show the GTA errors
 * @return: forwards the return code
 */
static int clean_up(GTA_PROVIDER_CTX * prov, int ret, gta_errinfo_t * errinfo)
{

    LOG_INFO("Clean up the provider environment");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    if (ret == 0) {
        if (prov->h_inst != NULL) {
            gta_instance_final(prov->h_inst, errinfo);
        }

        LOG_TRACE("OSSL Context free in clean");
        if (prov->libctx != NULL) {
            OSSL_LIB_CTX_free(prov->libctx);
        }

        LOG_TRACE("OSSL free in clean");
        if (prov != NULL) {
            OPENSSL_clear_free(prov, sizeof(GTA_PROVIDER_CTX));
        }
    }

    return ret;
}

#define OQS_OID_CNT 2
const char * oqs_oid_alg_list[OQS_OID_CNT] = {
    OQS_DILITHIUM_2_OID,
    OQS_DILITHIUM_2,
};

/**
 * Provider initialization function, called by OSSL's
 * OSSL_provider_init(), which is the entry point of the provider.
 */
int OSSL_provider_init(
    const OSSL_CORE_HANDLE * handle,
    const OSSL_DISPATCH * in,
    const OSSL_DISPATCH ** out,
    void ** provctx)
{

    LOG_INFO("Init OpenSSL provider");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    GTA_PROVIDER_CTX * prov = NULL;
    int ret = NOK;

    LOG_TRACE("Set provider name, version and files to null (only for testing)");
    const char *core_version = NULL, *core_prov_name = NULL, *core_module_filename = NULL;

    OSSL_PARAM requests_to_core[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_CORE_VERSION, &core_version, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_CORE_PROV_NAME, &core_prov_name, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_CORE_MODULE_FILENAME, &core_module_filename, 0),
        OSSL_PARAM_END};

    if ((prov = OPENSSL_zalloc(sizeof(GTA_PROVIDER_CTX))) == NULL) {
        LOG_ERROR("OSSL allocation failed");
        return NOK;
    }

    prov->core = handle;
    gtaossl_provider_init_openssl_core(in);
    prov->status = 1;

    const OSSL_DISPATCH * orig_in = in;
    OSSL_FUNC_core_obj_create_fn * c_obj_create = NULL;
    OSSL_FUNC_core_obj_add_sigid_fn * c_obj_add_sigid = NULL;

    for (; in->function_id != 0; in++) {

#ifdef LOG_FOR_CYCLE_ON
        LOG_TRACE_ARG("Value: in->function_id=%d", in->function_id)
#endif

        switch (in->function_id) {
        case OSSL_FUNC_CORE_OBJ_CREATE:
            c_obj_create = OSSL_FUNC_core_obj_create(in);
            LOG_TRACE("Get OSSL_FUNC_CORE_OBJ_CREATE function")
            break;
        case OSSL_FUNC_CORE_OBJ_ADD_SIGID:
            c_obj_add_sigid = OSSL_FUNC_core_obj_add_sigid(in);
            LOG_TRACE("Get OSSL_FUNC_CORE_OBJ_ADD_SIGID function")
            break;
        default:
#ifdef LOG_FOR_CYCLE_ON
            LOG_TRACE("Skip function")
#endif
            break;
        }
    }

    if (c_obj_create == NULL) {
        LOG_ERROR("OSS Create object function not initialized");
        return NOK;
    }

    if (c_obj_add_sigid == NULL) {
        LOG_ERROR("OSS Add sig ID function not initialized");
        return NOK;
    }

    /* The next for cycle can fix the following error:
     *
     * error setting certificate
     * 804B0D2CC17F0000:error:03000072:digital envelope routines:X509_PUBKEY_get0:decode
     * error:crypto/x509/x_pubkey.c:464: 804B0D2CC17F0000:error:0A00018F:SSL routines:SSL_CTX_use_certificate:ee key too
     * small:ssl/ssl_rsa.c:239:
     */
    LOG_INFO("Insert all OIDs to the global objects list");

    for (int i = 0; i < OQS_OID_CNT; i += 2) {
        if (!c_obj_create(handle, oqs_oid_alg_list[i], oqs_oid_alg_list[i + 1], oqs_oid_alg_list[i + 1])) {
            LOG_ERROR_ARG("Error registering NID for %s", oqs_oid_alg_list[i + 1]);
        }

        /* Create object (NID) again to avoid setup corner case problems
         * see https://github.com/openssl/openssl/discussions/21903
         * Not testing for errors is intentional.
         * At least one core version hangs up; so don't do this there:
         */

        if (!c_obj_add_sigid(handle, oqs_oid_alg_list[i + 1], "", oqs_oid_alg_list[i + 1])) {
            LOG_ERROR_ARG("Error registering %s with no hash", oqs_oid_alg_list[i + 1]);
        }

        if (OBJ_sn2nid(oqs_oid_alg_list[i + 1]) != 0) {
            LOG_TRACE_ARG(
                "Successfully registered %s with NID %d", oqs_oid_alg_list[i + 1], OBJ_sn2nid(oqs_oid_alg_list[i + 1]));
        } else {
            LOG_ERROR_ARG("Impossible error: NID unregistered for %s.", oqs_oid_alg_list[i + 1]);
        }
    }

    LOG_TRACE("Call GTA API instance init and register all necessary provider/profiles");
    gta_errinfo_t errinfo = 0;

    istream_from_buf_t init_config = {0};

    struct gta_instance_params_t inst_params = {
        NULL,
        {
            .calloc = &calloc,
            .free = &free,
            .mutex_create = NULL,
            .mutex_destroy = NULL,
            .mutex_lock = NULL,
            .mutex_unlock = NULL,
        },
        NULL};

    if (!istream_from_buf_init(&init_config, SERIALIZATION_FOLDER, sizeof(SERIALIZATION_FOLDER) - 1, &errinfo)) {
        return clean_up(prov, ret, &errinfo);
    }

    struct gta_provider_info_t provider_info = {
        .version = 0,
        .type = GTA_PROVIDER_INFO_CALLBACK,
        .provider_init = gta_sw_provider_init,
        .provider_init_config = (gtaio_istream_t *)&init_config,
        .profile_info = {
            .profile_name = "com.github.generic-trust-anchor-api.basic.signature",
            .protection_properties = {0},
            .priority = 0}};

    LOG_TRACE("Calling gta_instance_init");
    prov->h_inst = gta_instance_init(&inst_params, &errinfo);
    if (NULL == prov->h_inst) {
        LOG_ERROR("The gta_instance_init failed");
        return clean_up(prov, ret, &errinfo);
    }

    LOG_TRACE("Calling gta_register_provider");
    if (1 != gta_register_provider(prov->h_inst, &provider_info, &errinfo)) {
        LOG_ERROR("The gta_register_provider failed");
        return clean_up(prov, ret, &errinfo);
    }

    if (!istream_from_buf_close(&init_config, &errinfo)) {
        LOG_ERROR("The ibufstream closing failed");
        return clean_up(prov, ret, &errinfo);
    }

    if ((prov->libctx = OSSL_LIB_CTX_new_from_dispatch(handle, orig_in)) == NULL) {
        LOG_ERROR("OSSL context dispatch failed");
        return clean_up(prov, ret, &errinfo);
    }

    *out = gta_dispatch_table;
    *provctx = prov;

    LOG_TRACE("Only for testing: return values of parameters provided by the OSSL core");
    if (gtaossl_provider_core_get_params(handle, requests_to_core) == 1) {
        LOG_TRACE("Parameters provided by OSSL core");
        LOG_TRACE_ARG("OSSL_PROV_PARAM_CORE_VERSION: %s", core_version == NULL ? "null" : core_version);
        LOG_TRACE_ARG("OSSL_PROV_PARAM_CORE_PROV_NAME: %s", core_prov_name == NULL ? "null" : core_prov_name);
        LOG_TRACE_ARG(
            "OSSL_PROV_PARAM_CORE_MODULE_FILENAME: %s", core_module_filename == NULL ? "null" : core_module_filename);
    }

    ret = OK;
    LOG_INFO("End of OSSL provider initialization");
    return clean_up(prov, ret, &errinfo);
}
