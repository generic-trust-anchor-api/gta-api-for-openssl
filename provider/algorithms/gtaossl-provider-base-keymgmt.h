/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GTAOSSL_PROVIDER_BASE_KEYMGMT_H_
#define _GTAOSSL_PROVIDER_BASE_KEYMGMT_H_

#include "../gtaossl-provider.h"
#include <openssl/core_dispatch.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gta_keymanger_ctx_st GTA_KEYMANGER_CTX;

/**
 * Extended keymanger context
 * (with GTA context)
 */
struct gta_keymanger_ctx_st {
    const OSSL_CORE_HANDLE * core;
    OSSL_LIB_CTX * libctx;
    GTA_PROVIDER_CTX * provider_ctx;
    gta_context_handle_t h_ctx;
};

/**
 * The key management new function should create and return a pointer
 * to a structure that is GTA PKEY object extended with the OpenSSL
 * and GTA provider context.
 * This structure holds the key object and context during the key operation.
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/master/man7/provider-keymgmt/#key-object-information-functions
 *
 * @param[in] provctx: the parameter is a provider context
 *                     generated during the provider initialization.
 *
 * @return pointer to a key structure
 *
 * The preprocessor-generated function signature:
 *
 * void *gtaossl_provider_base_keymgmt_new(void *provctx)
 */
OSSL_FUNC_keymgmt_new_fn gtaossl_provider_base_keymgmt_new;

/**
 * Creates a provider-side GTA_PKEY object initialized with NULL pointer.
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/master/man7/provider-keymgmt/#key-object-information-functions
 *
 * @param[in] reference: reference to the key object
 * @param[in] reference_sz: size of the key object (not used)
 *
 * @return pointer to a key structure
 *
 * The preprocessor-generated function signature:
 *
 * void *gtaossl_provider_base_keymgmt_load(const void *reference, size_t reference_sz)
 */
OSSL_FUNC_keymgmt_load_fn gtaossl_provider_base_keymgmt_load;

/**
 * The function should free the passed keydata.
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/master/man7/provider-keymgmt/#key-object-information-functions
 *
 * @param[in] keydata: pointer of a key structure
 *
 * The preprocessor-generated function signature:
 *
 * void gtaossl_provider_base_keymgmt_free(void *keydata)
 */
OSSL_FUNC_keymgmt_free_fn gtaossl_provider_base_keymgmt_free;

/**
 * The function updates information data associated with the given keydata.
 *
 * @param[in] params: array of OSSL_PARAMs
 * @param[out] keydata: pointer of a key structure
 * @return OK = 1
 * @return NOK = 0
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/master/man7/provider-keymgmt/#key-object-information-functions
 *
 * The preprocessor-generated function signature:
 *
 * int gtaossl_provider_base_keymgmt_set_params(void *keydata, const OSSL_PARAM params[])
 */
OSSL_FUNC_keymgmt_set_params_fn gtaossl_provider_base_keymgmt_set_params;

/**
 * The function returns a descriptor of OSSL parameters.
 *
 * @param[in] provctx: provider context (not used)
 * @return array of OSSL_PARAM
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/master/man7/provider-keymgmt/#key-object-information-functions
 *
 * The preprocessor-generated function signature:
 *
 * const OSSL_PARAM *gtaossl_provider_base_keymgmt_settable_params(void *provctx)
 */
OSSL_FUNC_keymgmt_settable_params_fn gtaossl_provider_base_keymgmt_settable_params;

/**
 * The OSSL_FUNC_keymgmt_has() function checks whether the given keydata
 * contains the subsets of data indicated by the selector.
 * The current solution does not contain any implementation in the demo application,
 * but this function needs to defined to avoid the following error:
 * server: -
 * client: Could not find client certificate private key from gta-key.pem
 *         80FB619B377F0000:error:1608010C:STORE routines:ossl_store_handle_load_result:
 *         unsupported:crypto/store/store_result.c:151:
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/master/man7/provider-keymgmt/#key-object-information-functions
 *
 * @param[in] keydata: pointer of a key structure
 * @param[in] selection: type of the selection
 * @return OK = 1
 *
 * The preprocessor-generated function signature:
 *
 * int gtaossl_provider_base_keymgmt_has(const void *keydata, int selection)
 */
OSSL_FUNC_keymgmt_has_fn gtaossl_provider_base_keymgmt_has;

/**
 * The base key management import function imports data indicated
 * by selection into keydata with values taken from the OSSL_PARAM(3) array params:
 *
 * 1. In case of a public key, OSSL_PKEY_PARAM_PUB_KEY needs to be located and
 * copied into the GTA_PKEY structure object.
 *
 * 2. In case of key parameters selection, OSSL_PKEY_PARAM_GROUP_NAME can be located
 * and show in the log, because of debug purposes.
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
 * The preprocessor-generated function signature:
 *
 * int gtaossl_provider_base_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[])
 */
OSSL_FUNC_keymgmt_import_fn gtaossl_provider_base_keymgmt_import;

/**
 * The helper function should convert and copy key data
 * form an ASN1 (BIT STRING) structure.
 *
 * @param[in] keydata1: pointer of a key structure
 * @param[out] pub_key_from_data_1: byte array
 * @param[out] size_of_pub_key_from_data_1: size of the byte array
 */
void base_parse_key_data_1(
    const void * keydata1,
    unsigned char ** pub_key_from_data_1,
    size_t * size_of_pub_key_from_data_1);

#ifdef __cplusplus
}
#endif

#endif /* _GTAOSSL_PROVIDER_BASE_KEYMGMT_H_ */
