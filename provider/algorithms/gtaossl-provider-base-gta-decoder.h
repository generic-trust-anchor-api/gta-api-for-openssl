/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GTAOSSL_PROVIDER_BASE_GTA_DECODER_H_
#define _GTAOSSL_PROVIDER_BASE_GTA_DECODER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "gtaossl-provider-base-decoder.h"

/**
 * The decoder new context function should create and return a pointer
 * to a structure that is extended with a GTA provider and GTA_DECODER context.
 * This structure holds the decoder context during the decoding operation.
 *
 * @param[in/out] provctx: the parameter is a provider context
 *                         generated during the provider initialization.
 * @return a new context.
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-decoder/#description
 *
 * The preprocessor-generated function signature:
 *
 * void *gtaossl_provider_base_gta_decoder_newctx(void *provctx);
 */
OSSL_FUNC_decoder_newctx_fn gtaossl_provider_base_gta_decoder_newctx;

/**
 * The function should free the GTA decoder context.
 *
 * @param[in] ctx: pointer of the GTA decoder context
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-decoder/#description
 *
 * The preprocessor-generated function signature:
 *
 * void gtaossl_provider_base_gta_decoder_freectx(void *ctx);
 */
OSSL_FUNC_decoder_freectx_fn gtaossl_provider_base_gta_decoder_freectx;

/**
 * The function exports the GTA object but does not contain any implementation.
 * It is defined because of avoiding an error.
 *
 * @param[in] ctx: pointer of the GTA decoder context
 * @param[in] objref: input object
 * @param[in] objref_sz: size of the input object
 * @param[in] export_cb: callback function
 * @param[in] export_cbarg: arguments of the callback function
 * @return NOK = 0
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-decoder/#description
 *
 * The preprocessor-generated function signature:
 *
 * int gtaossl_provider_base_gta_decoder_export_object(void *ctx, const void *objref, size_t objref_sz, OSSL_CALLBACK
 * *export_cb, void *export_cbarg);
 */
OSSL_FUNC_decoder_export_object_fn gtaossl_provider_base_gta_decoder_export_object;

/**
 * Thew function should decode the data as read from the OSSL_CORE_BIO
 * (the key BIO objects are replaced with GTA API references,
 * because the GTA Provider must manage the public and private key pair.)
 * to produce decoded data or an object to be passed as reference in an OSSL_PARAM(3)
 * array along with possible other metadata that was decoded from the input.
 * (only the public key can be exported from the GTA context)
 *
 * The following steps are implemented:
 *
 * 1. Open the BIO object to read the data into a buffer.
 *
 * 2. Try to parse the GTA personalty and profile information.
 * If personalty and profile information are not available, the
 * public key is not able read from the GTA context and
 * the function must return false.
 *
 * 3. If personalty and profile information are available, the function
 * will open a GTA context and read the GTA_KEY_TYPE_ATTRIBUTE
 * ("com.github.generic-trust-anchor-api.keytype.openssl") from the personality.
 *
 * 4. The decoder needs to verify that the type of public key is the expected value.
 * ("EC" or "dilithium2")
 *
 * 5. Create a OSSL_PARAM parameter to describe the key type.
 *
 * @param[in] ctx: pointer to the GTA decoder context
 * @param[in] cin: input BIO object
 * @param[in] selection: type of the selection
 * @param[in] object_cb: object callback function
 * @param[in] object_cbarg: arguments of object callback function
 * @param[in] pw_cb: password callback function
 * @param[in] pw_cbarg: arguments of password callback function
 * @param[in] expected_keytype: expected key type as string
 * @return OK = 1
 * @return NOK = 0
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-decoder/#export-function
 */
int gtaossl_provider_base_gta_decoder_decode(
    void * ctx,
    OSSL_CORE_BIO * cin,
    int selection,
    OSSL_CALLBACK * object_cb,
    void * object_cbarg,
    OSSL_PASSPHRASE_CALLBACK * pw_cb,
    void * pw_cbarg,
    const char * expected_keytype);

/**
 * OSSL_FUNC_decoder_does_selection() should indicate if a particular
 * implementation supports any of the combinations given by selection.
 *
 * 1. In the current demo,
 * - If the selection is a private key, the function will return with true,
 * - In case of public key and parameter selection, return false.
 * - If the selection is 0, the function will return true.
 *
 * 2. In case of GTA API usage, the private must be handled by the GTA provider.
 * All private key related functions must be overwrite in the gtaossl provider.
 *
 * @param[in] provctx: provider context
 * @param[in] selection: type of the selection
 * @return OK = 1
 * @return NOK = 0
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-decoder/#description
 */
int gtaossl_provider_base_gta_does_selection(void * provctx, int selection);

#ifdef __cplusplus
}
#endif

#endif /* _GTAOSSL_PROVIDER_BASE_GTA_DECODER_H_ */
