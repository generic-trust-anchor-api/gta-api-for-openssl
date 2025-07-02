/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../../config/gtaossl-provider-config.h"
#include "../../gtaossl-provider.h"
#include "../../logger/gtaossl-provider-logger.h"
#include "../gtaossl-provider-base-gta-decoder.h"
#include <ctype.h>
#include <gta_api/gta_api.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <string.h>

static OSSL_FUNC_decoder_decode_fn gtaossl_provider_dilithium_gta_decoder_decode;
static OSSL_FUNC_decoder_does_selection_fn gtaossl_provider_dilithium_gta_does_selection;

/**
 * The function extends the base GTA decoder to specify the algorithm as
 * OQS_DILITHIUM_2("dilithium2").
 *
 * @param[in] ctx: pointer to the GTA decoder context
 * @param[in] cin: input BIO object
 * @param[in] selection: type of the selection
 * @param[in] object_cb: object callback function
 * @param[in] object_cbarg: arguments of object callback function
 * @param[in] pw_cb: password callback function
 * @param[in] pw_cbarg: arguments of password callback function
 * @return OK = 1
 * @return NOK = 0
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-decoder/#export-function
 */
static int gtaossl_provider_dilithium_gta_decoder_decode(
    void * ctx,
    OSSL_CORE_BIO * cin,
    int selection,
    OSSL_CALLBACK * object_cb,
    void * object_cbarg,
    OSSL_PASSPHRASE_CALLBACK * pw_cb,
    void * pw_cbarg)
{
    LOG_INFO("Decode GTA object to diltihium object");
    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    return gtaossl_provider_base_gta_decoder_decode(
        ctx, cin, selection, object_cb, object_cbarg, pw_cb, pw_cbarg, OQS_DILITHIUM_2);
}

/**
 * The function extends the base decoder selection.
 *
 * @param[in] provctx: provider context
 * @param[in] selection: type of the selection
 * @return OK = 1
 * @return NOK = 0
 *
 * More details can be found at the following URL:
 * - https://docs.openssl.org/3.2/man7/provider-decoder/#description
 */
static int gtaossl_provider_dilithium_gta_does_selection(void * provctx, int selection)
{

    LOG_DEBUG_ARG("CALL_FUNC(%s)", __func__);
    return gtaossl_provider_base_gta_does_selection(provctx, selection);
}

const OSSL_DISPATCH gta_to_dilithium_decoder_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))gtaossl_provider_base_gta_decoder_newctx},
    {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))gtaossl_provider_base_gta_decoder_freectx},
    {OSSL_FUNC_DECODER_DECODE, (void (*)(void))gtaossl_provider_dilithium_gta_decoder_decode},
    {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))gtaossl_provider_dilithium_gta_does_selection},
    {OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))gtaossl_provider_base_gta_decoder_export_object},
    {0, NULL}};
