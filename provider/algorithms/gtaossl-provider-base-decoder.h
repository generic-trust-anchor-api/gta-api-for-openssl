/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GTAOSSL_PROVIDER_BASE_DECODER_H_
#define _GTAOSSL_PROVIDER_BASE_DECODER_H_

#include "../gtaossl-provider.h"
#include <openssl/core_dispatch.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

typedef struct gta_der_decoder_ctx_st GTA_DER_DECODER_CTX;

/**
 * Extended der decoder context
 * (with GTA context)
 */
struct gta_der_decoder_ctx_st {
    const OSSL_CORE_HANDLE * core;
    OSSL_LIB_CTX * libctx;
    GTA_PROVIDER_CTX * provctx;
    gta_enum_handle_t h_persenum;
    gta_personality_attribute_name_t next_attribute;
};

typedef struct gta_decoder_ctx_st GTA_DECODER_CTX;

/**
 * Define GTA decoder context
 * (with GTA context)
 */
struct gta_decoder_ctx_st {
    const OSSL_CORE_HANDLE * core;
    OSSL_LIB_CTX * libctx;
    GTA_PROVIDER_CTX * provider_ctx;
    gta_context_handle_t h_ctx;
};

#ifdef __cplusplus
}
#endif

#endif /* _GTAOSSL_PROVIDER_BASE_DECODER_H_ */
