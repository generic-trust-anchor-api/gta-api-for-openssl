/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtaossl-provider-logger.h"

#include "../config/gtaossl-provider-config.h"
#include <assert.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * Base64 encoder
 */
int base_64_encode(const unsigned char * buffer, size_t length, char ** b64text)
{
    BIO * bio = NULL;
    BIO * b64 = NULL;
    BUF_MEM * bufferPtr = NULL;

    if (INT_MAX < length) {
        return NOK;
    }

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, (int)length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *b64text = (*bufferPtr).data;
    return OK;
}