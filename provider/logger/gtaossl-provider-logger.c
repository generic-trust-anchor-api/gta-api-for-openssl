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

size_t calc_decode_length(const char * b64input)
{
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=')
        padding = 2;
    else if (b64input[len - 1] == '=')
        padding = 1;

    return (len * 3) / 4 - padding;
}

/**
 * Allocate buffer and copy the string input into it.
 */
void * mem_dup(const void * mem, size_t size)
{
    void * out = malloc(size);

    if (out != NULL) {
        memcpy(out, mem, size);
    }

    return out;
}

/**
 * Remove a given sub string from a C string.
 */
char * str_remove(char * str, const char * sub)
{
    size_t len = strlen(sub);
    if (len > 0) {
        char * p = str;
        while ((p = strstr(p, sub)) != NULL) {
            memmove(p, p + len, strlen(p + len) + 1);
        }
    }
    return str;
}

/**
 * Base64 decoder
 */
int base_64_decode(const char * b64message, unsigned char ** buffer, size_t * length)
{

#ifdef LOG_B64_ON
    printf("\nBase64Decode input b64message = %s\n", b64message);
#endif

    BIO * bio = NULL;
    BIO * b64 = NULL;

    size_t decodeLen = calc_decode_length(b64message);
    *buffer = (unsigned char *)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, (int)strlen(b64message));
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *length = BIO_read(bio, *buffer, (int)strlen(b64message));

    *length = decodeLen;

    BIO_free_all(bio);
    return OK;
}

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