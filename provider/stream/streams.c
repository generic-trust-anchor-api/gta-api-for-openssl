/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "streams.h"

#include "../config/gtaossl-provider-config.h"
#include "../logger/gtaossl-provider-logger.h"
#include <gta_api/gta_api.h>
#include <gta_api/util/gta_memset.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Read byte array data to input stream.
 */
size_t istream_from_buf_read(istream_from_buf_t * istream, char * data, size_t len, gta_errinfo_t * p_errinfo)
{
    /* unused */
    (void)p_errinfo;

    /* Check how many bytes are still available in data buffer */
    size_t bytes_available = istream->buf_size - istream->buf_pos;
    if (bytes_available < len) {
        /* Write only as many bytes as requested in case more are available */
        len = bytes_available;
    }

    /* Copy the bytes from the buffer */
    memcpy(data, &(istream->buf[istream->buf_pos]), len);
    /* Set new position in data buffer */
    istream->buf_pos += len;

    /* Return number of read bytes */
    return len;
}

/**
 * Check end of the input stream.
 */
bool istream_from_buf_eof(istream_from_buf_t * istream, gta_errinfo_t * p_errinfo)
{
    /* unused */
    (void)p_errinfo;

    /* Return true if we are at the end of the buffer */
    return (istream->buf_pos == istream->buf_size);
}

/**
 * Initialize the input stream.
 */
void istream_from_buf_init(istream_from_buf_t * istream, const char * buf, size_t buf_size)
{
    istream->read = (gtaio_stream_read_t)istream_from_buf_read;
    istream->eof = (gtaio_stream_eof_t)istream_from_buf_eof;
    istream->buf = buf;
    istream->buf_size = buf_size;
    istream->buf_pos = 0;
}

/**
 * Finish function.
 */
bool ostream_finish(gtaio_ostream_t * ostream, gta_errinfo_t errinfo, gta_errinfo_t * p_errinfo)
{
    /* unused */
    (void)ostream;
    (void)errinfo;
    (void)p_errinfo;

    return true;
}

/**
 * Write byte to the output stream.
 */
size_t ostream_to_buf_write(ostream_to_buf_t * ostream, const char * data, size_t len, gta_errinfo_t * p_errinfo)
{
    /* unused */
    (void)p_errinfo;

    /* Check how many bytes are still available in data buffer */
    size_t bytes_available = ostream->buf_size - ostream->buf_pos;
    if (bytes_available < len) {
        /* Write only as many bytes as are still available in data buffer */
        len = bytes_available;
    }
    /* Copy the bytes to the buffer */
    memcpy(&(ostream->buf[ostream->buf_pos]), data, len);
    /* Set new position in data buffer */
    ostream->buf_pos += len;

    /* Return number of written bytes */
    return len;
}

/**
 * Initialize the output stream.
 */
void ostream_to_buf_init(ostream_to_buf_t * ostream, char * buf, size_t buf_size)
{
    ostream->write = (gtaio_stream_write_t)ostream_to_buf_write;
    ostream->finish = ostream_finish;
    ostream->buf = buf;
    ostream->buf_size = buf_size;
    ostream->buf_pos = 0;
    memset(buf, 0x00, buf_size);
}

/**
 * Compare bytes from the output stream with stored reference.
 */
size_t ocmpstream_write(ocmpstream_t * ostream, const char * data, size_t len, gta_errinfo_t * p_errinfo)
{
    /* unused */
    (void)p_errinfo;

    if (CMP_ONGOING == ostream->cmp_result) {
        /* Check whether the current part of the string matches */
        if (0 == strncmp(data, (ostream->buf + ostream->pos), len)) {
            /* Check whether the end of both strings is reached */
            if (('\0' == data[len - 1]) && ('\0' == ostream->buf[ostream->pos + len - 1])) {
                ostream->cmp_result = CMP_EQUAL;
            } else {
                ostream->pos += len;
            }
        } else {
            ostream->cmp_result = CMP_UNEQUAL;
        }
    }
    return len;
}

/**
 * Initialize the cmp stream.
 */
void ocmpstream_init(ocmpstream_t * ostream, char * buf)
{
    ostream->write = (gtaio_stream_write_t)ocmpstream_write;
    ostream->finish = (gtaio_stream_finish_t)ostream_finish;
    ostream->buf = buf;
    ostream->pos = 0;
    ostream->cmp_result = CMP_ONGOING;
}