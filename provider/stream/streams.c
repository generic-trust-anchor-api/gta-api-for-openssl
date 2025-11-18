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
 * Check how many bytes are still available in the input data buffer.
 *
 * @param[in] istream: input stream
 * @param[out] len: length of available bytes
 */
void check_available_bytes_in_input_buffer(istream_from_buf_t ** istream, size_t * len)
{

    size_t bytes_available = (*istream)->buf_size - (*istream)->buf_pos;

    if (bytes_available < (*len)) {
#ifdef LOG_BYTE_ARRARY_ON
        LOG_TRACE("Write only as many bytes as requested in case more are available");
#endif
        (*len) = bytes_available;
    }
}

/**
 * Read byte array data to input stream.
 */
GTA_DEFINE_FUNCTION(
    size_t,
    istream_from_buf_read,
    (istream_from_buf_t * istream, char * data, size_t len, gta_errinfo_t * p_errinfo))
{
    if (NULL == istream) {
#ifdef LOG_BYTE_ARRARY_ON
        LOG_ERROR("Input stream is null.");
#endif
        (*p_errinfo) = GTA_ERROR_PTR_INVALID;
        return NO_SIZE_INFO;
    }

    if (NULL == data) {
#ifdef LOG_BYTE_ARRARY_ON
        LOG_ERROR("Input data is null.");
#endif
        (*p_errinfo) = GTA_ERROR_PTR_INVALID;
        return NO_SIZE_INFO;
    }

    check_available_bytes_in_input_buffer(&istream, &len);

#ifdef LOG_BYTE_ARRARY_ON
    LOG_TRACE("Copy the bytes from the buffer.");
#endif
    memcpy(data, &(istream->buf[istream->buf_pos]), len);

#ifdef LOG_BYTE_ARRARY_ON
    LOG_TRACE("Set new position in data buffer.");
#endif
    istream->buf_pos += len;

    return len;
}

/**
 * Check end of the input stream.
 */
GTA_DEFINE_FUNCTION(bool, istream_from_buf_eof, (istream_from_buf_t * istream, gta_errinfo_t * p_errinfo))
{
    if (NULL == istream) {
#ifdef LOG_BYTE_ARRARY_ON
        LOG_ERROR("Input stream is null.");
#endif
        (*p_errinfo) = GTA_ERROR_PTR_INVALID;
        return false;
    }
    return (istream->buf_pos == istream->buf_size);
}

/**
 * Initialize the input stream.
 */
GTA_DEFINE_FUNCTION(
    bool,
    istream_from_buf_init,
    (istream_from_buf_t * istream, const char * buf, size_t buf_size, gta_errinfo_t * p_errinfo))
{
    if (NULL == istream) {
#ifdef LOG_BYTE_ARRARY_ON
        LOG_ERROR("Input stream is null.");
#endif
        (*p_errinfo) = GTA_ERROR_PTR_INVALID;
        return false;
    }

    if (NULL == buf) {
#ifdef LOG_BYTE_ARRARY_ON
        LOG_ERROR("Input buf is null.");
#endif
        (*p_errinfo) = GTA_ERROR_PTR_INVALID;
        return false;
    }

    istream->read = (gtaio_stream_read_t)istream_from_buf_read;
    istream->eof = (gtaio_stream_eof_t)istream_from_buf_eof;
    istream->buf = buf;
    istream->buf_size = buf_size;
    istream->buf_pos = 0;

    return true;
}

/**
 * Close the input stream.
 */
GTA_DEFINE_FUNCTION(bool, istream_from_buf_close, (istream_from_buf_t * istream, gta_errinfo_t * p_errinfo))
{
    if (NULL == istream) {
#ifdef LOG_BYTE_ARRARY_ON
        LOG_ERROR("Input stream is null.");
#endif
        (*p_errinfo) = GTA_ERROR_PTR_INVALID;
        return false;
    }

    gta_memset(istream, sizeof(istream_from_buf_t), 0, sizeof(istream_from_buf_t));
    return true;
}

/**
 * Finish function.
 */
GTA_DEFINE_FUNCTION(bool, ostream_finish, (gtaio_ostream_t * ostream, gta_errinfo_t errinfo, gta_errinfo_t * p_errinfo))
{
    return true;
}

/**
 * Check how many bytes are still available in the output data buffer.
 *
 * @param[in] ostream: output stream
 * @param[out] len: length of available bytes
 */
void check_available_bytes_in_ouput_buffer(ostream_to_buf_t ** ostream, size_t * len)
{

    size_t bytes_available = (*ostream)->buf_size - (*ostream)->buf_pos;

    if (bytes_available < (*len)) {
        (*len) = bytes_available;
    }
}

/**
 * Write byte from the output stream.
 */
GTA_DEFINE_FUNCTION(
    size_t,
    ostream_to_buf_write,
    (ostream_to_buf_t * ostream, const char * data, size_t len, gta_errinfo_t * p_errinfo))
{
    if (NULL == ostream) {
#ifdef LOG_BYTE_ARRARY_ON
        LOG_ERROR("Output stream is null.");
#endif
        (*p_errinfo) = GTA_ERROR_PTR_INVALID;
        return NO_SIZE_INFO;
    }

    if (NULL == data) {
#ifdef LOG_BYTE_ARRARY_ON
        LOG_ERROR("Data is null.");
#endif
        (*p_errinfo) = GTA_ERROR_PTR_INVALID;
        return NO_SIZE_INFO;
    }

    check_available_bytes_in_ouput_buffer(&ostream, &len);

#ifdef LOG_BYTE_ARRARY_ON
    LOG_TRACE("Copy the bytes from the buffer.");
#endif
    memcpy(&(ostream->buf[ostream->buf_pos]), data, len);

#ifdef LOG_BYTE_ARRARY_ON
    LOG_TRACE("Set new position in data buffer.");
#endif
    ostream->buf_pos += len;

    return len;
}

/**
 * Initialize the output stream.
 */
GTA_DEFINE_FUNCTION(
    bool,
    ostream_to_buf_init,
    (ostream_to_buf_t * ostream, char * buf, size_t buf_size, gta_errinfo_t * p_errinfo))
{
    if (NULL == ostream) {
#ifdef LOG_BYTE_ARRARY_ON
        LOG_ERROR("Output stream is null.");
#endif
        (*p_errinfo) = GTA_ERROR_PTR_INVALID;
        return false;
    }

    if (NULL == buf) {
#ifdef LOG_BYTE_ARRARY_ON
        LOG_ERROR("Out buffer is null.");
#endif
        (*p_errinfo) = GTA_ERROR_PTR_INVALID;
        return false;
    }

    ostream->write = (gtaio_stream_write_t)ostream_to_buf_write;
    ostream->finish = ostream_finish;
    ostream->buf = buf;
    ostream->buf_size = buf_size;
    ostream->buf_pos = 0;

    return true;
}

/**
 * Close the output stream.
 */
GTA_DECLARE_FUNCTION(bool, ostream_to_buf_close, (ostream_to_buf_t * ostream, gta_errinfo_t * p_errinfo))
{
    if (NULL == ostream) {
#ifdef LOG_BYTE_ARRARY_ON
        LOG_ERROR("Output stream is null.");
#endif
        (*p_errinfo) = GTA_ERROR_PTR_INVALID;
        return false;
    }

    gta_memset(ostream, sizeof(ostream_to_buf_t), 0, sizeof(ostream_to_buf_t));
    return true;
}
