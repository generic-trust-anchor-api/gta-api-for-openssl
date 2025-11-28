/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef STREAMS_H
#define STREAMS_H

#if defined(_MSC_VER) && (_MSC_VER > 1000)
/* Microsoft */
/*
 * Specifies that the file will be included (opened) only
 * once by the compiler in a build. This can reduce build
 * times as the compiler will not open and read the file
 * after the first #include of the module.
 */
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <gta_api/gta_api.h>
#include <stdio.h>

/*
 * gtaio input stream implementation to read from a temporary buffer.
 */
typedef struct istream_from_buf {
    /* Public interface as defined for gtaio input stream. */
    gtaio_stream_read_t read;
    gtaio_stream_eof_t eof;
    void * p_reserved2;
    void * p_reserved3;

    /* Private implementation details. */
    const char * buf; /* data buffer */
    size_t buf_size;  /* data buffer size */
    size_t buf_pos;   /* current position in data buffer */
} istream_from_buf_t;

/**
 * Read byte array data to input stream.
 *
 * @param[out] istream: input stream
 * @param[in] data: byte array
 * @param[in] len: length of byte array
 * @param[out] p_errinfo: error information
 * @return number of read bytes
 */
size_t istream_from_buf_read(istream_from_buf_t * istream, char * data, size_t len, gta_errinfo_t * p_errinfo);

/**
 * Check end of the input stream.
 *
 * @param[in] istream: input stream
 * @param p_errinfo: error information
 * @return true if at the end of the buffer
 */
bool istream_from_buf_eof(istream_from_buf_t * istream, gta_errinfo_t * p_errinfo);

/**
 * Initialize the input stream.
 *
 * @param[out] istream: input stream
 * @param[in] buf: input buffer
 * @param[in] buf_size: size of the input buffer
 * @return void (this function cannot fail)
 */
void istream_from_buf_init(istream_from_buf_t * istream, const char * buf, size_t buf_size);

/**
 * Finish function.
 *
 * @param[in] ostream: output steam
 * @param[in] errinfo: error information
 * @param[out] p_errinfo: error information
 * @return true if the reading of stream is finished
 */
bool ostream_finish(gtaio_ostream_t * ostream, gta_errinfo_t errinfo, gta_errinfo_t * p_errinfo);

/*
 * gtaio output stream implementation to write the output to a temporary buffer.
 */
typedef struct ostream_to_buf {
    /* Public interface as defined for gtaio output stream. */
    void * p_reserved0;
    void * p_reserved1;
    gtaio_stream_write_t write;
    gtaio_stream_finish_t finish;

    /* Private implementation details. */
    char * buf;      /* data buffer */
    size_t buf_size; /* data buffer size */
    size_t buf_pos;  /* current position in data buffer */
    gta_errinfo_t finish_errinfo;
} ostream_to_buf_t;

/**
 * Write byte from the output stream.
 *
 * @param[in] ostream: output steam
 * @param[out] data: byte array
 * @param[out] len: length of byte array
 * @param[out] p_errinfo: error information
 * @return number of written bytes
 */
size_t ostream_to_buf_write(ostream_to_buf_t * ostream, const char * data, size_t len, gta_errinfo_t * p_errinfo);

/**
 * Initialize the output stream.
 *
 * @param[out] ostream: output stream
 * @param[in] buf: output buffer
 * @param[in] buf_size: size of the output buffer
 * @return void (this function cannot fail)
 */
void ostream_to_buf_init(ostream_to_buf_t * ostream, char * buf, size_t buf_size);

/*
 * gtaio output stream implementation to compare a stream output with a string.
 */
typedef struct ocmpstream {
    /* public interface as defined for gtaio_ostream */
    void * p_reserved0;
    void * p_reserved1;
    gtaio_stream_write_t write;
    gtaio_stream_finish_t finish;

    /* private implementation details */
    char * buf; /* buffer holding the string to compare with the stream output */
    size_t pos; /* current position in the buffer */
    enum { CMP_ONGOING, CMP_EQUAL, CMP_UNEQUAL } cmp_result;
} ocmpstream_t;

/**
 * Compare bytes from the output stream with stored reference.
 *
 * @param[in] ostream: output steam
 * @param[out] data: byte array
 * @param[out] len: length of byte array
 * @param[out] p_errinfo: error information
 * @return number of written bytes
 */
size_t ocmpstream_write(ocmpstream_t * ostream, const char * data, size_t len, gta_errinfo_t * p_errinfo);

/**
 * Initialize the cmp stream.
 *
 * @param[out] ostream: output stream
 * @param[in] ref: reference string to compare
 * @return void (this function cannot fail)
 */
void ocmpstream_init(ocmpstream_t * ostream, char * ref);

#ifdef __cplusplus
}
#endif

#endif /* STREAMS_H */
