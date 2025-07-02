/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GTAOSSL_PROVIDER_LOGGER_H_
#define _GTAOSSL_PROVIDER_LOGGER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#define LOG_LEVEL_TRACE 0
#define LOG_LEVEL_DEBUG 1
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_WARN 3
#define LOG_LEVEL_ERROR 4

#if !defined(LOG_LEVEL)
#define LOG_LEVEL LOG_LEVEL_ERROR
#endif

#define LOG_USE_STDIO 1

#if LOG_USE_STDIO
#define LOG__STDIO_FPRINTF(stream, fmt, ...) fprintf(stream, fmt, __VA_ARGS__);
#define LOG__STDIO_FPRINTS(stream, fmt) fprintf(stream, fmt);
#else
#define LOG__STDIO_FPRINTF(stream, fmt, ...)
#define LOG__STDIO_FPRINTS(stream, fmt)
#endif

#define LOG__XSTR(x) #x
#define LOG__STR(x) LOG__XSTR(x)

#define LOG__EOL "|"
#define LOG__LSEP ": "
#define LOG__EOM "\n"

#define LOG__STRUCTURED(file, line, level, msg)                                                                        \
    level LOG__EOL "GTAOSSL_PROVIDER" LOG__LSEP "" file LOG__LSEP "[" line "]" LOG__EOL "Message: " msg LOG__EOM

#define LOG__LINE(file, line, level, msg) LOG__STRUCTURED(file, line, level, msg)

#define LOG__DECL_LOGLEVELF(T, fmt, ...)                                                                               \
    {                                                                                                                  \
        LOG__STDIO_FPRINTF(stdout, LOG__LINE(__FILE__, LOG__STR(__LINE__), #T, fmt), __VA_ARGS__);                     \
    }

#define LOG__DECL_LOGLEVELS(T, fmt)                                                                                    \
    {                                                                                                                  \
        LOG__STDIO_FPRINTS(stdout, LOG__LINE(__FILE__, LOG__STR(__LINE__), #T, fmt));                                  \
    }

#if LOG_LEVEL == LOG_LEVEL_TRACE
#define LOG_TRACE_ARG(fmt, ...) LOG__DECL_LOGLEVELF("TRACE", fmt, __VA_ARGS__);
#define LOG_TRACE(fmt) LOG__DECL_LOGLEVELS("TRACE", fmt);
#ifdef LOG_BYTE_ARRARY_ON
#define LOG_TRACE_KEY_DATA_ARG(fmt, ...) printf(fmt, __VA_ARGS__);
#define LOG_TRACE_KEY_DATA(fmt) printf(fmt);
#else
#define LOG_TRACE_KEY_DATA_ARG(fmt, ...)
#define LOG_TRACE_KEY_DATA(fmt)
#endif
#else
#define LOG_TRACE_ARG(fmt, ...)
#define LOG_TRACE(fmt)
#define LOG_TRACE_KEY_DATA_ARG(fmt, ...)
#define LOG_TRACE_KEY_DATA(fmt)
#endif

#if LOG_LEVEL <= LOG_LEVEL_DEBUG
#define LOG_DEBUG_ARG(fmt, ...) LOG__DECL_LOGLEVELF("DEBUG", fmt, __VA_ARGS__);
#define LOG_DEBUG(fmt) LOG__DECL_LOGLEVELS("DEBUG", fmt);
#else
#define LOG_DEBUG_ARG(fmt, ...)
#define LOG_DEBUG(fmt)
#endif

#if LOG_LEVEL <= LOG_LEVEL_INFO
#define LOG_INFO_ARG(fmt, ...) LOG__DECL_LOGLEVELF("INFO", fmt, __VA_ARGS__);
#define LOG_INFO(fmt) LOG__DECL_LOGLEVELS("INFO", fmt);
#else
#define LOG_INFO_ARG(fmt, ...)
#define LOG_INFO(fmt)
#endif

#if LOG_LEVEL <= LOG_LEVEL_WARN
#define LOG_WARN_ARG(fmt, ...) LOG__DECL_LOGLEVELF("WARNING", fmt, __VA_ARGS__);
#define LOG_WARN(fmt) LOG__DECL_LOGLEVELS("WARNING", fmt);
#else
#define LOG_WARN_ARG(fmt, ...)
#define LOG_WARN(fmt)
#endif

#if LOG_LEVEL <= LOG_LEVEL_ERROR
#define LOG_ERROR_ARG(fmt, ...) LOG__DECL_LOGLEVELF("ERROR", fmt, __VA_ARGS__);
#define LOG_ERROR(fmt) LOG__DECL_LOGLEVELS("ERROR", fmt);
#else
#define LOG_ERROR_ARG(fmt, ...)
#define LOG_ERROR(fmt)
#endif

/**
 * Allocate buffer and copy the string input into it.
 *
 * https://stackoverflow.com/questions/13663617/why-is-there-a-strdup-function-but-not-memdup-function-in-the-standard
 */
void * mem_dup(const void * mem, size_t size);

/**
 * Remove a given sub string from a C string.
 *
 * https://stackoverflow.com/questions/47116974/remove-a-substring-from-a-string-in-c
 */
char * str_remove(char * str, const char * sub);

/**
 * Base64 decoder
 *
 * @param[in] b64message: encoded message
 * @param buffer: decoded data
 * @param length: length of the decoded data
 *
 * @return OK = 1
 * @return NOK = 0
 */
int base_64_decode(const char * b64message, unsigned char ** buffer, size_t * length);

/**
 * Base64 encoder
 *
 * @param[in] buffer: byte array as input data
 * @param[in] length: length of the input data
 * @param b64text: base 64 encoded string
 *
 * @return OK = 1
 * @return NOK = 0
 */
int base_64_encode(const unsigned char * buffer, size_t length, char ** b64text);

#ifdef __cplusplus
}
#endif

#endif /* _GTAOSSL_PROVIDER_LOGGER_H_ */
