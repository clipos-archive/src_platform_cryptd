// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file cryptd_common.h
 * Cryptd common public header (for use by clients).
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * @n
 * All rights reserved.
 */

#ifndef _CRYPTD_COMMON_H
#define _CRYPTD_COMMON_H

#include <cryptd_files.h>
#include <cryptd_features.h>

#ifdef __cplusplus
extern "C" {
#endif

/*****************/
/*  logging      */
/*****************/
/**
 * Verbosity level. 
 * 0 means only error messages / warnings are displayed.
 * >0 means debug messages are displayed. Theoretically, 
 * the verbosity increases with the value, but no debug
 * messages with a level > 1 are generated at the moment.
 */
extern int g_verbose;
/**
 * Foreground / background option.
 * 0 means logging to STDOUT / STDERR, !0 means and logging to syslog.
 */
extern int g_daemonized;

/**
 * Retrieve version and features from the server.
 * @param s Socket to retrieve info from.
 * @param version Where to store the retrieved version number, if non-NULL.
 * @param features Where to store the retrieved features bitmask, if non-NULL.
 * @return CMD_OK on success, CMD error code on failure.
 */
extern uint32_t cryptd_get_info(int s, uint32_t *version, uint32_t *features);

/**
 * Check that the client version is compatible with the one sent by the server.
 * At the moment, this only checks that both major versions are the same.
 * @param version Version number sent by the server.
 * @return CMD_OK if client and server versions are compatible, CMD_VERCMP 
 * otherwise.
 */
extern uint32_t cryptd_check_version(uint32_t version);


/**
 * Read a list of ciphertext from the server into a newly allocated 
 * buffer.
 * This sends a CMD_GETLIST command to the server on the @a s socket,
 * and reads the list of ciphertexts in the wait queue associated to
 * @a s into a new buffer.
 * The returned list is a null-terminated string, containing ciphertext
 * titles separated by \n, or a NULL pointer if no ciphertexts are 
 * available in the wait queue.
 * @param s Connected socket to communicate with server.
 * @param out Where the allocated list should be returned. Note that 
 * if no ciphertexts are available, @a *out will be returned NULL.
 * @param len Where to return the length of the returned list (including
 * trailing null).
 * @return CMD_OK on success (including when no ciphertexts are available),
 * CMD error on failure.
 */
extern uint32_t cryptd_get_list(int s, char **out, uint32_t *len);

#ifdef __cplusplus
}
#endif

#endif /* _CRYPTD_COMMON_H */
