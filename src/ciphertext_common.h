// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file ciphertext_common.h
 * Cryptd common ciphertext dialogs.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * @n
 * All rights reserved.
 */

#ifndef CIPHERTEXT_COMMON_H
#define CIPHERTEXT_COMMON_H

#ifndef __U
/**
 * Unused attribute shortcut.
 */
#define __U __attribute__((unused))
#endif

#ifndef __H
/**
 * Hidden attribute shortcut.
 */
#define __H __attribute__((visibility("hidden")))
#endif

struct ciphertext;

/** 
 * Write a ciphertext struct to a socket.
 * The receiver can read it on the other end by calling @a get_ciphertext().
 * The ciphertext passed as argument only needs to have its @a title, 
 * @a tlen, @a content and @a clen fields defined.
 * @param s Socket to write the ciphertext to.
 * @param cpr Ciphertext to write to the socket.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t send_ciphertext(int s, const struct ciphertext *cpr) __H;

/**
 * Receive a ciphertext struct from a socket.
 * This is appropriate to read a ciphertext sent through put_ciphertext().
 * On success, the ciphertext's @a title, @tlen, @a content and @a clen
 * will be filled (and allocated in case of @a title and @a content).
 * Note that the function does not check for already allocated fields
 * in @a cpr - calling it on an already filled ciphertext will result
 * in a memory leak.
 * @param s Socket to read the ciphertext from.
 * @param cpr Ciphertext struct to fill with the read data. This must
 * be an allocated struct, with unallocated @a title and @a content
 * fields.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t recv_ciphertext(int s, struct ciphertext *cpr) __H;

#endif
