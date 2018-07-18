// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file cryptd_black.h
 * Cryptd ciphertext public header.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * @n
 * All rights reserved.
 */

#ifndef _CRYPTD_BLACK_H
#define _CRYPTD_BLACK_H

#include <cryptd_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/**********************/
/* ciphertext message */
/**********************/

/**
 * Ciphertext structure. Used both by the black side client to put / get
 * ciphertexts, and by the server to store them in the input / output
 * lists.
 */
typedef struct ciphertext {
	uint32_t uid;	/**< UID this ciphertext belongs to. Only used
				server-side. 
			*/
	char *title;	/**< 'Name' of the ciphertext (free form id).
				Getting the ciphertext through get_ciphertext()
				will ensure this string is null-terminated.
			*/
	uint32_t tlen; 	/**< Length of @a title string 
				(including trailing null)
			*/

	char *content;	/**< Encrypted content. */
	uint32_t clen;	/**< Length of encrypted content. */
	void *reserved;	/**< Reserved for future use. */

	struct ciphertext *prev, *next; /**< Double-linked chaining.
						Only used server-side. */
} ciphertext_t;

/**
 * Allocate a new (empty) ciphertext struct.
 * @return Newly allocated struct on success, NULL on failure.
 */
static inline ciphertext_t *
ciphertext_alloc(void)
{
	ciphertext_t* _new = (ciphertext_t*) calloc(1, sizeof(*_new));
	if (_new) {
		_new->uid = (uint32_t)-1;
		_new->prev = _new->next = _new;
	}
	return _new;
}

/**
 * Free a ciphertext struct, and its different fields.
 * @param cpr Ciphertext struct to free.
 */
static inline void
ciphertext_free(ciphertext_t *cpr)
{
	
	if (cpr->title) {
		memset(cpr->title, 0, cpr->tlen);
		free(cpr->title);
	}
	if (cpr->content)
		free(cpr->content);
	
	free(cpr);
}

/**
 * Request a ciphertext's content from the server (client use only).
 * This sends a request to the server for the ciphertext name @a cpr->title
 * (must be defined by the caller), and, if present, reads the encrypted
 * data into @a cpr->content.
 * Sets @a cpr->content (allocated, no check for previous allocations, which
 * will result in memory leaks) and @a cpr->clen. Requires @a cpr->title
 * and @a cpr->tlen to be defined.
 * Differs from @a get_ciphertext() in that :
 *  - an initial CMD_RECV is sent to the server
 *  - only the content is requested, the title is supplied by the caller
 *  - reading the content does not time out
 * @param s Connected socket to communicate with server.
 * @param cpr Ciphertext to read content into.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t cryptd_recv_ciphertext(int s, ciphertext_t *cpr);

/**
 * Send a ciphertext to the server (client use only).
 * This basically performs sends a CMD_SEND command to the server, before
 * calling @a put_ciphertext() if the server accepts the submission.
 * @param s Connected socket to communicate with server.
 * @param cpr Ciphertext to send to the server.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t cryptd_send_ciphertext(int, const ciphertext_t *);

/**
 * Send a file from the client to the diode.
 * Only valid on the DOWN socket. This performs the full transaction,
 * including the initial CMD_SENDCLR handshake.
 * @param s Connected client-server socket on which to send the file.
 * @param file File to send.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t cryptd_send_diode(int s, file_t *file);


#ifdef __cplusplus
}
#endif

#endif /* _CRYPTD_BLACK_H */
