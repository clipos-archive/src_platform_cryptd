// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file cryptd_red.h
 * Cryptd cleartext public header.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * @n
 * All rights reserved.
 */

#ifndef _CRYPTD_RED_H
#define _CRYPTD_RED_H

#include <cryptd_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/*****************/
/*  private key  */
/*****************/

/**
 * Private key + optional password structure.
 * Used both by client (without password field) to pass keys to the
 * daemon, and by server to manipulate them.
 */
typedef struct privkey {
	uint32_t len;	/**< PVR bundle length. */
	char *data;	/**< PVR bundle content. */
	char *subject;	/**< PVR subject name (NULL terminated).
			  	Daemon internal : valid only
				after encryption / decryption. */
} privkey_t;

/**
 * Allocate a new, empty private key.
 * @return Pointer to allocated private key, NULL on error.
 */
static inline privkey_t *
privkey_alloc(void)
{
	privkey_t* _new = (privkey_t *) malloc(sizeof(*_new));
	if (_new) {
		_new->data = _new->subject = NULL;
		_new->len = 0;
	}
	return _new;
}

/**
 * Erase and free a private key structure and its fields.
 * @param pvk Private key structure to free.
 */
static inline void
privkey_free(privkey_t *pvk)
{
	if (pvk->data) {
		memset(pvk->data, 0, pvk->len);
		free(pvk->data);
	}
	if (pvk->subject)
		free(pvk->subject);
	free(pvk);
}

/*****************/
/*  public key   */
/*****************/

/**
 * Public key structure.
 * Used both by the clients and internally in the server.
 */
typedef struct pubkey {
	uint32_t len;		/**< PPR bundle length. */
	char *data;		/**< PPR bundle content. */
	char *subject; 		/**< PPR Subject name (NULL terminated).
					Daemon internal : valid only
					after encryption. */
	struct pubkey *next, *prev;
} pubkey_t;


/**
 * Allocate a new, empty public key.
 * @return Pointer to allocated public key, NULL on error.
 */
static inline pubkey_t *
pubkey_alloc(void)
{
	pubkey_t* _new = (pubkey_t*) malloc(sizeof(*_new));

	if (_new) {
		_new->len = 0;
		_new->data = NULL;
		_new->subject = NULL;
		_new->prev = _new->next = _new;
	}

	return _new;
}

/*
 * Free a public key structure and its fields.
 * @param pub Public key structure to free.
 */
static inline void
pubkey_free(pubkey_t *pub)
{
	if (pub->data)
		free(pub->data);
	if (pub->subject) 
		free(pub->subject);
	free(pub);
}

/**********************/
/* cleartext settings */
/**********************/

/**
 * Full cleartext representation before encryption into an ACID
 * CSA archive (or after decryption from one).
 */
typedef struct cleartext {
	uint32_t uid;		/**< Client uid.
				     Daemon internal.
				     This is the red client's uid on sending,
				     and the black client's uid on reception.
				*/
	char *title;		/**< Message title. */
	uint32_t tlen;		/**< Message title length. */

	privkey_t *prv;		/**< Sender's private key. */
	
	pubkey_t *pubs;		/**< Dummy head of peer pubkeys. */
	
	file_t *files;		/**< Dummy head of file list. */

	uint32_t nlen;		/**< Sender name length 
				  	(excl. trailing NULL).
					Daemon internal: valid only 
					after decryption */
	char *name;		/**< Sender name, null-terminated. 
					Daemon internal: valid only 
					after decryption */
	char *ppr;		/**< Sender's public key.
					Daemon internal: valid only 
					if public key was requested
					by client. */
	uint32_t plen;		/**< Sender's public key length. */
} cleartext_t;

/**
 * Allocate a new, empty cleartext struct.
 * Also allocates dummy heads for the public keys and files lists.
 * @return Pointer to allocated cleartext struct, NULL on error.
 */
static inline cleartext_t *
cleartext_alloc(void)
{
	cleartext_t* _new = (cleartext_t*) calloc(1, sizeof(*_new));
	if (_new) {
		_new->uid = (uint32_t)-1;
		/* dummy head */
		_new->pubs = pubkey_alloc();
		if (!_new->pubs) {
			free(_new);
			return NULL;
		}
		_new->files = file_alloc();
		if (!_new->files) {
			free(_new->pubs);
			free(_new);
			return NULL;
		}

	}
	return _new;
}

/**
 * Erase and free a cleartext struct and its fields.
 * @param clr Cleartext structure to free.
 */
static inline void
cleartext_free(cleartext_t *clr)
{
	if (clr->prv)
		privkey_free(clr->prv);
	if (clr->pubs)
		list_free_all(clr->pubs, pubkey_t, pubkey_free);
	if (clr->files)
		list_free_all(clr->files, file_t, file_free);
	if (clr->title) {
		memset(clr->title, 0, clr->tlen);
		free(clr->title);
	}
	if (clr->name) {
		memset(clr->name, 0, clr->nlen);
		free(clr->name);
	}
	if (clr->ppr) {
		memset(clr->ppr, 0, clr->plen);
		free(clr->ppr);
	}
	free(clr);
}

/**
 * Send a full cleartext_t structure from the client to the server
 * over a connected socket (including initial CMD_SEND handshake).
 * @param s Connected socket to send cleartext over.
 * @param clr Cleartext struct to send.
 * @param err Where to store crypto error code, if non NULL.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t cryptd_send_cleartext(int s, 
			const cleartext_t *clr, uint32_t *err);


/**
 * Send a full cleartext_t structure to the server, and retrieve the 
 * encrypted content as byte array.
 * @param s Connected socket to send cleartext over.
 * @param clr Cleartext struct to send.
 * @param cipher Where to return the encrypted content.
 * @param clen Where to return the length of the encrypted content.
 * @param err Where to store crypto error code, if non NULL.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t cryptd_encrypt_cleartext(int s, const cleartext_t *clr, 
				char **cipher, uint32_t *clen, uint32_t *err);

/**
 * Receive a full cleartext_t structure in the client from the server
 * over a connected socket (including initial CMD_RECV handshake).
 * @param s Connected socket to send cleartext over.
 * @param clr Cleartext struct to fill with retrieved content.
 * @param pub_p If non-zero, receive the decrypted archive's signer
 * public key as part of the transfer. By default, that key is not
 * transmitted.
 * @param err Where to store crypto error code, if non NULL.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t cryptd_recv_cleartext(int s, cleartext_t *clr, 
					int pub_p, uint32_t *err);

/**
 * Send encrypted content to the server an retrieve the decrypted cleartext_t
 * structure.
 * @param s Connected socket to send cleartext over.
 * @param clr Cleartext struct to fill with retrieved content.
 * @param cipher Ciphertext content to send.
 * @param clen Length of ciphertext content to send.
 * @param pub_p If non-zero, receive the decrypted archive's signer
 * public key as part of the transfer. By default, that key is not
 * transmitted.
 * @param err Where to store crypto error code, if non NULL.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t cryptd_decrypt_ciphertext(int s, cleartext_t *clr, 
				char *cipher, uint32_t clen,
				int pub_p, uint32_t *err);

/**
 * Delete an encrypted message from the server's input list.
 * @param s Connected socket to send cleartext over.
 * @param name Name of the ciphertext to delete.
 * @param nlen Length of @a name.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t cryptd_delete_ciphertext(int s, char *name, uint32_t nlen);

/**
 * Write all the files from a cleartext_t struct on disk.
 * Note that the filenames are automatically assumed to be encoded
 * in ISO-8859-1, and converted from that encoding to the current locale.
 * @param base_path Base path from which to create the file paths.
 * @param clr Cleartext struct to write the files from.
 * @param overwrite If non-zero, existing files will be silently overwritten.
 * By default, existing files result in an error (note that in this case, some
 * files may already have been written).
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t cryptd_write_cleartext(const char *base_path, 
					cleartext_t *clr, int overwrite);

/*****************************/
/*  Diode client functions   */
/*****************************/
/* Only valid if compiled with WITH_DIODE. */

/**
 * Receive a file from the diode server in a client.
 * Only valid on the UP socket. This performs the full transaction,
 * including the initial CMD_RECVCLR handshake.
 * @param s Connected client-server socket on which to receive the file.
 * @param name Name of the file to read.
 * @param nlen Length of the file name.
 * @param file Where to store the received (and allocated) file.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t cryptd_recv_diode(int s, char *name, 
				uint32_t nlen, file_t **file);

/**
 * Read a list of files in the diode server waitqueue into a newly allocated
 * buffer.
 * Only valid on the UP socket
 * This sends a CMD_GETCLRLIST command to the server on the @a s socket,
 * and reads the list of files in the wait queue associated to
 * @a s into a new buffer.
 * The returned list is a null-terminated string, containing file
 * names separated by \n, or a NULL pointer if no ciphertexts are 
 * available in the wait queue.
 * @param s Connected socket to communicate with server.
 * @param out Where the allocated list should be returned. Note that 
 * if no files are available, @a *out will be returned NULL.
 * @param len Where to return the length of the returned list (including
 * trailing null).
 * @return CMD_OK on success (including when no files are available),
 * CMD error on failure.
 */
extern uint32_t cryptd_get_diode_list(int s, char **buf, uint32_t *len);

extern uint32_t cryptd_change_password(int s, privkey_t *prv, uint32_t *err);

#ifdef __cplusplus
}
#endif

#endif /* _CRYPTD_RED_H */
