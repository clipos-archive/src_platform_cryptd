// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file server.h
 * Cryptd main header.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN/DCSSI
 * Copyright (C) 2010-2012 SGDSN/ANSSI
 * @n
 * All rights reserved.
 */

/**
 * @mainpage cryptd documentation
 * This is the inline documentation for the cryptd package.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 */

#ifndef CRYPTD_PROTOS_H
#define CRYPTD_PROTOS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <clip/clip.h>
#include <clip/acidcrypt.h>

#include "log.h"
#include "cryptd_features.h"

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

                   /*****************************/
		   /*       Runtime options     */
		   /*****************************/

/** @name Runtime options */
/*@{*/

/**
 * Bitmask of @a cryptd_feature_t features currently supported.
 */
extern uint32_t g_features; 

/*@}*/


                   /*****************************/
		   /*        Logging macros     */
		   /*****************************/

			/* info.c */
/**
 * Send server info to a client.
 * Sends a cryptd_info_t describing the server's version and features.
 * @param s Socket to send info on.
 * @return CMD_OK on success, CMD error code on failure.
 */
extern uint32_t send_server_info(int s);

			/* cleartext_common.c */


                   /*****************************/
		   /*        Red subsystem      */
		   /*****************************/

/** @name Red subsystem  */
/*@{*/

			/* cleartext_server.c */

/**
 * Red socket connection handler.
 * This function is called after each new connection on the red socket
 * has been accept()ed. It reads the peer credentials on the socket, then
 * sets it to non-blocking mode, before reading the initial command sent
 * by the peer. It then handles the command, if it is supported on the 
 * red interface, before closing the connected socket and returning.
 * @param s Connected socket file descriptor. Passed automatically
 * by @a clip_accept_one(). Will be systematically closed by this call.
 * @param sock clip_sock_t structure for the listening socket on with the 
 * new connection was received. Passed by @a clip_accept_one(), and left
 * unchanged by the call.
 * @return 0 on success (i.e. the command code read on the socket was a 
 * supported one, and the handler function returned a sucess), -1 in all
 * other cases.
 */
extern int red_conn_handler(int s, struct clip_sock_t *sock);

/*@}*/

                   /*****************************/
		   /*      Black subsystem      */
		   /*****************************/

/** @name Black subsystem  */
/*@{*/

			/* ciphertext_server.c */

/**
 * Black socket connection handler.
 * This function is called after each new connection on the black socket
 * has been accept()ed. It reads the peer credentials on the socket, then
 * sets it to non-blocking mode, before reading the initial command sent
 * by the peer. It then handles the command, if it is supported on the 
 * black interface, before closing the connected socket and returning.
 * @param s Connected socket file descriptor. Passed automatically
 * by @a clip_accept_one(). Will be systematically closed by this call.
 * @param sock clip_sock_t structure for the listening socket on with the 
 * new connection was received. Passed by @a clip_accept_one(), and left
 * unchanged by the call.
 * @return 0 on success (i.e. the command code read on the socket was a 
 * supported one, and the handler function returned a sucess), -1 in all
 * other cases.
 */
extern int black_conn_handler(int s, struct clip_sock_t *sock);

/**
 * Initialize the black subsystem.
 * This initializes the heads of the input and output ciphertext lists.
 * @return 0 if initialization was successful, -1 otherwise.
 */
extern int ciphertext_init(void);

/**
 * Ciphertext lookup flag : look into input ciphertext list. 
 */
#define CIPHERTEXT_IN 	1
/**
 * Ciphertext lookup flag : look into output ciphertext list. 
 */
#define CIPHERTEXT_OUT 	2
struct ciphertext;

/**
 * Lookup for a ciphertext in one of the ciphertext queues.
 * This returns the first (if any) ciphertext in the specified queue
 * that matches the input title and uid.
 * @param title Title field of the ciphertext to look for.
 * @param tlen Length of the title field to look for.
 * @param dir Direction, selects the input ciphertext list if @a CIPHERTEXT_IN
 * is passed, or the output list if @a CIPHERTEXT_OUT is passed.
 * @param uid Uid of the ciphertext to look for.
 * @return Pointer to first matching ciphertext if found, NULL otherwise.
 */
extern struct ciphertext *ciphertext_lookup(const char *title, uint32_t tlen, 
							int dir, uint32_t uid);

/**
 * Test if a ciphertext matching a given title and uid exists in a given
 * ciphertext queue.
 * @param title Title field of the ciphertext to look for.
 * @param tlen Length of the title field to look for.
 * @param dir Direction, selects the input ciphertext list if @a CIPHERTEXT_IN
 * is passed, or the output list if @a CIPHERTEXT_OUT is passed.
 * @param uid Uid of the ciphertext to look for.
 * @return 1 if a matching ciphertext exists in the specified list, 0 otherwise.
 */
extern int ciphertext_exists(const char *title, uint32_t tlen, 
						int dir, uint32_t uid);
/**
 * Add a ciphertext to a given ciphertext queue.
 * @param cpr Ciphertext struct to add to the ciphertext queue.
 * @param dir Direction, selects the input ciphertext list if @a CIPHERTEXT_IN
 * is passed, or the output list if @a CIPHERTEXT_OUT is passed.
 * @return CMD_OK if the ciphertext was added successfully, CMD error code 
 * otherwise (e.g. because a ciphertext with the same title and uid already 
 * exists in the list).
 */
extern uint32_t ciphertext_add(struct ciphertext *cpr, int dir);

/**
 * Delete a ciphertext matching a given title and uid in a given 
 * ciphertext queue.
 * This looks up the first ciphertext matching the arguments, and if found
 * deletes it from its list before freeing it.
 * @param title Title field of the ciphertext to look for.
 * @param tlen Length of the title field to look for.
 * @param dir Direction, selects the input ciphertext list if @a CIPHERTEXT_IN
 * is passed, or the output list if @a CIPHERTEXT_OUT is passed.
 * @param uid Uid of the ciphertext to look for.
 * @return CMD_OK if the ciphertext was found and deleted successfully, 
 * CMD error code otherwise (e.g. because no matching ciphertext was found).
 */
extern uint32_t ciphertext_delete(const char *title, uint32_t tlen, 
						int dir, uint32_t uid);

/**
 * Allocate and return a string listing the contents of a given ciphertext
 * ciphertext queue.
 * The returned string is allocated by the function, null terminated, and 
 * lists the titles (separated by newlines) of all ciphertexts matching 
 * the specified uid in the ciphertext queue.
 * @param uid Uid of ciphertexts to be included in the list.
 * @param out Where the allocated string should be returned.
 * @param len Where the allocated string length should be returned.
 * @param dir Direction, selects the input ciphertext list if @a CIPHERTEXT_IN
 * is passed, or the output list if @a CIPHERTEXT_OUT is passed.
 * @return CMD_OK on success, CMD error code on failure (@a out and @a len left
 * untouched). Note that a NULL @a out and 0 @a len will be returned, along with
 * CMD_OK, if the list is empty.
 */
extern uint32_t ciphertext_list(uint32_t uid, char **out, 
					uint32_t *len, int dir);

/*@}*/

                   /*****************************/
		   /*      Crypto subsystem     */
		   /*****************************/

/** @name Crypto subsystem  */
/*@{*/

			/* crypt.c */

/**
 * Encrypt a cleartext.
 * This returns the resulting ciphertext without adding it to the
 * output queue.
 * The cleartext's title and uid are propagated to the ciphertext.
 * @param clr Cleartext to encrypt.
 * @param e Where to return crypto error code, if any.
 * @param cpr Where to return the new ciphertext.
 * @return CMD_OK in case of success, CMD error code otherwise.
 */
extern uint32_t do_encrypt(struct cleartext *clr, 
				int32_t *e, struct ciphertext **cpr);
/**
 * Encrypt a cleartext and add to the output queue.
 * This encrypts the given cleartext structure, and adds the resulting
 * ciphertext to the output ciphertext queue.
 * The cleartext's title and uid are propagated to the ciphertext, which
 * is silently added to the output queue.
 * @param clr Cleartext to encrypt.
 * @param e Where to return crypto error code, if any.
 * @return CMD_OK in case of success, CMD error code otherwise. Note that
 * an error will be returned if a ciphertext with the same title and uid
 * as the one resulting from encryption already exists in the output 
 * queue.
 */
extern uint32_t do_encrypt_add(struct cleartext *clr, int32_t *e);

/**
 * Decrypt a ciphertext.
 * @param cpr Ciphertext to decrypt.
 * @param clr Decrypted cleartext. Must be passed empty, will be filled 
 * with the decrypted content after a successfull decryption.
 * @param pubkey_p If non-zero, the ciphertext sender's public key will be
 * saved as well in @a clr, for later extraction on the red socket.
 * @param e Where to return crypto error code, if any.
 * @return CMD_OK on success, CMD error code on failure (@a clr is left 
 * untouched).
 */
extern uint32_t do_decrypt(struct ciphertext *cpr, 
			struct cleartext *clr, int pubkey_p, int32_t *e);

/**
 * Decrypt a ciphertext waiting in the input queue and matching 
 * a given title and uid.
 * The title and uid are passed as the fields of an otherwise empty
 * cleartext struct. If the ciphertext is found and successfully decrypted,
 * then the cleartext passed as argument will be completed with the decrypted
 * fields.
 * Note that this does not remove the ciphertext from the input queue - the 
 * caller needs to take care of that himself (presumably after making sure the
 * decrypted content has been correctly transfered to a client).
 * @param clr Cleartext to decrypt. Must be passed empty, with only the @a uid,
 * @a title and @a tlen fields set, to the uid and title of the ciphertext to
 * be decrypted. The other fields will be filled with the decrypted content
 * after a successfull decryption.
 * @param pubkey_p If non-zero, the ciphertext sender's public key will be
 * saved as well in @a clr, for later extraction on the red socket.
 * @param e Where to return crypto error code, if any.
 * @return CMD_OK on success, CMD error code on failure (@a clr is left 
 * untouched).
 */
extern uint32_t do_decrypt_lookup(struct cleartext *clr, 
						int pubkey_p, int32_t *e);

struct privkey;
extern uint32_t do_chpw(uint32_t uid, struct privkey *prv, int32_t *e);
/**
 * Initialize the crypto subsystem.
 * This is a NOP at the moment.
 * @return 0.
 */
extern int crypt_init(void);

/*@}*/

#ifdef WITH_DIODE
                   /****************************/
		   /*      Diode subsystem     */
		   /****************************/

/** @name Diode subsystem  */
/*@{*/

			/* diode.c */

/**
 * Initialize the diode subsystem.
 * This currently takes care of allocating a dummy head for the 
 * diode input file list.
 * @return 0 on success, -1 on failure (no side effect).
 */
extern int diode_init(void);

/**
 * Receive an input file on the diode's 'Low' socket, and try to add it 
 * to the input file list.
 * The file is only added to the list if no other file with the same uid
 * and title (basename of the input file path) exists in the input list.
 * @param s Connected socket on which an input request was received, typically
 * passed by a connection handler. Will not be closed by the function. Initial
 * state is expected to be immediately after reception of the CMD_SENDCLR 
 * command from the client.
 * @param uid Uid of the connecting client.
 * @return CMD_OK on success, CMD error code on failure.
 */
extern uint32_t recv_diode(int s, uint32_t uid);

/**
 * Transmit an input file from the input list to a client that requests it on
 * the 'High' socket.
 * The file to be transmitted is the first (should be unique) one matching the 
 * client's Uid, and the client sent title, if found in the input list. After
 * transmitting a file to the client, it is deleted from the input list and 
 * freed.
 * @param s Connected socket on which an output request was received, typically
 * passed by a connection handler. Will not be closed by the function. Initial
 * state is expected to be immediately after reception of the CMD_RECVCLR 
 * command from the client.
 * @param uid Uid of the connecting client.
 * @return CMD_OK on success, CMD error code on failure.
 */
extern uint32_t send_diode(int s, uint32_t uid);

/**
 * Generate a list of file titles in the input list for a given uid, and send
 * it to a client on the 'High' socket.
 * The list to be transmitted is temporarily allocated (and freed before 
 * returning to caller), and written as null-terminated string, with individual
 * titles separated by '\n' newlines. 
 * @param s Connected socket on which a list request was received, typically
 * passed by a connection handler. Will not be closed by the function. Initial
 * state is expected to be immediately after reception of the CMD_GETCLRLIST
 * command from the client.
 * @param uid Uid of the connecting client. Will be used as filter to generate
 * the input list.
 * @return CMD_OK on success, CMD error code on failure.
 */
extern uint32_t send_diode_list(int s, uint32_t uid);

/*@}*/
#endif

                   /***************************************/
		   /*      External command subsystem     */
		   /***************************************/

/** @name External command subsystem  */
/*@{*/

			/* extcmd.c */

/**
 * Set up the external command path on daemon initialization.
 * This only works once : once set, the command path cannot
 * be set again.
 * @param cmd Command path to use. This must be a null-terminated
 * full path (starting with '/'). The string will be copied into 
 * the external command subsystem, the caller can free the argument.
 * @return 0 on success, -1 on failure.
 */
extern int set_ext_cmd(const char *cmd);

/**
 * Run an external command to confirm decryption.
 */
#define EXTCMD_DECRYPT	1
/**
 * Run an external command to confirm encryption.
 */
#define EXTCMD_ENCRYPT	2
/**
 * Run an external command to confirm diode transfer.
 */
#define EXTCMD_CONFIRM	3
/**
 * Run an external command to enter old password before changing it.
 */
#define EXTCMD_CHPWOLD	4
/**
 * Run an external command to enter new password for a key.
 */
#define EXTCMD_CHPWNEW	5
/**
 * Run an external command to confirm deletion of a ciphertext.
 */
#define EXTCMD_DELETE	6

/**
 * External command argument.
 */
typedef struct {
	int dir;	/**< Type of external command : 
				EXTCMD_DECRYPT / EXTCMD_ENCRYPT ... */
	uint32_t uid;	/**< UID to run the command as */
	char *title;	/**< File name / archive title associated 
				to the command */
	uint32_t tlen;	/**< Length of @a title */
	char *dest;	/**< NULL-terminated string: recipient list. 
				Only used on EXTCMD_ENCRYPT commands */
	char *pass;	/**< Where to store a retrieved password.
				Only used on EXTCMD_DECRYPT / EXTCMD_ENCRYPT
				commands */
	uint32_t plen;	/**< Retrieved password (@a pass) length */
} extcmd_arg_t;

/**
 * Abstract UNIX socket used for communication between the slave 
 * daemon (jailed, ext. command caller) and master daemon (not jailed,
 * ext. command runner). Created at daemon startup, before
 * forking the slave.
 */
extern int g_extcmd_sock;

/**
 * External command socket connection handler.
 * Called on the master daemon after forking the slave. Waits for new
 * requests from the slave on the ext. cmd. socket. For each such request,
 * the command arguments are retrieved on the socket, then the requested
 * command is run and its output and return code are transfered back to the 
 * slave. Only one request is accepted at a time.
 * @return -1 on error (not that one request failing doesn't cause an 
 * error to be returned), doesn't return otherwise.
 */
extern int extcmd_handler(void);

/**
 * Ask the master daemon to run an external command.
 * @param arg External command to run.
 * @return CMD_OK on success, error code on failure.
 */
extern uint32_t run_ext_cmd(extcmd_arg_t *arg);

/*@}*/

#endif /* CRYPTD_PROTOS_H */
