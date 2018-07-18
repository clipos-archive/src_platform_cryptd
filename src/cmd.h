// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file cmd.h
 * Cryptd red/black client/server dialog header.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN/DCSSI
 * Copyright (C) 2010-2012 SGDSN/ANSSI
 * @n
 * All rights reserved.
 */

#ifndef _CRYPTD_CMD_H
#define _CRYPTD_CMD_H

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

/* Socket commands */

typedef struct cmd {
	uint32_t cmd;
	uint32_t data;
} cmd_t;

/* Error codes */
#define CMD_OK		0x0000	/* Success */
#define CMD_ORDER	0x0001	/* Unexpected command at this point */
#define CMD_FAULT	0x0002	/* Failure executing command */
#define CMD_INVAL	0x0003	/* Invalid command */
#define CMD_NOMEM	0x0004	/* Out of memory */
#define CMD_TIMOUT	0x0005	/* Timed-out waiting for command completion */
#define CMD_NOENT	0x0006	/* No such element */
#define CMD_PERM	0x0007	/* Permission denied */
#define CMD_EXIST	0x0008	/* Object already exists */
#define CMD_EMPTY	0x0009	/* Empty answer */
#define CMD_CRYPT	0x000a	/* Crypto Error */
#define	CMD_NOTSUP	0x000b	/* Feature not supported */
#define CMD_VERCMP	0x000c	/* Incompatible versions */
#define CMD_CANCEL	0x000d	/* Cancelled by user */

/* Server / client commands */
#define CMD_MSGTITLE	0x0100	/* Send data: cleartext / ciphertext title */
#define CMD_MSGDATA	0x0200	/* Send data: cleartext / ciphertext title */
#define CMD_PUBKEY	0x0300	/* Start sending a public key */
#define CMD_PRIVKEY	0x0500	/* Start sending a private key */
#define CMD_FILE	0x0600	/* Start sending cleartext file content */
#define CMD_PATH	0x0700	/* Start sending cleartext file path */
#define CMD_META	0x0800	/* Start sending cleartext file metadata */
#define CMD_NAME	0x0900	/* Signer's name */
#define CMD_LIST	0x0a00	/* Message names list */
#define CMD_PPR		0x0b00	/* Sender's public key bundle */
#define CMD_INFO	0x0c00	/* Get server info */

/* Client commands */
#define CMD_SEND		0x010000	/* Start sending a file to server */
#define CMD_RECV		0x020000	/* Start receiving a file from server */
#define CMD_RECVPUB		0x040000	/* Start receiving a decrypted file and 
						   sender's public key from server */
#define CMD_GETLIST		0x070000	/* Get available messages id list */
#define CMD_SENDCLR		0x080000	/* Start sending a diode file to server */
#define CMD_RECVCLR		0x090000	/* Start receiving a diode file from server */
#define CMD_GETCLRLIST		0x0a0000	/* Get diode files list */
#define CMD_CHPW		0x0b0000	/* Change password on a private key bundle */
#define CMD_ENCRYPT		0x0c0000	/* Send cleartext and retrieve ciphertext */
#define CMD_DECRYPT		0x0d0000	/* Send ciphertext and retrieve cleartext */
#define CMD_DECRYPTPUB		0x0e0000	/* Send ciphertext and retrieve cleartext 
						   and sender's public key. */
#define CMD_DELETE		0x0f0000	/* Delete ciphertext from list */

/* Master / slave commands */
#define CMD_EXTCMD		0x01000000	/* Run an external command */
#define CMD_EXTDIR		0x02000000	/* Send external command direction */
#define CMD_EXTUID		0x03000000	/* Send external command uid */
#define CMD_EXTTITLE		0x04000000	/* Send external command title */
#define CMD_EXTDEST		0x05000000	/* Send external command dest list */
#define CMD_EXTPASS		0x06000000	/* Send external command password */

extern uint32_t recv_cmd(int, cmd_t *) __H;
extern uint32_t recv_cmd_notimeout(int, cmd_t *) __H;
extern uint32_t recv_field(int, uint32_t, char **, uint32_t *, cmd_t *) __H;
extern uint32_t recv_field_notimeout(int, uint32_t, char **, 
						uint32_t *, cmd_t *) __H;

extern uint32_t send_cmd(int, uint32_t, uint32_t) __H;
extern uint32_t send_field(int, uint32_t, char *, uint32_t) __H;
extern uint32_t send_field_notimeout(int, uint32_t, char *, uint32_t) __H;
extern int set_nonblock(int);

#endif /* _CRYPTD_CMD_H */
