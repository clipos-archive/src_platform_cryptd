// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file cleartext_common.h
 * Cryptd common cleartext dialogs.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * @n
 * All rights reserved.
 */

#ifndef CLEARTEXT_COMMON_H
#define CLEARTEXT_COMMON_H

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

struct cleartext;

/**
 * Send a cleartext file (file_t) over a client-server socket
 * (without initial handshake).
 * Used both in server and client.
 * @param s Socket to send over.
 * @param file File to send.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t send_cleartext_file(int s, const file_t *file) __H;
		

/**
 * Receive a cleartext file over a client-server socket
 * (without initial handshake).
 * A newly allocated file is returned after reception.
 * Used both in server and client.
 * @param s Socket to receive over.
 * @param file Where to store received file.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t recv_cleartext_file(int s, file_t **file) __H;

/**
 * Send all the cleartext files (file_t) of a cleartext_t struct
 * over a client-server socket (without initial handshake).
 * Note that the dummy list head is not transmitted.
 * Used both in server and client.
 * @param s Socket to send over.
 * @param clr Cleartext struct to transfer files for.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t send_cleartext_files(int s, 
				const struct cleartext *clr) __H;

/**
 * Receive a list of cleartext files over a client-server socket
 * (without initial handshake) and add them to the list of files
 * of a cleartext_t struct.
 * The end of file transmission is detected when an unexpected 
 * command is received on the socket. That command is then returned
 * to the caller in @a c.
 * Used both in server and client.
 * @param s Socket to receive over.
 * @param clr Cleartext struct to add the received files into.
 * @param c Where to store the first unexpected command received
 * on the socket, marking the end of the file transfer.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t recv_cleartext_files(int s, 
			struct cleartext *clr, struct cmd *c) __H;

#endif
