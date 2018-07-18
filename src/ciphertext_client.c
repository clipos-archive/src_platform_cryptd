// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file ciphertext_client.c
 * Cryptd black client functions.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * Copyright (C) 2010 ANSSI
 * @n
 * All rights reserved.
 */

#include <clip/clip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "list.h"
#include "log.h"
#include "cmd.h"
#include "cryptd_black.h"
#include "cleartext_common.h"
#include "ciphertext_common.h"

/**
 * Prefix for message logging.
 */
const char *g_prefix = "crypt_client_black";

/*
 * Documented in cryptd_black.h.
 */
uint32_t
cryptd_recv_ciphertext(int s, struct ciphertext *cipher)
{
	uint32_t ret;
	cmd_t cmd;

	ret = send_cmd(s, CMD_RECV, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Rejected by server");
		return ret;
	}

	/* Handshake */
	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get handshake ack");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Failed to get handshake ack");
		return cmd.cmd;
	}
	DEBUG("Initial handshake OK");

	ret = send_field(s, CMD_MSGTITLE, cipher->title, cipher->tlen);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put ciphertext title");
		return ret;
	}

	ret = recv_field_notimeout(s, CMD_MSGDATA, &(cipher->content), 
						&(cipher->clen), NULL);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get ciphertext");
		return ret;
	}

	DEBUG("Got ciphertext");

	return CMD_OK;
}

/*
 * Documented in cryptd_black.h.
 */
uint32_t
cryptd_send_ciphertext(int s, const struct ciphertext *cipher)
{
	uint32_t ret;
	cmd_t cmd;

	ret = send_cmd(s, CMD_SEND, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Rejected by server");
		return ret;
	}

	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get handshake ack");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Failed to get handshake ack");
		return cmd.cmd;
	}

	ret = send_ciphertext(s, cipher);
	if (ret != CMD_OK)
		return ret;

	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put ciphertext");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Failed to put ciphertext");
		return cmd.cmd;
	}

	return CMD_OK;
}

/*
 * Documented in cryptd_red.h.
 */
uint32_t
cryptd_send_diode(int s, file_t *file)
{
	uint32_t ret;
	cmd_t cmd;

	ret = send_cmd(s, CMD_SENDCLR, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Rejected by server");
		return ret;
	}

	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get handshake ack");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Failed to get handshake ack");
		return cmd.cmd;
	}

	ret = send_cleartext_file(s, file);
	if (ret != CMD_OK)
		return ret;

	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get server confirmation");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Import rejected by server");
		return cmd.cmd;
	}

	return CMD_OK;
}


