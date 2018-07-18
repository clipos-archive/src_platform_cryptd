// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file cleartext_client.c
 * Cryptd red client functions.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * Copyright (C) 2010 ANSSI
 * @n
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <clip/clip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>

#include "list.h"
#include "log.h"
#include "cmd.h"
#include "cryptd_red.h"
#include "cryptd_black.h"
#include "cleartext_common.h"
#include "ciphertext_common.h"

const char *g_prefix = "crypt_client_red";

static uint32_t
put_privkey(int s, const privkey_t *prv)
{
	uint32_t ret;

	ret = send_field(s, CMD_PRIVKEY, prv->data, prv->len);
	if (ret != CMD_OK)
		CMD_ERROR(ret, "Failed to put private key");
	
	return ret;
}

static uint32_t
put_pubkeys(int s, const pubkey_t *head)
{
	const pubkey_t *iter;
	uint32_t ret;

	list_for_each(iter, head) {
		ret = send_field(s, CMD_PUBKEY, iter->data, iter->len);
		if (ret != CMD_OK) {
			CMD_ERROR(ret, "Failed to put public key");
			return ret;
		}
	}

	return CMD_OK;
}


/**
 * Common cleartext sending for cryptd_send_cleartext 
 * and cryptd_encrypt_cleartext.
 */
static uint32_t
do_send_cleartext(int s, const cleartext_t *clr, 
				uint32_t *err, uint32_t initcmd)
{
	uint32_t ret;
	cmd_t cmd = {
		.cmd = 0,
		.data = 0,
	};

	/* Initial handshake */
	ret = send_cmd(s, initcmd, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put handshake syn");
		return ret;
	}
	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get handshake ack");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Failed to get handshake ack");
		return ret;
	}

	ret = send_field(s, CMD_MSGTITLE, clr->title, clr->tlen);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put message title");
		return ret;
	}
	ret = put_pubkeys(s, clr->pubs);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put public keys");
		return ret;
	}

	ret = send_cleartext_files(s, clr);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put cleartext files");
		return ret;
	}

	ret = put_privkey(s, clr->prv);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put private keys");
		return ret;
	}
	
	/* Wait for encryption */
	ret = recv_cmd_notimeout(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Encryption failed");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Encryption failed");
		if (err && cmd.cmd == CMD_CRYPT)
			*err = cmd.data;
		return cmd.cmd;
	}

	return CMD_OK;
	DEBUG("Message encrypted");
	return CMD_OK;
}

/*
 * Documented in cryptd_red.h.
 */
uint32_t
cryptd_send_cleartext(int s, const cleartext_t *clr, uint32_t *err)
{
	return do_send_cleartext(s, clr, err, CMD_SEND);
}

/*
 * Documented in cryptd_red.h.
 */
uint32_t
cryptd_encrypt_cleartext(int s, const cleartext_t *clr, 
			char **cipher, uint32_t *clen, uint32_t *err)
{
	uint32_t ret;

	ret = do_send_cleartext(s, clr, err, CMD_ENCRYPT);
	if (ret != CMD_OK)
		return ret;

	ret = recv_field(s, CMD_MSGDATA, cipher, clen, NULL); 
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get ciphertext");
		return ret;
	}

	return CMD_OK;
}

/**
 * Common cleartext retrieval for recv_cleartext and decrypt_ciphertext.
 */
static uint32_t
do_recv_cleartext(int s, cleartext_t *clr, int pubkey_p, uint32_t *err)
{
	uint32_t ret;
	cmd_t cmd;

	ret = put_privkey(s, clr->prv);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to to put private key");
		return ret;
	}

	/* Wait for decryption */
	ret = recv_cmd_notimeout(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Decryption failed");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Decryption failed");
		if (err && cmd.cmd == CMD_CRYPT)
			*err = cmd.data;
		return cmd.cmd;
	}

	cmd.cmd = CMD_ORDER;
	ret = recv_cleartext_files(s, clr, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get cleartext files");
		return ret;
	}
	if (cmd.cmd != CMD_NAME) {
		CMD_ERROR(cmd.cmd, "Failed to get cleartext files");
		return cmd.cmd;
	}

	ret = recv_field(s, 0, &(clr->name), &(clr->nlen), &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to retrieve signer's name");
		return ret;
	}

	if (pubkey_p) {
		ret = recv_field(s, CMD_PPR, &(clr->ppr), &(clr->plen), NULL);
		if (ret != CMD_OK) {
			CMD_ERROR(ret, 
				"Failed to retrieve sender's public key");
			return ret;
		}
	}

	return CMD_OK;
}

/*
 * Documented in cryptd_red.h.
 */
uint32_t
cryptd_recv_cleartext(int s, cleartext_t *clr, int pubkey_p, uint32_t *err)
{
	uint32_t ret;
	cmd_t cmd;

	if (pubkey_p)
		ret = send_cmd(s, CMD_RECVPUB, 0);
	else
		ret = send_cmd(s, CMD_RECV, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put handshake syn");
		return ret;
	}

	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get handshake ack");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Failed to get handshake ack");
		return ret;
	}

	ret = send_field(s, CMD_MSGTITLE, clr->title, clr->tlen);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put message title");
		return ret;
	}

	return do_recv_cleartext(s, clr, pubkey_p, err);
}

/*
 * Documented in cryptd_red.h.
 */
uint32_t 
cryptd_decrypt_ciphertext(int s, cleartext_t *clr, 
			char *cipher, uint32_t clen, 
			int pubkey_p, uint32_t *err)
{
	uint32_t ret;
	cmd_t cmd;
	ciphertext_t cpr;

	memset(&cpr, 0, sizeof(cpr));

	cpr.title = clr->title;
	cpr.tlen = clr->tlen;
	cpr.content = cipher;
	cpr.clen = clen;

	if (pubkey_p)
		ret = send_cmd(s, CMD_DECRYPTPUB, 0);
	else
		ret = send_cmd(s, CMD_DECRYPT, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put handshake syn");
		return ret;
	}

	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get handshake ack");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Failed to get handshake ack");
		return ret;
	}

	ret = send_ciphertext(s, &cpr);
	if (ret != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Failed to send ciphertext");
		return ret;
	}

	return do_recv_cleartext(s, clr, pubkey_p, err);
}

#ifdef WITH_DIODE

/*
 * Documented in cryptd_red.h.
 */
uint32_t
cryptd_recv_diode(int s, char *name, uint32_t nlen, file_t **file)
{
	uint32_t ret;
	cmd_t cmd;

	ret = send_cmd(s, CMD_RECVCLR, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put handshake syn");
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

	ret = send_field(s, CMD_PATH, name, nlen);
	if (ret != CMD_OK) {
		ERROR("Failed to put message title");
		return ret;
	}

	/* Wait for external confirmation */
	ret = recv_cmd_notimeout(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Import refused by server");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Import refused by server");
		return cmd.cmd;
	}

	ret = recv_cleartext_file(s, file);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to read diode file %.*s", nlen, name);
		return ret;
	}
	return CMD_OK;
}

/*
 * Documented in cryptd_red.h.
 */
uint32_t
cryptd_get_diode_list(int s, char **buf, uint32_t *len)
{
	uint32_t ret;

	ret = send_cmd(s, CMD_GETCLRLIST, 0);
	if (ret != CMD_OK)
		return ret;

	ret = recv_field(s, CMD_LIST, buf, len, NULL);
	if (ret == CMD_OK) 
		return ret;
	if (ret == CMD_EMPTY) {
		*len = 0;
		*buf = NULL;
		return CMD_OK;
	}
	return ret;
}

#endif

/*
 * Documented in cryptd_red.h.
 */
uint32_t
cryptd_change_password(int s, privkey_t *prv, uint32_t *err)
{
	uint32_t ret;
	cmd_t cmd = {
		.cmd = CMD_OK,
		.data = 0,
	};

	char *data;
	uint32_t len;

	/* Initial handshake */
	ret = send_cmd(s, CMD_CHPW, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put handshake syn");
		return ret;
	}
	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get handshake ack");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Failed to get handshake ack");
		return ret;
	}

	ret = send_field(s, CMD_PRIVKEY, prv->data, prv->len);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to send private key");
		return ret;
	}
	
	/* Wait for password change */
	ret = recv_field_notimeout(s, CMD_PRIVKEY, &data, &len, &cmd);
	if (ret != CMD_OK || cmd.cmd != CMD_OK) {
		ret = (cmd.cmd != CMD_OK) ? cmd.cmd : ret;
		CMD_ERROR(ret, "Password change failed");
		if (err && cmd.cmd == CMD_CRYPT)
			*err = cmd.data;
		return ret;
	}

	memset(prv->data, 0, prv->len);
	free(prv->data);
	prv->data = data;
	prv->len = len;

	DEBUG("Password changed");
	return CMD_OK;
}

/*
 * Documented in cryptd_red.h.
 */
uint32_t
cryptd_delete_ciphertext(int s, char *name, uint32_t nlen)
{
	uint32_t ret;
	cmd_t cmd = {
		.cmd = 0,
		.data = 0,
	};

	/* Initial handshake */
	ret = send_cmd(s, CMD_DELETE, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put handshake syn");
		return ret;
	}
	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get handshake ack");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Failed to get handshake ack");
		return ret;
	}

	ret = send_field(s, CMD_MSGTITLE, name, nlen);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put message title");
		return ret;
	}

	/* Wait for deletion */
	ret = recv_cmd_notimeout(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Deletion failed");
		return ret;
	}
	if (cmd.cmd != CMD_OK) {
		CMD_ERROR(cmd.cmd, "Deletion failed");
		return cmd.cmd;
	}

	return CMD_OK;
	DEBUG("Message deleted");
	return CMD_OK;
}

