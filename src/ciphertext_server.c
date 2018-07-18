// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file ciphertext_server.c
 * Cryptd black server functions.
 *
 * Copyright (C) 2008-2009 SGDN/DCSSI
 * Copyright (C) 2011 SGDSN/ANSSI
 *
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 * @n
 * All rights reserved.
 */

#include <clip/clip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include "list.h"
#include "server.h"
#include "cmd.h"
#include "cryptd_black.h"
#include "ciphertext_common.h"
#include "cleanup.h"

static ciphertext_t *g_cipher_in = NULL;
static ciphertext_t *g_cipher_out = NULL;

int 
ciphertext_init(void)
{
	g_cipher_in = ciphertext_alloc();
	if (!g_cipher_in) 
		return -1;
	g_cipher_out = ciphertext_alloc();
	if (!g_cipher_out) {
		ciphertext_free(g_cipher_in);
		g_cipher_in = NULL;
		return -1;
	}

	return 0;
}

CLEANUP_FN(ciphertext_exit)
{
	ciphertext_t *iter;
	if (g_cipher_in) {
		list_for_each(iter, g_cipher_in) {
			LOG("Input ciphertext %.*s "
					"(%u bytes, uid %u) lost on exit",
					iter->tlen, iter->title,
					iter->clen, iter->uid);
		}
		list_free_all(g_cipher_in, ciphertext_t, ciphertext_free);
	}
	if (g_cipher_out) {
		list_for_each(iter, g_cipher_out) {
			LOG("Output ciphertext %.*s "
					"(%u bytes, uid %u) lost on exit",
					iter->tlen, iter->title,
					iter->clen, iter->uid);
		}
		list_free_all(g_cipher_out, ciphertext_t, ciphertext_free);
	}
}

inline ciphertext_t *
ciphertext_lookup(const char *title, uint32_t tlen, int dir, uint32_t uid)
{
	ciphertext_t *head, *iter;

	switch (dir) {
		case CIPHERTEXT_IN:
			head = g_cipher_in;
			break;
		case CIPHERTEXT_OUT:
			head = g_cipher_out;
			break;
		default:
			ERROR("Unknow direction %d", dir);
			return NULL;
	}

	list_for_each(iter, head) {
		if (uid && iter->uid != uid)
			continue;
		if (iter->tlen == tlen && !memcmp(iter->title, title, tlen))
			return iter;
	}

	return NULL;
}

inline int
ciphertext_exists(const char *title, uint32_t tlen, int dir, uint32_t uid)
{
	ciphertext_t *cpr = ciphertext_lookup(title, tlen, dir, uid);

	return (cpr) ? 1 : 0;
}

uint32_t
ciphertext_add(ciphertext_t *cipher, int dir)
{
	ciphertext_t *head;

	switch (dir) {
		case CIPHERTEXT_IN:
			head = g_cipher_in;
			break;
		case CIPHERTEXT_OUT:
			head = g_cipher_out;
			break;
		default:
			ERROR("Unknow direction %d", dir);
			return CMD_INVAL;
	}

	if (ciphertext_exists(cipher->title, cipher->tlen, dir, cipher->uid)) {
		ERROR("Cannot add ciphertext %.*s for uid %u: duplicate entry",
				cipher->tlen, cipher->title, cipher->uid);
		return CMD_EXIST;
	}

	list_add(cipher, head);
	return CMD_OK;
}

uint32_t
ciphertext_delete(const char *title, uint32_t tlen, int dir, uint32_t uid)
{
	const char *dstr = (dir == CIPHERTEXT_IN) ? "input" : "output";
	ciphertext_t *cpr = ciphertext_lookup(title, tlen, dir, uid);
	if (cpr) {
		list_del(cpr);
		ciphertext_free(cpr);
		DEBUG("Deleted ciphertext with title %.*s in %s"
			"wait queue", tlen, title, dstr);
		return CMD_OK;
	} else {
		ERROR("Could not find ciphertext with title %.*s in %s"
			"wait queue", tlen, title, dstr);
		return CMD_NOENT;
	}
}

static uint32_t
do_recv_ciphertext(int s, uint32_t uid)
{
	uint32_t ret;
	ciphertext_t *cpr = ciphertext_alloc();
	if (!cpr) {
		(void)send_cmd(s, CMD_NOMEM, 0);
		return CMD_NOMEM;
	}

	/* Ack sender */
	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK) 
		goto out;

	ret = recv_ciphertext(s, cpr);
	if (ret != CMD_OK)
		goto out;

	cpr->uid = uid;
	ret = ciphertext_add(cpr, CIPHERTEXT_IN);
	if (ret != CMD_OK)
		goto out;

	DEBUG("ciphertext added to input wait queue: %.*s: %u bytes (uid %u)", 
				cpr->tlen, cpr->title, cpr->clen, uid);

	if (send_cmd(s, CMD_OK, 0) != CMD_OK)
		ERROR("Failed to ack client");

	return CMD_OK;

out:
	ciphertext_free(cpr);
	(void)send_cmd(s, ret, 0);
	return ret;
}


static uint32_t
do_send_ciphertext(int s, uint32_t uid)
{
	uint32_t ret, tlen;
	char *title = NULL;
	ciphertext_t *cipher;

	/* Ack sender */
	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to ack client");
		return ret;
	}
	ret = recv_field(s, CMD_MSGTITLE, &title, &tlen, NULL);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to read message title");
		return ret;
	}
	DEBUG("looking for ciphertext with title %.*s", tlen, title);
	cipher = ciphertext_lookup(title, tlen, CIPHERTEXT_OUT, uid);

	if (!cipher) {
		(void)send_cmd(s, CMD_NOENT, 0);
		ERROR("Could not find ciphertext with title %.*s for uid %u",
					tlen, title, uid);
		ret = CMD_NOENT;
		goto out;
	}

	ret = send_field(s, CMD_MSGDATA, cipher->content, cipher->clen);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put message data");
		goto out;
	}
	DEBUG("exported ciphertext with title %.*s", tlen, title);

	list_del(cipher);
	ciphertext_free(cipher);
	/* Fall through */
out:
	memset(title, 0, tlen);
	free(title);
	return ret;
}

uint32_t 
ciphertext_list(uint32_t uid, char **out, uint32_t *len, int dir)
{
	ciphertext_t *iter, *head;
	uint32_t size = 0, csize;
	char *buf, *ptr;

	switch (dir) {
		case CIPHERTEXT_IN:
			head = g_cipher_in;
			break;
		case CIPHERTEXT_OUT:
			head = g_cipher_out;
			break;
		default:
			ERROR("Unsupported direction %d", dir);
			return CMD_INVAL;
	}

	list_for_each(iter, head) {
		if (iter->uid == uid)
			size += iter->tlen;
	}

	/* Empty list */
	if (!size) {
		*out = NULL;
		*len = 0;
		return CMD_OK;
	}
		

	csize = size;
	buf = malloc(size + 1);
	if (!buf) {
		ERROR("Out of memory allocating list of ciphertexts");
		return CMD_NOMEM;
	}

	ptr = buf;
	list_for_each(iter, head) {
		if (iter->uid == uid) {
			if (iter->tlen <= 1) {
				ERROR("Insufficient archive name length\n");
				free(buf);
				return CMD_FAULT;
			}
			if (csize < iter->tlen) {
				ERROR("Oops. "
					"Got my sizes messed up somehow...");
				free(buf);
				return CMD_FAULT;
			}
			memcpy(ptr, iter->title, iter->tlen - 1);
			ptr += iter->tlen - 1;
			*ptr++ = '\n';
			csize -= iter->tlen;
		}
	}
	*ptr = '\0';

	*out = buf;
	*len = size + 1;
	return CMD_OK;
}

static uint32_t
send_output_list(int s, uint32_t uid)
{
	char *list = NULL;
	uint32_t llen, ret;

	ret = ciphertext_list(uid, &list, &llen, CIPHERTEXT_OUT); 
	if (ret != CMD_OK) {
		ERROR("Failed to get list of output ciphertexts");
		return ret;
	}

	if (!list) {
		ret = send_cmd(s, CMD_LIST, 0);
	} else {
		ret = send_field(s, CMD_LIST, list, llen);
	}
	if (ret != CMD_OK)
		CMD_ERROR(ret, "Failed to send list of output ciphertexts");
	
	if (list)
		free(list);
	return ret;
}


#define check_feature(cmd, feature) do {\
	DEBUG("got "#cmd); \
	if ((g_features & (feature)) != (feature)) {\
		ERROR(#cmd" command not supported: " \
			"missing "#feature" feature"); \
		(void)send_cmd(s, CMD_NOTSUP, 0); \
		goto out; \
	} \
} while (0);

int
black_conn_handler(int s, struct clip_sock_t *__s __attribute__((unused)))
{
	uint32_t ret, uid, gid;
	cmd_t cmd;
	int retval = -1;

	/* Get client uid first */
	if (clip_getpeereid(s, &uid, &gid)) {
		ERROR("failed to get peer eid");
		goto out;
	}
	LOG("Got connect from uid %d on black sock", uid);
	
	if (set_nonblock(s)) {
		ERROR("failed to set client socket non-blocking");
		goto out;
	}

	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "failed to read initial command");
		goto out;
	}

	switch (cmd.cmd) {
		/* Info */
		case CMD_INFO:
			ret = send_server_info(s);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_INFO treatment %s", (retval) ? "nok" : "ok");
			break;
		/* Crypto diode */
		case CMD_SEND:
			check_feature(CMD_SEND, CryptdCrypt);
			ret = do_recv_ciphertext(s, uid);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_SEND treatment %s", (retval) ? "nok" : "ok");
			break;
		case CMD_RECV:
			check_feature(CMD_RECV, CryptdCrypt);
			ret = do_send_ciphertext(s, uid);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_RECV treatment %s", 
					(retval) ? "nok" : "ok");
			break;
		case CMD_GETLIST:
			check_feature(CMD_GETLIST, CryptdCrypt);
			ret = send_output_list(s, uid);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_GETLIST treatment %s", 
						(retval) ? "nok" : "ok");
			break;			
#ifdef WITH_DIODE
		/* Cleartext diode */
		case CMD_SENDCLR:
			check_feature(CMD_SENDCLR, CryptdDiode);
			ret = recv_diode(s, uid);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_SENDCLR treatment %s", 
					(retval) ? "nok" : "ok");
			break;
#endif
		/* Default */
		default:
			ERROR("Unsupported client command: %d from uid %u",
				cmd.cmd, uid);
			break;
	}

out:
	(void)close(s);
	return retval;	
}
