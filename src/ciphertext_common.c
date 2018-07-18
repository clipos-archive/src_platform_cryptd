// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file ciphertext_common.c
 * Cryptd server / client common ciphertext functions.
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
#include "ciphertext_common.h"

/* 
 * Documented in ciphertext_common.h. 
 */
uint32_t
send_ciphertext(int s, const ciphertext_t *cpr)
{
	uint32_t ret;

	ret = send_field(s, CMD_MSGTITLE, cpr->title, cpr->tlen);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put ciphertext title");
		return ret;
	}

	ret = send_field(s, CMD_MSGDATA, cpr->content, cpr->clen);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put ciphertext content");
		return ret;
	}
	return CMD_OK;
}

/* 
 * Documented in ciphertext_common.h. 
 */
uint32_t
recv_ciphertext(int s, ciphertext_t *cpr)
{
	uint32_t ret;

	char *title;
	uint32_t tlen;

	ret = recv_field(s, CMD_MSGTITLE, &title, &tlen, NULL);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get ciphertext title");
		return ret;
	}

	if (tlen + 1 < tlen) {
		ERROR("Title overflow");
		free(title);
		return CMD_FAULT;
	}

	/* Make sure the title is null-terminated */
	if (title[tlen-1] != '\0') {
		cpr->title = realloc(title, tlen + 1);
		if (!cpr->title) {
			ERROR("Out of memory copying title %.*s",
					tlen, title);
			free(title);
			return CMD_NOMEM;
		}
		cpr->title[tlen] = '\0';
		cpr->tlen = tlen + 1;
	} else {
		cpr->title = title;
		cpr->tlen = tlen;
	}

	ret = recv_field(s, CMD_MSGDATA, &(cpr->content), &(cpr->clen), NULL);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get ciphertext content");
		return ret;
	}

	return CMD_OK;
}
