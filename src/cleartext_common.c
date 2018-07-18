// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file cleartext_common.c
 * Cryptd server / client common cleartext functions.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2009 SGDN
 * @n
 * All rights reserved.
 */

#include <clip/clip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "list.h"
#include "server.h"
#include "cmd.h"
#include "cryptd_red.h"
#include "cleartext_common.h"

/*
 * Documented in cryptd_red.h.
 */
inline uint32_t
send_cleartext_file(int s, const file_t *file)
{
	uint32_t ret;

	ret = send_field(s, CMD_PATH, file->path, file->plen);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put file path");
		return ret;
	}
	ret = send_field(s, CMD_META, 
			(char *)file->meta, sizeof(*(file->meta)));
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put file metadata");
		return ret;
	}
	ret = send_field(s, CMD_FILE, file->content, file->clen);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put file content");
		return ret;
	}

	return CMD_OK;
}

static uint32_t
recv_one_file(int s, file_t **out, cmd_t *save, int first)
{
	uint32_t ret, len;
	char *path = NULL;
	uint32_t plen;

	file_t *file = file_alloc();
	if (!file) {
		ERROR("Out of memory");
		return CMD_NOMEM;
	}

	if (first)
		ret = recv_field(s, 0, &path, &plen, save);
	else
		ret = recv_field(s, CMD_PATH, &path, &plen, save);
	if (ret != CMD_OK) {
		if (ret != CMD_ORDER)
			CMD_ERROR(ret, "Failed to get file path");
		goto err;
	}

	/* Make sure the path is NULL-terminated */
	if (path[plen - 1] != '\0') {
		file->path = malloc(plen + 1);
		if (!file->path) {
			ERROR("Out of memory copying path %.*s", plen, path);
			goto err;
		}
		memcpy(file->path, path, plen);
		memset(path, 0, plen);
		free(path);
		path = NULL;
		file->path[plen] = '\0';
		file->plen = plen + 1;
	} else {
		file->path = path;
		file->plen = plen;
		/* Avoid double free on error */
		path = NULL;
	}
		
	ret = recv_field(s, CMD_META, 
			(char **)&(file->meta), &len, NULL);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get file metadata");
		goto err;
	}
	if (len != sizeof(*(file->meta))) {
		ERROR("Got wrong length for file metadata: %u != %u",
				len, sizeof(*(file->meta)));
		goto err;
	}
	ret = recv_field(s, CMD_FILE, &(file->content), &(file->clen), NULL);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get file content");
		goto err;
	}

	*out = file;

	return CMD_OK;
err:
	if (path) {
		memset(path, 0, plen);
		path = NULL;
	}
	file_free(file);
	return ret;
}

/*
 * Documented in cryptd_red.h.
 */
uint32_t 
recv_cleartext_file(int s, file_t **file)
{
	return recv_one_file(s, file, NULL, 0);
}

/*
 * Documented in cryptd_red.h.
 */
uint32_t 
send_cleartext_files(int s, const cleartext_t *clr)
{
	const file_t *iter;
	uint32_t ret;

	list_for_each(iter, clr->files) {
		ret = send_cleartext_file(s, iter);
		if (ret != CMD_OK)
			return ret;
	}

	return CMD_OK;
}
		
/*
 * Documented in cryptd_red.h
 */
uint32_t
recv_cleartext_files(int s, cleartext_t *clr, cmd_t *save)
{
	uint32_t ret;
	int first = (save->cmd == CMD_PATH) ? 1 : 0;
	file_t *file;

	do {
		file = NULL;
		ret = recv_one_file(s, &file, save, first);
		if (file)
			list_add(file, clr->files);
		first = 0;
	} while (ret == CMD_OK);

	if (ret != CMD_ORDER)
		return ret;

	return CMD_OK;
}
