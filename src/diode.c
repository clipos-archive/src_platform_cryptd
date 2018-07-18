// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file diode.c
 * Cryptd diode functions.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2009 SGDN/DCSSI
 * Copyright (C) 2010-2012 SGDSN/ANSSI
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
#include "cryptd_red.h"
#include "cleanup.h"
#include "cleartext_common.h"

#include <clip/acidcrypt.h>

/**
 * Diode input file list head.
 * Initialized as a dummy head by diode_init().
 * Freed by diode_exit().
 */
static file_t *g_diode_head = NULL;

/*
 * Documented in server.h.
 */
int 
diode_init(void)
{
	g_diode_head = file_alloc();
	if (!g_diode_head) {
		ERROR("Out of memory allocating diode head");
		return -1;
	}
	return 0;
}

/**
 * Cleanup function : free all files in the input list on exit,
 * logging those non-dummy files that are being lost.
 */
CLEANUP_FN(diode_exit)
{
	file_t *iter;
	if (g_diode_head) {
		list_for_each(iter, g_diode_head) {
			LOG("Diode file %.*s "
					"(%u bytes, uid %u) lost on exit",
					iter->plen, iter->path,
					iter->clen, iter->uid);
		}
		list_free_all(g_diode_head, file_t, file_free);
	}
}

/**
 * Lookup a file by name and uid in the input list.
 * @param name Name of the file.
 * @param nlen Length of @a name.
 * @param uid UID to lookup.
 * @return Pointer to the first matching file if found, 
 * NULL otherwise.
 */
static inline file_t *
diode_lookup(const char *name, uint32_t nlen, uint32_t uid)
{
	file_t *iter;

	list_for_each(iter, g_diode_head) {
		if (iter->uid == uid && iter->plen == nlen 
					&& !memcmp(iter->path, name, nlen))
			return iter;
	}

	return NULL;
}

/**
 * Test for the presence of a file matching a given name and
 * uid in the input list.
 * @param name Name of the file.
 * @param nlen Length of @a name.
 * @param uid UID to lookup.
 * @return 1 if a matching file is found, 0 otherwise.
 */
static inline int
diode_exists(const char *name, uint32_t nlen, uint32_t uid)
{
	file_t *file = diode_lookup(name, nlen, uid);

	return (file) ? 1 : 0;
}

/**
 * Add a file to the input list.
 * This takes care of avoiding duplicates, by returning an
 * error if a file with the same name and uid already exists
 * in the list.
 * @param file File to add to the list.
 * @return CMD_OK on success, CMD_EXIST if a matching file 
 * already exists (new file not added).
 */
static uint32_t
diode_add(file_t *file)
{
	if (diode_exists(file->path, file->plen, file->uid)) {
		ERROR("Cannot add file %.*s to diode for uid %u, "
			"duplicate entry", file->plen, file->path, file->uid);
		return CMD_EXIST;
	}

	list_add(file, g_diode_head);
	return CMD_OK;
}

/*
 * Documented in server.h.
 */
uint32_t
recv_diode(int s, uint32_t uid)
{
	uint32_t ret;
	file_t *file = NULL;

	/* Ack sender */
	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK) 
		goto err;

	ret = recv_cleartext_file(s, &file);
	if (ret != CMD_OK)
		goto err;

	file->uid = uid;
	ret = diode_add(file);
	if (ret != CMD_OK)
		goto err;

	DEBUG("file added to diode wait queue: %.*s: %u bytes (uid %u)", 
				file->plen, file->path, file->clen, uid);
	/* Send OK to client */
	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to send OK to client");
		return ret; /* Do NOT free file ! */
	}
	return CMD_OK;

out:
	if (file)
		file_free(file);
	return ret;
err:
	/* Send back error to the client */
	(void)send_cmd(s, ret, 0);
	goto out;
}

/**
 * Run an external command to confirm the transfert of a file.
 * This is called when reading the file from the 'up' socket.
 * @param name Name of the file to be transfered.
 * @param nlen Length of @a name.
 * @param uid UID of the file to be transfered. Also used as the uid
 * under which the external command is run.
 * @return CMD_OK if transfer is confirmed, error code 
 * otherwise (transfer denied or error).
 */
static inline uint32_t
confirm(char *name, uint32_t len, uint32_t uid)
{
	extcmd_arg_t arg = {
		.dir = EXTCMD_CONFIRM,
		.uid = uid,
		.title = name,
		.tlen = len,
		.dest = NULL,
	};

	return run_ext_cmd(&arg); 
}

/*
 * Documented in server.h
 */
uint32_t
send_diode(int s, uint32_t uid)
{
	uint32_t ret, nlen;
	char *name = NULL, *tmp;
	file_t *file;

	/* Ack sender */
	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to ack client");
		goto err;
	}
	ret = recv_field(s, CMD_PATH, &name, &nlen, NULL);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to read file name");
		goto err;
	}

	if (name[nlen - 1] != '\0') {
		tmp = realloc(name, nlen + 1);
		if (!tmp) {
			ERROR("Out of memory copying name %.*s", nlen, name);
			ret = CMD_NOMEM;
			goto err;
		}
		name = tmp;
		name[nlen] = '\0';
		++nlen;
	}

	DEBUG("looking for file %.*s in diode (uid %u)", nlen, name, uid);
	file = diode_lookup(name, nlen, uid);

	if (!file) {
		(void)send_cmd(s, CMD_NOENT, 0);
		ERROR("Could not find file %.*s in diode (uid %u)", 
							nlen, name, uid);
		ret = CMD_NOENT;
		goto err;
	}


	ret = confirm(name, nlen, uid);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Diode transfer of file %.*s denied by "
				"external command (uid %u)", nlen, name, uid);
		goto err;
	}

	/* Note: we dump here, to make sure we log even partial
	 * imports.
	 */
	dump_cleartext_import(file);

	/* Send OK to client */
	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to send OK to client");
		goto err;
	}

	ret = send_cleartext_file(s, file);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put diode file %.*s (uid %u)",
							nlen, name, uid);
		goto err;
	}
	DEBUG("exported file %.*s (uid %u)", nlen, name, uid);

	list_del(file);
	file_free(file);
	/* Fall through */
out:
	if (name) {
		memset(name, 0, nlen);
		free(name);
	}
	return ret;
err:
	/* Send error back to client */
	(void)send_cmd(s, ret, 0);
	goto out;
}

/**
 * Generate a string listing all files in the input list matching a given uid.
 * This string is in turn returned to the up client to answer a CMD_GETCLRLIST
 * command. The new string is allocated by this function, null-terminated, and 
 * contains the names of matching files in the input list, separated by '\n' 
 * newlines.
 */
static uint32_t 
diode_list(uint32_t uid, char **out, uint32_t *len)
{
	file_t *iter;
	uint32_t size = 0, csize;
	char *buf, *ptr;

	list_for_each(iter, g_diode_head) {
		if (iter->uid == uid)
			size += iter->plen;
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
		ERROR("Out of memory allocating list of diode files");
		return CMD_NOMEM;
	}

	ptr = buf;
	list_for_each(iter, g_diode_head) {
		if (iter->uid == uid) {
			if (iter->plen <= 1) {
				ERROR("Insufficient file name length\n");
				free(buf);
				return CMD_FAULT;
			}
			if (csize < iter->plen) {
				ERROR("Oops. Got my sizes messed up somehow...");
				free(buf);
				return CMD_FAULT;
			}
			memcpy(ptr, iter->path, iter->plen - 1);
			ptr += iter->plen - 1;
			*ptr++ = '\n';
			csize -= iter->plen;
		}
	}
	*ptr = '\0';

	*out = buf;
	*len = size + 1;
	return CMD_OK;
}

/*
 * Documented in server.h.
 */
uint32_t
send_diode_list(int s, uint32_t uid)
{
	char *list = NULL;
	uint32_t llen, ret;

	ret = diode_list(uid, &list, &llen); 
	if (ret != CMD_OK) {
		ERROR("Failed to get list of diode files");
		return ret;
	}

	if (!list) {
		ret = send_cmd(s, CMD_LIST, 0);
	} else {
		ret = send_field(s, CMD_LIST, list, llen);
	}
	if (ret != CMD_OK)
		CMD_ERROR(ret, "Failed to send list of diode files");
	
	if (list)
		free(list);
	return ret;
}
