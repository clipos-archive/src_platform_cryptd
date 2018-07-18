// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file client_common.c
 * Cryptd red/black clients common functions.
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
#include "cryptd_red.h"
#include "cryptd_black.h"

/*
 * Documented in cryptd_black.h.
 */
uint32_t
cryptd_get_list(int s, char **buf, uint32_t *len)
{
	uint32_t ret;

	ret = send_cmd(s, CMD_GETLIST, 0);
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

uint32_t
cryptd_get_info(int s, uint32_t *version, uint32_t *features)
{
	uint32_t ret, len;
	cryptd_info_t *info;

	memset(&info, 0, sizeof(info));

	ret = send_cmd(s, CMD_INFO, 0);
	if (ret != CMD_OK)
		return ret;

	ret = recv_field(s, CMD_INFO, (char **)&info, &len, NULL);
	if (ret != CMD_OK)
		return ret;

	if (len != sizeof(*info)) {
		ERROR("invalid info length: %u", len);
		free(info);
		return CMD_FAULT;
	}

	if (version)
		*version = info->version;
	if (features)
		*features = info->features;

	free(info);
	return CMD_OK;
}

uint32_t
cryptd_check_version(uint32_t version)
{
	uint32_t cverm, sverm; /* major versions */

	cverm = VERNUM >> 16;
	sverm = version >> 16;

	if (sverm != cverm) {
		ERROR("client and server have different major versions, "
					"0x%x != 0x%x", cverm, sverm);
		return CMD_VERCMP;
	}

	return CMD_OK;
}
