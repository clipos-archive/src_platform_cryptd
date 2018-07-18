// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file server_common.c
 * Cryptd server comon code.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2010 ANSSI
 * @n
 * All rights reserved.
 */

#include <sys/types.h>
#include <errno.h>

#include "server.h"
#include "cmd.h"

uint32_t
send_server_info(int s)
{
	uint32_t ret;
	cryptd_info_t info = {
		.version = VERNUM,
		.features = g_features,
	};

	ret = send_field(s, CMD_INFO, (void *)&info, sizeof(info));
	if (ret != CMD_OK)
		CMD_ERROR(ret, "Failed to send daemon info");

	return ret;
}

