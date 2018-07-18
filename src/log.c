// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file log.c
 * Cryptd logging helpers.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * @n
 * All rights reserved.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <syslog.h>

#include "server.h"
#include <clip/acidfile.h>
#include <clip/acidcrypt.h>

static inline void
vlog_syslog(int lvl, const char *fmt, va_list args)
{
	int prio = LOG_DAEMON; 
	switch (lvl) {
		case 0:
			prio |= LOG_ERR;
			break;
		case 1:
			prio |= LOG_INFO;
			break;
		default:
			prio |= LOG_DEBUG;
			break;
	}
	
	vsyslog(prio, fmt, args);
}

static inline void
vlog_std(int lvl, const char *fmt, va_list args)
{
	FILE *out = (lvl) ? stdout : stderr;

	vfprintf(out, fmt, args);
}

void
acidfile_log(int lvl, const char *fmt, ...)
{
	va_list args;
	if (g_verbose < lvl)
		return;
	
	va_start(args, fmt);

	if (g_daemonized)
		vlog_syslog(lvl, fmt, args);
	else 
		vlog_std(lvl, fmt, args);
	va_end(args);
}

void
acidcrypt_log(int lvl, const char *fmt, ...)
{
	va_list args;
	if (g_verbose < lvl)
		return;
	
	va_start(args, fmt);

	if (g_daemonized)
		vlog_syslog(lvl, fmt, args);
	else 
		vlog_std(lvl, fmt, args);
	va_end(args);
}
