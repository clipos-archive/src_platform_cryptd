// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file log.h
 * Cryptd logging header.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * Copyright (C) 2010 ANSSI
 * @n
 * All rights reserved.
 */

/**
 * @mainpage cryptd documentation
 * This is the inline documentation for the cryptd package.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 */

#ifndef CRYPTD_LOG_H
#define CRYPTD_LOG_H

#include <stdio.h>
#include <syslog.h>

/** @name Runtime options */
/*@{*/

/**
 * Verbosity level. 
 * 0 means only error messages / warnings are displayed.
 * >0 means debug messages are displayed. Theoretically, 
 * the verbosity increases with the value, but no debug
 * messages with a level > 1 are generated at the moment.
 */
extern int g_verbose;

/**
 * Foreground / background option.
 * 0 means the daemon is running in the foreground and logging
 * to STDOUT / STDERR, !0 means it's running in the background
 * and logging to syslog.
 */
extern int g_daemonized;

/**
 * Prefix to append to log messages.
 * Should be 'master' for the master process, 'slave' for the
 * slave processes.
 */
extern const char *g_prefix;

/*@}*/


/** @name Logging macros */
/*@{*/

/**
 * Base logging macro.
 * Log message if current verbosity level is > @a lev, in @a slev syslog
 * facility (when not logging to STDOUT / STDERR), using @fmt and @args as
 * printf-like variadic message.
 */
#define _LOG(lev, slev, fmt, args...) do {\
	if (g_verbose >= lev) { \
		if (!g_daemonized) { \
		if (g_prefix) \
			printf("[%s]%s(%s:%d): "fmt"\n", g_prefix,\
						__FUNCTION__,  \
						__FILE__, __LINE__, ##args); \
		else \
			printf("%s(%s:%d): "fmt"\n", __FUNCTION__, \
						__FILE__, __LINE__, ##args); \
		} else { \
			if (g_prefix) \
			syslog(LOG_DAEMON|slev, \
					"[%s]%s(%s:%d): "fmt"\n", g_prefix, \
						__FUNCTION__, \
						__FILE__, __LINE__, ##args); \
			else \
			syslog(LOG_DAEMON|slev, \
					"%s(%s:%d): "fmt"\n", __FUNCTION__, \
						__FILE__, __LINE__, ##args); \
		} \
	} \
} while (0)

/**
 * Log to LOG_NOTICE.
 */
#define LOG(fmt, args...) _LOG(0, LOG_NOTICE, fmt, ##args);
/**
 * Log to LOG_NOTICE if @a g_verbose > 0.
 */
#define LOG2(fmt, args...) _LOG(1, LOG_NOTICE, fmt, ##args);
/** 
 * Log to LOG_DEBUG.
 */
#define DEBUG(fmt, args...) _LOG(0, LOG_DEBUG, fmt, ##args);
		
/**
 * Log to LOG_ERR / STDERR, whatever the value of @a g_verbose.
 */
#define ERROR(fmt, args...) do {\
	if (!g_daemonized) { \
		if (g_prefix) \
			fprintf(stderr, "[%s]%s(%s:%d): "fmt"\n", g_prefix, \
						__FUNCTION__, \
						__FILE__, __LINE__, ##args); \
		else \
			fprintf(stderr, "%s(%s:%d): "fmt"\n", __FUNCTION__, \
						__FILE__, __LINE__, ##args); \
	} else { \
		if (g_prefix) \
			syslog(LOG_DAEMON|LOG_ERR, "[%s]%s(%s:%d): "fmt"\n", \
						g_prefix, __FUNCTION__, \
						__FILE__, __LINE__, ##args); \
		else \
			syslog(LOG_DAEMON|LOG_ERR, "%s(%s:%d): "fmt"\n", \
						__FUNCTION__, \
						__FILE__, __LINE__, ##args); \
	} \
} while (0)

/**
 * Log to LOG_ERR / STDERR, with the strerror() for the last errno automatically
 * appended to the log message.
 */
#define ERROR_ERRNO(fmt, args...) \
	ERROR(fmt": %s", ##args, strerror(errno))

			
			/* dump.c */

/**
 * Dump a binary buffer in hexified form.
 * The buffer is dumped either to STDOUT / STDERR 
 * or syslog, depending on @a g_daemonized.
 * @param msg Message to prepend to the dumped buffer. Must be null-terminated.
 * @param level Level of verbosity. Dump will only be performed if @a level 
 * is <= @a g_verbose.
 * @param data Pointer to the buffer to be dumped.
 * @param len Length of buffer to dump.
 */
extern void dump(const char *msg, int level, const char *data, uint32_t len);


			/* cmd.c */

/**
 * Return an error string for a given command error code.
 * @param cmd Command error code.
 * @return Null-terminated constant error string matching @a cmd,
 * or "<unknown>" if the input code is not supported.
 */
extern const char *cmderr(uint32_t cmd);

/**
 * Return a command error code matching a given errno error code.
 * @param err Errno error to convert.
 * @return Command (cmd_t) error code matching @a err. The @a CMD_INVAL code is
 * returned if no better fit can be found.
 */
extern uint32_t errno2cmd(int err);

/** 
 * Log an error message to LOG_ERR / STDERR, with the error string matching
 * the command error code @a cmd automatically appended to the message.
 */
#define CMD_ERROR(cmd, fmt, args...) \
	ERROR(fmt" : %s", ##args, cmderr(cmd))

struct cleartext;
struct file;
extern void dump_cleartext_encrypt(const struct cleartext *);
extern void dump_cleartext_decrypt(const struct cleartext *);
extern void dump_cleartext_import(const struct file *);

/*@}*/

#endif /* CRYPTD_LOG_H */

