// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file client_black.c
 * Cryptd black client main.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * Copyright (C) 2010 ANSSI
 * @n
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <ctype.h>

#include "list.h"
#include "cryptd_black.h"
#include "log.h"
#include "cmd.h"

static const char *g_sockpath = NULL;
static const char *g_name = NULL;
static file_t *g_file = NULL;

int g_verbose = 0;
int g_daemonized = 0; /* Not used */

static inline int
check_options(void)
{
	if (!g_sockpath) {
		ERROR("missing socket path");
		return -1;
	}

	if (!g_name) {
		ERROR("missing input file");
		return -1;
	}
	return 0;
}

static void
print_help(const char *exe)
{
	printf("%s [-v+] -S <sock> -i <file>\n", exe);
}

#define set_if_not_set(var, msg) do {					\
	if (var) {							\
		ERROR(msg"already set to %s, can't set "		\
				"it to %s", var, optarg);		\
		return -1;						\
	}								\
	var = optarg;							\
} while (0)

static int
get_options(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "S:i:hv")) != -1) {
		switch (c) {
			case 'S':
				set_if_not_set(g_sockpath, "socket path");
				break;
			case 'i':
				set_if_not_set(g_name, "input file");
				break;
			case 'h':
				print_help((argc) ? basename(argv[0])
						: "crypt_client_down");
				exit(0);
				break;				
			case 'v':
				g_verbose++;
				break;
			default:
				ERROR("Unsupported option %c", c);
				return -1;
				break;
		}
	}

	if (check_options()) {
		ERROR("Invalid arguments");
		return -1;
	}

	return 0;
}

static int
sock_connect(void)
{
	int s;
	struct sockaddr_un sau;

	sau.sun_family = AF_UNIX;
	snprintf(sau.sun_path, sizeof(sau.sun_path), 
		"%s", g_sockpath);

	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		ERROR_ERRNO("socket (%s)", g_sockpath);
		return s;
	}
	if (connect(s, (struct sockaddr *)&sau, sizeof(struct sockaddr_un)) < 0)	{
		ERROR_ERRNO("connect %s", g_sockpath);
		close(s);
		return -1;
	}

	if (set_nonblock(s)) {
		close(s);
		return -1;
	}
	
	return s;
}

int main(int argc, char *argv[])
{
	int s = -1;
	int ret = EXIT_FAILURE;
	uint32_t version, features;

	g_prefix = "crypt_client_down";

	if (get_options(argc, argv))
		goto out;

	if (cryptd_get_cleartext_file(g_name, 0, &g_file)) {
		ERROR("Failed to read input file");
		goto out;
	}
	s = sock_connect();
	if (s < 0)
		goto out;

	if (cryptd_get_info(s, &version, &features)) {
		ERROR("Failed to get server info");
		goto out;
	}
	printf("Connected, server version 0x%x, features 0x%x\n", 
						version, features);

	close(s);
	s = sock_connect();
	if (s < 0)
		goto out;

	if (cryptd_send_diode(s, g_file)) {
		ERROR("Failed to send file");
		goto out;
	}

	printf("File %s imported successfully\n", g_name);

	ret = EXIT_SUCCESS;
	/* Fall through */
out:
	if (s != -1)
		close(s);
	if (g_file)
		file_free(g_file);
	return ret;
}
