// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file client_red.c
 * Cryptd red client main.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * Copyright (C) 2010 ANSSI
 * @n
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <utime.h>
#include <errno.h>

#include "list.h"
#include "cryptd_red.h"
#include "log.h"
#include "cmd.h"

static const char *g_sockpath = NULL;
static const char *g_outpath = NULL;
static char *g_name = NULL;
static file_t *g_file = NULL;
static int g_recv, g_list;

int g_verbose = 0;
int g_daemonized = 0; /* Not used */

#define set_if_not_set(var, msg) do {					\
	if (var) {							\
		ERROR(msg"already set to %s, can't set "		\
				"it to %s", var, optarg);		\
		return -1;						\
	}								\
	var = optarg;							\
} while (0)

static inline int
check_options(void)
{
	int sum = g_recv + g_list;
	if (sum > 1) {
		ERROR("Only one action may be specified at the same time");
		return -1;
	}
	if (!sum) {
		ERROR("At least one action must be specified");
		return -1;
	}
	if (!g_sockpath) {
		ERROR("missing socket path");
		return -1;
	}
	if (g_recv) {
		if (!g_outpath) {
			ERROR("Missing output file path");
			return -1;
		}
		if (!g_name) {
			ERROR("Missing file name");
			return -1;
		}
	}

	return 0;
}

static void
print_help(const char *exe)
{
	printf("%s [-v+] -S <sock> -l\n", exe);
	printf("%s [-v+] -S <sock> -t <name> -o <output> -r\n", exe);
}

static int
get_options(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "hlo:rS:t:v")) != -1) {
		switch (c) {
			case 'S':
				set_if_not_set(g_sockpath, "socket path");
				break;
			case 'l':
				g_list = 1;
				break;
			case 'o':
				set_if_not_set(g_outpath, "output path");
				break;
			case 'r':
				g_recv = 1;
				break;
			case 'h':
				print_help((argc) ? basename(argv[0])
						: "crypt_client_up");
				exit(0);
				break;
			case 'v':
				g_verbose++;
				break;
			case 't':
				set_if_not_set(g_name, "file name");
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

	g_prefix = "crypt_client_up";

	if (get_options(argc, argv))
		goto out;

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

	if (g_recv) {
		if (cryptd_recv_diode(s, g_name, strlen(g_name), &g_file)) {
			ERROR("Failed to read file");
			goto out;
		}

		printf("Imported file %s\n", g_name); 

		if (cryptd_write_cleartext_file(g_outpath, g_file, 0)) {
			ERROR("Failed to output file");
		} else {
			ret = EXIT_SUCCESS;
		}
	} else if (g_list) {
		char *buf = NULL;
		uint32_t len;
		if (cryptd_get_diode_list(s, &buf, &len)) {
			ERROR("Failed to retrieve diode list");
		} else {
			if (buf) {
				printf("Diode list:\n%.*s\n", len, buf);
				free(buf);
			} else {
				puts("Empty diode list");
			}
			ret = EXIT_SUCCESS;
		}
	}
			

	/* Fall through */
out:
	if (s != -1)
		close(s);
	if (g_file)
		file_free(g_file);
	return ret;
}
