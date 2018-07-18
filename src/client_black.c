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

static ciphertext_t *g_ciphertext = NULL;
static const char *g_sockpath = NULL;
static const char *g_outfile = NULL;
static int g_send, g_recv, g_list;

int g_verbose = 0;
int g_daemonized = 0; /* Not used */

static inline int
get_content(const char *arg)
{
	if (g_ciphertext->content) {
		ERROR("Double definition of message content");
		return -1;
	}
	if (cryptd_get_file(arg, &(g_ciphertext->content), &(g_ciphertext->clen))) {
		ERROR("Failed to read archive from %s", arg);
		return -1;
	}
	return 0;
}

static inline int
get_title(const char *arg)
{
	if (g_ciphertext->title) {
		ERROR("Double definition of message title");
		return -1;
	}
	g_ciphertext->title = strdup(arg);
	if (!g_ciphertext->title) {
		ERROR("So soon out of memory ?");
		return -1;
	}
	g_ciphertext->tlen = strlen(arg) + 1;
	return 0;
}

static inline int
check_options(void)
{
	int sum = g_send + g_recv + g_list;
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
	if (g_send) {
		if (!g_ciphertext->content) {
			ERROR("Missing ciphertext content");
			return -1;
		}
		if (!g_ciphertext->title) {
			ERROR("Missing title");
			return -1;
		}
		return 0;
	} 
	if (g_recv) {
		if (!g_outfile) {
			ERROR("Missing output file path");
			return -1;
		}
		if (!g_ciphertext->title) {
			ERROR("Missing title");
			return -1;
		}
		return 0;
	}

	return 0;
}

static void
print_help(const char *exe)
{
	printf("%s [-v+] -S <sock> -l\n", exe);
	printf("%s [-v+] -S <sock> -i <csa archive> -t <title> -s\n", exe);
	printf("%s [-v+] -S <sock> -o <output> -t <title> -r\n", exe);
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

	while ((c = getopt(argc, argv, "S:i:lo:t:srhv")) != -1) {
		switch (c) {
			case 'S':
				set_if_not_set(g_sockpath, "socket path");
				break;
			case 'i':
				if (get_content(optarg))
					return -1;
				break;
			case 'l':
				g_list = 1;
				break;
			case 'o':
				set_if_not_set(g_outfile, "output path");
				break;
			case 's':
				g_send = 1;
				break;
			case 'r':
				g_recv = 1;
				break;
			case 't':
				if (get_title(optarg))
					return -1;
				break;
			case 'h':
				print_help((argc) ? basename(argv[0])
						: "crypt_client_black");
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

	g_ciphertext = ciphertext_alloc();
	if (!g_ciphertext) {
		ERROR("So soon out of memory ?");
		return EXIT_FAILURE;
	}

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
		if (cryptd_recv_ciphertext(s, g_ciphertext)) {
			ERROR("Failed to get ciphertext %.*s", 
				g_ciphertext->tlen, g_ciphertext->title);
			goto out;
		}

		printf("Got ciphertext %.*s\n", 
				g_ciphertext->tlen, g_ciphertext->title);


		if (cryptd_write_file(g_outfile, g_ciphertext->content, 
						g_ciphertext->clen, 0)) {
			ERROR("Failed to output ciphertext %.*s", 
				g_ciphertext->tlen, g_ciphertext->title);

		} else {	
			printf("Ciphertext written to %s\n", g_outfile);
			ret = EXIT_SUCCESS;
		}
	} else if (g_send) {
		if (cryptd_send_ciphertext(s, g_ciphertext)) {
			ERROR("Error sending ciphertext %.*s", 
				g_ciphertext->tlen, g_ciphertext->title);

			goto out;
		}

		printf("Ciphertext %.*s sent successfully\n", 
				g_ciphertext->tlen, g_ciphertext->title);


		ret = EXIT_SUCCESS;
	} else if (g_list) {
		char *buf = NULL;
		uint32_t len;
		if (cryptd_get_list(s, &buf, &len)) {
			ERROR("Failed to retrieve output list");
		} else {
			if (buf) {
				printf("Output list:\n%.*s\n", len, buf);
				free(buf);
			} else {
				puts("Output list is empty.");
			}
			ret = EXIT_SUCCESS;
		}
	}

	/* Fall through */
out:
	if (s != -1)
		close(s);
	ciphertext_free(g_ciphertext);
	return ret;
}
