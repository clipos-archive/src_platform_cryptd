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

static cleartext_t *g_cleartext = NULL;
static const char *g_sockpath = NULL;
static const char *g_outpath = NULL;
static const char *g_cipherpath = NULL;
static int g_send, g_recv, g_list, g_delete, g_pubkey_p, 
				g_chpw, g_encrypt, g_decrypt;

int g_verbose = 0;
int g_daemonized = 0; /* Not used */

static inline int
get_pubkey(const char *name)
{
	pubkey_t *pp = pubkey_alloc();
	if (!pp) {
		ERROR("Out of memory getting %s", name);
		return -1;
	}
	if (cryptd_get_file(name, &(pp->data), &(pp->len))) {
		pubkey_free(pp);
		return -1;
	}
	list_add(pp, g_cleartext->pubs);

	return 0;
}

static inline int
get_privkey(const char *name)
{
	privkey_t *pv;
	if (g_cleartext->prv) {
		ERROR("We already have a private key, will not add %s", name);
		return -1;
	}

	pv = privkey_alloc();
	if (!pv) {
		ERROR("Out of memory getting %s", name);
		return -1;
	}
	if (cryptd_get_file(name, &(pv->data), &(pv->len))) {
		privkey_free(pv);
		return -1;
	}

	g_cleartext->prv = pv;

	return 0;
}

static inline int
get_title(const char *arg)
{
	if (g_cleartext->title) {
		ERROR("Double definition of message title");
		return -1;
	}
	g_cleartext->title = strdup(arg);
	if (!g_cleartext->title) {
		ERROR("So soon out of memory ?");
		return -1;
	}
	g_cleartext->tlen = strlen(arg) + 1;
	return 0;
}

static inline int
add_file(const char *name, int fullpath)
{
	file_t *file = NULL;
	if (cryptd_get_cleartext_file(name, fullpath, &file)) {
		ERROR("Failed to get cleartext file %s", name);
		return -1;
	}

	list_add(file, g_cleartext->files);
	return 0;
}

#define set_if_not_set(var, msg) do {					\
	if (var) {							\
		ERROR(msg"already set to %s, can't set "		\
				"it to %s", var, optarg);		\
		return -1;						\
	}								\
	var = optarg;							\
} while (0)

static inline int
check_options(int pcount, int fcount)
{
	int sum = g_send + g_recv + g_list + g_chpw 
			+ g_decrypt + g_encrypt + g_delete;
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
	if (g_send || g_encrypt) {
		if (!pcount) {
			ERROR("Missing public key");
			return -1;
		}
		if (!g_cleartext->prv) {
			ERROR("Missing private key");
			return -1;
		}
		if (!fcount) {
			ERROR("Missing content");
			return -1;
		}
		if (g_pubkey_p) {
			ERROR("Get pubkey only available when receiving");
			return -1;
		}
		return 0;
	} 
	if (g_send || g_delete || g_recv) {
		if (!g_cleartext->title) {
			ERROR("Missing title");
			return -1;
		}
	}
	if (g_recv || g_decrypt) {
		if (!g_outpath) {
			ERROR("Missing output file path");
			return -1;
		}
		if (!g_cleartext->prv) {
			ERROR("Missing private key");
			return -1;
		}
		return 0;
	}
	if (g_encrypt || g_decrypt) {
		if (!g_cipherpath) {
			ERROR("Missing ciphertext path");
			return -1;
		}
	}
	if (g_chpw) {
		if (!g_outpath) {
			ERROR("Missing output key path");
			return -1;
		}
		if (!g_cleartext->prv) {
			ERROR("Missing private key");
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
	printf("%s [-v+] -S <sock> -t <title> -b\n", exe);
	printf("%s [-v+] -S <sock> -K <priv> -o <output> -p\n", exe);
	printf("%s [-v+] -S <sock> -k <pub> [-k <pub2>...] -K <priv> "
			"-t <title> [-i <file>]+ [-I <path>]+ -s\n", exe);
	printf("%s [-v+] -S <sock> -K <priv> -t <title> -o <output> -r|-R\n", 
			exe);
	printf("%s [-v+] -S <sock> -K <priv> [-k <pub>]+ [-i <file>]+ "
			"-t <title> -c <ciphertext> -e\n", exe);
	printf("%s [-v+] -S <sock> -K <priv> -c <ciphertext> "
			"-o <output> -d\n", exe);
}

static int
get_options(int argc, char *argv[])
{
	int c, pcnt = 0, fcnt = 0;

	while ((c = getopt(argc, argv, "bc:dDehi:I:k:K:lo:prRsS:t:v")) != -1) {
		switch (c) {
			case 'b':
				g_delete = 1;
				break;
			case 'c':
				set_if_not_set(g_cipherpath, "ciphertext path");
				break;
			case 'd':
				g_decrypt = 1;
				break;
			case 'D':
				g_decrypt = 1;
				g_pubkey_p = 1;
				break;
			case 'e':
				g_encrypt = 1;
				break;
			case 'S':
				set_if_not_set(g_sockpath, "socket path");
				break;
			case 'k':
				if (get_pubkey(optarg))
					return -1;
				pcnt++;
				break;
			case 'K':
				if (get_privkey(optarg))
					return -1;
				break;
			case 'I':
				if (add_file(optarg, 1))
					return -1;
				fcnt++;
				break;
			case 'i':
				if (add_file(optarg, 0))
					return -1;
				fcnt++;
				break;	
			case 'l':
				g_list = 1;
				break;
			case 'o':
				set_if_not_set(g_outpath, "output path");
				break;
			case 'p':
				g_chpw = 1;
				break;
			case 's':
				g_send = 1;
				break;
			case 'r':
				g_recv = 1;
				break;
			case 'R':
				g_recv = 1;
				g_pubkey_p = 1;
				break;
			case 'h':
				print_help((argc) ? basename(argv[0])
						: "crypt_client_red");
				exit(0);
				break;
			case 'v':
				g_verbose++;
				break;
			case 't':
				if (get_title(optarg))
					return -1;
				break;
			default:
				ERROR("Unsupported option %c", c);
				return -1;
				break;
		}
	}

	if (check_options(pcnt, fcnt)) {
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

	g_cleartext = cleartext_alloc();
	if (!g_cleartext) {
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

	if (g_send) {
		if (cryptd_send_cleartext(s, g_cleartext, NULL))
			goto out;

		printf("Message %.*s encrypted\n", 
				g_cleartext->tlen, g_cleartext->title);

		ret = EXIT_SUCCESS;
 	} else if (g_encrypt) {
		char *cipher = NULL;
		uint32_t clen = 0;
		if (cryptd_encrypt_cleartext(s, g_cleartext, 
						&cipher, &clen, NULL))
			goto out;
		printf("Message %.*s encrypted\n", 
				g_cleartext->tlen, g_cleartext->title);
		if (cryptd_write_file(g_cipherpath, cipher, clen, 0))
			goto out;
		printf("Ciphertext written to %s\n", g_cipherpath);
		free(cipher);
		ret = EXIT_SUCCESS;
	} else if (g_recv) {
		if (cryptd_recv_cleartext(s, g_cleartext, g_pubkey_p, NULL))
			goto out;

		printf("Retrieved cleartext %.*s\n", 
				g_cleartext->tlen, g_cleartext->title);

		if (cryptd_write_cleartext(g_outpath, g_cleartext, 0)) {
			ERROR("Failed to output cleartext");
		} else {
			printf("Cleartext %.*s from %.*s written to %s\n", 
					g_cleartext->tlen, g_cleartext->title,
					g_cleartext->nlen, g_cleartext->name, 
					g_outpath);
			ret = EXIT_SUCCESS;
		}
	} else if (g_decrypt) {
		char *cipher = NULL;
		uint32_t clen = 0;
		if (cryptd_get_file(g_cipherpath, &cipher, &clen))
			goto out;
		if (!g_cleartext->title) {
			g_cleartext->title = strdup("w0mbat");
			if (!g_cleartext->title) {
				ERROR("Out of memory");
				goto out;
			}
			g_cleartext->tlen = sizeof("w0mbat");
		}
		if (cryptd_decrypt_ciphertext(s, g_cleartext, 
					cipher, clen, g_pubkey_p, NULL)) {
			free(cipher);
			goto out;
		}
		printf("cleartext %.*s successfully retrieved\n",
					g_cleartext->tlen, g_cleartext->title);
		free(cipher);
		if (cryptd_write_cleartext(g_outpath, g_cleartext, 0)) {
			ERROR("Failed to output cleartext");
		} else {
			printf("Cleartext %.*s from %.*s written to %s\n", 
					g_cleartext->tlen, g_cleartext->title,
					g_cleartext->nlen, g_cleartext->name, 
					g_outpath);
			ret = EXIT_SUCCESS;
		}
	} else if (g_list) {
		char *buf = NULL;
		uint32_t len;
		if (cryptd_get_list(s, &buf, &len)) {
			ERROR("Failed to retrieve input list");
		} else {
			if (buf) {
				printf("Input list:\n%.*s\n", len, buf);
				free(buf);
			} else {
				puts("Empty input list.");
			}
			ret = EXIT_SUCCESS;
		}
	} else if (g_chpw) {
		uint32_t ec = 0;
		if (cryptd_change_password(s, g_cleartext->prv, &ec)) {
			ERROR("Failed to change password: %d\n", ec);
			goto out;
		}
		printf("Password changed OK\n");
		if (cryptd_write_file(g_outpath, g_cleartext->prv->data, 
				g_cleartext->prv->len, 0)) {
			ERROR("Failed to output new key");
		} else {
			printf("New key saved to %s\n", g_outpath);
			ret = EXIT_SUCCESS;
		}
	} else if (g_delete) {
		if (cryptd_delete_ciphertext(s, 
				g_cleartext->title, g_cleartext->tlen)) {
			ERROR("Failed to delete ciphertext");
			goto out;
		}

		printf("Deleted cleartext %.*s\n", 
				g_cleartext->tlen, g_cleartext->title);
		ret = EXIT_SUCCESS;
	}

	/* Fall through */
out:			
	if (s != -1)
		close(s);
	cleartext_free(g_cleartext);
	return ret;
}
