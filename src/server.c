// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file server.c
 * Cryptd server main.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * @n
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <clip/clip.h>
#include <clip/acidcrypt.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <grp.h>

#include "server.h"
#include "cmd.h"


/*************************************************************/
/*                     Global options                        */
/*************************************************************/

#include <linux/capability.h>
#ifdef WITH_VSERVER
#include <clip/clip-vserver.h>
#include <@VSERVER_CONTEXT@>

#define CRYPTD_CTX_FLAGS ( \
			VXF_INFO_NSPACE | \
			VXF_HIDE_MOUNT 	| \
			VXF_HIDE_VINFO	| \
			VXF_INFO_INIT	| \
			VXF_INFO_HIDE	\
		)

/* We need to authorize SETUID / SETGID in the context
 * to be able to further drop our privs... */
#define CRYPTD_CTX_CAPS 	((1UL << CAP_SETUID) | (1UL << CAP_SETGID))

static char *g_addr = "127.0.0.1";
static unsigned long g_xid = 0;
#endif

static char *g_root = "/var/empty";

#define RANDOM_DEV "/dev/urandom"

static clip_sock_t g_socks[2] = {
	{
		.sock = -1,
		.name = "cleartext",
		.path = NULL,
		.handler = red_conn_handler,
	},
	{
		.sock = -1,
		.name = "ciphertext",
		.path = NULL,
		.handler = black_conn_handler,
	}
};

static int g_foreground = 0;
static pid_t g_slave = 0;
int g_verbose = 0;
int g_daemonized = 0;
uint32_t g_features = 0;
const char *g_prefix = "master";

#define SOCK_RED	0
#define SOCK_BLACK	1


/*************************************************************/
/*                     Options parsing                       */
/*************************************************************/

#ifdef WITH_VSERVER
#define OPTS	"A:b:c:f:Fhp:r:R:X:v"
#define OPTHELP	"[-A <addr> -R <root> -X <xid>]"
#else
#define OPTS	"b:c:f:Fhp:r:R:v"
#define OPTHELP "[-R <root>]"
#endif

static void
print_help(const char *exe)
{
	printf("%s -r <red sock path> -b <black sock path> -f <features>"
			"-c <cmd> [-p <lib>+] [-v [-v]] [-F] "OPTHELP"\n", exe);
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
set_features(const char *arg) 
{
	const char *ptr;

	for (ptr = arg; *ptr; ptr++) {
		switch (*ptr) {
			case 'c':
				g_features |= CryptdCrypt|CryptdDelete;
				break;
			case 'd':
#ifdef WITH_DIODE
				g_features |= CryptdDiode;
				break;
#else
				ERROR("Diode features are not supported.");
				return -1;
#endif
			case 'e':
				g_features |= CryptdEncrypt;
				break;
			case 'p':
				g_features |= CryptdChPw;
				break;
			default:
				ERROR("Unsupported feature: %c", *ptr);
				return -1;
		}
	}

	return 0;
}

static int
get_options(int argc, char *argv[])
{
	int c;
#ifdef WITH_VSERVER
	unsigned long tmp;
	char *end;
#endif
	while ((c = getopt(argc, argv, OPTS)) != -1) {
		switch (c) {
#ifdef WITH_VSERVER
			case 'A':
				g_addr = optarg;
				break;
			case 'X':
				errno = 0;
				tmp = strtoul(optarg, &end, 0);
				if (tmp == ULONG_MAX && errno == ERANGE) {
					ERROR("xid out of bounds: %s", optarg);
					return -1;
				}
				if (*end) {
					ERROR("trailing chars after xid: %s",
							optarg);
					return -1;
				}
				g_xid = tmp;
				break;
#endif /* WITH_VSERVER */	
			case 'f':
				if (set_features(optarg)) 
					return -1;
				break;
			case 'b':
				set_if_not_set(g_socks[SOCK_BLACK].path, 
						"black socket path");
				break;
			case 'c':
				if (set_ext_cmd(optarg))
					return -1;
				break;
			case 'F':
				g_foreground = 1;
				break;
			case 'h':
				print_help((argc > 0) ? basename(argv[0])
						: "cryptd");
				exit(0);
				break;
			case 'p':
				if (acidcrypt_preload_lib(optarg)) {
					ERROR("Failed to preload ACID "
						"library for %s", optarg);
					return -1;
				}
				break;
			case 'r':
				set_if_not_set(g_socks[SOCK_RED].path, 
						"red socket path");
				break;
			case 'R':
				g_root = optarg;
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

	if (!g_socks[SOCK_RED].path) {
		ERROR("Missing red socket");
		print_help(basename(argv[0]));
		return -1;
	}

	if (!g_features) {
		ERROR("No features defined");
		return -1;
	}

	if (g_features & (CryptdCrypt | CryptdDiode)) {
		if (!g_socks[SOCK_BLACK].path) {
			ERROR("Missing black socket");
			print_help(basename(argv[0]));
			return -1;
		}
	}

	LOG("cryptd version 0x%x, features: 0x%x", VERNUM, g_features);

	return 0;
}

/*************************************************************/
/*                     Signal handlers                       */
/*************************************************************/

extern void (*const __start_cleanup_fns)(void);
extern void (*const __stop_cleanup_fns)(void);

static void
run_cleanup(void)
{
	void (*const *f)(void) = &__start_cleanup_fns;
	while (f < &__stop_cleanup_fns)
		(*f++)();
}

static void
interrupt_handler(int sig)
{
	if (g_slave) {
		/* We only log in the master. 
		 * Note that logging in the slave would mean two
		 * more messages on each interrupt, since the
		 * slave is cloned when entering a vserver context.
		 */
		LOG("interrupted by signal %d", sig);
		/* We kill the whole process group, rather than just the 
		 * slave to ensure that :
		 *  - external commands we might be currently running
		 *    are killed
		 *  - both of the cloned slaves gets killed, if the slave
		 *    used vserver for jailing itself.
		 */
		if (kill(0, sig))
			ERROR_ERRNO("Failed to kill slave daemon");
	}

	run_cleanup();

	exit(0);
}

static void
sigchld_action(int sig, siginfo_t *info, void *data __U)
{
	if (sig != SIGCHLD || info->si_signo != SIGCHLD) {
		ERROR("sigchld_action called on !SIGCHLD");
		return;
	}

	if (!g_slave || info->si_pid != g_slave)
		return;

	ERROR("Slave got killed ? Exiting");
	run_cleanup();

	switch (sig) {
		case SIGINT:
		case SIGTERM:
			exit(0);
		default:
			exit(1);
	}
}
	
static const int const caught_signals[] = 
	{ SIGHUP, SIGINT, SIGQUIT, SIGABRT, SIGALRM, SIGTERM, SIGUSR1, SIGUSR2 };

static int 
install_sighandlers(void)
{
	unsigned int i;
	sigset_t sigmask;
	struct sigaction sig = {
		.sa_handler = interrupt_handler,
		.sa_flags = SA_RESETHAND,
		.sa_restorer = NULL
	};

	if (sigemptyset(&sigmask)) {
		ERROR_ERRNO("sigemptyset failed");
		return -1;
	}
	for (i = 0; i < sizeof(caught_signals)/sizeof(int) ; i++) {
		if (sigaddset(&sigmask, caught_signals[i])) {
			ERROR_ERRNO("sigaddset %d failed", caught_signals[i]);
			return -1;
		}
	}
	memcpy(&sig.sa_mask, &sigmask, sizeof(sigmask));
		
	for (i = 0; i < sizeof(caught_signals)/sizeof(int); i++) {
		if (sigaction(caught_signals[i], &sig, NULL)) {
			ERROR_ERRNO("failed to install signal %d handler",
							caught_signals[i]);
			return -1;
		}
	}

	sig.sa_handler = NULL;
	if (sigemptyset(&sigmask)) {
		ERROR_ERRNO("sigemptyset failed");
		return -1;
	}
	memcpy(&sig.sa_mask, &sigmask, sizeof(sigmask));
	sig.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;
	sig.sa_sigaction = sigchld_action;

	if (sigaction(SIGCHLD, &sig, NULL)) {
		ERROR_ERRNO("failed to install SIGCHLD handler");
		return -1;
	}

	return 0;
}

/*************************************************************/
/*                     Main loop                             */
/*************************************************************/

static int
slave_drop_privs(void)
{
	int fd;

	fd = open(RANDOM_DEV, O_RDONLY|O_NOFOLLOW);
	if (fd == -1) {
		ERROR_ERRNO("open %s failed", RANDOM_DEV);
		return -1;
	}
	if (acidcrypt_set_random_fd(fd)) {
		ERROR("Failed to set acidcrypt random fd");
		goto err;
	}
#ifdef WITH_VSERVER
	if (g_xid) {
		if (clip_jailself(g_xid, CRYPTD_CTX_CAPS, 
				CRYPTD_CTX_FLAGS, g_addr, g_root)) {
			ERROR("Failed to jail self in %s (xid %lu)", 
							g_root, g_xid);
			goto err;
		}
	}
#else
	if (clip_chroot(g_root)) {
		ERROR_ERRNO("Failed to chroot in %s", g_root);
		goto err;
	}
#endif

	if (setgroups(0, NULL)) {
		ERROR_ERRNO("setgroups failed");
		goto err;
	}

	if (setgid(PRIVSEP_GID)) {
		ERROR_ERRNO("setgid failed");
		goto err;
	}
	
	if (setuid(PRIVSEP_UID)) {
		ERROR_ERRNO("setuid failed");
		goto err;
	}

	return 0;
err:
	close(fd);
	return -1;
}

static inline int
master_drop_privs(void)
{
	/* We simply drop all caps (that we used e.g. to jail the slave daemon)
	 * except CAP_KILL, which we'll need to kill the slave */
	return clip_reducecaps((1UL << CAP_KILL));
}

static int
slave_server_loop(void)
{
	int i, sock;
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		ERROR_ERRNO("signal");
		return 1;
	}

	for (i = 0; i < 2; i++) {
		if (!g_socks[i].path)
			continue;
		memset(&(g_socks[i].sau), 0, sizeof(g_socks[i].sau));
		sock = clip_sock_listen(g_socks[i].path, &(g_socks[i].sau), 0);
		if (sock < 0)
			goto out;
		g_socks[i].sock = sock;
	}

	if (slave_drop_privs()) {
		ERROR("Slave failed to drop its privileges");
		return -1;
	}
	
	for (;;) {
		if (clip_accept_one(g_socks, 2, 0))
			ERROR("Connection failed");
	}

out: 
	for (i = 0; i < 2; i++) {
		if (g_socks[i].sock != -1)
			(void)close(g_socks[i].sock);
	}
	return -1;
}

static int 
server_loop(void)
{
	int socks[2];
	pid_t pid;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks)) {
		ERROR_ERRNO("socketpair failed");
		return -1;
	}

	if (set_nonblock(socks[0])) {
		ERROR_ERRNO("Failed to set extcmd socket non-blocking");
		return -1;
	}

	pid = fork();
	switch (pid) {
		case -1:
			ERROR_ERRNO("fork failed");
			return -1;
		case 0:
			if (close(socks[0])) {
				ERROR_ERRNO("close failed");
				exit(EXIT_FAILURE);
			}
			g_extcmd_sock = socks[1];
			g_prefix = "slave";

			exit(slave_server_loop());
			break;
		default:
			if (close(socks[1])) 
				ERROR_ERRNO("close failed");

			g_extcmd_sock = socks[0];
			g_slave = pid;

			if (master_drop_privs()) {
				ERROR("Master daemon failed to drop privs");
				/* Let's exit nicely */
				interrupt_handler(SIGABRT);
				ERROR("WTF ?");
				exit(1);
			}
			(void)extcmd_handler();
			ERROR("Exited from the main loop?");
			interrupt_handler(SIGABRT);
	}

	interrupt_handler(SIGABRT);
	ERROR("We really shouldn't be here");
	return -1;
}

/*************************************************************/
/*                     Main                                  */
/*************************************************************/

int 
main (int argc, char *argv[])
{
	if (get_options(argc, argv))
		return EXIT_FAILURE;
	
	if (install_sighandlers())
		return EXIT_FAILURE;

	if (!g_foreground) {
		if (clip_daemonize()) {
			ERROR("Failed to daemonize");
			return EXIT_FAILURE;
		}
		g_daemonized = 1;
		/* Open syslog with NDELAY, to allow chrooting afterwards */
		openlog("cryptd", LOG_CONS|LOG_PID|LOG_NDELAY, LOG_DAEMON);
	}
	
	if (ciphertext_init()) {
		ERROR("failed to initialize ciphertext module");
		return EXIT_FAILURE;
	}
	if (crypt_init()) {
		ERROR("failed to initialize ccsd backend");
		return EXIT_FAILURE;
	}
#ifdef WITH_DIODE
	if (diode_init()) {
		ERROR("failed to initialize diode");
		return EXIT_FAILURE;
	}
#endif
	(void)server_loop();
	run_cleanup();
	return EXIT_FAILURE;
}
