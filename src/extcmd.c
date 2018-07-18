// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file extcmd.c
 * Cryptd external command launcher.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN/DCSSI
 * Copyright (C) 2010-2012 SGDSN/ANSSI
 * @n
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "list.h"
#include "server.h"
#include "cryptd_red.h"
#include "cleanup.h"
#include "cmd.h"

#include <clip/acidfile.h>

int g_extcmd_sock;

/*************************************************************/
/*                   Extcmd configuration                    */
/*************************************************************/

static char *g_ext_cmd = NULL;
/* Grrr, can't be const because of execve's silly prototype */
static char *arg_encrypt = "encrypt";
static char *arg_decrypt = "decrypt";
static char *arg_confirm = "confirm";
static char *arg_chpwold = "chpwold";
static char *arg_chpwnew = "chpwnew";
static char *arg_delete = "delete";
#define PASS_MAXLEN	1024

int 
set_ext_cmd(const char * cmd)
{
	struct stat buf;

	if (g_ext_cmd) {
		ERROR("cannot set external commmand twice");
		return -1;
	}
	if (!cmd || *cmd != '/') {
		ERROR("external command (%s) is not an absolute path", cmd);
		return -1;
	}

	if (stat(cmd, &buf)) {
		ERROR_ERRNO("failed to stat external command (%s)", cmd);
		return -1;
	}

	if (!S_ISREG(buf.st_mode)) {
		ERROR("external command %s is not a regular file", cmd);
		return -1;
	}

	if ((buf.st_mode & (S_IRUSR|S_IXUSR)) != (S_IRUSR|S_IXUSR)) {
		ERROR("insufficient permissions on external command %s", cmd);
		return -1;
	}

	g_ext_cmd = strdup(cmd);
	if (!g_ext_cmd) {
		ERROR("out of memory setting external command");
		return -1;
	}

	return 0;
}

CLEANUP_FN(my_exit)
{
	if (g_ext_cmd)
		free(g_ext_cmd);
}

/*************************************************************/
/*                   Master extcmd handling                  */
/*************************************************************/

static uint32_t
recv_extcmd(int s, extcmd_arg_t *arg)
{
	cmd_t cmd;
	uint32_t ret, tmp;

	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK || cmd.cmd != CMD_EXTDIR) {
		CMD_ERROR(ret,"Failed to read extcmd dir");
		return CMD_FAULT;
	}
	arg->dir = cmd.data;

	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK || cmd.cmd != CMD_EXTUID) {
		CMD_ERROR(ret,"Failed to read extcmd uid");
		return CMD_FAULT;
	}
	arg->uid = cmd.data;

	ret = recv_field(s, CMD_EXTTITLE, (char **)&(arg->title), 
						&(arg->tlen), NULL);
	if (ret != CMD_OK) {
		CMD_ERROR(ret,"Failed to read extcmd title");
		return CMD_FAULT;
	}

	if (arg->dir == EXTCMD_ENCRYPT) {
		ret = recv_field(s, CMD_EXTDEST, (char **)&(arg->dest), 
								&tmp, NULL);
		if (ret != CMD_OK) {
			CMD_ERROR(ret,"Failed to read extcmd dest list");
			return CMD_FAULT;
		}
		if (*(arg->dest + tmp - 1) != '\0') {
			ERROR("Extcmd dest list is not NULL-terminated");
			return CMD_FAULT;
		}
		/* Empty dest list */
		if (*(arg->dest) == '\0') {
			free(arg->dest);
			arg->dest = NULL;
		}
	}

	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret,"Failed to ack transmission of extcmd");
		return CMD_FAULT;
	}

	return 0;
}

static inline void __attribute__((noreturn))
run_cmd(extcmd_arg_t *arg, char *dir, int fd)
{
	char *uidstr = NULL, *tstr = NULL, *dstr = NULL;
	char * myargv[] = { g_ext_cmd, dir, NULL };
	char * myenvp[] = { NULL, NULL, NULL, NULL };
	int f, nofiles;

	if (asprintf(&uidstr, "UID=%u", arg->uid) == -1) {
		ERROR("Out of memory allocating uid env var");
		goto out;
	}
	if (asprintf(&tstr, "TITLE=%.*s", arg->tlen, arg->title) == -1) {
		ERROR("Out of memory allocating id env var");
		goto out;
	}
	if (arg->dest && asprintf(&dstr, "DEST=%s", arg->dest) == -1) {
		ERROR("Out of memory allocating recipient env var");
		goto out;
	}

	/* Close all fds except our writing pipe to the daemon */
	nofiles = getdtablesize();
	for (f = 0; f < nofiles; f++) {
		if (f == fd)
			continue;
		if (close(f) && errno != EBADF) {
			ERROR("Failed to close fd %d", f);
			goto out;
		}
	}
		

	if (dup2(fd, STDOUT_FILENO) == -1) {
		ERROR_ERRNO("Failed to open pipe as STDOUT");
		goto out;
	}

	myenvp[0] = uidstr;
	myenvp[1] = tstr;
	myenvp[2] = dstr;

	(void)execve(g_ext_cmd, myargv, myenvp);
	/* Fall through on error */
out:
	ERROR_ERRNO("failed to execute external command %s", g_ext_cmd);
	_exit(EXIT_FAILURE);
}

static inline uint32_t
read_pass(int fd, extcmd_arg_t *arg)
{
	ssize_t rlen;
	uint32_t ret = CMD_FAULT;
	char *buf = malloc(PASS_MAXLEN);

	if (!buf) {
		ERROR_ERRNO("Out of memory allocating pass buffer");
		return CMD_NOMEM;
	}

	rlen = read(fd, buf, PASS_MAXLEN);
	if (rlen == -1) {
		ERROR_ERRNO("Failed to read on pipe");
		goto err;
	}
	if (!rlen || *buf == '\n' || *buf == '\0') {
		ERROR("Empty password");
		ret = CMD_CANCEL;
		goto err;
	}
	if (rlen >= PASS_MAXLEN) {
		ERROR("Truncated password");
		ret = CMD_INVAL;
		goto err;
	}
	/* Chomp trailing null */
	if (buf[rlen-1] == '\0') {
		rlen--;
	}
	/* Chomp trailing newline */
	if (buf[rlen-1] == '\n') {
		rlen--;
	}

	arg->pass = buf;
	arg->plen = rlen;
	return 0;
err:
	if (rlen > 0)
		memset(buf, 0, (rlen > PASS_MAXLEN) ? PASS_MAXLEN : rlen);
	free(buf);
	return ret;
}

#define FD_READ		0
#define FD_WRITE 	1

static uint32_t
do_run_ext_cmd(extcmd_arg_t *arg, char *dir, int getpass)
{
	pid_t pid, wret;
	int status, fds[2], ret = CMD_FAULT;

	if (pipe(fds)) {
		ERROR_ERRNO("pipe() failed");
		return CMD_FAULT;
	}

	pid = fork();
	switch (pid) {
		case -1:
			ERROR_ERRNO("Failed to fork external command");
			return CMD_FAULT;
		case 0:
			run_cmd(arg, dir, fds[FD_WRITE]);
			/* Not reached */
			_exit(EXIT_FAILURE);
		default:
			break;
	}

	if (close(fds[FD_WRITE])) {
		ERROR_ERRNO("Failed to close write end of pipe");
		return CMD_FAULT;
	}

	if (getpass) {
		ret = read_pass(fds[FD_READ], arg);
		if (ret != CMD_OK)
			goto out_close;
	}

	wret = waitpid(pid, &status, 0);
	if (wret == -1) {
		ERROR_ERRNO("waitpid failure while running external command");
		goto out_close;
	}
	if (wret != pid) {
		ERROR("unexpected waitpid result: %d != %d", wret, pid);
		goto out_close;
	}
	if (!WIFEXITED(status)) {
		ERROR("external command did not exit normally");
		if (WIFSIGNALED(status)) 
			ERROR("terminated by signal: %d", WTERMSIG(status));
		else 
			ERROR("no signal ??");
		goto out_close;
	}

	ret = (WEXITSTATUS(status)) ? CMD_CANCEL : CMD_OK;
	/* Fall through */
out_close:
	if (close(fds[FD_READ])) 
		ERROR_ERRNO("Failed to close read end of pipe");
	return ret; 
}

static int
handle_extcmd(int s)
{
	uint32_t ret = CMD_OK;
	int retval = -1, pass = 0;
	extcmd_arg_t arg;
	char *dir;
	
	memset(&arg, 0, sizeof(arg));
	ret = recv_extcmd(s, &arg);
	if (ret != CMD_OK)
		goto err;

	switch (arg.dir) {
		case EXTCMD_ENCRYPT:
			dir = arg_encrypt;
			pass = 1;
			break;
		case EXTCMD_DECRYPT:
			dir = arg_decrypt;
			pass = 1;
			break;
		case EXTCMD_CONFIRM:
			dir = arg_confirm;
			break;
		case EXTCMD_CHPWOLD:
			dir = arg_chpwold;
			pass = 1;
			break;
		case EXTCMD_CHPWNEW:
			dir = arg_chpwnew;
			pass = 1;
			break;
		case EXTCMD_DELETE:
			dir = arg_delete;
			break;
		default:
			ERROR("unsupported action: %d", arg.dir);
			goto err;
	}

	DEBUG("running external command %s %s", g_ext_cmd, dir);
	ret = do_run_ext_cmd(&arg, dir, pass);
	if (ret != CMD_OK) {
		goto err;
	}

	if (pass) {
		ret = send_field(s, CMD_EXTPASS, arg.pass, arg.plen);
		if (ret != CMD_OK) {
			ERROR("Error putting extcmd password");
			goto free;
		}
	} else {
		ret = send_cmd(s, CMD_OK, 0);
		if (ret != CMD_OK) {
			ERROR("Error sending OK to slave");
			goto free;
		}
	}

	retval = 0;
	/* Fall through */
free:
	if (arg.dest) 
		free(arg.dest);
	if (arg.title) {
		memset(arg.title, 0, arg.tlen);
		free(arg.title);
	}
	if (arg.pass) {
		memset(arg.pass, 0, arg.plen);
		free(arg.pass);
	}
	return retval;
	
err:
	ret = send_cmd(s, (ret == CMD_OK) ? CMD_FAULT : ret, 0);
	if (ret != CMD_OK)
		CMD_ERROR(ret, "Failed to send error to slave");
	goto free;
}

int
extcmd_handler(void)
{
	cmd_t cmd;
	uint32_t ret;
	int s = g_extcmd_sock;

	if (!g_ext_cmd)
		return -1;

	for (;;) {
		ret = recv_cmd_notimeout(s, &cmd);
		if (ret != CMD_OK) {
			CMD_ERROR(ret,"Failed to get initial extcmd command");
			continue;
		}

		if (cmd.cmd != CMD_EXTCMD) {
			ERROR("Invalid extcmd command: %u", cmd.cmd);
			continue;
		}	
		LOG("Got extcmd request");

		if (handle_extcmd(s)) {
			ERROR("Extcmd failed");
		} else {
			LOG("Extcmd OK");
		}
	}

	return -1;
}

/*************************************************************/
/*                   Slave extcmd handling                   */
/*************************************************************/

static uint32_t
send_extcmd(int s, extcmd_arg_t *arg)
{
	cmd_t cmd;
	uint32_t ret;

	ret = send_cmd(s, CMD_EXTDIR, arg->dir);
	if (ret != CMD_OK) {
		CMD_ERROR(ret,"Failed to transmit extcmd dir");
		return CMD_FAULT;
	}

	ret = send_cmd(s, CMD_EXTUID, arg->uid);
	if (ret != CMD_OK) {
		CMD_ERROR(ret,"Failed to transmit extcmd uid");
		return CMD_FAULT;
	}

	ret = send_field(s, CMD_EXTTITLE, arg->title, arg->tlen);
	if (ret != CMD_OK) {
		CMD_ERROR(ret,"Failed to transmit extcmd title");
		return CMD_FAULT;
	}

	if (arg->dir == EXTCMD_ENCRYPT) {
		ret = send_field(s, CMD_EXTDEST, arg->dest, 
					strlen(arg->dest) + 1);
		if (ret != CMD_OK) {
			CMD_ERROR(ret,"Failed to transmit extcmd dest list");
			return CMD_FAULT;
		}
	}

	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK || cmd.cmd != CMD_OK) {
		CMD_ERROR(ret,"Failed to transmit extcmd");
		return CMD_FAULT;
	}

	return 0;
}

uint32_t
run_ext_cmd(extcmd_arg_t *arg)
{
	uint32_t ret;
	int s = g_extcmd_sock;
	cmd_t cmd, answer;
	memset(&answer, 0, sizeof(answer));

	ret = send_cmd(s, CMD_EXTCMD, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to send extcmd request");
		return ret;
	}

	ret = send_extcmd(s, arg);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to send extcmd args");
		return ret;
	}

	if (arg->dir == EXTCMD_CONFIRM || arg->dir == EXTCMD_DELETE) {
		ret = recv_cmd_notimeout(s, &cmd);
		if (ret != CMD_OK) {
			CMD_ERROR(ret, "Failed to read master's return value");
			return ret;
		}
		if (cmd.cmd != CMD_OK) {
			CMD_ERROR(cmd.cmd, "Master does not confirm");
			return cmd.cmd;
		}
	} else {
		ret = recv_field_notimeout(s, CMD_EXTPASS, 
				&(arg->pass), &(arg->plen), &answer);
		if (ret != CMD_OK) {
			if (answer.cmd != CMD_OK)
				ret = answer.cmd;
			CMD_ERROR(ret, "Failed to read password from extcmd");
			return ret;
		}
	}

	return CMD_OK;
}
