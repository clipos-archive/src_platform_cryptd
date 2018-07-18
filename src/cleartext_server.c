// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file cleartext_server.c
 * Cryptd red server functions.
 *
 * Copyright (C) 2008-2009 SGDN/DCSSI
 * Copyright (C) 2011 SGDSN/ANSSI
 *
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 * @n
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <clip/clip.h>

#include "list.h"
#include "server.h"
#include "cmd.h"
#include "cryptd_red.h"
#include "cryptd_black.h"
#include "cleartext_common.h"
#include "ciphertext_common.h"

static inline uint32_t
get_privkey(int s, cleartext_t *clr, cmd_t *save_cmd)
{
	privkey_t *prv;
	uint32_t ret;

	prv = privkey_alloc();
	if (!prv) 
		return CMD_NOMEM;

	if (save_cmd) 
		ret = recv_field(s, 0, &(prv->data), &(prv->len), save_cmd);
	else
		ret = recv_field(s, CMD_PRIVKEY, 
					&(prv->data), &(prv->len), NULL);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Error getting privkey");
		goto err;
	}

	clr->prv = prv;

	return CMD_OK;

err:
	privkey_free(prv);
	return ret;
}

static uint32_t
get_pubkey(int s, cleartext_t *clr, cmd_t *save_cmd)
{
	pubkey_t *pk;
	uint32_t ret;

	pk = pubkey_alloc();
	if (!pk)
		return CMD_NOMEM;

	ret = recv_field(s, CMD_PUBKEY, 
			&(pk->data), &(pk->len), save_cmd);

	if (ret != CMD_OK) {
		pubkey_free(pk);
		return ret;
	}

	list_add(pk, clr->pubs);

	return CMD_OK;
}

static uint32_t
get_pubkeys(int s, cleartext_t *clr, cmd_t *save_cmd)
{
	uint32_t ret;

	do {
		ret = get_pubkey(s, clr, save_cmd);
	} while (ret == CMD_OK);

	/* ret should now be CMD_ORDER : we expect to stop when receiving
	 * CMD_CLEARTEXT */
	if (ret != CMD_ORDER) {
		CMD_ERROR(ret, "Failed to get public key");
		return ret;
	}

	return CMD_OK;
}

static uint32_t
get_cleartext(int s, cleartext_t **clr)
{
	uint32_t ret;
	cleartext_t *recv;
	cmd_t saved_cmd = {
		.cmd = 0,
		.data = 0,
	};

	recv = cleartext_alloc();
	if (!recv)
		return CMD_NOMEM;

	ret = recv_field(s, CMD_MSGTITLE, &(recv->title), &(recv->tlen), NULL);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get cleartext title");
		goto err;
	}
	
	ret = get_pubkeys(s, recv, &saved_cmd);
	if (ret != CMD_OK)
		goto err;
	if (saved_cmd.cmd != CMD_PATH) {
		ERROR("Wrong command %x after pubkeys", saved_cmd.cmd);
		ret = CMD_ORDER;
		goto err;
	}
	
	ret = recv_cleartext_files(s, recv, &saved_cmd);
	if (ret != CMD_OK)
		goto err;
	if (saved_cmd.cmd != CMD_PRIVKEY) {
		ERROR("Wrong command %x after files", saved_cmd.cmd);
		ret = CMD_ORDER;
		goto err;
	}

	ret = get_privkey(s, recv, &saved_cmd);
	if (ret != CMD_OK)
		goto err;

	*clr = recv;
	return CMD_OK;

err:
	cleartext_free(recv);
	return ret;
}

static uint32_t
recv_cleartext(int s, uint32_t uid)
{
	cleartext_t *clr;
	uint32_t ret;
	int32_t crypt_err = 0;

	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK)
		return ret;

	ret = get_cleartext(s, &clr);
	if (ret != CMD_OK)
		return ret;

	clr->uid = uid;

	if (ciphertext_exists(clr->title, clr->tlen, CIPHERTEXT_OUT, uid)) {
		ERROR("Ciphertext with title %.*s already present in output "
				"wait queue", clr->tlen, clr->title);
		ret = CMD_EXIST;
		(void)send_cmd(s, ret, 0);
		goto out;
	}

	ret = do_encrypt_add(clr, &crypt_err);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Encryption failed");
		(void)send_cmd(s, ret, crypt_err);
		goto out;
	}

	dump_cleartext_encrypt(clr);

	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to ack encryption");
		goto out;
	}

	/* Fall through */
out:
	cleartext_free(clr);
	return ret;
}

static inline uint32_t
encrypt_cleartext(int s, uint32_t uid)
{
	cleartext_t *clr = NULL;
	ciphertext_t *cpr = NULL;
	uint32_t ret;
	int32_t crypt_err = 0;

	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK)
		return ret;

	ret = get_cleartext(s, &clr);
	if (ret != CMD_OK)
		return ret;

	clr->uid = uid;

	ret = do_encrypt(clr, &crypt_err, &cpr);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Encryption failed");
		(void)send_cmd(s, ret, crypt_err);
		goto out;
	}

	dump_cleartext_encrypt(clr);

	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to ack encryption");
		goto out;
	}

	ret = send_field(s, CMD_MSGDATA, cpr->content, cpr->clen);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to put message data");
		goto out;
	}

	/* Fall through */
out:
	if (cpr)
		ciphertext_free(cpr);
	if (clr)
		cleartext_free(clr);
	return ret;
}


static inline uint32_t
get_decrypted_msg(int s, uint32_t uid, cleartext_t **out, 
				int pubkey_p, int32_t *crypt_err)
{
	uint32_t ret;
	char *name, *tmp;
	uint32_t nlen;
	cleartext_t *clr = cleartext_alloc();
	if (!clr) {
		ERROR("Out of memory allocating decrypted cleartext");
		return CMD_NOMEM;
	}

	ret = recv_field(s, CMD_MSGTITLE, &name, &nlen, NULL);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get message title to decrypt");
		goto err;
	}

	if (name[nlen - 1] != '\0') {
		tmp = realloc(name, nlen + 1);
		if (!tmp) {
			ERROR("Out of memory copying title %.*s", nlen, name);
			free(name);
			goto err;
		}
		name = tmp;
		name[nlen] = '\0';
		++nlen;
	}
	clr->title = name;
	clr->tlen = nlen;
		
	ret = get_privkey(s, clr, NULL);
	if (ret != CMD_OK) 
		goto err;

	clr->uid = uid;
	ret = do_decrypt_lookup(clr, pubkey_p, crypt_err);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Decryption error");
		goto err;
	}
	
	dump_cleartext_decrypt(clr);
	*out = clr;
	return CMD_OK;

err:
	cleartext_free(clr);
	return ret;
}

static uint32_t
send_cleartext(int s, uint32_t uid, int pubkey_p)
{
	uint32_t ret;
	cleartext_t *clr = NULL;
	int32_t crypt_err = 0;

	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK)
		return ret;

	ret = get_decrypted_msg(s, uid, &clr, pubkey_p, &crypt_err);
	if (ret != CMD_OK) {
		ERROR("Failed to get cleartext");
		(void)send_cmd(s, ret, crypt_err);
		goto out;
	}

	/* Decryption ok - client side will get this without
	 * a time-out */
	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK)
		goto out;

	ret = send_cleartext_files(s, clr);
	if (ret != CMD_OK)
		goto out;

	/* Signer's name */
	ret = send_field(s, CMD_NAME, clr->name, clr->nlen);
	if (ret != CMD_OK)
		goto out;

	if (pubkey_p) {
		ret = send_field(s, CMD_PPR, clr->ppr, clr->plen);
		if (ret != CMD_OK)
			goto out;
	}

	ret = ciphertext_delete(clr->title, clr->tlen, CIPHERTEXT_IN, uid);
	/* Fall through */
out:
	if (clr)
		cleartext_free(clr);
	return ret;
}

static inline uint32_t
get_decrypt_ciphertext(int s, uint32_t uid, cleartext_t **out, 
				int pubkey_p, int32_t *crypt_err)
{
	uint32_t ret;
	ciphertext_t *cpr = ciphertext_alloc();
	cleartext_t *clr = cleartext_alloc();
	if (!clr || !cpr) {
		ERROR("Out of memory allocating ciphertext / cleartext");
		return CMD_NOMEM;
	}

	ret = recv_ciphertext(s, cpr);
	if (ret != CMD_OK)
		goto err;

	cpr->uid = uid;
	clr->uid = uid;

	clr->title = strndup(cpr->title, cpr->tlen);
	if (!clr->title) {
		ERROR("Out of memory copying ciphertext title");
		goto err;
	}
	clr->tlen = cpr->tlen;
		
	ret = get_privkey(s, clr, NULL);
	if (ret != CMD_OK) 
		goto err;

	ret = do_decrypt(cpr, clr, pubkey_p, crypt_err);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Decryption error");
		goto err;
	}
	
	dump_cleartext_decrypt(clr);
	*out = clr;
	ciphertext_free(cpr);
	return CMD_OK;

err:
	ciphertext_free(cpr);
	cleartext_free(clr);
	return ret;
}



static uint32_t
decrypt_ciphertext(int s, uint32_t uid, int pubkey_p)
{
	uint32_t ret;
	cleartext_t *clr = NULL;
	int32_t crypt_err = 0;

	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK)
		return ret;

	ret = get_decrypt_ciphertext(s, uid, &clr, pubkey_p, &crypt_err);
	if (ret != CMD_OK) {
		ERROR("Failed to get cleartext");
		(void)send_cmd(s, ret, crypt_err);
		goto out;
	}

	/* Decryption ok - client side will get this without
	 * a time-out */
	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK)
		goto out;

	ret = send_cleartext_files(s, clr);
	if (ret != CMD_OK)
		goto out;

	/* Signer's name */
	ret = send_field(s, CMD_NAME, clr->name, clr->nlen);
	if (ret != CMD_OK)
		goto out;

	if (pubkey_p) {
		ret = send_field(s, CMD_PPR, clr->ppr, clr->plen);
		if (ret != CMD_OK)
			goto out;
	}

	/* Fall through */
out:
	if (clr)
		cleartext_free(clr);
	return ret;
}

static uint32_t
send_input_list(int s, uint32_t uid)
{
	char *list = NULL;
	uint32_t llen, ret;

	ret = ciphertext_list(uid, &list, &llen, CIPHERTEXT_IN); 
	if (ret != CMD_OK) {
		ERROR("Failed to get list of input ciphertexts");
		return ret;
	}

	if (!list) {
		ret = send_cmd(s, CMD_LIST, 0);
	} else {
		ret = send_field(s, CMD_LIST, list, llen);
	}
	if (ret != CMD_OK)
		CMD_ERROR(ret, "Failed to send list of input ciphertexts");
	
	if (list)
		free(list);
	return ret;
}

static uint32_t 
change_password(int s, uint32_t uid)
{
	privkey_t *prv = NULL;
	uint32_t ret;
	int32_t crypt_err = 0;

	prv = privkey_alloc();
	if (!prv) {
		ERROR("Out of memory");
		return CMD_NOMEM;
	}

	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK)
		goto out;

	ret = recv_field(s, CMD_PRIVKEY, &(prv->data), &(prv->len), NULL);
	if (ret != CMD_OK) {
		ERROR("Failed to receive original key");
		goto out;
	}

	ret = do_chpw(uid, prv, &crypt_err);
	if (ret != CMD_OK)
		goto out;

	ret = send_field(s, CMD_PRIVKEY, prv->data, prv->len);
	if (ret != CMD_OK) {
		ERROR("Failed to send new key");
		goto out;
	}
	/* Fall through */
out:
	if (ret != CMD_OK)
		(void)send_cmd(s, ret, crypt_err);
	if (prv)
		privkey_free(prv);
	return ret;
}

static inline uint32_t
confirm_delete(char *name, uint32_t len, uint32_t uid)
{
	extcmd_arg_t arg = {
		.dir = EXTCMD_DELETE,
		.uid = uid,
		.title = name,
		.tlen = len,
		.dest = NULL,
	};

	return run_ext_cmd(&arg);
}

static uint32_t 
delete_ciphertext(int s, uint32_t uid)
{
	uint32_t ret;
	char *name = NULL, *tmp;
	uint32_t nlen;
	ciphertext_t *cpr;

	ret = send_cmd(s, CMD_OK, 0);
	if (ret != CMD_OK)
		return ret;

	ret = recv_field(s, CMD_MSGTITLE, &name, &nlen, NULL);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "Failed to get message title to delete");
		return ret;
	}

	if (name[nlen - 1] != '\0') {
		tmp = realloc(name, nlen + 1);
		if (!tmp) {
			ERROR("Out of memory copying title %.*s", nlen, name);
			ret = CMD_NOMEM;
			goto out;
		}
		name = tmp;
		name[nlen] = '\0';
		++nlen;
	}

	cpr = ciphertext_lookup(name, nlen, CIPHERTEXT_IN, uid);
	if (!cpr) {
		ERROR("Could not find ciphertext with title %.*s in input"
			"wait queue", nlen, name);
		ret = CMD_NOENT;
		goto out;
	}

	ret = confirm_delete(name, nlen, uid);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "User %d did not confirm deletion of "
				"ciphertext %.*s", uid, nlen, name);
		goto out;
	}
		
	list_del(cpr);
	ciphertext_free(cpr);
	LOG("Deleted ciphertext %.*s for uid %d", nlen, name, uid);
	
	/* Fall through */
out:
	(void)send_cmd(s, ret, 0);
	if (name) {
		memset(name, 0, nlen);
		free(name);
	}
	return ret;
}

#define check_feature(cmd, feature) do {\
	DEBUG("got "#cmd); \
	if ((g_features & (feature)) != (feature)) {\
		ERROR(#cmd" command not supported: " \
			"missing "#feature" feature"); \
		(void)send_cmd(s, CMD_NOTSUP, 0); \
		goto out; \
	} \
} while (0);

int
red_conn_handler(int s, struct clip_sock_t *__s __attribute__((unused)))
{
	uint32_t ret, uid, gid;
	cmd_t cmd;
	int retval = -1;

	/* Get client uid first */
	if (clip_getpeereid(s, &uid, &gid)) {
		ERROR("failed to get peer eid");
		goto out;
	}
	LOG("Got connect from uid %d on red sock", uid);

	if (set_nonblock(s)) {
		ERROR("failed to set client socket non-blocking");
		goto out;
	}

	ret = recv_cmd(s, &cmd);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "failed to get initial command");
		goto out;
	}

	switch (cmd.cmd) {
		/* Info */
		case CMD_INFO:
			ret = send_server_info(s);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_INFO treatment %s", (retval) ? "nok" : "ok");
			break;
		/* Crypto diode */
		case CMD_SEND:
			check_feature(CMD_SEND, CryptdCrypt);
			ret = recv_cleartext(s, uid);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_SEND treatment %s", (retval) ? "nok" : "ok");
			break;
		case CMD_RECV:
			check_feature(CMD_RECV, CryptdCrypt);
			ret = send_cleartext(s, uid, 0);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_RECV treatment %s", (retval) ? "nok" : "ok");
			break;
		case CMD_RECVPUB:
			check_feature(CMD_RECVPUB, CryptdCrypt);
			ret = send_cleartext(s, uid, 1);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_RECVPUB treatment %s", 
						(retval) ? "nok" : "ok");
			break;
		case CMD_GETLIST:
			check_feature(CMD_GETLIST, CryptdCrypt);
			ret = send_input_list(s, uid);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_GETLIST treatment %s", 
						(retval) ? "nok" : "ok");
			break;
		/* Cleartext diode */
#ifdef WITH_DIODE
		case CMD_RECVCLR:
			check_feature(CMD_RECVCLR, CryptdDiode);
			ret = send_diode(s, uid);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_RECVCLR treatment %s", 
						(retval) ? "nok" : "ok");
			break;
		case CMD_GETCLRLIST:
			check_feature(CMD_GETCLRLIST, CryptdDiode);
			DEBUG("got CMD_GETCLRLIST");
			ret = send_diode_list(s, uid);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_GETCLRLIST treatment %s", 
						(retval) ? "nok" : "ok");
			break;
#endif /* WITH_DIODE */
		case CMD_CHPW:
			check_feature(CMD_CHPW, CryptdChPw);
			DEBUG("got CMD_CHPW");
			ret = change_password(s, uid);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_CHPW treatment %s", 
						(retval) ? "nok" : "ok");
			break;
		case CMD_DECRYPT:
			check_feature(CMD_DECRYPT, CryptdEncrypt);
			DEBUG("got CMD_DECRYPT");
			ret = decrypt_ciphertext(s, uid, 0);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_DECRYPT treatment %s", 
						(retval) ? "nok" : "ok");
			break;
		case CMD_DECRYPTPUB:
			check_feature(CMD_DECRYPTPUB, CryptdEncrypt);
			DEBUG("got CMD_DECRYPTPUB");
			ret = decrypt_ciphertext(s, uid, 1);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_DECRYPTPUB treatment %s", 
						(retval) ? "nok" : "ok");
			break;
		case CMD_ENCRYPT:
			check_feature(CMD_ENCRYPT, CryptdEncrypt);
			DEBUG("got CMD_ENCRYPT");
			ret = encrypt_cleartext(s, uid);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_ENCRYPT treatment %s", 
						(retval) ? "nok" : "ok");
			break;
		case CMD_DELETE:
			DEBUG("got CMD_DELETE");
			ret = delete_ciphertext(s, uid);
			retval = (ret == CMD_OK) ? 0 : -1;
			LOG("CMD_DELETE treatment %s", 
						(retval) ? "nok" : "ok");
			break;
		/* Default */
		default:
			ERROR("Unsupported client command: %d from uid %u",
				cmd.cmd, uid);
			break;
	}

out:
	(void)close(s);
	return retval;
}

#undef check_feature


	

	
	


	


