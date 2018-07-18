// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file crypt.c
 * Cryptd main cryptographic functions.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN/DCSSI
 * Copyright (C) 2012 SGDSN/ANSSI
 * @n
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "list.h"
#include "server.h"
#include "cmd.h"
#include "cryptd_red.h"
#include "cryptd_black.h"
/* Must be after server.h for uint32_t definition */
#include <clip/acidfile.h>
#include <clip/acidcrypt.h>

int
crypt_init(void)
{ 
	return 0;
}

static acid_ctx_t *
acid_connect(privkey_t *prv, char *pass, uint32_t plen, ErrCode *e)
{
	acid_ctx_t *ctx = NULL;
	acid_keybundle_t *kb = NULL;
	ErrCode ec = CC_OK;

	if (prv->subject) {
		ERROR("Private key already connected for %s", prv->subject);
		ec = CC_INVALID;
		goto out;
	}
	if (acidfile_keybundle_parse(prv->data, prv->len, 
					Acid_FType_Priv, &kb)) {
		ERROR("Private key parsing failed");
		ec = CC_BAD_ARGS;
		goto out;
	}

	ctx = acid_ctx_new(kb, pass, plen, &ec);
	if (!ctx) {
		ERROR("Failed to create ACID context");
		goto out;
	}
	prv->subject = acid_key_get_field(kb->certs->next, ACID_Subject);
	if (!prv->subject) {
		ERROR("Failed to copy PRV subject");
		acid_ctx_free(ctx);
		ctx = NULL;
		ec = CC_MEM; /* Possibly, or CC_BAD_ARGS */
		goto out;
	}
	LOG("Connected as %s", prv->subject);
	/* Fall through */
out:
	if (kb)
		acid_keybundle_free(kb);
	if (e && ec != CC_OK)
		*e = ec;
	return ctx;
}

/* Move keys from one chain to another, without duplicates */
static inline void
move_keys_to_chain(acid_key_t *dst, acid_key_t *src)
{
	acid_key_t *cur, *next, *iter;
	const char *serial;

	next = src->next;
outloop:
	while (next != src) {
		cur = next;
		next = next->next;
		serial = acid_key_field(cur, ACID_Serial);
		if (!serial)
			break;
		af_list_for_each(iter, dst) {
			if (!strcmp(serial, acid_key_field(iter, ACID_Serial)))
				goto outloop;
		}
		af_list_del(cur);
		af_list_add(cur, dst);
	}
}

static inline ErrCode
add_dest(acid_key_t *sender, acid_key_t *dests, 
			acid_key_t *chead, pubkey_t *iter)
{
	ErrCode ec = CC_INVALID;
	acid_key_t *tmp = NULL;
	int ret;
	
	if (acidfile_check_headers(iter->data, iter->len, 
					Acid_FType_Pub, NULL)) {
		ERROR("Failed to parse public key");
		ec = CC_PARSE_CERTIFICATES;
		goto out;
	}
	if (acidfile_pxr_get_certs(iter->data, &tmp)) {
		ERROR("Failed to get certs from public key");
		ec = CC_PARSE_CERTIFICATES;
		goto out;
	}
	/* Should be the same subject on all certs of the same pubkey_t */
	iter->subject = acid_key_get_field(tmp->next, ACID_Subject);

	ret = acid_key_intersect(sender, dests, tmp);
	tmp = NULL; /* acid_key_intersect frees tmp in all cases */
	if (ret < 0) {
		ec = CC_INVALID;
		goto out;
	}
	if (!ret) {
		ERROR("Could not find a matching token for all recipients");
		ec = CC_BAD_PERS;
		goto out;
	}

	if (acidfile_pxr_get_cert_chain(iter->data, &tmp)) {
		ERROR("Failed to get cert chain from public key");
		ec = CC_PARSE_CERTIFICATES;
		goto out;
	}
	/* TODO: we should clean up a bit - we're probably adding 
	 * intermediate certs that are not needed by the keys we
	 * add.
	 */
	move_keys_to_chain(chead, tmp);
	ec = CC_OK;
	/* Fall through */
out:
	if (tmp)
		acid_key_free_all(tmp);
	return ec;
}

/* Build a list of all first keys in each bundle */
static ErrCode
get_certs(const cleartext_t *clr, acid_key_t **certs, acid_key_t **cert_chain)
{
	acid_key_t *sender = NULL, *dests = NULL, *chain = NULL;
	pubkey_t *iter;
	unsigned int i = 0;
	ErrCode ec = CC_MEM;

	if (acidfile_check_headers(clr->prv->data, clr->prv->len, 
					Acid_FType_Priv, NULL)) {
		ERROR("Failed to parse private key");
		ec = CC_PARSE_CERTIFICATES;
		goto err;
	}
	if (acidfile_pxr_get_certs(clr->prv->data, &sender)) {
		ERROR("Failed to get certs from private key");
		ec = CC_PARSE_CERTIFICATES;
		goto err;
	}

	dests = acid_key_alloc();
	if (!dests) {
		ERROR("Out of memory");
		goto err;
	}

	chain = acid_key_alloc();
	if (!chain) {
		ERROR("Out of memory");
		goto err;
	}

	list_for_each(iter, clr->pubs) {
		ec = add_dest(sender, dests, chain, iter);
		if (ec != CC_OK)
			goto err;
		i++;
	}
	if (acid_key_intersect_best_fit(sender, dests)) {
		ec = CC_DATE;
		goto err;
	}

	DEBUG("Added %u public keys", i);
	acid_key_free_all(sender); /* Yeah, we'll re-parse it, I know... */
	*certs = dests;
	*cert_chain = chain;
	return CC_OK;

err:
	if (sender)
		acid_key_free_all(sender);
	if (dests)
		acid_key_free_all(dests);
	if (chain)
		acid_key_free_all(chain);
	return ec;
}

#define _copy(src, slen, dst, dlen) do {\
	dst = malloc(slen); \
	if (!dst) { \
		ERROR("Out of memory"); \
		goto err; \
	} \
	memcpy(dst, src, slen); \
	dlen = slen; \
} while (0)

#define _move(src, slen, dst, dlen) do {\
	dst = src; \
	src = NULL; \
	dlen = slen; \
	slen = 0; \
} while (0)

static acidcrypt_file_t *
get_acid_files(const file_t *files)
{
	acidcrypt_file_t *head, *cur;
	file_t *iter;
	unsigned int i = 0;
	char *ptr;
	uint32_t len;

	head = acidcrypt_file_alloc();
	if (!head) {
		ERROR("Out of memory");
		return NULL;
	}

	list_for_each(iter, files) {
		cur = acidcrypt_file_alloc();
		if (!cur) {
			ERROR("Out of memory");
			goto err;
		}
		_move(iter->content, iter->clen, cur->content, cur->clen);
		/* Rewrite iter->clen, it is used for the cleartext dump
		 * later on ... Yes, I know... */
		iter->clen = cur->clen;
		ptr = iter->path;
		len = iter->plen;
		/* Skip leading slashes - we don't want absolute
		 * paths in the archives */
		while (len && (*ptr == '\\' || *ptr == '/')) {
			ptr++;
			len--;
		}
		/* No move here ! */
		_copy(ptr, len, cur->path, cur->plen);
		ptr = cur->path;
		/* Windozify path */
		while ((ptr = strchr(ptr, '/')))
			*ptr++ = '\\'; /* OK since path is null-terminated */

		if (acidfile_get_datestr(&(iter->meta->ctime), 
					&(cur->cdate), &(cur->cdlen)))
			goto err;
		if (acidfile_get_datestr(&(iter->meta->mtime), 
					&(cur->mdate), &(cur->mdlen)))
			goto err;
		if (acidfile_get_datestr(&(iter->meta->atime), 
					&(cur->adate), &(cur->adlen)))
			goto err;

		/* For some reason, cryptofiler 7 (7.0.1.9) doesn't 
		 * like a trailing 'Z' here... Don't ask me why :( 
		 * It likes it fine everywhere else, though, so I'm not
		 * removing the trailing 'Z' from acidfile_get_datestr()
		 * output, since it is supposed to be there according to 
		 * the spec.
		 */
#define unZify(ptr, len) do { \
	if (ptr[len - 1] == 'Z') { \
		ptr[len - 1] = '\0'; \
		len--; \
	} \
} while (0)
		unZify(cur->cdate, cur->cdlen);
		unZify(cur->mdate, cur->mdlen);
		unZify(cur->adate, cur->adlen);
#undef unZify

		af_list_add(cur, head);
		i++;
	}

	DEBUG("Added %u files", i);
	return head;

err:
	af_list_free_all(head, acidcrypt_file_t, acidcrypt_file_free);
	return NULL;
}

static int
build_csa(acid_ctx_t *ctx, acid_key_t *certs, acid_key_t *peer_chain, 
			acidcrypt_file_t *files,
			char **out, uint32_t *len, ErrCode *e)
{
	acid_csa_t *csa = NULL;
	acid_csa_sig_t *sig = NULL;
	char *buff = NULL, *sbuff = NULL, *tmp;
	uint32_t blen, sblen;
	ErrCode ec = CC_OK;

	ec = acidcrypt_encrypt(ctx, files, certs, peer_chain, 0, &csa);
	if (ec != CC_OK) {
		ERROR("Failed to encrypt files");
		goto err;
	}

	if (acidfile_csa_put(csa, &buff, &blen)) {
		ERROR("Failed to build csa");
		goto err;
	}

	ec = acidcrypt_build_sig(ctx, buff, blen, &sig);
	if (ec != CC_OK) {
		ERROR("Failed to create signature");
		goto err;
	}

	if (acidfile_csa_put_sig(sig, &sbuff, &sblen)) {
		ERROR("Failed to build signature trailer");
		goto err;
	}

	tmp = realloc(buff, blen + sblen);
	if (!tmp) {
		ERROR("Out of memory");
		goto err;
	}

	buff = tmp;
	memcpy(buff + blen, sbuff, sblen);
	blen += sblen;

	free(sbuff);
	acid_csa_sig_free(sig);
	acid_csa_free(csa);
	
	*out = buff;
	*len = blen;
	return 0;

err:
	if (buff)
		free(buff);
	if (sbuff)
		free(sbuff);
	if (sig)
		acid_csa_sig_free(sig);
	if (csa)
		acid_csa_free(csa);
	if (e && ec != CC_OK)
		*e = ec;
	return -1;
}

static inline char *
get_dest_string(const acid_key_t *certs) 
{
	const acid_key_t *iter;
	size_t total = 1; /* 1 for trailing 0 */
	char *str, *ptr;
	const char *tmp;

	af_list_for_each(iter, certs) {
		/* +1 for trailing \n */
		tmp = acid_key_field(iter, ACID_Subject);
		if (!tmp) 
			ERROR("Missing Subject Name"); /* Don't error out */
		else
			total += strlen(tmp) + 1;
	}

	/* Must be zeroed in case we have no certs */
	str = calloc(1, total);
	if (!str) {
		ERROR("Out of memory");
		return NULL;
	}

	ptr = str;
	af_list_for_each(iter, certs) {
		ptr += sprintf(ptr, "%s\n", 
				acid_key_field(iter, ACID_Subject));	
	}

	return str;
}

static inline uint32_t
get_pwd_encrypt(cleartext_t *clr, acid_key_t *certs, 
				char **pass, uint32_t *plen)
{
	uint32_t ret;
	extcmd_arg_t arg = {
		.dir = EXTCMD_ENCRYPT,
		.uid = clr->uid,
		.title = clr->title,
		.tlen = clr->tlen,
		.dest = NULL,
	};
	char *dests = NULL;

	dests = get_dest_string(certs);
	if (!dests)
		return CMD_NOMEM;
	arg.dest = dests;

	ret = run_ext_cmd(&arg);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "External command failed");
		goto out;
	}
	
	*pass = arg.pass;
	*plen = arg.plen;
	ret = CMD_OK;
	/* Fall through */
out:
	memset(dests, 0, strlen(dests));
	free(dests);
	return ret;
}

static inline uint32_t
_encrypt(cleartext_t *clr, ciphertext_t *cpr, 
		acid_key_t *certs, acid_key_t *peer_chain, 
		char *pass, uint32_t plen, ErrCode *ec)
{
	acid_ctx_t *ctx = NULL;
	acidcrypt_file_t *files = NULL;
	uint32_t ret;

	ret = CMD_FAULT;
	files = get_acid_files(clr->files);
	if (!files)
		goto out;

	ret = CMD_CRYPT;
	ctx = acid_connect(clr->prv, pass, plen, ec);
	if (!ctx)
		goto out;

	if (build_csa(ctx, certs, peer_chain, files, &(cpr->content), &(cpr->clen), ec)) {
		ERROR("Encryption failed");
		goto out;
	}

	ret = CMD_OK;
	/* Fall through */
out:
	if (ctx)
		acid_ctx_free(ctx);
	if (files)
		af_list_free_all(files, acidcrypt_file_t, acidcrypt_file_free);
	return ret;
}

uint32_t
do_encrypt(cleartext_t *clr, int32_t *e, ciphertext_t **out)
{
	uint32_t ret;
	ciphertext_t *cpr = NULL;
	ErrCode ec = CC_OK;
	char *pass = NULL;
	uint32_t plen = 0;
	acid_key_t *certs = NULL, *peer_chain = NULL;

	ec = get_certs(clr, &certs, &peer_chain);
	if (ec != CC_OK) {
		if (ec != CC_MEM)
			ret = CMD_CRYPT;
		else
			ret = CMD_NOMEM;
		goto err;
	}

	ret = get_pwd_encrypt(clr, certs, &pass, &plen);
	if (ret != CMD_OK)
		goto err;

	cpr = ciphertext_alloc();
	if (!cpr) {
		ret = CMD_NOMEM;
		ERROR("Out of memory");
		goto err;
	}

	ret = _encrypt(clr, cpr, certs, peer_chain, pass, plen, &ec);
	if (ret != CMD_OK)
		goto err;

	ret = CMD_NOMEM;
	_copy(clr->title, clr->tlen, cpr->title, cpr->tlen);
	cpr->uid = clr->uid;

	*out = cpr;
	ret = CMD_OK;
	/* Fall through */
err:
	if (pass) {
		memset(pass, 0, plen);
		free(pass);
	}
	if (certs)
		acid_key_free_all(certs);
	if (peer_chain)
		acid_key_free_all(peer_chain);
	if (e && ec != CC_OK)
		*e = ec;
	return ret;
}

uint32_t
do_encrypt_add(cleartext_t *clr, int32_t *e)
{
	uint32_t ret;
	ciphertext_t *cpr = NULL;
	
	ret = do_encrypt(clr, e, &cpr);
	if (ret != CMD_OK) 
		return ret;

	ret = ciphertext_add(cpr, CIPHERTEXT_OUT);
	if (ret != CMD_OK) {
		ciphertext_free(cpr);
		return ret;
	}
	
	return CMD_OK;
}


static inline uint32_t
_build_ppr(acid_csa_sig_t *sig, char **pubkey, uint32_t *plen)
{
	acid_keybundle_t *kb = NULL;
	acid_key_t *pub;
	uint32_t ret = CMD_NOMEM;

	kb = acid_keybundle_alloc();
	if (!kb)
		goto out;

	kb->version = 4;
	kb->type = Acid_FType_Pub;

	if (acidfile_current_datestr(&kb->date, &kb->dlen))
		goto out;

	kb->certs = acid_key_alloc();
	if (!kb->certs)
		goto out;

	pub = acid_key_copy(sig->cert);
	if (!pub)
		goto out;

	af_list_add(pub, kb->certs);

	kb->cert_chain = acid_key_copy_cert_chain(pub, sig->cert_chain);
	if (!kb->cert_chain)
		goto out;

	if (acidfile_keybundle_put(kb, pubkey, plen))
		ret = CMD_FAULT;
	else
		ret = CMD_OK;
	/* Fall through */
out:
	if (kb)
		acid_keybundle_free(kb);
	return ret;
}

static uint32_t
_decrypt(acid_ctx_t *ctx, char *bundle, uint32_t blen, char **name, 
		char **pubkey, uint32_t *plen, acidcrypt_file_t **out, ErrCode *e)
{
	acidcrypt_file_t *files = NULL;
	acid_csa_t *csa = NULL;
	acid_csa_sig_t *sig = NULL;
	ErrCode ec = CC_OK;
	uint32_t ret;

	if (acidfile_check_headers(bundle, blen, Acid_FType_CSA, NULL)) {
		ERROR("Corrupted CSA headers");
		ret = CMD_INVAL;
		goto out;
	}
	
	if (acidfile_csa_get_sig(bundle, blen, &sig)) {
		ERROR("Signature extraction failed");
		ret = CMD_INVAL;
		goto out;
	}

	ec = acidcrypt_check_sig_no_datecheck(ctx, sig, bundle);
	if (ec != CC_OK) {
		ERROR("Signature check failed");
		ret = CMD_CRYPT;
		goto out;
	}

	if (acidfile_csa_parse(bundle, blen, &csa)) {
		ERROR("CSA parsing failed");
		ret = CMD_INVAL;
		goto out;
	}

	/* We use the global signer certificate for decryption.
	 * Note that when this certificate is different from the one
	 * in section 2 of the CSA bundle, the global signer cert is
	 * the one to use for decryption. This happens when someone
	 * re-encrypts an archive originally encrypted by someone else :
	 * in that case, section 2 still contains the original encrypter
	 * certificate, but encryption is done with the global signer key.
	 */
	ec = acidcrypt_decrypt(ctx, sig->cert, csa, &files);
	if (ec != CC_OK) {
		ERROR("Failed to decrypt files");
		ret = CMD_CRYPT;
		goto out;
	}

	if (name) {
		*name = acid_key_get_field(sig->cert, ACID_Subject);
		if (!*name) {
			ERROR("Failed to copy signer's name");
			af_list_free_all(files, acidcrypt_file_t, 
							acidcrypt_file_free);
			ret = CMD_INVAL;
			goto out;
		}
	}
	if (pubkey) {
		if (_build_ppr(sig, pubkey, plen)) {
			ERROR("Failed to build sender's ppr");
			af_list_free_all(files, acidcrypt_file_t, 
							acidcrypt_file_free);
			ret = CMD_INVAL;
			goto out;
		}
	}

	*out = files;
	ret = CMD_OK;

	/* Fall through */
out:
	if (csa)
		acid_csa_free(csa);
	if (sig)
		acid_csa_sig_free(sig);
	if (e && ec != CC_OK)
		*e = ec;
	return ret;
}

static file_t *
_acidfile2file(acidcrypt_file_t *file)
{
	file_t *new;
	char *ptr;
	uint32_t len;

	new = file_alloc();
	if (!new) {
		ERROR("Out of memory");
		return NULL;
	}

	ptr = file->path;
	len = file->plen;
	/* Skip leading slashes (windoze or UNIX). We don't
	 * want to extract to an absolute path...
	 */
	while (len && (*ptr == '\\' || *ptr == '/')) {
		ptr++;
		len--;
	}
	/* No move here... */
	_copy(ptr, len, new->path, new->plen);
	/* Switch to unixy path */
	ptr = new->path;
	while ((ptr = strchr(ptr, '\\')))
		*ptr++ = '/'; /* OK since path is null-terminated */

	_move(file->content, file->clen, new->content, new->clen);
	_move(file->hash, file->hlen, new->hash, new->hlen);
	new->meta = malloc(sizeof(*(new->meta)));
	if (!new->meta) {
		ERROR("Out of memory");
		goto err;
	}

	new->meta->attrs = file->attrs;
	new->meta->ctime = acidfile_get_time(file->cdate, file->cdlen);
	new->meta->mtime = acidfile_get_time(file->mdate, file->mdlen);
	new->meta->atime = acidfile_get_time(file->adate, file->adlen);

	if (new->meta->ctime == -1 || new->meta->mtime == -1 
					|| new->meta->atime == -1) {
		ERROR("Date conversion failed");
		goto err;
	}

	return new;

err:
	file_free(new);
	return NULL;
}

static uint32_t
decrypt_ciphertext(acid_ctx_t *ctx, ciphertext_t *cpr, 
			cleartext_t *clr, int pubkey_p, ErrCode *e)
{

	acidcrypt_file_t *files, *iter;
	file_t *cur;
	uint32_t ret;

	if (pubkey_p)
		ret = _decrypt(ctx, cpr->content, cpr->clen, &clr->name, 
					&clr->ppr, &clr->plen, &files, e);
	else
		ret = _decrypt(ctx, cpr->content, cpr->clen, &clr->name, 
						NULL, NULL, &files, e);
	if (ret != CMD_OK)
		return ret;

	af_list_for_each(iter, files) {
		cur = _acidfile2file(iter);
		if (!cur) {
			ERROR("Could not parse acid file");
			ret = CMD_FAULT;
			goto out;
		}
		list_add(cur, clr->files);
	}		
	
	clr->nlen = strlen(clr->name);
	if (!clr->title) {
		clr->title = malloc(cpr->tlen);
		if (clr->title) {
			memcpy(clr->title, cpr->title, cpr->tlen);
			clr->tlen = cpr->tlen;
		} else {
			ERROR("Out of memory allocating cleartext title");
			ret = CMD_NOMEM;
			goto out;
		}
	}
	ret = CMD_OK;
	/* Fall through */
out:
	af_list_free_all(files, acidcrypt_file_t, acidcrypt_file_free);
	return ret;
}

static inline uint32_t
get_pwd_decrypt(cleartext_t *clr, char **pass, uint32_t *plen)
{
	uint32_t ret;
	extcmd_arg_t arg = {
		.dir = EXTCMD_DECRYPT,
		.uid = clr->uid,
		.title = clr->title,
		.tlen = clr->tlen,
		.dest = NULL,
	};

	ret = run_ext_cmd(&arg);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "External command failed");
		return ret;
	}

	*pass = arg.pass;
	*plen = arg.plen;

	return CMD_OK;
}

uint32_t
do_decrypt(ciphertext_t *cpr, cleartext_t *clr, int pubkey_p, int32_t *e)
{
	acid_ctx_t *ctx = NULL;
	uint32_t ret, plen = 0;
	char *pass = NULL;
	ErrCode ec = CC_OK;

	ret = get_pwd_decrypt(clr, &pass, &plen);
	if (ret != CMD_OK)
		goto out;

	ctx = acid_connect(clr->prv, pass, plen, &ec);
	if (!ctx) {
		ret = CMD_CRYPT;
		goto out;
	}
	
	if (decrypt_ciphertext(ctx, cpr, clr, pubkey_p, &ec)) {
		ERROR("Decryption failed");
		ret = CMD_CRYPT;
		goto out;
	}

	ret = CMD_OK;
	/* Fall through */
out:
	if (ctx)
		acid_ctx_free(ctx);
	if (e && ec != CC_OK)
		*e = ec;

	if (pass) {
		memset(pass, 0, plen);
		free(pass);
	}

	return ret;
}

uint32_t
do_decrypt_lookup(cleartext_t *clr, int pubkey_p, int32_t *e)
{
	ciphertext_t *cpr;
	DEBUG("looking for ciphertext %.*s", clr->tlen, clr->title);
	cpr = ciphertext_lookup(clr->title, clr->tlen, CIPHERTEXT_IN, clr->uid);

	if (!cpr) {
		ERROR("No ciphertext with title %.*s found", 
						clr->tlen, clr->title);
		return CMD_NOENT;
	}

	/* Note: caller still has to delete the ciphertext from the input
	 * list. */
	return do_decrypt(cpr, clr, pubkey_p, e);
}

static inline uint32_t
get_pwd_chpw(int old_p, uint32_t uid, 
	char *name, char **pass, uint32_t *plen)
{
	uint32_t ret;
	extcmd_arg_t arg = {
		.uid = uid,
		.title = name,
	};

	arg.tlen = strlen(name);

	if (old_p)
		arg.dir = EXTCMD_CHPWOLD;
	else
		arg.dir = EXTCMD_CHPWNEW;

	ret = run_ext_cmd(&arg);
	if (ret != CMD_OK) {
		CMD_ERROR(ret, "External command (getting %s password) failed",
				(old_p) ? "old" : "new");
		return ret;
	}

	*pass = arg.pass;
	*plen = arg.plen;

	return CMD_OK;
}

uint32_t
do_chpw(uint32_t uid, privkey_t *prv, int32_t *e)
{
	uint32_t ret = CMD_INVAL;
	acid_keybundle_t *kb = NULL;
	ErrCode ec = CC_OK;

	char *opw = NULL, *npw = NULL, *key = NULL;
	uint32_t olen = 0, nlen = 0, klen = 0;
	char *name = NULL;

	if (acidfile_keybundle_parse(prv->data, prv->len, 
					Acid_FType_Priv, &kb)) {
		ERROR("Private key parsing failed");
		ec = CC_BAD_ARGS;
		goto out;
	}
	
	name = acid_key_get_field(kb->certs->next, ACID_Subject);

	ret = get_pwd_chpw(1, uid, name, &opw, &olen);
	if (ret != CMD_OK)
		goto out;
	ret = get_pwd_chpw(0, uid, name, &npw, &nlen);
	if (ret != CMD_OK)
		goto out;

	ec = acidcrypt_chpw(kb, opw, olen, npw, nlen);
	if (ec != CC_OK) {
		ERROR("Password change failed");
		ret = CMD_CRYPT;
		goto out;
	}

	if (acidfile_keybundle_put(kb, &key, &klen)) {
		ERROR("Failed to serialize new key");
		ret = CMD_FAULT;
		goto out;
	}
	
	memset(prv->data, 0, prv->len);
	free(prv->data);
	prv->data = key;
	prv->len = klen;
	ret = CMD_OK;
	/* Fall through */

out:
	if (kb)
		acid_keybundle_free(kb);
	if (e && ec != CC_OK)
		*e = ec;
	if (name)
		free(name);
	if (opw) {
		memset(opw, 0, olen);
		free(opw);
	}
	if (npw) {
		memset(npw, 0, nlen);
		free(npw);
	}
	return ret;
}

