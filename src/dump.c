// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file dump.c
 * Cryptd dump helper.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * @n
 * All rights reserved.
 */

#include <string.h>

#include "list.h"
#include "server.h"
#include "cryptd_red.h"

void
dump(const char *msg, int level, const char *data, uint32_t len) 
{
	int curlen = 0;
	char *ptr, *str;
	size_t mlen = 0;

	if (msg) 
		mlen = strlen(msg);
	/* 2 chars for each byte of data, +1 for space every 4 bytes of data
	 * + 1 for one newline each 32 bytes of data, + 1 for possible newline, 
	 * + 1 for trailing null byte.
	 */
	str = malloc(mlen + 2 * len + len / 4 + len / 32 + 2);
	if (!str) {
		ERROR("Could not alloc dump buffer");
		return;
	}
	ptr = str;
	if (mlen) {
		memcpy(ptr, msg, mlen);
		ptr += mlen;
	}
	while (len--) {
		sprintf(ptr, "%02x", *data++ & 0xff);
		/* Note: trailing null byte gets overwritten at
		 * each step.
		 */
		ptr += 2;
		curlen++;
		if (!(curlen % 32)) {
			*(ptr++) = '\n';
		} else if (!(curlen % 4)) {
			*(ptr++) = ' ';
		}
	}
	if (curlen % 32)
		*(ptr++) = '\n';
	*ptr = '\0';

	if (!g_daemonized) {
		fputs(str, stdout);
	} else {
		/* syslog merges multi-line messages in one line, which
		 * is not what we want => we need to feed it one line 
		 * at a time. 
		 */
		char *base = str;
		while ((ptr = strchr(base, '\n'))) {			
			syslog(level, "%.*s\n", ptr - base, base);
			base = ptr + 1;
		}
	}
	free(str);
}

#define _log(fmt, args...) do {\
	if (!g_daemonized) \
		fprintf(stderr, fmt"\n", ##args); \
	else \
		syslog(LOG_AUTHPRIV|LOG_NOTICE, fmt"\n", ##args); \
} while (0)

void
dump_cleartext_decrypt(const cleartext_t *clr)
{
	file_t *fiter;

	_log("CRYPTD DECRYPT: Decrypted cleartext %.*s "
					"from %.*s for %s (uid %u)",
				clr->tlen, clr->title, clr->nlen, 
				clr->name, clr->prv->subject, clr->uid);
	_log("CRYPTD DECRYPT: Decrypted files: ");
	list_for_each(fiter, clr->files) {
		_log("CRYPTD DECRYPT:   %.*s (%u bytes)", fiter->plen, 
						fiter->path, fiter->clen);
		dump("CRYPTD DECRYPT:     with hash: ", 
			LOG_AUTHPRIV|LOG_NOTICE, fiter->hash, fiter->hlen);
	}
	_log("CRYPTD DECRYPT: End of decrypted cleartext dump (%.*s)", 
							clr->tlen, clr->title);
}

void
dump_cleartext_encrypt(const cleartext_t *clr)
{
	file_t *fiter;
	pubkey_t *kiter;

	_log("CRYPTD ENCRYPT: Encrypted cleartext %.*s from %s (uid %u)",
			clr->tlen, clr->title, clr->prv->subject, clr->uid);
	_log("CRYPTD ENCRYPT: Encrypted file names:");
	list_for_each(fiter, clr->files) {
		_log("CRYPTD ENCRYPT:   %.*s (%u bytes)", 
				fiter->plen, fiter->path, fiter->clen);
	}
	if (af_list_empty(clr->pubs)) {
		_log("CRYPTD ENCRYPT: No recipients.");
	} else {
		_log("CRYPTD ENCRYPT: Recipients:");
		list_for_each(kiter, clr->pubs) {
			_log("CRYPTD ENCRYPT: \t%s", kiter->subject);
		}
	}
	_log("CRYPTD ENCRYPT: End of encrypted cleartext dump (%.*s)", clr->tlen, clr->title);
}

void
dump_cleartext_import(const file_t *file)
{
	char *h;
	uint32_t l;

	_log("CRYPTD IMPORT: imported file %.*s (%u bytes) for uid %u",
			file->plen, file->path, file->clen, file->uid);
	if (file->hash) {
		h = file->hash;
		l = file->hlen;
	} else {
		if (acidcrypt_hash(file->content, file->clen, &h, &l, "")) {
			ERROR("Failed to hash %.*s", file->plen, file->path);
			return;
		}
	}
	dump("CRYPTD IMPORT:   with hash: ", LOG_AUTHPRIV|LOG_NOTICE, h, l);
	if (!file->hash)
		free(h);
}
