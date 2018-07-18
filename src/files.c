// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file files.c
 * Cryptd file access functions.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * @n
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <utime.h>

#ifdef LIBRARY
#include <pthread.h>
#endif
#include <iconv.h>
#include <langinfo.h>

#include "list.h"
#include "cryptd_red.h"
#include "log.h"
#include "cmd.h"
#include <clip/acidfile.h>

/*
 * Documented in cryptd_files.h.
 */
inline uint32_t
cryptd_read_fd(int fd, char *buf, size_t len, const char *name)
{
	size_t remaining;
	ssize_t rlen;
	char *ptr;

	remaining = len;
	ptr = buf;
	while (remaining) {
		rlen = read(fd, ptr, remaining);	
		if (rlen < 0) {
			if (errno == EINTR)
				continue;
			ERROR_ERRNO("Error reading %s", name);
			return errno2cmd(errno);
		}
		if (!rlen) {
			ERROR("Truncated file %s", name);
			return CMD_FAULT;
		}
		ptr += rlen;
		remaining -= rlen;
	}
	
	return CMD_OK;
}

/** Lock file path, relative to the directory holding the accessed file. */
#define LOCK_FILE "lock"

/** 
 * Lock a directory before accessing one of the files it contains.
 * This locking is done by setting a read @a flock type lock on the 
 * file named 'lock' in the directory containing the file.That file
 * is created (with default permissions 0400) if it does not exist
 * yet.
 * The function blocks until the lock can be acquired. Note that it
 * doesn't close the opened lock file, instead returning the opened
 * file descriptor for the caller to unlock and close as she sees fit.
 * @param name Name of the file to be accessed. The lock will be set
 * on a file named <dirname(name)"/lock">.
 * @return positive (>=0) value on success, corresponding to the opened
 * lock file file descriptor, or -1 on error.
 */
static int
lock_dir(const char *name)
{
	char *lockname, *ptr;
	int fd;
	struct flock lock = {
		.l_type = F_RDLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
		.l_pid = 0,
	};
	int ret = -1;

	ptr = strrchr(name, '/');
	if (!ptr) {
		ERROR("CCSD file path %s is not absolute\n", name);
		return -1;
	}

	lockname = malloc(ptr - name + sizeof(LOCK_FILE) + 1);
	if (!lockname) {
		ERROR("Cannot allocate memory for lock file name\n");
		return -1;
	}
	sprintf(lockname, "%.*s/%s", ptr - name, name, LOCK_FILE);

	fd = open(lockname, O_RDONLY|O_NOFOLLOW);
	if (fd == -1 && errno == ENOENT)
		fd = open(lockname, O_RDONLY|O_NOFOLLOW|O_CREAT|O_EXCL, S_IRUSR);
	if (fd == -1) {
		ERROR_ERRNO("Cannot open lock file %s\n", lockname);
		goto out_free;
	}
	if (fcntl(fd, F_SETLKW, &lock)) {
		ERROR_ERRNO("Cannot lock lock file %s\n", lockname);
		if (close(fd))
			ERROR_ERRNO("Cannot close lock file %s\n", lockname);
		goto out_free;
	}
	ret = fd;
	/* Fall through */
out_free:
	free(lockname);
	return ret;
}

/**
 * Release a lock taken through lock_dir().
 * @param fd File descriptor for the locked file, as returned by @a lock_dir()
 * @param name Name of the file to which access was protected by the lock 
 * (for logging purposes only).
 * @return 0 on success, -1 on failure.
 */
static int
unlock_dir(int fd, const char *name)
{
	struct flock lock = {
		.l_type = F_UNLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
		.l_pid = 0,
	};
	int ret = -1;

	if (fcntl(fd, F_SETLK, &lock)) {
		ERROR_ERRNO("Cannot unlock lock file for %s\n", name);
		goto out_close;
	}
	ret = 0;
out_close:
	if (close(fd))
		ERROR_ERRNO("Cannot close lock file for %s\n", name);
	return ret;
}

/*
 * Documented in cryptd_files.h.
 */
uint32_t
cryptd_get_file_stat(const char *name, char **data, size_t *len, struct stat *st)
{
	int fd;
	size_t flen;
	char *buf;
	uint32_t ret;

	fd = open(name, O_RDONLY|O_NOFOLLOW);
	if (fd == -1) {
		ERROR_ERRNO("Could not open %s", name);
		return errno2cmd(errno);
	}
	if (fstat(fd, st)) {
		ERROR_ERRNO("Could not fstat %s", name);
		ret = errno2cmd(errno);
		goto out_close;
	}

	flen = st->st_size;
	if (!flen) {
		ERROR("empty file: %s", name);
		ret = CMD_EMPTY;
		goto out_close;
	}

	buf = malloc(flen);
	if (!buf) {
		ERROR("out of memory reading %s", name);
		ret = CMD_NOMEM;
		goto out_close;
	}

	ret = cryptd_read_fd(fd, buf, flen, name);
	if (ret != CMD_OK)
		goto out_free;

	if (close(fd)) {
		ERROR_ERRNO("Could not close %s", name);
		ret = errno2cmd(errno);
		goto out_free; /* Double close, should fail anyway */
	}

	*data = buf;
	*len = flen;
	return CMD_OK;

out_free:
	memset(buf, 0, flen);
	free(buf);
out_close:
	(void)close(fd);
	
	return ret;
}

/*
 * Documented in cryptd_files.h.
 */
uint32_t
cryptd_get_file(const char *name, char **data, size_t *len)
{
	struct stat st;

	return cryptd_get_file_stat(name, data, len, &st);
}

/*
 * Documented in cryptd_files.h.
 */
uint32_t
cryptd_get_file_locked(const char *name, char **data, size_t *len)
{
	int lockfd;
	uint32_t ret;

	lockfd = lock_dir(name);
	if (lockfd == -1)
		return CMD_FAULT;
	ret = cryptd_get_file(name, data, len);
	(void)unlock_dir(lockfd, name);

	return ret;
}

/*
 * Documented in cryptd_files.h.
 */
uint32_t
cryptd_read_file(const char *name , char *buf, size_t len)
{
	int fd;
	uint32_t ret;
	
	fd = open(name, O_RDONLY|O_NOFOLLOW);
	if (fd == -1) {
		ERROR_ERRNO("Could not open %s", name);
		return errno2cmd(errno);
	}

	ret = cryptd_read_fd(fd, buf, len, name);
	(void)close(fd);
	return ret;
}

/*
 * Documented in cryptd_files.h.
 */
uint32_t
cryptd_write_file(const char *name, const char *data, size_t len, int overwrite)
{
	int fd;
	size_t remaining;
	const char *ptr;
	ssize_t wlen;

	uint32_t ret;

	int flags;
	if (overwrite)
		flags = O_WRONLY|O_NOFOLLOW|O_CREAT|O_TRUNC;
	else
		flags = O_WRONLY|O_NOFOLLOW|O_CREAT|O_EXCL;

	fd = open(name, flags, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		ERROR_ERRNO("Could not open %s", name);
		return errno2cmd(errno);
	}

	ptr = data;
	remaining = len;

	while (remaining) {
		wlen = write(fd, ptr, remaining);
		if (wlen < 0) {
			if (errno == EINTR)
				continue;
			ERROR_ERRNO("Error writing to %s", name);
			ret = errno2cmd(errno);
			goto out_close;
		}
		if (!wlen) {
			ERROR("Short write on %s ?", name);
			ret = CMD_FAULT;
			goto out_close;
		}
		
		ptr += wlen;
		remaining -= wlen;
	}

	ret = CMD_OK;
	/* Fall through */
out_close:
	if (close(fd)) {
		ERROR_ERRNO("Could not close %s", name);
		return errno2cmd(errno);
	}
	return ret;
}

/*********************************************/
/* codeset handling for encrypted file names */
/*********************************************/

/* Cryptofiler stores filenames in ISO-8859 - let's do the same.
 * Note: on the other hand, the certificate fields in key bundles 
 * (e.g. subject name) seem (as far as I can tell) to be UTF-8. 
 * Go figure. 
 */

/** 
 * Iconv handle to encode path names stored in a CSA archive.
 * Converts from current locale encoding to ISO-8859.
 * Protected (in library code) by @a iconv_lock mutex.
 */
static iconv_t encode_conv = (iconv_t)-1;

/** 
 * Iconv handle to decode path names stored in a CSA archive.
 * Converts from ISO-8859 to current locale encoding.
 * Protected (in library code) by @a iconv_lock mutex.
 */
static iconv_t decode_conv = (iconv_t)-1;

#ifdef LIBRARY
/**
 * Pthread mutex to protect @a encode_conv and @a decode_conv
 * from concurrent accesses.
 */
static pthread_mutex_t iconv_lock;

void acidfile_mutex_init(void) _attr(constructor, visibility("hidden"));
void acidfile_mutex_exit(void) _attr(destructor, visibility("hidden"));

/**
 * Library constructor : initialize the @a iconv_lock mutex.
 */
void _attr(constructor, visibility("hidden"))
acidfile_mutex_init(void)
{
	int perr = pthread_mutex_init(&iconv_lock, NULL);
	if (perr) {
		ERROR("Failed to initialize mutex: %s", strerror(perr));
		abort();
	}
}

/**
 * Library destructor : destroy the @a iconv_lock mutex.
 */
void _attr(destructor, visibility("hidden"))
acidfile_mutex_exit(void)
{
	int perr = pthread_mutex_destroy(&iconv_lock);
	if (perr) {
		ERROR("Failed to destroy mutex: %s", strerror(perr));
	}
}
#endif

/**
 * Convert a path name between ISO-8859 and the current locale encoding.
 * @param in Path name to convert.
 * @param outptr Where to store the converted path name.
 * @param encode_p Boolean : non-zero when encoding (convert from locale 
 * to ISO), zero when decoding (convert from ISO to locale).
 * @return 0 on success, -1 on error.
 */
static int 
convert_filename(char *in, char **outptr, int encode_p)
{
	iconv_t conv;
	char *buf = NULL, *out;
	size_t inlen, outlen;

#ifdef LIBRARY
	int perr;

	perr = pthread_mutex_lock(&iconv_lock);
	if (perr) {
		ERROR("Failed to lock library mutex: %s", strerror(perr));
		return -1;
	}
#endif

	inlen = strlen(in) + 1;
	if (encode_p) {
		/* Encoding: from locale encoding to ISO */
		if (encode_conv == (iconv_t)-1)
			encode_conv = iconv_open("ISO-8859-15//IGNORE", 
							nl_langinfo(CODESET));
		conv = encode_conv;
		/* Since we're converting to a monobyte format, 
		 * the output length is at most as much as the 
		 * input length */
		outlen = inlen; 
	} else {
		/* Decoding: from ISO to locale encoding */
		if (decode_conv == (iconv_t)-1)
			decode_conv = iconv_open(nl_langinfo(CODESET), 
								"ISO-8859-15");
		conv = decode_conv;
		/* If converting to e.g. UTF-8, we might need 4 bytes 
		 * per character at most. This may or may not be enough
		 * for more exotic encodings, in which case an error might
		 * be raised - but I don't believe the likelyhood of this 
		 * happening warrants the extra pain it would take to handle
		 * it.
		 */
		outlen = 4U * inlen;
	}
		
	if (conv == (iconv_t)-1) {
		ERROR_ERRNO("Failed to create encoding converter");
		goto err;
	}

	buf = malloc(outlen);
	if (!buf) {
		ERROR("Out of memory for converted path");
		goto err;
	}
	memset(buf, 0, outlen);

	/* Reset converter's state first */
	(void)iconv(conv, NULL, NULL, NULL, NULL);

	out = buf; /* iconv increments the pointer ... */
	if (iconv(conv, &in, &inlen, &out, &outlen) == (size_t)-1) {
		ERROR_ERRNO("Encoding conversion failed");
		goto err;
	}

#ifdef LIBRARY
	(void)pthread_mutex_unlock(&iconv_lock);
#endif
	*outptr = buf;
	return 0;

err:
#ifdef LIBRARY
	(void)pthread_mutex_unlock(&iconv_lock);
#endif

	if (buf)
		free(buf);
	return -1;
}

static inline int
encode_filename(char *in, char **outptr)
{
	return convert_filename(in, outptr, 1);
}

static inline int
decode_filename(char *in, char **outptr)
{
	return convert_filename(in, outptr, 0);
}

/*************************/
/*    cleartext files    */
/*************************/

#define PUBKEY_EXT ".acidppr"

static uint32_t 
get_cleartext_file(const char *name, int fullpath, file_t **out, int encode)
{
	struct stat st;
	char *path = NULL;
	file_t *file = file_alloc();
	uint32_t ret;

	if (!file) {
		ERROR("Out of memory getting %s", name);
		return CMD_NOMEM;
	}

	file->meta = malloc(sizeof(*(file->meta)));
	if (!file->meta) {
		ERROR("Out of memory getting %s", name);
		ret = CMD_NOMEM;
		goto err;
	}
	ret = cryptd_get_file_stat(name, &(file->content), &(file->clen), &st);
	if (ret != CMD_OK) {
		ERROR("Could not get content of %s", name);
		goto err;
	}
	if (fullpath)
		path = strdup(name);
	else
		path = strdup(basename(name));

	if (!path) {
		ERROR("Out of memory getting %s", name);
		ret = CMD_NOMEM;
		goto err;
	}

	if (encode) {
		if (encode_filename(path, &(file->path))) {
			ERROR("Failed to convert input file name");
			ret = CMD_INVAL;
			goto err;
		}
		free(path);
		path = NULL;
	} else {
		file->path = path;
		path = NULL;
	}
	
	file->plen = strlen(file->path) + 1;
	file->meta->ctime = st.st_ctime;
	file->meta->mtime = st.st_mtime;
	file->meta->atime = st.st_atime;
	file->meta->attrs = 0U;

	*out = file;

	return CMD_OK;
	
err:
	if (path)
		free(path);
	file_free(file);
	return ret;
}

/*
 * Documented in cryptd_files.h.
 */
uint32_t 
cryptd_get_cleartext_file_encode(const char *name, int fullpath, file_t **out)
{
	return get_cleartext_file(name, fullpath, out, 1);
}

/*
 * Documented in cryptd_files.h.
 */
uint32_t 
cryptd_get_cleartext_file(const char *name, int fullpath, file_t **out)
{
	return get_cleartext_file(name, fullpath, out, 0);
}


static inline uint32_t
_put_file(const file_t *file, int ow, int decode)
{
	char *ptr, *path, *dpath = NULL;
	size_t len;
	ssize_t wlen;
	uint32_t ret;
	const struct timeval tv[2] = {
		{ 
			.tv_sec = file->meta->atime,
			.tv_usec = 0,
		},
		{
			.tv_sec = file->meta->mtime,
			.tv_usec = 0,
		}
	};
	int flags, fd = -1;

	if (ow)
		flags = O_WRONLY|O_NOFOLLOW|O_CREAT|O_TRUNC;
	else
		flags = O_WRONLY|O_NOFOLLOW|O_CREAT|O_EXCL;

	if (decode) {
		if (decode_filename(file->path, &dpath)) {
			ERROR("Failed to decode file path");
			return CMD_INVAL;
		}
		path = dpath;
	} else {
		path = file->path;
	}

	fd = open(path, flags, S_IRUSR|S_IWUSR);
	if (fd == -1) {
		ERROR_ERRNO("create %s", path);
		ret = errno2cmd(errno);
		goto out;
	}

	ptr = file->content;
	len = file->clen;
	for (;;) {
		wlen = write(fd, ptr, len);
		if (wlen < 0) {
			if (errno == EINTR)
				continue;
			ERROR_ERRNO("write %s", path);
			ret = errno2cmd(errno);
			goto out;
		}
		len -= wlen;
		ptr += wlen;
		if (!len)
			break;
	}

	if (futimes(fd, tv)) {
		ERROR_ERRNO("futimes %s", path);
		ret = errno2cmd(errno);
		goto out;
	}
	ret = CMD_OK;
	/* Fall through */
out:
	if (fd != -1 && close(fd))
		ERROR_ERRNO("close %s", path);
	if (dpath)
		free(dpath);
	return ret;
}

static inline uint32_t
_try_mkdir(const char *path, int ow)
{
	struct stat st;
	if (!mkdir(path, S_IRWXU))
		return 0;

	if (errno != EEXIST) {
		ERROR_ERRNO("mkdir %s", path);
		return errno2cmd(errno);
	}
	
	/* File or directory exists */

	/* Racy, but should not be an issue */
	if (stat(path, &st)) {
		ERROR_ERRNO("stat dir %s", path);
		return errno2cmd(errno);
	}

	if (S_ISDIR(st.st_mode))
		return 0;

	/* Not a directory */
	if (!ow) {
		ERROR("Path %s exists and is not a dir, will not overwrite it",
				path);
		return CMD_EXIST;
	}

	/* Overwrite path */
	if (unlink(path)) {
		ERROR_ERRNO("unlink dir path %s", path);
		return errno2cmd(errno);
	}

	if (mkdir(path, S_IRWXU)) {
		ERROR_ERRNO("mkdir %s (2nd try)", path);
		return errno2cmd(errno);
	}
		
	return CMD_OK;
}

static inline uint32_t
_put_dir(const file_t *dir, int ow, int decode, int do_utime)
{
	uint32_t ret;
	/* There are some who call me ... Tim ? */
	const struct utimbuf tim = {
		.actime = dir->meta->atime,
		.modtime = dir->meta->mtime,
	};
	char *path, *dpath = NULL;

	if (decode) {
		if (decode_filename(dir->path, &dpath)) {
			ERROR("Failed to decode directory path");
			return CMD_INVAL;
		}
		path = dpath;
	} else {
		path = dir->path;
	}

	ret = _try_mkdir(path, ow);
	if (ret != CMD_OK) {
		free(path);
		return ret;
	}

	/* Hmmm, nice and racy... */
	if (do_utime && utime(path, &tim)) {
		ERROR_ERRNO("utime %s", path);
		free(path);
		return errno2cmd(errno);
	}

	if (dpath)
		free(dpath);
	return CMD_OK;
}

uint32_t
cryptd_write_pxr(const char *subject, uint32_t slen, 
		const char *content, uint32_t clen, int ow)
{
	int fd, tmp, flags;
	uint32_t ret;
	const char *ptr;
	char *path = NULL;
	size_t len, plen;
	ssize_t wlen;
	
	plen = slen + sizeof(PUBKEY_EXT);
	path = malloc(plen);
	if (!path) {
		ERROR("Out of memory allocating public key path for %s",
					subject);
		return CMD_NOMEM;
	}
	tmp = snprintf(path, plen, "%.*s%s", slen, subject, PUBKEY_EXT);
	if ((size_t)tmp != plen - 1) {
		ERROR("Truncated output while writing public key "
			"path for %.*s (%d != %u)", slen, subject, tmp, plen - 1);
		ret = CMD_FAULT;
		goto out;
	}
	
	if (ow)
		flags = O_WRONLY|O_NOFOLLOW|O_CREAT|O_TRUNC;
	else
		flags = O_WRONLY|O_NOFOLLOW|O_CREAT|O_EXCL;

	fd = open(path, flags, S_IRUSR|S_IWUSR);
	if (fd == -1) {
		ERROR_ERRNO("create %s", path);
		ret = errno2cmd(errno);
		goto out;
	}

	ptr = content;
	len = clen;
	for (;;) {
		wlen = write(fd, ptr, len);
		if (wlen < 0) {
			if (errno == EINTR)
				continue;
			ERROR_ERRNO("write %s", path);
			ret = errno2cmd(errno);
			goto out_closefd;
		}
		len -= wlen;
		ptr += wlen;
		if (!len)
			break;
	}

	ret = CMD_OK;

	/* Fall through */
out_closefd:
	if (close(fd))
		ERROR_ERRNO("close %s", path);

	/* Fall through */
out:
	if (path)
		free(path);
	return ret;
}

static inline uint32_t
put_one_file(file_t *file, int ow, int decode)
{
	char *ptr = file->path;
	uint32_t ret;

	/* Create subdirs, as needed */
	while ((ptr = strchr(ptr, '/'))) {
		*ptr = '\0';
		ret = _put_dir(file, ow, decode, 0);
		if (ret != CMD_OK) {
			*ptr = '/';
			return ret;
		}
		*ptr++ = '/';
	}

	if (file->meta->attrs & ACID_FATTR_DIR)
		return _put_dir(file, ow, decode, 1);
	else 
		return _put_file(file, ow, decode);
}

static uint32_t 
write_cleartext_file(const char *path, file_t *file, int overwrite, int decode)
{
	char *cwd;
	uint32_t ret;
	
	cwd = get_current_dir_name();
	if (!cwd) {
		ERROR_ERRNO("getcwd");
		return errno2cmd(errno);
	}

	if (chdir(path)) {
		ERROR_ERRNO("chdir %s", path);
		free(cwd);
		return errno2cmd(errno);
	}

	ret = _put_file(file, overwrite, decode);
	if (ret != CMD_OK) {
		ERROR("Failed to put %.*s", file->plen, file->path);
		goto out;
	}

	printf("%.*s written to %s\n", file->plen, file->path, path);
	/* Fall through */
out:
	if (chdir(cwd))
		ERROR_ERRNO("chdir %s", cwd);

	free(cwd);
	return ret;
}

/*
 * Documented in cryptd_common.h.
 */
uint32_t 
cryptd_write_cleartext_file_decode(const char *path, file_t *file, int overwrite)
{
	return write_cleartext_file(path, file, overwrite, 1);
}

/*
 * Documented in cryptd_common.h.
 */
uint32_t 
cryptd_write_cleartext_file(const char *path, file_t *file, int overwrite)
{
	return write_cleartext_file(path, file, overwrite, 0);
}

/*
 * Documented in cryptd_red.h.
 */
uint32_t 
cryptd_write_cleartext(const char *path, cleartext_t *clr, int overwrite)
{
	file_t *iter;
	char *cwd;
	uint32_t ret = CMD_EMPTY;
	int cnt = 0;
	
	cwd = get_current_dir_name();
	if (!cwd) {
		ERROR_ERRNO("getcwd");
		return errno2cmd(errno);
	}

	if (chdir(path)) {
		ERROR_ERRNO("chdir %s", path);
		free(cwd);
		return errno2cmd(errno);
	}

	list_for_each(iter, clr->files) {
		/* We're writing a bunch of files extracted from a 
		 * CSA archive, we'll assume their names are encoded
		 * inISO-8859-1.
		 */
		ret = put_one_file(iter, overwrite, 1);
		if (ret != CMD_OK) {
			ERROR("Failed to put %s", iter->path);
			goto out;
		}
		cnt++;
	}

	if (clr->name && clr->ppr) {
		ret = cryptd_write_pxr(clr->name, clr->nlen, clr->ppr, 
						clr->plen, overwrite);
		if (ret != CMD_OK) {
			ERROR("Failed to put sender's public key");
			goto out;
		}
	}
	
	printf("%d files written to %s\n", cnt, path);
	/* ret = CMD_OK; */
	/* Fall through */
out:
	if (chdir(cwd))
		ERROR_ERRNO("chdir %s", cwd);

	free(cwd);
	return ret;
}


