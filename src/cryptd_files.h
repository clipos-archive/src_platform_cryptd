// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file cryptd_files.h
 * Cryptd file access header.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * Copyright (C) 2010 ANSSI
 * @n
 * All rights reserved.
 */

#ifndef _CRYPTD_FILES_H
#define _CRYPTD_FILES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

/** @name File access helpers  */
/*@{*/

/**
 * Read from a file descriptor into a pre-allocated buffer.
 * Just like read(2), but handles interruptions, and reads
 * exactly the requested number of bytes, or returns an
 * error.
 * @param fd File descriptor to read from. Must have been
 * opened by the caller, with O_RDONLY or O_RDWR.
 * @param buf Buffer to read into. Must have been allocated by
 * the caller to a length of at least @a len.
 * @param len Length to read from the file.
 * @param name Name of the file to read from (null-terminated), for
 * logging purposes only.
 * @return CMD_OK on success (@a len bytes have been read), CMD error
 * code on failure (including CMD_FAULT if less than @a len bytes could
 * be read into @a buf).
 */
extern uint32_t cryptd_read_fd(int fd, char *buf, size_t len, const char *name);

/**
 * Read from a file into a pre-allocated buffer.
 * This opens the file at the path requested by the caller, 
 * and reads exactly the requested number of bytes into a buffer
 * allocated by the caller, or returns an error. Note that the 
 * file is opened with the O_RDONLY|O_NOFOLLOW flags.
 * @param name Path to the file to read from.
 * @param buf Buffer to read into. Must have been allocated by
 * the caller to a length of at least @a len.
 * @param len Length to read from the file.
 * @return CMD_OK on success (@a len bytes have been read), CMD error
 * code on failure (including CMD_FAULT if less than @a len bytes could
 * be read into @a buf).
 */
extern uint32_t cryptd_read_file(const char *name, char *buf, size_t len);

/**
 * Read the whole content of a file into a new buffer.
 * This opens the file at the path requested by the caller,
 * and reads its whole content into a new buffer, which is allocated
 * by the function, then returns the allocated buffer and its length
 * to the caller.
 * Note that the file is opened with the O_RDONLY|O_NOFOLLOW flags.
 * @param name Path to the file to read from.
 * @param data Where the allocated buffer should be returned.
 * @param len Where the length of the allocated buffer should be returned.
 * @return CMD_OK on success (@a data and @a len set to non-null values), 
 * CMD error otherwise (@a data and @a len left untouched).
 */
extern uint32_t cryptd_get_file(const char *name, char **data, size_t *len);

/**
 * Read the whole content of a file, while holding a lock to that file.
 * This does exactly the same thing as @a read_file(), but puts a lock
 * on the directory holding the file before opening it.
 * More precisely, the file named 'lock', in the same directory as 
 * @a path, is created if needed, then is locked for reading (F_RDLCK
 * fcntl() cooperative lock), before an attempt is made to open the file
 * under @a path for reading. The lock is systematically released before
 * returning. Taking the lock is a blocking call - the function will wait
 * (possibly indefinitely) for the lock to be available.
 * @see get_file()
 * @param name Path to the file to read from.
 * @param data Where the allocated buffer should be returned.
 * @param len Where the length of the allocated buffer should be returned.
 * @return CMD_OK on success (@a data and @a len set to non-null values), 
 * CMD error otherwise (@a data and @a len left untouched).
 */
extern uint32_t cryptd_get_file_locked(const char *name, char **data, size_t *len);

struct stat;
/**
 * Read the whole content of a file (without locking) into a new buffer, and
 * return that buffer and the stats for the file that was read.
 * This does the same thing as @a read_file(), but also returns the struct stat
 * for the read file. This avoids the race condition incurred when doing a 
 * stat() call on the same path before or after reading.
 * @see get_file()
 * @param name Path to the file to read from.
 * @param data Where the allocated buffer should be returned.
 * @param len Where the length of the allocated buffer should be returned.
 * @param st Where to return the stat structure for the file read. Must be allocated
 * by caller.
 * @return CMD_OK on success (@a data and @a len set to non-null values), 
 * CMD error otherwise (@a data and @a len left untouched).
 */
extern uint32_t cryptd_get_file_stat(const char *name, char **data, 
						size_t *len, struct stat *st);

/**
 * Create a new file, and write the contents of a memory buffer to it.
 * Note that in case an error is returned because all bytes
 * could not be written, deleting the created file is a responsibility of
 * the caller.
 * @param name Path to the file to be created.
 * @param buf Memory buffer to write to the file.
 * @param len Number of bytes to write to the file.
 * @param overwrite If non-null, the function will overwrite preexisting
 * files at @a name. By default, a preexisting file will not be overwritten,
 * and the function will return a CMD_EXIST error code.
 * @return CMD_OK on success, CMD error code on failure.
 */
extern uint32_t cryptd_write_file(const char *name, const char *buf, 
				size_t len, int overwrite);

/*@}*/

/*********************/
/*  cleartext file   */
/*********************/

/**
 * Cleartext file metadata.
 */
struct file_meta {
	uint32_t attrs; /**< Bitmask of file attributes (ACID attributes). */
	time_t ctime;	/**< File creation time. */
	time_t mtime;	/**< File last modification time. */
	time_t atime;	/**< File last access time. */
} __attribute__((packed));

/**
 * Cleartext file representation.
 */
typedef struct file {
	char *content;	/**< Content of the file. */
	uint32_t clen;	/**< File content length. */
	
	char *path;	/**< File path (null terminated, unix-style)
				N.B. : server-side will ensure null 
				termination and convert windoze paths
				to unix ones.  Paths are converted back to
				windoze style in encrypted archives.
			*/
	uint32_t plen;	/**< File path length, including trailing null. */

	char *hash;	/**< Optional CCSD hash of the file's content. */
	uint32_t hlen;  /**< Optional CCSD hash length. */
	
	struct file_meta *meta; /**< File metadata. */
	
	uint32_t uid;	/**< Uid of the client that imported the file.
			Daemon internal: used only by diode. */
	struct file *next, *prev; /**< File double-linked chaining. */
} file_t;


/**
 * Allocate a new, empty file structure.
 * Note that file metadata struct is not allocated.
 * @return Pointer to allocated file, NULL on error.
 */
static inline file_t *
file_alloc(void)
{
	file_t* _new = (file_t*) calloc(1, sizeof(*_new));

	if (_new) 
		_new->prev = _new->next = _new;

	return _new;
}

/**
 * Erase and free a file structure and its fields.
 * @param file File structure to free.
 */
static inline void
file_free(file_t *file)
{
	if (file->path) {
		memset(file->path, 0, file->plen);
		free(file->path);
	}
	if (file->content) {
		memset(file->content, 0, file->clen);
		free(file->content);
	}
	if (file->hash) {
		free(file->hash);
	}
	if (file->meta) {
		memset(file->meta, 0, sizeof(*(file->meta)));
		free(file->meta);
	}
	free(file);
}

/**
 * Read a file from disk into a new file_t struct.
 * @param name Name (path) of the file to read.
 * @param fullpath If non-zero, include the full path in @a name into
 * the @a path field of the returned file_t. By default, only the file
 * basename is written into @a path.
 * @param file Where to return the allocated file_t.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t cryptd_get_cleartext_file(const char *name, 
				int fullpath, file_t **file);

/**
 * Read a file from disk into a new file_t struct, and encode its name
 * into ISO-8859-1.
 * This is appropriate for files encrypted into a CSA archive, whose 
 * names should be encoded that way.
 * @param name Name (path) of the file to read.
 * @param fullpath If non-zero, include the full path in @a name into
 * the @a path field of the returned file_t. By default, only the file
 * basename is written into @a path.
 * @param file Where to return the allocated file_t.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t cryptd_get_cleartext_file_encode(const char *name, 
				int fullpath, file_t **file);

/**
 * Write a file_t on disk.
 * @param base_path Base path from which to create the file_t path.
 * @param file File to write.
 * @param overwrite If non-zero, existing files will be silently overwritten.
 * By default, existing files result in an error.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t cryptd_write_cleartext_file(const char *base_path, 
					file_t *file, int overwrite);
/**
 * Write a file_t on disk after decoding its name from ISO-8859-1.
 * This is appropriate for files decrypted from a CSA archive, where they
 * are stored with encoded names.
 * @param base_path Base path from which to create the file_t path.
 * @param file File to write.
 * @param overwrite If non-zero, existing files will be silently overwritten.
 * By default, existing files result in an error.
 * @return CMD_OK on success, CMD error on failure.
 */
extern uint32_t cryptd_write_cleartext_file_decode(const char *base_path, 
					file_t *file, int overwrite);


extern uint32_t cryptd_write_pxr(const char *subject, uint32_t slen, 
		const char *content, uint32_t clen, int ow);

#ifdef __cplusplus
}
#endif

#endif /*  _CRYPTD_FILES_H */

