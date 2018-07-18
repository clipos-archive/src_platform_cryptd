// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file cryptd_features.h
 * Cryptd supported features header.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2010 ANSSI
 * @n
 * All rights reserved.
 */

#ifndef CRYPTD_FEATURES_H
#define CRYPTD_FEATURES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/**
 * Features supported by the daemon (can be enabled when
 * launching the daemon).
 */
typedef enum {
	CryptdCrypt = 	0x0001,	/**< Encryption diode supported */
	CryptdDiode = 	0x0002,	/**< Cleartext diode supported */
	CryptdChPw = 	0x0004, /**< Password change on PVR supported */
	CryptdEncrypt = 0x0008,	/**< Encryption / decryption on 
				     red socket supported */
	CryptdDelete = 	0x0010, /**< Deletion of input ciphertexts supported
					on red socket */
} cryptd_feature_t;

/**
 * Information about the daemon, transmitted to clients.
 * Describes both the daemon version, and the features
 * supported by the running daemon.
 */
typedef struct {
	uint32_t version;	/**< Cryptd daemon version */
	uint32_t features;	/**< Cryptd daemon supported features */
} __attribute__((packed)) cryptd_info_t;

#ifdef __cplusplus
}
#endif

#endif /* CRYPTD_FEATURES_H */
