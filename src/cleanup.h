// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file cleanup.h
 * Cryptd cleanup function support.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * @n
 * All rights reserved.
 */

#ifndef CRYPTD_CLEANUP_H
#define CRYPTD_CLEANUP_H

/* 
 * Can't be static (otherwise linker drops it - at least ld 2.18,
 * ld 2.16 was fine with static cleanup fonctions), so we settle
 * for the next best thing - hidden visibility, though that does
 * not change much in an executable...
 */
#define CLEANUP_FN(name) \
	static void name(void); \
	void (*const fn_##name)(void) \
		__attribute__((unused, section("cleanup_fns"), visibility("hidden"))) = &name; \
	static void name(void)
			  
#endif /* CRYPTD_CLEANUP_H */
