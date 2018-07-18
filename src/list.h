// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file list.h
 * Cryptd common double-linked list macros.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * @n
 * All rights reserved.
 */

#ifndef _CRYPTD_LIST_H
#define _CRYPTD_LIST_H

#define list_init(new) (new)->prev = (new)->next = (new)

#define list_empty(node) ((node)->next == (node))

#define list_add(new, head) do {	\
	(new)->prev = (head)->prev; 	\
	(new)->next = (head); 		\
	(head)->prev->next = new; 	\
	(head)->prev = new; 		\
} while (0)

#define list_del(node) do {\
	(node)->prev->next = (node)->next; 	\
	(node)->next->prev = (node)->prev; 	\
	(node)->next = (node)->prev = NULL; 	\
} while (0)

#define list_for_each(iter, head) \
	for (iter = (head)->next; iter != (head); iter = iter->next)
	
#define list_free_all(head, type, fun) do {	\
	type *_iter = (head)->prev; 		\
	while (_iter != (head)) { 		\
		list_del(_iter); 		\
		fun(_iter); 			\
		_iter = (head)->prev; 		\
	}					\
	fun(head);				\
} while (0)

#define list_get_len(head, count, type) do { 	\
	type *_iter;				\
	(count) = 0;				\
	list_for_each(_iter, (head)) {		\
		(count)++;			\
	}					\
} while (0)

#endif /* _CRYPTD_LIST_H */
