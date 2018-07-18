// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file crypt_ccsd.c
 * Cryptd CCSD crypto backend.
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * Copyright (C) 2008-2009 SGDN
 * @n
 * All rights reserved.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>


#include "server.h"
/* Must be after server.h for uint32_t definition */
#include <clip/acidfile.h>
#include <clip/acidcrypt.h>

#include "cleanup.h"

/** 
 * CCSD Malloc.
 * @author DGA-MI
 */
void *
PtrAlloc(I64 x)
{
  return ((x) ? malloc((size_t)(x)) : NULL);
}

/** 
 * CCSD Free.
 * @author DGA-MI
 */
void 
PtrFree(void *ptr)
{
  if (ptr) {free(ptr);}
}

/** 
 * CCSD CurrentDate.
 * @author DGA-MI
 */
I32 
CurrentDate(I32 *p_zone, I32 *p_year, I32 *p_month, 
		I32 *p_day, I32 *p_hour, I32 *p_mn)
{
  time_t tempo;
  struct tm *date;

  time(&tempo);

  date = gmtime(&tempo);

  *p_zone = 'Z';		
  *p_year = 1900+date->tm_year;
  *p_month = date->tm_mon+1;	
  *p_day = date->tm_mday;
  *p_hour = date->tm_hour;
  *p_mn = date->tm_min;
  return(0);
}
