/* Copyright (C) 2000,2001 Red Hat, Inc.
 *
 * This is free software; you can redistribute it and/or modify it under 
 * the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public 
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ident "$Id$"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <libuser/user_private.h>
#include <crypt.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define LU_DEFAULT_SALT_TYPE "$1$"

gint
lu_str_case_equal(gconstpointer v1, gconstpointer v2)
{
	g_return_val_if_fail(v1 != NULL, 0);
	g_return_val_if_fail(v2 != NULL, 0);
	return (g_strcasecmp((char*)v1, (char*)v2) == 0);
}

gint
lu_str_equal(gconstpointer v1, gconstpointer v2)
{
	g_return_val_if_fail(v1 != NULL, 0);
	g_return_val_if_fail(v2 != NULL, 0);
	return (strcmp((char*)v1, (char*)v2) == 0);
}

#define UNACCEPTABLE "!*:$,"
#define ACCEPTABLE "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
		   "abcdefghijklmnopqrstuvwxyz" \
		   "./0123456789"

static gboolean
is_acceptable(const char c)
{
#ifdef VIOLATE_SUSV2
	return (strchr(UNACCEPTABLE, c) == NULL);
#else
	return (strchr(ACCEPTABLE, c) != NULL);
#endif
}

static void
fill_urandom(char *output, size_t length)
{
	int fd;
	size_t got = 0;

	fd = open("/dev/urandom", O_RDONLY);
	g_return_if_fail(fd != -1);

	memset(output, '\0', length);

	while(got < length) {
		read(fd, output + got, 1);
		if(isprint(output[got]) &&
		   !isspace(output[got]) &&
		   is_acceptable(output[got])) {
			got++;
		}
	}

	close(fd);
}

const char *
lu_make_crypted(const char *plain, const char *previous)
{
	char salt[2048];
	char *p;
	size_t stlen = 0;

	memset(salt, '\0', sizeof(salt));

	if((previous != NULL) && (previous[0] == '$')) {
		/* If we got a previous salt, and it's got a dollar sign,
		 * figure out the length of the salt type. */
		p = strchr(previous + 1, '$');
		if(p) {
			p++;
			stlen = p - previous;
			if(stlen > 2048) {
				stlen = 2048;
			}
		}
		strncpy(salt, previous, stlen);
	} else if((previous != NULL) && (previous[0] != '$')) {
		/* Otherwise, it's a standard descrypt(). */
		stlen = 0;
	} else if(previous == NULL) {
		/* Fill in the default crypt length. */
		strncpy(salt, LU_DEFAULT_SALT_TYPE, sizeof(salt) - 1);
		stlen = strlen(salt);
	}

	fill_urandom(salt + stlen, sizeof(salt) - stlen - 1);

	return crypt(plain, salt);
}
