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

#include <glib.h>
#include <sys/types.h>
#include <crypt.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include "apputil.h"

static void
fill_urandom(char *output, size_t length)
{
	int fd;
	size_t got = 0;
	const char *unacceptable = "!*:$,";

	fd = open("/dev/urandom", O_RDONLY);
	g_return_if_fail(fd != -1);

	memset(output, '\0', length);

	while(got < length) {
		read(fd, output + got, 1);
		if(isprint(output[got]) &&
		   !isspace(output[got]) &&
		   !strchr(unacceptable, output[got])) {
			got++;
		}
	}

	close(fd);
}

const char *
make_crypted(const char *plain, const char *previous)
{
	char salt[2048];
	char *p;
	size_t stlen = 0;

	memset(salt, '\0', sizeof(salt));

	if((previous != NULL) && (previous[0] == '$')) {
		p = strchr(previous + 1, '$');
		if(p) {
			p++;
			stlen = p - previous;
			if(stlen > 2048) {
				stlen = 2048;
			}
		}
		strncpy(salt, previous, stlen);
	}

	fill_urandom(salt + stlen, sizeof(salt) - stlen - 1);

	return crypt(plain, salt);
}

gboolean
populate_homedir(const char *skeleton, const char *directory,
		 uid_t owner, gid_t group, mode_t mode)
{
	g_print(_("Feature not implemented: "));
	g_print(_("NOT creating home directory '%s'.\n"), directory);
	return FALSE;
}

gboolean
move_homedir(const char *oldhome, const char *directory)
{
	g_print(_("Feature not implemented: "));
	g_print(_("NOT moving %s to %s.\n"), oldhome, directory);
	return FALSE;
}

gboolean
remove_homedir(const char *directory)
{
	g_print(_("Feature not implemented: "));
	g_print(_("NOT removing %s.\n"), directory);
	return FALSE;
}
