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
