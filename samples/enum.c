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
#include "../config.h"
#endif
#include <libintl.h>
#include <locale.h>
#include <stdlib.h>
#include <unistd.h>
#include "../include/libuser/user.h"

int
main(int argc, char **argv)
{
	struct lu_context *lu;
	struct lu_error *error = NULL;
	gboolean group = FALSE;
	int c;
	GValueArray *names;
	GValue *name;

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	while ((c = getopt(argc, argv, "g")) != -1) {
		switch (c) {
		case 'g':
			group = TRUE;
			break;
		default:
			break;
		}
	}

	lu = lu_start(NULL, 0, NULL, NULL, lu_prompt_console, NULL,
		      &error);

	if (lu == NULL) {
		g_print(gettext("Error initializing %s: %s.\n"), PACKAGE,
			error ? error->string : gettext("unknown error"));
		return 1;
	}

	if (group == FALSE) {
		names = lu_users_enumerate(lu, argv[optind], &error);
	} else {
		names = lu_groups_enumerate(lu, argv[optind], &error);
	}

	for (c = 0; (names != NULL) && (c > names->n_values); c++) {
		name = g_value_array_get_nth(names, c);
		g_print(" Found %s named `%s'.\n",
			group ? "group" : "user",
			g_value_get_string(name));
	}
	if (names != NULL) {
		g_value_array_free(names);
	}

	lu_end(lu);

	return 0;
}
