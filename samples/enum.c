/*
 * Copyright (C) 2000-2002 Red Hat, Inc.
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
#include "../lib/user.h"

int
main(int argc, char **argv)
{
	struct lu_context *lu;
	struct lu_error *error = NULL;
	gboolean group = FALSE, full = FALSE;
	int c;
	size_t i;
	struct lu_ent *ent;
	GValueArray *names;
	GValue *name;
	GPtrArray *accounts;

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	while ((c = getopt(argc, argv, "fg")) != -1) {
		switch (c) {
		case 'f':
			full = TRUE;
			break;
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

	if (full == FALSE) {
		if (group == FALSE) {
			names = lu_users_enumerate(lu, argv[optind], &error);
		} else {
			names = lu_groups_enumerate(lu, argv[optind], &error);
		}

		for (i = 0; (names != NULL) && (i < names->n_values); i++) {
			name = g_value_array_get_nth(names, i);
			g_print(" Found %s named `%s'.\n",
				group ? "group" : "user",
				g_value_get_string(name));
		}
		if (names != NULL) {
			g_value_array_free(names);
		}
	} else {
		if (group == FALSE) {
			accounts = lu_users_enumerate_full(lu, argv[optind], &error);
		} else {
			accounts = lu_groups_enumerate_full(lu, argv[optind], &error);
		}
		for (i = 0; (accounts != NULL) && (i < accounts->len); i++) {
			ent = g_ptr_array_index(accounts, i);
			g_print("Found account:\n");
			lu_ent_dump(ent, stdout);
			lu_ent_free(ent);
		}
		if (accounts != NULL) {
			g_ptr_array_free(accounts, TRUE);
		}
	}

	lu_end(lu);

	return 0;
}
