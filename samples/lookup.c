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
#include "../lib/user_private.h"

int
main(int argc, char **argv)
{
	struct lu_context *lu;
	gboolean success = FALSE, group = FALSE, byid = FALSE;
	int c;
	struct lu_ent *ent, *tmp;
	struct lu_error *error = NULL;
	const char *modules = NULL;

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	while ((c = getopt(argc, argv, "m:gn")) != -1) {
		switch (c) {
		case 'g':
			group = TRUE;
			break;
		case 'n':
			byid = TRUE;
			break;
		case 'm':
			modules = optarg;
			break;
		default:
			break;
		}
	}

	lu = lu_start(NULL, 0, modules, modules,
		      lu_prompt_console, NULL, &error);

	if (lu == NULL) {
		g_print(gettext("Error initializing %s: %s\n"), PACKAGE,
			error ? error->string : gettext("unknown error"));
		return 1;
	}

	c = optind < argc ? atol(argv[optind]) : 0;

	tmp = lu_ent_new();
	if (group) {
		if (byid) {
			g_print(gettext("Searching for group with ID %d.\n"),
				c);
			success = lu_group_lookup_id(lu, c, tmp, &error);
		} else {
			g_print(gettext("Searching for group named %s.\n"),
				argv[optind]);
			success = lu_group_lookup_name(lu, argv[optind], tmp,
						       &error);
		}
	} else {
		if (byid) {
			g_print(gettext
				("Searching for user with ID %d.\n"), c);
			success = lu_user_lookup_id(lu, c, tmp, &error);
		} else {
			g_print(gettext("Searching for user named %s.\n"),
				argv[optind]);
			success =
			    lu_user_lookup_name(lu, argv[optind], tmp,
						&error);
		}
	}

	ent = tmp;
	if (success) {
		fflush(NULL);
		lu_ent_dump(ent, stdout);
		fflush(NULL);
	} else {
		g_print(gettext("Entry not found.\n"));
	}

	lu_ent_free(ent);

	lu_end(lu);

	return 0;
}
