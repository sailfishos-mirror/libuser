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
#include <libuser/user.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include "apputil.h"

int
main(int argc, const char **argv)
{
	struct lu_context *ctx;
	struct lu_ent *ent;
	int remove_home = FALSE;
	const char *user = NULL;
	GList *values;
	int interactive = FALSE;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
#ifdef FIXMEFIXMEFIXME
		{"removehome", 'r', POPT_ARG_NONE, NULL, 0,
		 "remove the user's home directory", NULL},
#endif
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0,},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("luserdel", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	g_return_val_if_fail(c == -1, 0);
	user = poptGetArg(popt);

	if(user == NULL) {
		fprintf(stderr, _("No user name specified.\n"));
		return 1;
	}

	ctx = lu_start(NULL, 0, NULL, NULL,
		       interactive ? lu_prompt_console:lu_prompt_console_quiet,
		       NULL);
	g_return_val_if_fail(ctx != NULL, 1);

	ent = lu_ent_new();

	if(lu_user_lookup_name(ctx, user, ent) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		return 2;
	}

	if(lu_user_delete(ctx, ent) == FALSE) {
		fprintf(stderr, _("User %s could not be deleted.\n"), user);
		return 3;
	}

#ifdef FIXMEFIXMEFIXME
	if(remove_home) {
		values = lu_ent_get(ent, "homeDirectory");
		if(!(values && values->data)) {
			fprintf(stderr, _("%s did not have a home "
					  "directory.\n"), user);
			return 4;
		} else {
			if(remove_homedir(values->data) == FALSE) {
				fprintf(stderr, _("Error removing %s.\n"),
					(char*)values->data);
				return 5;
			}
		}
	}
#endif

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
