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
#include <stdio.h>
#include <stdlib.h>
#include <popt.h>
#include <string.h>
#include <unistd.h>
#include "../lib/user.h"
#include "apputil.h"

int
main(int argc, const char **argv)
{
	struct lu_context *ctx;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	GValueArray *values = NULL;
	GValue *value;
	const char *user = NULL, *tmp = NULL;
	gid_t gid;
	int interactive = FALSE;
	int remove_home = 0, dont_remove_group = 0;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		{"dontremovegroup", 'G', POPT_ARG_NONE, &dont_remove_group, 0,
		 "don't remove the user's private group, if the user has one",
		 NULL},
		{"removehome", 'r', POPT_ARG_NONE, &remove_home, 0,
		 "remove the user's home directory", NULL},
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0,},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("luserdel", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}
	user = poptGetArg(popt);

	if (user == NULL) {
		fprintf(stderr, _("No user name specified.\n"));
		poptPrintUsage(popt, stderr, 0);
		return 1;
	}

	ctx = lu_start(NULL, 0, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		if (error != NULL) {
			fprintf(stderr, _("Error initializing %s: %s.\n"),
				PACKAGE, error->string);
		} else {
			fprintf(stderr, _("Error initializing %s.\n"),
				PACKAGE);
		}
		return 1;
	}

	ent = lu_ent_new();

	if (lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		return 2;
	}

	if (lu_user_delete(ctx, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s could not be deleted: %s.\n"),
			user, error->string);
		return 3;
	}

	lu_hup_nscd();

	if (!dont_remove_group) {
		values = lu_ent_get(ent, LU_GIDNUMBER);
		if ((values == NULL) || (values->n_values == 0)) {
			fprintf(stderr, _("%s did not have a gid number.\n"),
				user);
			return 4;
		} else {
			value = g_value_array_get_nth(values, 0);
			if (G_VALUE_HOLDS_LONG(value)) {
				gid = g_value_get_long(value);
			} else
			if (G_VALUE_HOLDS_STRING(value)) {
				gid = atol(g_value_get_string(value));
			} else {
				g_assert_not_reached();
			}
			if (lu_group_lookup_id(ctx, gid, ent, &error) == FALSE){
				fprintf(stderr, _("No group with GID %ld "
					"exists, not removing.\n"), (long) gid);
				return 5;
			}
			values = lu_ent_get(ent, LU_GROUPNAME);
			if (values == NULL) {
				fprintf(stderr, _("Group with GID %ld did not "
					"have a group name.\n"), (long) gid);
				return 6;
			}
			value = g_value_array_get_nth(values, 0);
			tmp = g_value_get_string(value);
			if (strcmp(tmp, user) == 0) {
				if (lu_group_delete(ctx, ent, &error) == FALSE){
					fprintf(stderr, _("Group %s could not "
						"be deleted: %s.\n"), tmp,
						error->string);
					return 7;
				}
			}
		}
	}

	lu_hup_nscd();

	if (remove_home) {
		values = lu_ent_get(ent, LU_HOMEDIRECTORY);
		if ((values == NULL) || (values->n_values == 0)) {
			fprintf(stderr, _("%s did not have a home "
				"directory.\n"), user);
			return 8;
		} else {
			value = g_value_array_get_nth(values, 0);
			tmp = g_value_get_string(value);
			if (lu_homedir_remove(tmp, &error) == FALSE) {
				fprintf(stderr, _("Error removing %s: %s.\n"),
					tmp, error->string);
				return 9;
			}
		}
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
