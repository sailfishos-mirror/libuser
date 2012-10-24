/*
 * Copyright (C) 2000-2002, 2004 Red Hat, Inc.
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <config.h>
#include <libintl.h>
#include <locale.h>
#include <stdint.h>
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
	GValueArray *values;
	GValue *value;
	const char *user, *tmp;
	int interactive = FALSE;
	int remove_home = 0, dont_remove_group = 0;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 N_("prompt for all information"), NULL},
		{"dontremovegroup", 'G', POPT_ARG_NONE, &dont_remove_group, 0,
		 N_("don't remove the user's private group, if the user has "
		    "one"), NULL},
		{"removehome", 'r', POPT_ARG_NONE, &remove_home, 0,
		 N_("remove the user's home directory"), NULL},
		POPT_AUTOHELP POPT_TABLEEND
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

	poptFreeContext(popt);

	ctx = lu_start(NULL, 0, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
		return 1;
	}

	ent = lu_ent_new();

	if (lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		return 2;
	}

	if (lu_user_delete(ctx, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s could not be deleted: %s.\n"),
			user, lu_strerror(error));
		return 3;
	}

	lu_nscd_flush_cache("passwd");

	if (!dont_remove_group) {
		values = lu_ent_get(ent, LU_GIDNUMBER);
		if (values == NULL) {
			fprintf(stderr, _("%s did not have a gid number.\n"),
				user);
			return 4;
		} else {
			gid_t gid;

			value = g_value_array_get_nth(values, 0);
			gid = lu_value_get_id(value);
			g_assert(gid != LU_VALUE_INVALID_ID);
			if (lu_group_lookup_id(ctx, gid, ent, &error) == FALSE){
				fprintf(stderr, _("No group with GID %jd "
					"exists, not removing.\n"),
					(intmax_t)gid);
				return 5;
			}
			values = lu_ent_get(ent, LU_GROUPNAME);
			if (values == NULL) {
				fprintf(stderr, _("Group with GID %jd did not "
					"have a group name.\n"),
					(intmax_t)gid);
				return 6;
			}
			value = g_value_array_get_nth(values, 0);
			tmp = g_value_get_string(value);
			if (strcmp(tmp, user) == 0) {
				if (lu_group_delete(ctx, ent, &error)
				    == FALSE){
					fprintf(stderr, _("Group %s could not "
							  "be deleted: %s.\n"),
						tmp, lu_strerror(error));
					return 7;
				}
			}
			lu_nscd_flush_cache("group");
		}
	}

	if (remove_home) {
		values = lu_ent_get(ent, LU_HOMEDIRECTORY);
		if (values == NULL) {
			fprintf(stderr, _("%s did not have a home "
				"directory.\n"), user);
			return 8;
		} else {
			value = g_value_array_get_nth(values, 0);
			tmp = g_value_get_string(value);
			if (lu_homedir_remove(tmp, &error) == FALSE) {
				fprintf(stderr, _("Error removing %s: %s.\n"),
					tmp, lu_strerror(error));
				return 9;
			}
		}
		/* Delete the user's mail spool. */
		if (lu_mail_spool_remove(ctx, ent) != TRUE) {
			fprintf(stderr, _("Error removing mail spool.\n"));
			return 1;
		}
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
