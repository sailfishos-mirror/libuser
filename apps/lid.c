/*
 * Copyright (C) 2001, 2002, 2004, 2006, 2009 Red Hat, Inc.
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

#include <config.h>
#include <grp.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "../lib/user.h"
#include "apputil.h"

static void
do_id (struct lu_context *ctx, const char *name, int nameonly,
       gboolean (*lookup_name) (lu_context_t *, const char *, struct lu_ent *,
				lu_error_t **),
       GValueArray *(*enumerate) (lu_context_t *, const char *, lu_error_t **),
       gboolean (*lookup_member) (lu_context_t *, const char *, struct lu_ent *,
				  lu_error_t **),
       const char *id_attribute, const char *id_descr)
{
	GValueArray *values;
	struct lu_error *error;
	struct lu_ent *ent;

	error = NULL;

	ent = lu_ent_new();
	if (lookup_name(ctx, name, ent, &error) == FALSE) {
		if (error != NULL) {
			fprintf(stderr, _("Error looking up %s: %s\n"), name,
				lu_strerror(error));
			lu_error_free(&error);
		} else
			fprintf(stderr, _("%s does not exist\n"), name);
		exit(1);
	}
	lu_ent_clear_all(ent);

	values = enumerate(ctx, name, &error);
	if (error != NULL) {
		fprintf(stderr, _("Error looking up %s: %s\n"), name,
			lu_strerror(error));
		lu_error_free(&error);
		exit(1);
	}
	if (values != NULL) {
		size_t i;

		for (i = 0; i < values->n_values; i++) {
			GValue *value;
			const char *found;

			value = g_value_array_get_nth(values, i);
			found = g_value_get_string(value);
			if (!nameonly
			    && lookup_member(ctx, found, ent, &error)) {
				GValueArray *attrs;
				id_t id;

				attrs = lu_ent_get(ent, id_attribute);
				if (attrs == NULL)
					id = LU_VALUE_INVALID_ID;
				else {
					value = g_value_array_get_nth(attrs, 0);
					id = lu_value_get_id(value);
				}
				if (id != LU_VALUE_INVALID_ID)
					g_print(" %s(%s=%jd)\n", found,
						id_descr, (intmax_t)id);
				else
					g_print(" %s\n", found);
			} else {
				if (error != NULL)
					lu_error_free(&error);
				g_print(" %s\n", found);
			}
			lu_ent_clear_all(ent);
		}
		g_value_array_free(values);
	}
	lu_ent_free(ent);
}

int
main(int argc, const char **argv)
{
	const char *name;
	struct lu_context *ctx;
	struct lu_error *error = NULL;
	int interactive = FALSE;
	int groupflag = FALSE, nameonly = FALSE;
	int c;
	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		{"group", 'g', POPT_ARG_NONE, &groupflag, 0,
		 "list members of a named group instead of the group "
		 "memberships for the named user", NULL},
		{"onlynames", 'n', POPT_ARG_NONE, &nameonly, 0,
		 "only list membership information by name, and not UID/GID",
		 NULL},
		POPT_AUTOHELP POPT_TABLEEND
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lid", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}
	name = poptGetArg(popt);

	if (name == NULL) {
		if (groupflag) {
			struct group *grp;

			grp = getgrgid(getgid());
			if (grp != NULL) {
				fprintf(stderr, _("No group name specified, "
						  "using %s.\n"), grp->gr_name);
				name = g_strdup(grp->gr_name);
			} else {
				fprintf(stderr, _("No group name specified, "
					"no name for gid %d.\n"), getgid());
				poptPrintUsage(popt, stderr, 0);
				exit(1);
			}
		} else {
			struct passwd *pwd;

			pwd = getpwuid(getuid());
			if (pwd != NULL) {
				fprintf(stderr, _("No user name specified, "
					"using %s.\n"), pwd->pw_name);
				name = g_strdup(pwd->pw_name);
			} else {
				fprintf(stderr, _("No user name specified, "
					"no name for uid %d.\n"),
					getuid());
				poptPrintUsage(popt, stderr, 0);
				exit(1);
			}
		}
	}

	ctx = lu_start(name, groupflag ? lu_user : lu_group, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
		return 1;
	}

	if (groupflag)
		do_id(ctx, name, nameonly, lu_group_lookup_name,
		      lu_users_enumerate_by_group, lu_user_lookup_name,
		      LU_UIDNUMBER, "uid");
	else
		do_id(ctx, name, nameonly, lu_user_lookup_name,
		      lu_groups_enumerate_by_user, lu_group_lookup_name,
		      LU_GIDNUMBER, "gid");

	lu_end(ctx);

	return 0;
}
