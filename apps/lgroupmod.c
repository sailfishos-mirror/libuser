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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include <string.h>
#include "../include/libuser/user_private.h"
#include "apputil.h"

int
main(int argc, const char **argv)
{
	const char *userPassword = NULL, *cryptedUserPassword = NULL,
		   *gid = NULL, *addAdmins = NULL, *remAdmins = NULL,
		   *addMembers = NULL, *remMembers = NULL, *group = NULL,
		   *tmp = NULL;
	char **admins = NULL, **members = NULL;
	long gidNumber = -2, oldGidNumber = -2;
	struct lu_context *ctx = NULL;
	struct lu_ent *ent = NULL;
	struct lu_error *error = NULL;
	GValueArray *values = NULL, *gidvalues = NULL;
	GValue *value, *gidvalue, val;
	int change = FALSE, lock = FALSE, unlock = FALSE;
	int interactive = FALSE;
	int c, i;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		{"gid", 'g', POPT_ARG_LONG, &gidNumber, 0,
		 "gid to change group to", "NUM"},
		{"name", 'n', POPT_ARG_STRING, &gid, 0,
		 "change group to have given name", "NAME"},
		{"plainpassword", 'P', POPT_ARG_STRING, &userPassword, 0,
		 "plaintext password for use with group", "STRING"},
		{"password", 'p', POPT_ARG_STRING, &cryptedUserPassword, 0,
		 "pre-hashed password for use with group", "STRING"},
		{"admin-add", 'A', POPT_ARG_STRING, &addAdmins, 0,
		 "list of administrators to add", "STRING"},
		{"admin-remove", 'a', POPT_ARG_STRING, &remAdmins, 0,
		 "list of administrators to remove", "STRING"},
		{"member-add", 'M', POPT_ARG_STRING, &addMembers, 0,
		 "list of group members to add", "STRING"},
		{"member-remove", 'm', POPT_ARG_STRING, &remMembers, 0,
		 "list of group members to remove", "STRING"},
		{"lock", 'L', POPT_ARG_NONE, &lock, 0, "lock group"},
		{"unlock", 'U', POPT_ARG_NONE, &unlock, 0, "unlock group"},
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lgroupmod", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] group"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}
	group = poptGetArg(popt);

	if (group == NULL) {
		fprintf(stderr, _("No group name specified.\n"));
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

	if (lock && unlock) {
		fprintf(stderr, _("Both -L and -U specified.\n"));
		return 2;
	}

	ent = lu_ent_new();

	if (lu_group_lookup_name(ctx, group, ent, &error) == FALSE) {
		fprintf(stderr, _("Group %s does not exist.\n"), group);
		return 3;
	}

	change = gid || addAdmins || remAdmins || cryptedUserPassword ||
		 addMembers || remMembers || (gidNumber != -2);

	if (gid != NULL) {
		values = lu_ent_get(ent, LU_GROUPNAME);
		lu_ent_clear(ent, LU_GROUPNAME);
		if (values) {
			memset(&val, 0, sizeof(val));
			g_value_init(&val, G_TYPE_STRING);
			g_value_set_string(&val, gid);
			lu_ent_add(ent, LU_GROUPNAME, &val);
		}
	}
	if (gidNumber != -2) {
		values = lu_ent_get(ent, LU_GIDNUMBER);
		if (values) {
			value = g_value_array_get_nth(values, 0);
			oldGidNumber = g_value_get_long(value);
		}

		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_LONG);
		g_value_set_long(&val, gidNumber);

		lu_ent_clear(ent, LU_GIDNUMBER);
		lu_ent_add(ent, LU_GIDNUMBER, &val);
	}

	if (addAdmins) {
		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_STRING);
		admins = g_strsplit(addAdmins, ",", 0);
		if (admins) {
			for (c = 0; admins && admins[c]; c++) {
				g_value_set_string(&val, admins[c]);
				lu_ent_add(ent, LU_ADMINISTRATORUID, &val);
			}
			lu_hup_nscd();
			g_strfreev(admins);
			admins = NULL;
		}
	}
	if (remAdmins) {
		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_STRING);
		admins = g_strsplit(remAdmins, ",", 0);
		if (admins) {
			for (c = 0; admins && admins[c]; c++) {
				g_value_set_string(&val, admins[c]);
				lu_ent_del(ent, LU_ADMINISTRATORUID, &val);
			}
			lu_hup_nscd();
			g_strfreev(admins);
			admins = NULL;
		}
	}

	if (addMembers) {
		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_STRING);
		members = g_strsplit(addMembers, ",", 0);
		if (members) {
			for (c = 0; members && members[c]; c++) {
				g_value_set_string(&val, admins[c]);
				lu_ent_add(ent, LU_MEMBERUID, &val);
			}
			lu_hup_nscd();
			g_strfreev(members);
			members = NULL;
		}
	}
	if (remMembers) {
		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_STRING);
		members = g_strsplit(remMembers, ",", 0);
		if (members) {
			for (c = 0; members && members[c]; c++) {
				g_value_set_string(&val, admins[c]);
				lu_ent_del(ent, LU_MEMBERUID, &val);
			}
			lu_hup_nscd();
			g_strfreev(members);
			members = NULL;
		}
	}

	if (userPassword) {
		if (lu_group_setpass(ctx, ent, userPassword, &error) == FALSE) {
			fprintf(stderr, _("Failed to set password for group "
				"%s.\n"), group);
			return 4;
		}
	}

	if (cryptedUserPassword) {
		char *tmp = NULL;
		tmp = g_strconcat("{crypt}", cryptedUserPassword, NULL);
		if (lu_group_setpass(ctx, ent, tmp, &error) == FALSE) {
			fprintf(stderr, _("Failed to set password for group "
				"%s.\n"), group);
			return 5;
		}
		g_free(tmp);
	}

	if (lock) {
		if (lu_group_lock(ctx, ent, &error) == FALSE) {
			fprintf(stderr, _("Group %s could not be locked.\n"),
				group);
			return 6;
		}
	}

	if (unlock) {
		if (lu_group_unlock(ctx, ent, &error) == FALSE) {
			fprintf(stderr, _("Group %s could not be unlocked.\n"),
				group);
			return 7;
		}
	}

	if (change && lu_group_modify(ctx, ent, &error) == FALSE) {
		fprintf(stderr, _("Group %s could not be modified.\n"), group);
		return 8;
	}
	lu_hup_nscd();

	lu_ent_free(ent);

	if ((oldGidNumber != -2) && (gidNumber != -2)) {
		values = lu_users_enumerate_by_group(ctx, gid, &error);
		if (error != NULL) {
			lu_error_free(&error);
		}
		if (values) {
			ent = lu_ent_new();

			memset(&val, 0, sizeof(val));
			g_value_init(&val, G_TYPE_LONG);
			g_value_set_long(&val, gidNumber);

			for (i = 0; i < values->n_values; i++) {
				value = g_value_array_get_nth(values, i);
				tmp = g_value_get_string(value);
				if (lu_user_lookup_name (ctx, tmp, ent,
							 &error)) {
					lu_ent_clear(ent, LU_GIDNUMBER);
					lu_ent_add(ent, LU_GIDNUMBER, &val);
					lu_user_modify(ctx, ent, &error);
					if (error != NULL) {
						lu_error_free(&error);
					}
					lu_hup_nscd();
				}
			}

			lu_ent_free(ent);
		}
	}

	lu_end(ctx);

	return 0;
}
