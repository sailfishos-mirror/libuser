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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ident "$Id$"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include <string.h>
#include "../lib/user_private.h"
#include "apputil.h"

int
main(int argc, const char **argv)
{
	const char *userPassword = NULL, *cryptedUserPassword = NULL,
		   *gid = NULL, *addAdmins = NULL, *remAdmins = NULL,
		   *addMembers = NULL, *remMembers = NULL, *group = NULL,
		   *tmp = NULL, *gid_number_str = NULL;
	char **admins = NULL, **members = NULL;
	gid_t gidNumber = LU_VALUE_INVALID_ID;
	gid_t oldGidNumber = LU_VALUE_INVALID_ID;
	struct lu_context *ctx = NULL;
	struct lu_ent *ent = NULL;
	struct lu_error *error = NULL;
	GValueArray *values = NULL, *users = NULL;
	GValue *value, val;
	int change = FALSE, lock = FALSE, unlock = FALSE;
	int interactive = FALSE;
	int c;
	size_t i;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		{"gid", 'g', POPT_ARG_STRING, &gid_number_str, 0,
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
		{"lock", 'L', POPT_ARG_NONE, &lock, 0, "lock group", NULL},
		{"unlock", 'U', POPT_ARG_NONE, &unlock, 0, "unlock group", NULL},
		POPT_AUTOHELP POPT_TABLEEND
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
	if (gid_number_str != NULL) {
		intmax_t val;
		char *p;

		errno = 0;
		val = strtoimax(gid_number_str, &p, 10);
		if (errno != 0 || *p != 0 || p == gid_number_str
		    || (gid_t)val != val) {
			fprintf(stderr, _("Invalid group ID %s\n"),
				gid_number_str);
			poptPrintUsage(popt, stderr, 0);
			return 1;
		}
		gidNumber = val;
	}
	
	ctx = lu_start(NULL, 0, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
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

	if (userPassword) {
		if (lu_group_setpass(ctx, ent, userPassword, FALSE, &error)
		    == FALSE) {
			fprintf(stderr, _("Failed to set password for group "
				"%s: %s\n"), group, lu_strerror(error));
			return 4;
		}
	}

	if (cryptedUserPassword) {
		if (lu_group_setpass(ctx, ent, cryptedUserPassword, TRUE,
				     &error) == FALSE) {
			fprintf(stderr, _("Failed to set password for group "
				"%s: %s\n"), group, lu_strerror(error));
			return 5;
		}
	}

	if (lock) {
		if (lu_group_lock(ctx, ent, &error) == FALSE) {
			fprintf(stderr,
				_("Group %s could not be locked: %s\n"), group,
				lu_strerror(error));
			return 6;
		}
	}

	if (unlock) {
		if (lu_group_unlock(ctx, ent, &error) == FALSE) {
			fprintf(stderr,
				_("Group %s could not be unlocked: %s\n"),
				group, lu_strerror(error));
			return 7;
		}
	}

	change = gid || addAdmins || remAdmins || addMembers || remMembers;

	if (gid != NULL) {
		values = lu_ent_get(ent, LU_GROUPNAME);
		lu_ent_clear(ent, LU_GROUPNAME);
		if (values) {
			memset(&val, 0, sizeof(val));
			g_value_init(&val, G_TYPE_STRING);
			g_value_set_string(&val, gid);
			lu_ent_add(ent, LU_GROUPNAME, &val);
			g_value_unset(&val);
		} else
			gid = group;
	} else
		gid = group;
	if (addAdmins) {
		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_STRING);
		admins = g_strsplit(addAdmins, ",", 0);
		if (admins) {
			for (c = 0; admins && admins[c]; c++) {
				g_value_set_string(&val, admins[c]);
				lu_ent_add(ent, LU_ADMINISTRATORNAME, &val);
				g_value_reset(&val);
			}
			lu_hup_nscd();
			g_strfreev(admins);
			admins = NULL;
		}
		g_value_unset(&val);
	}
	if (remAdmins) {
		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_STRING);
		admins = g_strsplit(remAdmins, ",", 0);
		if (admins) {
			for (c = 0; admins && admins[c]; c++) {
				g_value_set_string(&val, admins[c]);
				lu_ent_del(ent, LU_ADMINISTRATORNAME, &val);
				g_value_reset(&val);
			}
			lu_hup_nscd();
			g_strfreev(admins);
			admins = NULL;
		}
		g_value_unset(&val);
	}

	if (addMembers) {
		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_STRING);
		members = g_strsplit(addMembers, ",", 0);
		if (members) {
			for (c = 0; members && members[c]; c++) {
				g_value_set_string(&val, members[c]);
				lu_ent_add(ent, LU_MEMBERNAME, &val);
				g_value_reset(&val);
			}
			lu_hup_nscd();
			g_strfreev(members);
			members = NULL;
		}
		g_value_unset(&val);
	}
	if (remMembers) {
		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_STRING);
		members = g_strsplit(remMembers, ",", 0);
		if (members) {
			for (c = 0; members && members[c]; c++) {
				g_value_set_string(&val, members[c]);
				lu_ent_del(ent, LU_MEMBERNAME, &val);
				g_value_reset(&val);
			}
			lu_hup_nscd();
			g_strfreev(members);
			members = NULL;
		}
		g_value_unset(&val);
	}

	if (change && lu_group_modify(ctx, ent, &error) == FALSE) {
		fprintf(stderr, _("Group %s could not be modified: %s\n"),
			group, lu_strerror(error));
		return 8;
	}
	if (gidNumber != LU_VALUE_INVALID_ID) {
		users = lu_users_enumerate_by_group(ctx, gid, &error);

		values = lu_ent_get(ent, LU_GIDNUMBER);
		if (values) {
			value = g_value_array_get_nth(values, 0);
			oldGidNumber = lu_value_get_id(value);
			g_assert(oldGidNumber != LU_VALUE_INVALID_ID);
		}

		memset(&val, 0, sizeof(val));
		lu_value_init_set_id(&val, gidNumber);

		lu_ent_clear(ent, LU_GIDNUMBER);
		lu_ent_add(ent, LU_GIDNUMBER, &val);

		g_value_unset(&val);

		if (error != NULL)
			lu_error_free(&error);
		if (lu_group_modify(ctx, ent, &error) == FALSE) {
			fprintf(stderr,
				_("Group %s could not be modified: %s\n"),
				group, lu_strerror(error));
			return 8;
		}
	}

	lu_hup_nscd();

	lu_ent_free(ent);

	if (oldGidNumber != LU_VALUE_INVALID_ID &&
	    gidNumber != LU_VALUE_INVALID_ID && users != NULL) {
		ent = lu_ent_new();

		memset(&val, 0, sizeof(val));
		lu_value_init_set_id(&val, gidNumber);

		for (i = 0; i < users->n_values; i++) {
			value = g_value_array_get_nth(users, i);
			tmp = g_value_get_string(value);
			if (lu_user_lookup_name (ctx, tmp, ent, &error)) {
				values = lu_ent_get(ent, LU_GIDNUMBER);
				if (values &&
				    lu_value_get_id(g_value_array_get_nth(values, 0)) ==
				    oldGidNumber) {
					lu_ent_clear(ent, LU_GIDNUMBER);
					lu_ent_add(ent, LU_GIDNUMBER, &val);
					lu_user_modify(ctx, ent, &error);
					if (error != NULL)
						lu_error_free(&error);
					lu_hup_nscd();
				}
			}
		}

		g_value_unset(&val);
		lu_ent_free(ent);
	}

	lu_end(ctx);

	return 0;
}
