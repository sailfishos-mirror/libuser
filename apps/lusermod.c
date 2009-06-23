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

#include <config.h>
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
		   *uid = NULL, *old_uid, *user, *gecos = NULL,
		   *oldHomeDirectory, *homeDirectory = NULL,
		   *loginShell = NULL, *gid_number_str = NULL,
		   *uid_number_str = NULL;
	uid_t uidNumber = LU_VALUE_INVALID_ID;
	gid_t gidNumber = LU_VALUE_INVALID_ID;
	struct lu_context *ctx;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	GValueArray *values, *groups = NULL;
	GValue *value, val;
	int change, move_home = FALSE, lock = FALSE, unlock = FALSE;
	int interactive = FALSE;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		{"gecos", 'c', POPT_ARG_STRING, &gecos, 0,
		 "GECOS information", "STRING"},
		{"directory", 'd', POPT_ARG_STRING, &homeDirectory, 0,
		 "home directory", "STRING"},
		{"movedirectory", 'm', POPT_ARG_NONE, &move_home, 0,
		 "move home directory contents", NULL},
		{"shell", 's', POPT_ARG_STRING, &loginShell, 0,
		 "set shell for user", "STRING"},
		{"uid", 'u', POPT_ARG_STRING, &uid_number_str, 0,
		 "set UID for user", "NUM"},
		{"gid", 'g', POPT_ARG_STRING, &gid_number_str, 0,
		 "set primary GID for user", "NUM"},
		{"login", 'l', POPT_ARG_STRING, &uid, 0,
		 "change login name for user", "STRING"},
		{"plainpassword", 'P', POPT_ARG_STRING, &userPassword, 0,
		 "plaintext password for the user", "STRING"},
		{"password", 'p', POPT_ARG_STRING, &cryptedUserPassword, 0,
		 "pre-hashed password for the user", "STRING"},
		{"lock", 'L', POPT_ARG_NONE, &lock, 0, "lock account", NULL},
		{"unlock", 'U', POPT_ARG_NONE, &unlock, 0,
		 "unlock account", NULL},
		POPT_AUTOHELP POPT_TABLEEND
	};

	/* Set up i18n. */
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	/* Start up the library. */
	popt = poptGetContext("lusermod", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}

	/* We need to have been passed a user name on the command-line.  We
	 * could just delete some randomly-selected victim^H^H^H^H^H^Huser,
	 * but that would probably upset most system administrators. */
	user = poptGetArg(popt);
	if (user == NULL) {
		fprintf(stderr, _("No user name specified.\n"));
		poptPrintUsage(popt, stderr, 0);
		return 1;
	}
	if (gid_number_str != NULL) {
		intmax_t val;
		char *p;

		errno = 0;
		val = strtoimax(gid_number_str, &p, 10);
		if (errno != 0 || *p != 0 || p == gid_number_str
		    || (gid_t)val != val || (gid_t)val == LU_VALUE_INVALID_ID) {
			fprintf(stderr, _("Invalid group ID %s\n"),
				gid_number_str);
			poptPrintUsage(popt, stderr, 0);
			return 1;
		}
		gidNumber = val;
	}
	if (uid_number_str != NULL) {
		intmax_t val;
		char *p;

		errno = 0;
		val = strtoimax(uid_number_str, &p, 10);
		if (errno != 0 || *p != 0 || p == uid_number_str
		    || (uid_t)val != val || (uid_t)val == LU_VALUE_INVALID_ID) {
			fprintf(stderr, _("Invalid user ID %s\n"),
				uid_number_str);
			poptPrintUsage(popt, stderr, 0);
			return 1;
		}
		uidNumber = val;
	}


	/* Start up the library. */
	ctx = lu_start(NULL, 0, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
		return 1;
	}

	/* Sanity-check arguments. */
	if (lock && unlock) {
		fprintf(stderr, _("Both -L and -U specified.\n"));
		return 2;
	}

	/* Look up the user's record. */
	ent = lu_ent_new();
	if (lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		return 3;
	}

	/* If the user's password needs to be changed, try to change it. */
	if (userPassword != NULL) {
		if (lu_user_setpass(ctx, ent, userPassword, FALSE, &error)
		    == FALSE) {
			fprintf(stderr,
				_("Failed to set password for user %s: %s.\n"),
				user, lu_strerror(error));
			return 5;
		}
	}

	/* If we need to change a user's crypted password, try to change it,
	 * though it might fail if an underlying mechanism doesn't support
	 * using them. */
	if (cryptedUserPassword != NULL) {
		if (lu_user_setpass(ctx, ent, cryptedUserPassword, TRUE,
				    &error) == FALSE) {
			fprintf(stderr,
				_("Failed to set password for user %s: %s.\n"),
				user, lu_strerror(error));
			return 6;
		}
	}

	/* If we need to lock/unlock the user's account, do that. */
	if (lock) {
		if (lu_user_lock(ctx, ent, &error) == FALSE) {
			fprintf(stderr,
				_("User %s could not be locked: %s.\n"),
				user, lu_strerror(error));
			return 7;
		}
	}
	if (unlock) {
		if (lu_user_unlock(ctx, ent, &error) == FALSE) {
			fprintf(stderr,
				_("User %s could not be unlocked: %s.\n"),
				user, lu_strerror(error));
			return 8;
		}
	}

	/* Determine if we actually need to change anything. */
	change = uid || gecos || homeDirectory || loginShell ||
		 uidNumber != LU_VALUE_INVALID_ID ||
		 gidNumber != LU_VALUE_INVALID_ID;

	/* Change the user's UID and GID. */
	memset(&val, 0, sizeof(val));

	if (uidNumber != LU_VALUE_INVALID_ID) {
		lu_value_init_set_id(&val, uidNumber);
		lu_ent_clear(ent, LU_UIDNUMBER);
		lu_ent_add(ent, LU_UIDNUMBER, &val);
		g_value_unset(&val);
	}
	if (gidNumber != LU_VALUE_INVALID_ID) {
		struct lu_ent *group_ent;

		group_ent = lu_ent_new();
		if (lu_group_lookup_id(ctx, gidNumber, group_ent, &error)
		    == FALSE) {
			fprintf(stderr, _("Warning: Group with ID %jd does not "
					  "exist.\n"), (intmax_t)gidNumber);
			if (error != NULL)
				lu_error_free(&error);
		}
		lu_ent_free(group_ent);
		lu_value_init_set_id(&val, gidNumber);
		lu_ent_clear(ent, LU_GIDNUMBER);
		lu_ent_add(ent, LU_GIDNUMBER, &val);
		g_value_unset(&val);
	}

	/* Change the user's shell and GECOS information. */
	g_value_init(&val, G_TYPE_STRING);

	if (loginShell != NULL) {
		g_value_set_string(&val, loginShell);
		lu_ent_clear(ent, LU_LOGINSHELL);
		lu_ent_add(ent, LU_LOGINSHELL, &val);
	}
	if (gecos != NULL) {
		g_value_set_string(&val, gecos);
		lu_ent_clear(ent, LU_GECOS);
		lu_ent_add(ent, LU_GECOS, &val);
	}

	/* If the user changed names or home directories, we need to keep track
	 * of the old values. */
	old_uid = NULL;
	if (uid != NULL) {
		values = lu_ent_get(ent, LU_USERNAME);
		value = g_value_array_get_nth(values, 0);
		old_uid = lu_value_strdup(value);
		g_value_set_string(&val, uid);
		lu_ent_clear(ent, LU_USERNAME);
		lu_ent_add(ent, LU_USERNAME, &val);
		groups = lu_groups_enumerate_by_user(ctx, old_uid, &error);
		if (error)
			lu_error_free(&error);
	}
	oldHomeDirectory = NULL;
	if (homeDirectory != NULL) {
		values = lu_ent_get(ent, LU_HOMEDIRECTORY);
		value = g_value_array_get_nth(values, 0);
		oldHomeDirectory = lu_value_strdup(value);
		g_value_set_string(&val, homeDirectory);
		lu_ent_clear(ent, LU_HOMEDIRECTORY);
		lu_ent_add(ent, LU_HOMEDIRECTORY, &val);
	}

	g_value_unset(&val);

	/* If we need to change anything about the user, do it. */
	if (change && (lu_user_modify(ctx, ent, &error) == FALSE)) {
		fprintf(stderr, _("User %s could not be modified: %s.\n"),
			user, lu_strerror(error));
		return 9;
	}
	lu_nscd_flush_cache("passwd");

	/* If the user's name changed, we need to update supplemental
	 * group membership information. */
	if (change && (old_uid != NULL)) {
		size_t i;

		for (i = 0; (groups != NULL) && (i < groups->n_values); i++) {
			struct lu_ent *group;
			const char *username, *groupname;
			GValueArray *members, *admins;
			size_t j;

			/* Get the name of this group. */
			value = g_value_array_get_nth(groups, i);
			groupname = g_value_get_string(value);
			/* Look up the group. */
			members = admins = NULL;
			group = lu_ent_new();
			if (lu_group_lookup_name(ctx, groupname, group,
						 &error)) {
				/* Get a list of the group's members. */
				members = lu_ent_get(group, LU_MEMBERNAME);
				admins = lu_ent_get(group, LU_ADMINISTRATORNAME);
			}
			/* Search for this user in the member list. */
			for (j = 0;
			     (members != NULL) && (j < members->n_values);
			     j++) {
				value = g_value_array_get_nth(members, j);
				username = g_value_get_string(value);
				/* If it holds the user's old name, then
				 * set its value to the new name. */
				if (strcmp(old_uid, username) == 0) {
					/* Modifies the entity in-place. */
					g_value_set_string(value, uid);
					break;
				}
			}
			/* Do the same for the administrator list. */
			for (j = 0;
			     (admins != NULL) && (j < admins->n_values);
			     j++) {
				value = g_value_array_get_nth(admins, j);
				username = g_value_get_string(value);
				/* If it holds the user's old name, then
				 * set its value to the new name. */
				if (strcmp(old_uid, username) == 0) {
					/* Modifies the entity in-place. */
					g_value_set_string(value, uid);
					break;
				}
			}
			/* Save the changes to the group. */
			if (lu_group_modify(ctx, group, &error) == FALSE)
				fprintf(stderr, _("Group %s could not be "
						  "modified: %s.\n"),
					groupname, lu_strerror(error));
			lu_ent_free(group);
		}
       		lu_nscd_flush_cache("group");
	}

	/* If we need to move the user's directory, we do that now. */
	if (change && move_home) {
		if (oldHomeDirectory == NULL) {
			fprintf(stderr, _("No old home directory for %s.\n"),
				user);
			return 10;
		}
		if (homeDirectory == NULL) {
			fprintf(stderr, _("No new home directory for %s.\n"),
				user);
			return 11;
		}
		if (lu_homedir_move(oldHomeDirectory, homeDirectory,
				    &error) == FALSE) {
			fprintf(stderr, _("Error moving %s to %s: %s.\n"),
				oldHomeDirectory, homeDirectory,
				lu_strerror(error));
			return 12;
		}
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
