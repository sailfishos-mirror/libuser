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
		   *uid = NULL, *old_uid = NULL, *user = NULL, *gecos = NULL, *oldHomeDirectory,
		   *homeDirectory = NULL, *loginShell = NULL;
	long uidNumber = -2, gidNumber = -2;
	struct lu_context *ctx = NULL;
	struct lu_ent *ent = NULL;
	struct lu_error *error = NULL;
	GList *values, *i;
	int change = FALSE, move_home = FALSE, lock = FALSE, unlock = FALSE;
	int interactive = FALSE;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0, "prompt for all information", NULL},
		{"gecos", 'c', POPT_ARG_STRING, &gecos, 0, "GECOS information", "STRING"},
		{"directory", 'd', POPT_ARG_STRING, &homeDirectory, 0, "home directory", "STRING"},
		{"movedirectory", 'm', POPT_ARG_NONE, &move_home, 0, "move home directory contents"},
		{"shell", 's', POPT_ARG_STRING, &loginShell, 0, "set shell for user", "STRING"},
		{"uid", 'u', POPT_ARG_LONG, &uidNumber, 0, "set UID for user", "NUM"},
		{"gid", 'g', POPT_ARG_LONG, &gidNumber, 0, "set primary GID for user", "NUM"},
		{"login", 'l', POPT_ARG_STRING, &uid, 0, "change login name for user", "STRING"},
		{"plainpassword", 'P', POPT_ARG_STRING, &userPassword, 0, "plaintext password for the user", "STRING"},
		{"password", 'p', POPT_ARG_STRING, &cryptedUserPassword, 0, "pre-hashed password for the user", "STRING"},
		{"lock", 'L', POPT_ARG_NONE, &lock, 0, "lock account"},
		{"unlock", 'U', POPT_ARG_NONE, &unlock, 0, "unlock account"},
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0,},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lusermod", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	if(c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"), poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}
	user = poptGetArg(popt);

	if(user == NULL) {
		fprintf(stderr, _("No user name specified.\n"));
		poptPrintUsage(popt, stderr, 0);
		return 1;
	}

	ctx = lu_start(NULL, 0, NULL, NULL, interactive ? lu_prompt_console:lu_prompt_console_quiet, NULL, &error);
	if(ctx == NULL) {
		if(error != NULL) {
			fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE, error->string);
		} else {
			fprintf(stderr, _("Error initializing %s.\n"), PACKAGE);
		}
		return 1;
	}

	if(lock && unlock) {
		fprintf(stderr, _("Both -L and -U specified.\n"));
		return 2;
	}

	ent = lu_ent_new();

	if(lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		return 3;
	}

	change = userPassword || cryptedUserPassword || uid || gecos || oldHomeDirectory || homeDirectory || loginShell ||
		 (uidNumber != -2) || (gidNumber != -2);

	if(loginShell)
		lu_ent_set(ent, LU_LOGINSHELL, loginShell);
	if(uidNumber != -2) {
		lu_ent_set_numeric(ent, LU_UIDNUMBER, uidNumber);
	}
	if(gidNumber != -2) {
		lu_ent_set_numeric(ent, LU_GIDNUMBER, gidNumber);
	}
	if(uid) {
		values = lu_ent_get(ent, LU_USERNAME);
		if(values) {
			old_uid = (char*)values->data;
		}
		lu_ent_set(ent, LU_USERNAME, uid);
	}
	if(gecos)
		lu_ent_set(ent, LU_GECOS, gecos);
	if(homeDirectory) {
		values = lu_ent_get(ent, LU_HOMEDIRECTORY);
		if(values) {
			oldHomeDirectory = values->data;
		} else {
			fprintf(stderr, _("Error reading old home directory for %s: %s.\n"), user, error->string);
			return 4;
		}
		lu_ent_set(ent, LU_HOMEDIRECTORY, homeDirectory);
	}

	if(userPassword) {
		if(lu_user_setpass(ctx, ent, userPassword, &error) == FALSE) {
			fprintf(stderr, _("Failed to set password for user %s: %s.\n"), user, error->string);
			return 5;
		}
	}

	if(cryptedUserPassword) {
		char *tmp = NULL;
		tmp = g_strconcat("{crypt}", cryptedUserPassword, NULL);
		if(lu_user_setpass(ctx, ent, tmp, &error) == FALSE) {
			fprintf(stderr, _("Failed to set password for user %s: %s.\n"), user, error->string);
			return 6;
		}
		g_free(tmp);
	}

	if(lock) {
		if(lu_user_lock(ctx, ent, &error) == FALSE) {
			fprintf(stderr, _("User %s could not be locked: %s.\n"), user, error->string);
			return 7;
		}
	}

	if(unlock) {
		if(lu_user_unlock(ctx, ent, &error) == FALSE) {
			fprintf(stderr, _("User %s could not be unlocked: %s.\n"), user, error->string);
			return 8;
		}
	}

	if(change && (lu_user_modify(ctx, ent, &error) == FALSE)) {
		fprintf(stderr, _("User %s could not be modified: %s.\n"), user, error->string);
		return 9;
	}
	lu_hup_nscd();

	if(change && old_uid && uid) {
		struct lu_ent *group = NULL;
		values = lu_groups_enumerate_by_user(ctx, old_uid, NULL, &error);
		if(error) {
			lu_error_free(&error);
		}
		group = lu_ent_new();
		for(i = values; i != NULL; i = g_list_next(values)) {
			if(lu_group_lookup_name(ctx, values->data, ent, &error)) {
				GList *gid;
				char *tmp;
				tmp = g_strdup_printf("%ld", gidNumber);
				gid = lu_ent_get(ent, LU_GIDNUMBER);
				if(strcmp(tmp, (char*)gid->data) != 0) {
					lu_ent_del(ent, LU_MEMBERUID, old_uid);
					lu_ent_add(ent, LU_MEMBERUID, uid);
					if(!lu_group_modify(ctx, ent, &error)) {
						if(error) {
							lu_error_free(&error);
						}
					}
					lu_hup_nscd();
				}
				g_free(tmp);
			} else {
				if(error) {
					lu_error_free(&error);
				}
			}
		}
		g_list_free(values);
	}


	if(change && move_home) {
		if(oldHomeDirectory == NULL) {
			fprintf(stderr, _("No old home directory for %s.\n"), user);
			return 10;
		}
		if(homeDirectory == NULL) {
			fprintf(stderr, _("No new home directory for %s.\n"), user);
			return 11;
		}
		if(lu_homedir_move(oldHomeDirectory, homeDirectory, &error) == FALSE) {
			fprintf(stderr, _("Error moving %s to %s: %s.\n"), oldHomeDirectory, homeDirectory, error->string);
			return 12;
		}
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
