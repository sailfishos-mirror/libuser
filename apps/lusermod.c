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
#include "../include/libuser/user_private.h"
#include "apputil.h"

int
main(int argc, const char **argv)
{
	const char *userPassword = NULL, *cryptedUserPassword = NULL,
		   *uid = NULL, *user = NULL, *gecos = NULL, *oldHomeDirectory,
		   *homeDirectory = NULL, *loginShell = NULL;
	long uidNumber = -2, gidNumber = -2;
	struct lu_context *ctx = NULL;
	struct lu_ent *ent = NULL;
	struct lu_error *error = NULL;
	GList *values;
	int change = FALSE, move_home = FALSE, lock = FALSE, unlock = FALSE;
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
		 "move home directory contents"},
		{"shell", 's', POPT_ARG_STRING, &loginShell, 0,
		 "set shell for user", "STRING"},
		{"uid", 'u', POPT_ARG_LONG, &uidNumber, 0,
		 "set UID for user", "NUM"},
		{"gid", 'g', POPT_ARG_LONG, &gidNumber, 0,
		 "set primary GID for user", "NUM"},
		{"login", 'l', POPT_ARG_STRING, &uid, 0,
		 "change login name for user", "STRING"},
		{"plainpassword", 'P', POPT_ARG_STRING, &userPassword, 0,
		 "plaintext password for the user", "STRING"},
		{"password", 'p', POPT_ARG_STRING, &cryptedUserPassword, 0,
		 "pre-hashed password for the user", "STRING"},
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
	g_return_val_if_fail(c == -1, 0);
	user = poptGetArg(popt);

	if(user == NULL) {
		fprintf(stderr, _("No user name specified.\n"));
		return 1;
	}

	ctx = lu_start(NULL, 0, NULL, NULL, interactive ? lu_prompt_console:lu_prompt_console_quiet, NULL, NULL);
	g_return_val_if_fail(ctx != NULL, 1);

	if(lock && unlock) {
		fprintf(stderr, _("Both -L and -U specified.\n"));
		return 2;
	}

	ent = lu_ent_new();

	if(lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		return 3;
	}

	change = userPassword || cryptedUserPassword || uid ||
		 gecos || oldHomeDirectory || homeDirectory || loginShell ||
		 (uidNumber != -2) || (gidNumber != -2);

	if(loginShell)
		lu_ent_set(ent, LU_LOGINSHELL, loginShell);
	if(uidNumber != -2) {
		char *tmp = g_strdup_printf("%ld", uidNumber);
		lu_ent_set(ent, LU_UIDNUMBER, tmp);
		g_free(tmp);
	}
	if(gidNumber != -2) {
		char *tmp = g_strdup_printf("%ld", gidNumber);
		lu_ent_set(ent, LU_GIDNUMBER, tmp);
		g_free(tmp);
	}
	if(uid)
		lu_ent_set(ent, LU_USERNAME, uid);
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
