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
	const char *userPassword = NULL, *cryptedUserPassword = NULL,
		   *gecos = NULL, *homeDirectory = NULL, *loginShell = NULL,
		   *skeleton = NULL, *name = NULL;
	struct lu_context *ctx = NULL;
	struct lu_ent *ent = NULL;
	long uidNumber = -2, gidNumber = -2;
	GList *values;
	int dont_create_group = FALSE,
	    dont_create_home = FALSE,
	    system_account = FALSE,
	    interactive = FALSE;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		{"reserved", 'r', POPT_ARG_NONE, &system_account, 0,
		 "make this a system group"},
		{"gecos", 'c', POPT_ARG_STRING, &gecos, 0,
		 "GECOS information for new user", "STRING"},
		{"directory", 'd', POPT_ARG_STRING, &homeDirectory, 0,
		 "home directory for new user", "STRING"},
		{"skeleton", 'k', POPT_ARG_STRING, &skeleton, 0,
		 "directory with files for the new user", "STRING"},
		{"shell", 's', POPT_ARG_STRING, &homeDirectory, 0,
		 "shell for new user", "STRING"},
		{"uid", 'u', POPT_ARG_LONG, &uidNumber, 0,
		 "uid for new user", "NUM"},
		{"gid", 'g', POPT_ARG_LONG, &gidNumber, 0,
		 "gid for new user", "NUM"},
#ifdef FIXMEFIXMEFIXME
		{"nocreatehome", 'M', POPT_ARG_NONE, &dont_create_home, 0,
		 "don't create home directory for user"},
#endif
		{"nocreategroup", 'n', POPT_ARG_NONE, &dont_create_group, 0,
		 "don't create group with same name as user"},
		{"plainpassword", 'P', POPT_ARG_STRING, &userPassword, 0,
		 "plaintext password for use with group", "STRING"},
		{"password", 'p', POPT_ARG_STRING, &cryptedUserPassword, 0,
		 "pre-hashed password for use with group", "STRING"},
		POPT_AUTOHELP
	       	{NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("useradd", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	g_return_val_if_fail(c == -1, 0);
	name = poptGetArg(popt);

	if(name == NULL) {
		fprintf(stderr, _("No user name specified.\n"));
		return 1;
	}

	ctx = lu_start(NULL, 0, NULL, NULL,
		       interactive ? lu_prompt_console:lu_prompt_console_quiet,
		       NULL);
	g_return_val_if_fail(ctx != NULL, 1);

	if(skeleton == NULL) {
		values = lu_cfg_read(ctx, "defaults/skeleton", "/etc/skel");
		if(values && values->data) {
			skeleton = g_strdup((char*)values->data);
			g_list_free(values);
		}
	}
	if(skeleton == NULL) {
		skeleton = "/etc/skel";
	}

	if(!dont_create_group) {
		ent = lu_ent_new();
		lu_ent_group_default(ctx, name, system_account, ent);
		if(gidNumber != -2) {
			char *tmp = g_strdup_printf("%ld", gidNumber);
			lu_ent_set(ent, LU_GIDNUMBER, tmp);
			g_free(tmp);
		}
		if(lu_group_add(ctx, ent) == FALSE) {
			fprintf(stderr, _("Error creating group for %s.\n"),
				name);
			return 2;
		}
		lu_ent_free(ent);
	}

	ent = lu_ent_new();
	lu_ent_user_default(ctx, name, system_account, ent);
	if(gecos)
		lu_ent_set(ent, LU_GECOS, gecos);
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
	if(homeDirectory)
		lu_ent_set(ent, LU_HOMEDIRECTORY, homeDirectory);
	if(loginShell)
		lu_ent_set(ent, LU_LOGINSHELL, loginShell);
	if(userPassword) {
		values = lu_ent_get(ent, LU_USERPASSWORD);
		if(values && values->data) {
			cryptedUserPassword = make_crypted(userPassword,
							   values->data);
		} else {
			cryptedUserPassword = make_crypted(userPassword, "$1$");
		}
	}
	if(cryptedUserPassword) {
		char *tmp = NULL;
		tmp = g_strconcat("{crypt}", cryptedUserPassword, NULL);
		lu_ent_set(ent, LU_USERPASSWORD, tmp);
		g_free(tmp);
	}
	if(userPassword) {
		lu_ent_add(ent, LU_USERPASSWORD, userPassword);
	}

	if(lu_user_add(ctx, ent) == FALSE) {
		fprintf(stderr, _("Account creation failed.\n"));
		return 3;
	}

	if(!dont_create_home) {
		uid_t uid;
		gid_t gid;
		char *uid_string = NULL, *gid_string = NULL;

		if(uidNumber != -2) {
			values = lu_ent_get(ent, LU_USERNAME);
			if(values) {
				uidNumber = strtol((char*)values->data,
						   &uid_string, 10);
			}
		}
		values = lu_ent_get(ent, LU_GIDNUMBER);
		if(gidNumber != -2) {
			if(values) {
				gidNumber = strtol((char*)values->data,
						   &gid_string, 10);
			}
		}

		if(uid_string && (*uid_string != '\0')) {
			fprintf(stderr, _("Bad UID for %s.\n"), name);
			return 7;
		}
		if(gid_string && (*gid_string != '\0')) {
			fprintf(stderr, _("Bad GID for %s.\n"), name);
			return 7;
		}

		values = lu_ent_get(ent, LU_HOMEDIRECTORY);
		if(values) {
			homeDirectory = (char*)values->data;
		}

		if(homeDirectory == NULL) {
			fprintf(stderr, _("No home directory for %s.\n"), name);
			return 7;
		}
#ifdef FIXMEFIXMEFIXME
		if(populate_homedir(skeleton, homeDirectory,
				    uid, gid, 0700) == FALSE) {
			fprintf(stderr, _("Error creating %s.\n"),
				homeDirectory);
			return 8;
		}
#endif
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
