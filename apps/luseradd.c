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
		   *gecos = NULL, *homeDirectory = NULL, *loginShell = NULL,
		   *skeleton = NULL, *name = NULL, *gid = NULL;
	struct lu_context *ctx = NULL;
	struct lu_ent *ent = NULL;
	struct lu_error *error = NULL;
	long uidNumber = -2, gidNumber = -2;
	GList *list;
	GValueArray *values;
	GValue *value, val;
	int dont_create_group = FALSE, dont_create_home = FALSE,
	    system_account = FALSE, interactive = FALSE;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		{"reserved", 'r', POPT_ARG_NONE, &system_account, 0,
		 "make this a system group", NULL},
		{"gecos", 'c', POPT_ARG_STRING, &gecos, 0,
		 "GECOS information for new user", "STRING"},
		{"directory", 'd', POPT_ARG_STRING, &homeDirectory, 0,
		 "home directory for new user", "STRING"},
		{"skeleton", 'k', POPT_ARG_STRING, &skeleton, 0,
		 "directory with files for the new user", "STRING"},
		{"shell", 's', POPT_ARG_STRING, &loginShell, 0,
		 "shell for new user", "STRING"},
		{"uid", 'u', POPT_ARG_LONG, &uidNumber, 0,
		 "uid for new user", "NUM"},
		{"gid", 'g', POPT_ARG_STRING, &gid, 0,
		 "gid for new user", NULL},
		{"nocreatehome", 'M', POPT_ARG_NONE, &dont_create_home, 0,
		 "don't create home directory for user", NULL},
		{"nocreategroup", 'n', POPT_ARG_NONE, &dont_create_group, 0,
		 "don't create group with same name as user", NULL},
		{"plainpassword", 'P', POPT_ARG_STRING, &userPassword, 0,
		 "plaintext password for use with group", "STRING"},
		{"password", 'p', POPT_ARG_STRING, &cryptedUserPassword, 0,
		 "pre-hashed password for use with group", "STRING"},
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("luseradd", argc, argv, options, 0);
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

	if (skeleton == NULL) {
		list = lu_cfg_read(ctx, "defaults/skeleton", "/etc/skel");
		if (list && list->data) {
			skeleton = g_strdup((char *) list->data);
			g_list_free(list);
		}
	}
	if (skeleton == NULL) {
		skeleton = "/etc/skel";
	}

	/* Select a group for the user to be in. */
	if (gid == NULL) {
		if (dont_create_group) {
			gid = "users";
		} else {
			gid = name;
		}
	}

	/* Try to convert the given GID to a number. */
	if (gid != NULL) {
		char *p;
		ent = lu_ent_new();
		gidNumber = strtol(gid, &p, 10);
		if ((p == NULL) || (*p != '\0')) {
			/* It's not a number, so it's a group name -- see if
			 * it's being used. */
			if (lu_group_lookup_name(ctx, gid, ent, &error)) {
				/* Retrieve the group's GID. */
				values = lu_ent_get(ent, LU_GIDNUMBER);
				value = g_value_array_get_nth(values, 0);
				gidNumber = g_value_get_long(value);
			} else {
				/* No such group -- can we create it? */
				if (!dont_create_group) {
					if (error) {
						lu_error_free(&error);
					}
					lu_group_default(ctx, gid, FALSE, ent);
					if (lu_group_add(ctx, ent, &error)) {
						/* Save the GID. */
						values = lu_ent_get(ent,
								    LU_GIDNUMBER);
						value = g_value_array_get_nth(values, 0);
						gidNumber = g_value_get_long(value);
						lu_hup_nscd();
					} else {
						/* Aargh!  Abandon all hope. */
						g_print(_("Error creating "
							"group `%s'.\n"), gid);
						if (error) {
							lu_error_free(&error);
						}
						lu_end(ctx);
						return 1;
					}
				} else {
					/* Can't get there from here. */
					g_print(_("No group named `%s' "
						"exists.\n"), gid);
					lu_end(ctx);
					return 1;
				}
			}
		} else {
			/* It's a group number -- see if it's being used. */
			if (!lu_group_lookup_id(ctx, gidNumber, ent, &error)) {
				/* No such group -- can we create one with the user's name? */
				if (!dont_create_group) {
					if (error) {
						lu_error_free(&error);
					}
					lu_group_default(ctx, name, FALSE, ent);
					memset(&val, 0, sizeof(val));
					g_value_init(&val, G_TYPE_LONG);
					g_value_set_long(&val, gidNumber);
					lu_ent_clear(ent, LU_GIDNUMBER);
					lu_ent_add(ent, LU_GIDNUMBER);
					if (!lu_group_add(ctx, ent, &error)) {
						/* Aargh!  Abandon all hope. */
						g_print(_("Error creating "
							"group `%s' with GID "
							"%ld.\n"), name,
							gidNumber);
						if (error) {
							lu_error_free(&error);
						}
						lu_end(ctx);
						return 1;
					}
					lu_hup_nscd();
				} else {
					/* Can't get there from here. */
					g_print(_("No group with GID %ld "
						"exists.\n"), gidNumber);
					lu_end(ctx);
					return 1;
				}
			}
		}
		lu_ent_free(ent);
	}

	ent = lu_ent_new();
	lu_user_default(ctx, name, system_account, ent);
	if (gecos)
		lu_ent_set(ent, LU_GECOS, gecos);
	if (uidNumber != -2) {
		lu_ent_set_numeric(ent, LU_UIDNUMBER, uidNumber);
	}
	if (gidNumber != -2) {
		lu_ent_set_numeric(ent, LU_GIDNUMBER, gidNumber);
	}
	if (homeDirectory)
		lu_ent_set(ent, LU_HOMEDIRECTORY, homeDirectory);
	if (loginShell)
		lu_ent_set(ent, LU_LOGINSHELL, loginShell);
	if (userPassword) {
		values = lu_ent_get(ent, LU_USERPASSWORD);
		if (values && values->data) {
			cryptedUserPassword =
			    lu_make_crypted(userPassword, values->data);
		} else {
			cryptedUserPassword =
			    lu_make_crypted(userPassword, "$1$");
		}
	}
	if (cryptedUserPassword) {
		char *tmp = NULL;
		tmp = g_strconcat("{crypt}", cryptedUserPassword, NULL);
		lu_ent_set(ent, LU_USERPASSWORD, tmp);
		g_free(tmp);
	}
	if (userPassword) {
		lu_ent_add(ent, LU_USERPASSWORD, userPassword);
	}

	if (lu_user_add(ctx, ent, &error) == FALSE) {
		fprintf(stderr, _("Account creation failed: %s.\n"),
			error->string);
		return 3;
	}
	lu_hup_nscd();

	if (!dont_create_home || system_account) {
		char *uid_string = NULL, *gid_string = NULL;

		values = lu_ent_get(ent, LU_UIDNUMBER);
		if (values) {
			uidNumber =
			    strtol((char *) values->data, &uid_string, 10);
		}
		values = lu_ent_get(ent, LU_GIDNUMBER);
		if (values) {
			gidNumber =
			    strtol((char *) values->data, &gid_string, 10);
		}

		if (uid_string && (*uid_string != '\0')) {
			fprintf(stderr, _("Bad UID for %s.\n"), name);
			return 4;
		}
		if (gid_string && (*gid_string != '\0')) {
			fprintf(stderr, _("Bad GID for %s.\n"), name);
			return 5;
		}

		values = lu_ent_get(ent, LU_HOMEDIRECTORY);
		if (values) {
			homeDirectory = (char *) values->data;
		}

		if (homeDirectory == NULL) {
			fprintf(stderr, _("No home directory for %s.\n"),
				name);
			return 6;
		}
		if (lu_homedir_populate
		    (skeleton, homeDirectory, uidNumber, gidNumber, 0700,
		     &error) == FALSE) {
			fprintf(stderr, _("Error creating %s: %s.\n"),
				homeDirectory, error->string);
			return 7;
		}
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
