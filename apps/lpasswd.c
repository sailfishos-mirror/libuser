/*
 * Copyright (C) 2000-2002 Red Hat, Inc.
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
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <popt.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
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
	char *password = NULL, *cryptedPassword = NULL;
	const char *user;
	int c;
	int plain_fd = -1, crypted_fd = -1;
	int interactive = 0, groupflag = 0;
	poptContext popt;
	gboolean is_crypted;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		{"group", 'g', POPT_ARG_NONE, &groupflag, 0,
		 "set group password instead of user password", NULL},
		{"plainpassword", 'P', POPT_ARG_STRING, &password, 0,
		 "new plain password", NULL},
		{"password", 'p', POPT_ARG_STRING, &cryptedPassword, 0,
		 "new crypted password", NULL},
		{"plainpassword-fd", 'F', POPT_ARG_INT, &plain_fd, 0,
		 "read new plain password from given descriptor", NULL},
		{"password-fd", 'f', POPT_ARG_INT, &crypted_fd, 0,
		 "read new crypted password from given descriptor", NULL},
		POPT_AUTOHELP POPT_TABLEEND
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lpasswd", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}
	user = poptGetArg(popt);

	lu_authenticate_unprivileged(user, "passwd");

	if ((user == NULL) || (geteuid() != getuid())) {
		struct passwd *pwd;
		pwd = getpwuid(getuid());
		if (pwd != NULL) {
			fprintf(stderr, _("Changing password for %s.\n"),
				user = strdup(pwd->pw_name));
		} else {
			fprintf(stderr, _("No user name specified.\n"));
			poptPrintUsage(popt, stderr, 0);
			return 1;
		}
	}

	ctx = lu_start(user, groupflag ? lu_group : lu_user, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
		return 1;
	}

	if ((password == NULL) && (cryptedPassword == NULL) &&
	    (plain_fd == -1) && (crypted_fd == -1)) {
		do {
			struct lu_prompt prompts[2];

			memset(&prompts, 0, sizeof(prompts));
			prompts[0].key = "lpasswd/password1";
			prompts[0].prompt = N_("New password");
			prompts[0].domain = PACKAGE;
			prompts[1].key = "lpasswd/password2";
			prompts[1].prompt = N_("New password (confirm)");
			prompts[1].domain = PACKAGE;
			if (lu_prompt_console(prompts, G_N_ELEMENTS(prompts),
					      NULL, &error)) {
				if (prompts[0].value &&
				    strlen(prompts[0].value) &&
				    prompts[1].value &&
				    strlen(prompts[1].value)) {
					if (strcmp(prompts[0].value,
						   prompts[1].value) == 0) {
						password = g_strdup(prompts[0].value);
						prompts[0].free_value(prompts[0].value);
						prompts[1].free_value(prompts[1].value);
					} else {
						fprintf(stderr, _("Passwords "
							"do not match, try "
							"again.\n"));
					}
				} else {
					fprintf(stderr, _("Password change "
						"canceled.\n"));
					return 1;
				}
			}
			if (error) {
				lu_error_free(&error);
			}
		} while (password == NULL);
	}

	ent = lu_ent_new();

	if (!groupflag) {
		if (lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
			fprintf(stderr, _("User %s does not exist.\n"), user);
			return 2;
		}
	} else {
		if (lu_group_lookup_name(ctx, user, ent, &error) == FALSE) {
			fprintf(stderr, _("Group %s does not exist.\n"), user);
			return 2;
		}
	}

	if (plain_fd != -1) {
		char buf[LINE_MAX + 1];
		int i;

		i = read(plain_fd, buf, sizeof(buf) - 1);
		while ((i > 0) &&
		       ((buf[i - 1] == '\r') || (buf[i - 1] == '\n')))
			i--;
		buf[i] = '\0';
		password = g_strdup(buf);
		is_crypted = FALSE;
	} else if (crypted_fd != -1) {
		char buf[LINE_MAX + 1];
		int i;
		i = read(crypted_fd, buf, sizeof(buf) - 1);
		while ((i > 0) &&
		       ((buf[i - 1] == '\r') || (buf[i - 1] == '\n')))
			i--;
		buf[i] = '\0';
		password = g_strdup(buf);
		is_crypted = TRUE;
	} else if (cryptedPassword != NULL) {
		password = g_strdup(cryptedPassword);
		is_crypted = TRUE;
	} else {
		is_crypted = FALSE;
		/* the password variable is already set */
	}

	if (!groupflag) {
		if (lu_user_setpass(ctx, ent, password, is_crypted, &error)
		    == FALSE) {
			fprintf(stderr, _("Error setting password for user "
					  "%s: %s.\n"), user,
				lu_strerror(error));
			return 3;
		}
	} else {
		if (lu_group_setpass(ctx, ent, password, is_crypted, &error)
		    == FALSE) {
			fprintf(stderr, _("Error setting password for group "
					  "%s: %s.\n"), user,
				lu_strerror(error));
			return 3;
		}
	}

	lu_ent_free(ent);

	lu_end(ctx);

	fprintf(stderr, _("Password changed.\n"));

	return 0;
}
