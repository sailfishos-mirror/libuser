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
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <popt.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/libuser/user.h"
#include "apputil.h"

int
main(int argc, const char **argv)
{
	struct lu_context *ctx = NULL;
	struct lu_ent *ent = NULL;
	struct lu_error *error = NULL;
	char *password = NULL, *cryptedPassword = NULL;
	const char *user = NULL;
	int c;
	int plain_fd = -1, crypted_fd = -1;
	int interactive = 0, group = 0;
	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0, "prompt for all information", NULL},
		{"group", 'g', POPT_ARG_NONE, &group, 0, "set group password instead of user password", NULL},
		{"plainpassword", 'P', POPT_ARG_STRING, &password, 0, "new plain password", NULL},
		{"password", 'p', POPT_ARG_STRING, &cryptedPassword, 0, "new crypted password", NULL},
		{"plainpassword-fd", 'F', POPT_ARG_INT, &plain_fd, 0, "read new plain password from given descriptor", NULL},
		{"password-fd", 'f', POPT_ARG_INT, &crypted_fd, 0, "read new crypted password from given descriptor", NULL},
		POPT_AUTOHELP
	       	{NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lpasswd", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	g_return_val_if_fail(c == -1, 0);
	user = poptGetArg(popt);

	if((user == NULL) || (geteuid() != getuid())) {
		struct passwd *pwd;
		pwd = getpwuid(getuid());
		if(pwd != NULL) {
			fprintf(stderr, _("Changing password for %s.\n"), user = strdup(pwd->pw_name));
		} else {
			fprintf(stderr, _("No user name specified.\n"));
			return 1;
		}
	}

	ctx = lu_start(user, group ? lu_group : lu_user, NULL, NULL, interactive ? lu_prompt_console : lu_prompt_console_quiet,
		       NULL, &error);
	if(ctx == NULL) {
		if(error != NULL) {
			fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE, error->string);
		} else {
			fprintf(stderr, _("Error initializing %s.\n"), PACKAGE);
		}
		return 1;
	}

	lu_authenticate_unprivileged(ctx, user, "passwd");

	if((password == NULL) && (cryptedPassword == NULL) && (plain_fd == -1) && (crypted_fd == -1)) {
		struct lu_prompt prompts[2];
		do {
			memset(&prompts, 0, sizeof(prompts));
			prompts[0].key = "lpasswd/password1";
			prompts[0].prompt = _("New password");
			prompts[1].key = "lpasswd/password2";
			prompts[1].prompt = _("New password (confirm)");
			if(lu_prompt_console(prompts, sizeof(prompts) / sizeof(prompts[0]), NULL, &error)) {
				if(prompts[0].value && strlen(prompts[0].value) && prompts[1].value && strlen(prompts[1].value)) {
					if(strcmp(prompts[0].value, prompts[1].value) == 0) {
						password = strdup(prompts[0].value);
						prompts[0].free_value(prompts[0].value);
						prompts[1].free_value(prompts[1].value);
					} else {
						fprintf(stderr, _("Passwords do not match, try again.\n"));
					}
				} else {
					fprintf(stderr, _("Password change canceled.\n"));
					return 1;
				}
			}
			if(error) {
				lu_error_free(&error);
			}
		} while(password == NULL);
	}

	ent = lu_ent_new();

	if(!group) {
		if(lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
			fprintf(stderr, _("User %s does not exist.\n"), user);
			return 2;
		}
	} else {
		if(lu_group_lookup_name(ctx, user, ent, &error) == FALSE) {
			fprintf(stderr, _("Group %s does not exist.\n"), user);
			return 2;
		}
	}

	if(plain_fd != -1) {
		char buf[LINE_MAX];
		int i;
		memset(buf, '\0', sizeof(buf));
		i = read(plain_fd, buf, sizeof(buf));
		while((i > 0) && ((buf[i - 1] == '\r') || (buf[i - 1] == '\n'))) {
			buf[--i] = '\0';
		}
		password = buf;
	} else
	if(crypted_fd != -1) {
		char buf[LINE_MAX];
		int i;
		memset(buf, '\0', sizeof(buf));
		i = read(crypted_fd, buf, sizeof(buf));
		while((i > 0) && ((buf[i - 1] == '\r') || (buf[i - 1] == '\n'))) {
			buf[--i] = '\0';
		}
		password = g_strconcat("{crypt}", buf, NULL);
	} else
	if(cryptedPassword != NULL) {
		password = g_strconcat("{crypt}", cryptedPassword, NULL);
	} else {
		/* the password variable is already set */
	}

	if(!group) {
		if(lu_user_setpass(ctx, ent, password, &error) == FALSE) {
			fprintf(stderr, _("Error setting password for user %s: %s.\n"), user, error->string);
			return 3;
		}
	} else {
		if(lu_group_setpass(ctx, ent, password, &error) == FALSE) {
			fprintf(stderr, _("Error setting password for group %s: %s.\n"), user, error->string);
			return 3;
		}
	}

	lu_ent_free(ent);

	lu_end(ctx);

	fprintf(stderr, _("Password changed.\n"));

	return 0;
}