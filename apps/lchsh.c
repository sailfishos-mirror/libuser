/* Copyright (C) 2001 Red Hat, Inc.
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
#include <sys/stat.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/libuser/user.h"
#include "apputil.h"

int
main(int argc, const char **argv)
{
	const char *user = NULL;
	struct lu_context *ctx = NULL;
	struct lu_error *error = NULL;
	struct lu_ent *ent = NULL;
	GValueArray *values = NULL;
	GValue *value, val;
	int i;
	int interactive = FALSE;
	int c;
	struct lu_prompt prompts[1];
	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	/* Set up i18n. */
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	/* Parse arguments. */
	popt = poptGetContext("lchsh", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] [user]"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}
	user = poptGetArg(popt);

	/* If no user was specified, or we're setuid, force the user name to
	 * be that of the current user. */
	if ((user == NULL) || (geteuid() != getuid())) {
		struct passwd *pwd = NULL;
		pwd = getpwuid(getuid());
		if (pwd != NULL) {
			user = g_strdup(pwd->pw_name);
		} else {
			fprintf(stderr, _("No user name specified, no name for "
				"uid %d.\n"), getuid());
			poptPrintUsage(popt, stderr, 0);
			exit(1);
		}
	}
	/* Give the user some idea of what's going on. */
	g_print(_("Changing shell for %s.\n"), user);

	/* Start up the library. */
	ctx = lu_start(user, lu_user, NULL, NULL,
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

	/* Authenticate the user if we need to. */
	lu_authenticate_unprivileged(ctx, user, "chsh");

	/* Look up this user's record. */
	ent = lu_ent_new();
	if (lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
		g_print(_("User %s does not exist.\n"), user);
		exit(1);
	}

	/* Read the user's shell. */
	values = lu_ent_get(ent, LU_LOGINSHELL);
	if ((values != NULL) && (values->n_values > 0)) {
		value = g_value_array_get_nth(values, 0);
		/* Fill in the prompt structure using the user's shell. */
		memset(&prompts, 0, sizeof(prompts));
		prompts[0].key = "lchfn/shell";
		prompts[0].prompt = N_("New Shell");
		prompts[0].domain = PACKAGE;
		prompts[0].visible = TRUE;
		prompts[0].default_value = g_value_get_string(value);
		/* Prompt for a new shell. */
		if (lu_prompt_console(prompts, G_N_ELEMENTS(prompts),
				      NULL, &error)) {
			/* Modify the in-memory structure's shell attribute. */
			memset(&val, 0, sizeof(val));
			g_value_init(&val, G_TYPE_STRING);
			g_value_set_string(&val, prompts[0].value);
			if (prompts[0].free_value != NULL) {
				prompts[0].free_value(prompts[0].value);
				prompts[0].value = NULL;
			}
			lu_ent_clear(ent, LU_LOGINSHELL);
			lu_ent_add(ent, LU_LOGINSHELL, &val);
			/* Modify the user's record in the information store. */
			if (lu_user_modify(ctx, ent, &error)) {
				g_print(_("Shell changed.\n"));
				lu_hup_nscd();
			}
		}
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
