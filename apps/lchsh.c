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
	struct lu_prompt prompt;
	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

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

	if ((user == NULL) || (geteuid() != getuid())) {
		struct passwd *pwd = NULL;
		pwd = getpwuid(getuid());
		if (pwd != NULL) {
			user = strdup(pwd->pw_name);
		} else {
			fprintf(stderr, _("No user name specified, no name for "
				"uid %d.\n"), getuid());
			poptPrintUsage(popt, stderr, 0);
			exit(1);
		}
	}
	g_print(_("Changing shell for %s.\n"), user);

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

	lu_authenticate_unprivileged(ctx, user, "chsh");

	ent = lu_ent_new();
	if (lu_user_lookup_name(ctx, user, ent, &error)) {
		values = lu_ent_get(ent, LU_LOGINSHELL);
		if ((values != NULL) && (values->n_values > 0)) {
			memset(&prompt, 0, sizeof(prompt));
			prompt.key = "lchfn/shell";
			prompt.prompt = _("New Shell");
			prompt.visible = TRUE;
			value = g_value_array_get_nth(values, 0);
			prompt.default_value = g_value_get_string(value);
			if (lu_prompt_console(&prompt, 1, NULL, &error)) {
				memset(&val, 0, sizeof(val));
				g_value_init(&val, G_TYPE_STRING);
				g_value_set_string(&val, prompt.value);
				lu_ent_clear(ent, LU_LOGINSHELL);
				lu_ent_add(ent, LU_LOGINSHELL, &val);
				if (lu_user_modify(ctx, ent, &error)) {
					g_print(_("Shell changed.\n"));
					lu_hup_nscd();
				}
			}
		}
	} else {
		g_print(_("User %s does not exist.\n"), user);
	}
	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
