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
	GList *values, *l, *i;
	int interactive = FALSE;
	int c;
	struct lu_prompt prompt;
	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0, "prompt for all information", NULL},
		POPT_AUTOHELP
	       	{NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lchsh", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] [user]"));
	c = poptGetNextOpt(popt);
	g_return_val_if_fail(c == -1, 0);
	user = poptGetArg(popt);

	if(user == NULL) {
		struct passwd *pwd = NULL;
		pwd = getpwuid(getuid());
		if(pwd != NULL) {
			user = pwd->pw_name;
		} else {
			fprintf(stderr, _("No user name specified, no name for uid %d.\n"), getuid());
			exit(1);
		}
	}
	g_print(_("Changing shell for %s.\n"), user);

	ctx = lu_start(user, lu_user, NULL, NULL, interactive ? lu_prompt_console : lu_prompt_console_quiet, NULL, &error);
	if(error) {
		fprintf(stderr, _("error: %s\n"), error->string);
	}
	g_return_val_if_fail(ctx != NULL, 1);

	ent = lu_ent_new();
	if(lu_user_lookup_name(ctx, user, ent, &error)) {
		i = lu_ent_get(ent, LU_LOGINSHELL);
		if(i) {
			memset(&prompt, 0, sizeof(prompt));
			prompt.key = "lchfn/shell";
			prompt.prompt = _("New Shell");
			prompt.visible = TRUE;
			prompt.default_value = i->data;
			if(lu_prompt_console(&prompt, 1, NULL, &error)) {
				lu_ent_set(ent, LU_LOGINSHELL, prompt.value);
				if(lu_user_modify(ctx, ent, &error)) {
					g_print(_("Shell changed.\n"));
				}
			}
		}
	}
	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
