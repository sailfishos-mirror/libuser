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
	struct lu_context *ctx;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	const char *group;
	int interactive = FALSE;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lgroupdel", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] group"));
	c = poptGetNextOpt(popt);
	g_return_val_if_fail(c == -1, 0);
	group = poptGetArg(popt);

	if(group == NULL) {
		fprintf(stderr, _("No group name specified.\n"));
		return 1;
	}

	ctx = lu_start(NULL, 0, NULL, NULL,
		       interactive ? lu_prompt_console:lu_prompt_console_quiet,
		       NULL, &error);
	g_return_val_if_fail(ctx != NULL, 1);

	ent = lu_ent_new();

	if(lu_group_lookup_name(ctx, group, ent, &error) == FALSE) {
		fprintf(stderr, _("Group %s does not exist.\n"), group);
		return 2;
	}

	if(lu_group_delete(ctx, ent, &error) == FALSE) {
		fprintf(stderr, _("Group %s could not be deleted.\n"), group);
		return 3;
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
