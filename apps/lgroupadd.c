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
	const char *name = NULL;
	long gidNumber = -2;
	struct lu_context *ctx = NULL;
	struct lu_ent *ent = NULL;
	struct lu_error *error = NULL;
	int interactive = FALSE;
	int system_account = FALSE;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0, "prompt for all information", NULL},
		{"gid", 'g', POPT_ARG_LONG, &gidNumber, 0, "gid to force for new group", "NUM"},
		{"reserved", 'r', POPT_ARG_NONE, &system_account, 0, "make this a system group"},
		POPT_AUTOHELP
	       	{NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lgroupadd", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] group"));
	c = poptGetNextOpt(popt);
	if(c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"), poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}
	name = poptGetArg(popt);

	if(name == NULL) {
		fprintf(stderr, _("No group name specified.\n"));
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

	ent = lu_ent_new();
	lu_group_default(ctx, name, system_account, ent);

	if(gidNumber != -2) {
		lu_ent_set_numeric(ent, LU_GIDNUMBER, gidNumber);
	}

	if(lu_group_add(ctx, ent, &error) == FALSE) {
		fprintf(stderr, _("Group creation failed.\n"));
		return 2;
	}
	lu_hup_nscd();

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
