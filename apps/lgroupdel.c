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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include "../lib/user.h"
#include "../lib/user_private.h"
#include "apputil.h"

int
main(int argc, const char **argv)
{
	struct lu_context *ctx = NULL;
	struct lu_ent *ent = NULL;
	struct lu_error *error = NULL;
	const char *group;
	int interactive = FALSE;
	int c;
	int result;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 N_("prompt for all information"), NULL},
		POPT_AUTOHELP POPT_TABLEEND
	};

	/* Set up for i18n. */
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	/* Parse arguments. */
	popt = poptGetContext("lgroupdel", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] group"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		result = 1;
		goto done;
	}
	group = poptGetArg(popt);

	/* The caller has to specify a group name. */
	if (group == NULL) {
		fprintf(stderr, _("No group name specified.\n"));
		poptPrintUsage(popt, stderr, 0);
		result = 1;
		goto done;
	}

	/* Start up the library. */
	ctx = lu_start(NULL, 0, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
		result = 1;
		goto done;
	}

	/* Look up the group structure. */
	ent = lu_ent_new();
	if (lu_group_lookup_name(ctx, group, ent, &error) == FALSE) {
		fprintf(stderr, _("Group %s does not exist.\n"), group);
		result = 2;
		goto done;
	}

	/* Delete the group. */
	if (lu_group_delete(ctx, ent, &error) == FALSE) {
		fprintf(stderr, _("Group %s could not be deleted: %s\n"),
			group, lu_strerror(error));
		lu_audit_logger(AUDIT_DEL_GROUP, "delete-group", group,
				AUDIT_NO_ID, 0);
		result = 3;
		goto done;
	}

	lu_nscd_flush_cache(LU_NSCD_CACHE_GROUP);

	lu_audit_logger(AUDIT_DEL_GROUP, "delete-group", group,
			AUDIT_NO_ID, 1);
	result = 0;

 done:
	if (ent) lu_ent_free(ent);

	if (ctx) lu_end(ctx);

	poptFreeContext(popt);

	return result;
}
