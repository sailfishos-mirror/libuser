/*
 * Copyright (C) 2000-2002, 2004 Red Hat, Inc.
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
#include <libintl.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <popt.h>
#include <string.h>
#include <unistd.h>
#include "../lib/user.h"
#include "../lib/user_private.h"
#include "apputil.h"

int
main(int argc, const char **argv)
{
	struct lu_context *ctx = NULL;
	struct lu_ent *ent = NULL;
	struct lu_error *error = NULL;
	const char *user;
	int interactive = FALSE;
	int remove_home = 0, dont_remove_group = 0;
	int c;
	int result;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 N_("prompt for all information"), NULL},
		{"dontremovegroup", 'G', POPT_ARG_NONE, &dont_remove_group, 0,
		 N_("don't remove the user's private group, if the user has "
		    "one"), NULL},
		{"removehome", 'r', POPT_ARG_NONE, &remove_home, 0,
		 N_("remove the user's home directory"), NULL},
		POPT_AUTOHELP POPT_TABLEEND
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("luserdel", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		result = 1;
		goto done;
	}
	user = poptGetArg(popt);

	if (user == NULL) {
		fprintf(stderr, _("No user name specified.\n"));
		poptPrintUsage(popt, stderr, 0);
		result = 1;
		goto done;
	}

	ctx = lu_start(NULL, 0, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
		result = 1;
		goto done;
	}

	ent = lu_ent_new();

	if (lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		result = 2;
		goto done;
	}

	if (lu_user_delete(ctx, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s could not be deleted: %s.\n"),
			user, lu_strerror(error));
		lu_audit_logger(AUDIT_DEL_USER, "delete-user", user,
				AUDIT_NO_ID, 0);
		result = 3;
		goto done;
	}
	lu_audit_logger(AUDIT_DEL_USER, "delete-user", user,
			AUDIT_NO_ID, 1);

	lu_nscd_flush_cache(LU_NSCD_CACHE_PASSWD);

	if (!dont_remove_group) {
		struct lu_ent *group_ent;
		gid_t gid;
		const char *tmp;

		gid = lu_ent_get_first_id(ent, LU_GIDNUMBER);
		if (gid == LU_VALUE_INVALID_ID) {
			fprintf(stderr, _("%s did not have a gid number.\n"),
				user);
			result = 4;
			goto done;
		}
		group_ent = lu_ent_new();
		if (lu_group_lookup_id(ctx, gid, group_ent, &error) == FALSE) {
			fprintf(stderr, _("No group with GID %jd exists, not "
					  "removing.\n"), (intmax_t)gid);
			result = 5;
			goto done;
		}
		tmp = lu_ent_get_first_string(group_ent, LU_GROUPNAME);
		if (tmp == NULL) {
			fprintf(stderr, _("Group with GID %jd did not have a "
					  "group name.\n"), (intmax_t)gid);
			result = 6;
			goto done;
		}
		if (strcmp(tmp, user) == 0) {
			if (lu_group_delete(ctx, group_ent, &error) == FALSE) {
				fprintf(stderr, _("Group %s could not be "
						  "deleted: %s.\n"), tmp,
					lu_strerror(error));
				lu_audit_logger_with_group (AUDIT_DEL_GROUP,
					"delete-group", user, AUDIT_NO_ID,
					tmp, 0);
				result = 7;
				goto done;
			}
		}
		lu_audit_logger_with_group (AUDIT_DEL_GROUP,
					    "delete-group", user,
					    AUDIT_NO_ID, tmp, 1);
		lu_ent_free(group_ent);
		lu_nscd_flush_cache(LU_NSCD_CACHE_GROUP);
	}

	if (remove_home) {
		if (lu_homedir_remove_for_user(ent, &error) == FALSE) {
			fprintf(stderr,
				_("Error removing home directory: %s.\n"),
				lu_strerror(error));
			lu_audit_logger(AUDIT_USER_MGMT,
					"deleting-home-directory", user,
					AUDIT_NO_ID, 0);
			result = 9;
			goto done;
		}
		lu_audit_logger(AUDIT_USER_MGMT, "deleting-home-directory", user,
				AUDIT_NO_ID, 1);

		/* Delete the user's mail spool. */
		if (lu_mail_spool_remove(ctx, ent, &error) != TRUE) {
			fprintf(stderr, _("Error removing mail spool: %s"),
				lu_strerror(error));
			result = 1;
			goto done;
		}
	}

	result = 0;

 done:
	if (ent) lu_ent_free(ent);

	if (ctx) lu_end(ctx);

	poptFreeContext(popt);

	return result;
}
