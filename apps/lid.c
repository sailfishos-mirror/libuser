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
#include <grp.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include <pwd.h>
#include <stdlib.h>
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
	int group = FALSE, nameonly = FALSE;
	int c;
	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0, "prompt for all information", NULL},
		{"group", 'g', POPT_ARG_NONE, &group, 0, "list members of a named group instead of the group memberships for "
		 "the named user", NULL},
		{"onlynames", 'n', POPT_ARG_NONE, &nameonly, 0, "only list membership information by name, and not UID/GID",
		 NULL},
		POPT_AUTOHELP
	       	{NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lid", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	g_return_val_if_fail(c == -1, 0);
	user = poptGetArg(popt);

	if(user == NULL) {
		struct passwd *pwd = NULL;
		struct group *grp = NULL;
		if(group) {
			grp = getgrgid(getgid());
			if(grp != NULL) {
				fprintf(stderr, _("No group name specified, using %s.\n"), grp->gr_name);
				user = grp->gr_name;
			} else {
				fprintf(stderr, _("No group name specified, no name for gid %d.\n"), getgid());
				exit(1);
			}
		} else {
			pwd = getpwuid(getuid());
			if(pwd != NULL) {
				fprintf(stderr, _("No user name specified, using %s.\n"), pwd->pw_name);
				user = pwd->pw_name;
			} else {
				fprintf(stderr, _("No user name specified, no name for uid %d.\n"), getuid());
				exit(1);
			}
		}
	}

	ctx = lu_start(user, group ? lu_user : lu_group, NULL, NULL,
		       interactive ? lu_prompt_console : lu_prompt_console_quiet, NULL, &error);
	if(ctx == NULL) {
		if(error != NULL) {
			fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE, error->string);
		} else {
			fprintf(stderr, _("Error initializing %s.\n"), PACKAGE);
		}
		return 1;
	}

	if(group) {
		values = lu_users_enumerate_by_group(ctx, user, NULL, &error);
		if(values) {
			for(l = values; l && l->data; l = g_list_next(l)) {
				ent = lu_ent_new();
				if(!nameonly && lu_user_lookup_name(ctx, (char*)l->data, ent, &error)) {
					i = lu_ent_get(ent, LU_UIDNUMBER);
					if(i) {
						g_print(" %s(uid=%s)\n", (char*)l->data, (char*)i->data);
					} else {
						g_print(" %s\n", (char*)l->data);
					}
				} else {
					if(error) {
						lu_error_free(&error);
					}
					g_print(" %s\n", (char*)l->data);
				}
				lu_ent_free(ent);
			}
			g_list_free(values);
		}
	} else {
		values = lu_groups_enumerate_by_user(ctx, user, NULL, &error);
		if(values) {
			for(l = values; l && l->data; l = g_list_next(l)) {
				ent = lu_ent_new();
				if(!nameonly && lu_group_lookup_name(ctx, (char*)l->data, ent, &error)) {
					i = lu_ent_get(ent, LU_GIDNUMBER);
					if(i) {
						g_print(" %s(gid=%s)\n", (char*)l->data, (char*)i->data);
					} else {
						g_print(" %s\n", (char*)l->data);
					}
				} else {
					if(error) {
						lu_error_free(&error);
					}
					g_print(" %s\n", (char*)l->data);
				}
				lu_ent_free(ent);
			}
			g_list_free(values);
		}
	}

	lu_end(ctx);

	return 0;
}