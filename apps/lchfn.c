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
	GList *i = NULL;
	int interactive = FALSE;
	int c;
	struct lu_prompt prompts[6];
	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0, "prompt for all information", NULL},
		POPT_AUTOHELP
	       	{NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};
	char **fields;

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lchfn", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] [user]"));
	c = poptGetNextOpt(popt);
	g_return_val_if_fail(c == -1, 0);
	user = poptGetArg(popt);

	if((user == NULL) || (geteuid() != getuid())) {
		struct passwd *pwd = NULL;
		pwd = getpwuid(getuid());
		if(pwd != NULL) {
			user = strdup(pwd->pw_name);
		} else {
			fprintf(stderr, _("No user name specified, no name for uid %d.\n"), getuid());
			exit(1);
		}
	}
	g_print(_("Changing finger information for %s.\n"), user);

	ctx = lu_start(user, lu_user, NULL, NULL, interactive ? lu_prompt_console : lu_prompt_console_quiet, NULL, &error);
	if(ctx == NULL) {
		if(error != NULL) {
			fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE, error->string);
		} else {
			fprintf(stderr, _("Error initializing %s.\n"), PACKAGE);
		}
		return 1;
	}

	lu_authenticate_unprivileged(ctx, user, "chfn");

	ent = lu_ent_new();
	if(lu_user_lookup_name(ctx, user, ent, &error)) {
		i = lu_ent_get(ent, LU_GECOS);
		if(i) {
			GList *sn, *gn;

			memset(&prompts, 0, sizeof(prompts));

			fields = g_strsplit((char*)i->data, ",", sizeof(prompts) / sizeof(prompts[0]));

			prompts[0].key = "lchfn/name";
			prompts[0].prompt = _("Name");
			prompts[0].visible = TRUE;
			prompts[0].default_value = (fields && fields[0]) ? fields[0] : NULL;

			sn = lu_ent_get(ent, LU_SN);
			prompts[1].key = "lchfn/surname";
			prompts[1].prompt = _("Surname");
			prompts[1].visible = TRUE;
			prompts[1].default_value = (sn && sn->data && (strlen((char*)sn->data) > 0)) ? (char*)sn->data : NULL;

			gn = lu_ent_get(ent, LU_GIVENNAME);
			prompts[2].key = "lchfn/givenname";
			prompts[2].prompt = _("Given Name");
			prompts[2].visible = TRUE;
			prompts[2].default_value = (gn && gn->data && (strlen((char*)gn->data) > 0)) ? (char*)gn->data : NULL;

			prompts[3].key = "lchfn/office";
			prompts[3].prompt = _("Office");
			prompts[3].visible = TRUE;
			prompts[3].default_value = (fields && fields[0] && fields[1]) ? fields[1] : NULL;

			prompts[4].key = "lchfn/officephone";
			prompts[4].prompt = _("Office Phone");
			prompts[4].visible = TRUE;
			prompts[4].default_value = (fields && fields[0] && fields[1] && fields[2]) ? fields[2] : NULL;

			prompts[5].key = "lchfn/homephone";
			prompts[5].prompt = _("Home Phone");
			prompts[5].visible = TRUE;
			prompts[5].default_value = (fields && fields[0] && fields[1] && fields[2] && fields[3]) ? fields[3] : NULL;

			if(lu_prompt_console(prompts, sizeof(prompts) / sizeof(prompts[0]), NULL, &error)) {
				if(prompts[0].value && strlen(prompts[0].value)) {
					if(lu_ent_get(ent, LU_CN)) {
						lu_ent_set(ent, LU_CN, prompts[0].value);
					}
				}
				if(prompts[1].value && strlen(prompts[1].value)) {
					if(lu_ent_get(ent, LU_SN)) {
						lu_ent_set(ent, LU_SN, prompts[1].value);
					}
				}
				if(prompts[2].value && strlen(prompts[2].value)) {
					if(lu_ent_get(ent, LU_GIVENNAME)) {
						lu_ent_set(ent, LU_GIVENNAME, prompts[2].value);
					}
				}
				if(prompts[3].value && strlen(prompts[3].value)) {
					if(lu_ent_get(ent, LU_ROOMNUMBER)) {
						lu_ent_set(ent, LU_ROOMNUMBER, prompts[3].value);
					}
				}
				if(prompts[4].value && strlen(prompts[4].value)) {
					if(lu_ent_get(ent, LU_TELEPHONENUMBER)) {
						lu_ent_set(ent, LU_TELEPHONENUMBER, prompts[4].value);
					}
				}
				if(prompts[5].value && strlen(prompts[5].value)) {
					if(lu_ent_get(ent, LU_HOMEPHONE)) {
						lu_ent_set(ent, LU_HOMEPHONE, prompts[5].value);
					}
				}

				lu_ent_set(ent, LU_GECOS, g_strjoin(",",
								    prompts[0].value ?: "",
								    prompts[3].value ?: "",
								    prompts[4].value ?: "",
								    prompts[5].value ?: "",
								    NULL));

				if(lu_user_modify(ctx, ent, &error)) {
					g_print(_("Finger information changed.\n"));
				} else {
					if(error && error->string) {
						g_print(_("Finger information not changed: %s.\n"), error->string);
					} else {
						g_print(_("Finger information not changed: unknown error.\n"));
					}
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
