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
	const char *user = NULL, *gecos = NULL, *sn, *cn, *gn;
	struct lu_context *ctx = NULL;
	struct lu_error *error = NULL;
	struct lu_ent *ent = NULL;
	GValueArray *values;
	GValue *value, val;
	int interactive = FALSE;
	int c;
	struct lu_prompt prompts[6];
	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};
	char **fields;
	size_t fields_len;

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lchfn", argc, argv, options, 0);
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
			fprintf(stderr, _("No user name specified, no name "
				"for uid %d.\n"), getuid());
			poptPrintUsage(popt, stderr, 0);
			exit(1);
		}
	}
	g_print(_("Changing finger information for %s.\n"), user);

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

	lu_authenticate_unprivileged(ctx, user, "chfn");

	ent = lu_ent_new();
	if (lu_user_lookup_name(ctx, user, ent, &error)) {
		values = lu_ent_get(ent, LU_GECOS);
		if (values != NULL) {
			value = g_value_array_get_nth(values, 0);
			gecos = g_value_get_string(value);

			memset(&prompts, 0, sizeof(prompts));

			fields = g_strsplit(gecos, ",", G_N_ELEMENTS(prompts));

			fields_len = 0;
			if (fields != NULL) {
				while (fields[fields_len] != NULL) {
					fields_len++;
				}
			}

			prompts[0].key = "lchfn/name";
			prompts[0].prompt = _("Name");
			prompts[0].visible = TRUE;
			prompts[0].default_value = (fields_len > 0) ?
						   fields[0] : NULL;

			values = lu_ent_get(ent, LU_SN);
			if ((values != NULL) && (values->n_values > 0)) {
				value = g_value_array_get_nth(values, 0);
				sn = g_value_get_string(value);
			} else {
				sn = NULL;
			}
			prompts[1].key = "lchfn/surname";
			prompts[1].prompt = _("Surname");
			prompts[1].visible = TRUE;
			prompts[1].default_value = sn;

			values = lu_ent_get(ent, LU_GIVENNAME);
			if ((values != NULL) && (values->n_values > 0)) {
				value = g_value_array_get_nth(values, 0);
				gn = g_value_get_string(value);
			} else {
				gn = NULL;
			}
			prompts[2].key = "lchfn/givenname";
			prompts[2].prompt = _("Given Name");
			prompts[2].visible = TRUE;
			prompts[2].default_value = gn;

			prompts[3].key = "lchfn/office";
			prompts[3].prompt = _("Office");
			prompts[3].visible = TRUE;
			prompts[3].default_value = (fields_len > 1) ?
						   fields[1] : NULL;

			prompts[4].key = "lchfn/officephone";
			prompts[4].prompt = _("Office Phone");
			prompts[4].visible = TRUE;
			prompts[4].default_value = (fields_len > 2) ?
						   fields[2] : NULL;

			prompts[5].key = "lchfn/homephone";
			prompts[5].prompt = _("Home Phone");
			prompts[5].visible = TRUE;
			prompts[5].default_value = (fields_len > 3) ?
			      		 	   fields[3] : NULL;

			if (lu_prompt_console(prompts,
					      G_N_ELEMENTS(prompts),
					      NULL,
					      &error)) {
				memset(&val, 0, sizeof(val));
				g_value_init(&val, G_TYPE_STRING);
				if (prompts[0].value &&
				    strlen(prompts[0].value)) {
					g_value_set_string(&val,
							   prompts[0].value);
					lu_ent_clear(ent, LU_COMMONNAME);
					lu_ent_add(ent, LU_COMMONNAME, &val);
				}
				if (prompts[1].value &&
				    strlen(prompts[1].value)) {
					g_value_set_string(&val,
							   prompts[1].value);
					lu_ent_clear(ent, LU_SN);
					lu_ent_add(ent, LU_SN, &val);
				}
				if (prompts[2].value &&
				    strlen(prompts[2].value)) {
					g_value_set_string(&val,
							   prompts[2].value);
					lu_ent_clear(ent, LU_GIVENNAME);
					lu_ent_add(ent, LU_GIVENNAME, &val);
				}
				if (prompts[3].value
				    && strlen(prompts[3].value)) {
					g_value_set_string(&val,
							   prompts[3].value);
					lu_ent_clear(ent, LU_ROOMNUMBER);
					lu_ent_add(ent, LU_ROOMNUMBER, &val);
				}
				if (prompts[4].value
				    && strlen(prompts[4].value)) {
					g_value_set_string(&val,
							   prompts[4].value);
					lu_ent_clear(ent, LU_TELEPHONENUMBER);
					lu_ent_add(ent, LU_TELEPHONENUMBER,
						   &val);
				}
				if (prompts[5].value
				    && strlen(prompts[5].value)) {
					g_value_set_string(&val,
							   prompts[5].value);
					lu_ent_clear(ent, LU_HOMEPHONE);
					lu_ent_add(ent, LU_HOMEPHONE, &val);
				}

				lu_ent_clear(ent, LU_GECOS);
				g_value_set_string(&val,
						   prompts[5].value);
				g_strjoin(",",
					  prompts[0].value ?: "",
					  prompts[1].value ?: "",
					  prompts[2].value ?: "",
					  prompts[3].value ?: "",
					  prompts[4].value ?: "",
					  prompts[5].value ?: "",
					  NULL);
				lu_ent_add(ent, LU_GECOS, &val);

				if (lu_user_modify(ctx, ent, &error)) {
					g_print(_("Finger information "
						"changed.\n"));
					lu_hup_nscd();
				} else {
					if (error && error->string) {
						g_print(_("Finger information "
							"not changed: %s.\n"),
							error->string);
					} else {
						g_print(_("Finger information "
							"not changed: unknown "
							"error.\n"));
					}
				}
			}
			g_strfreev(fields);
		}
	} else {
		g_print(_("User %s does not exist.\n"), user);
	}
	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
