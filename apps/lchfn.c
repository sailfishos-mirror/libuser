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

#define NAME_KEY		"lchfn/name"
#define SURNAME_KEY		"lchfn/surname"
#define GIVENNAME_KEY		"lchfn/givenname"
#define OFFICE_KEY		"lchfn/office"
#define OFFICEPHONE_KEY		"lchfn/officephone"
#define HOMEPHONE_KEY		"lchfn/homephone"
#define EMAIL_KEY		"lchfn/email"

int
main(int argc, const char **argv)
{
	const char *user = NULL, *gecos = NULL, *sn, *cn, *gn, *email;
	char *name, *office, *officephone, *homephone;
	struct lu_context *ctx = NULL;
	struct lu_error *error = NULL;
	struct lu_ent *ent = NULL;
	GValueArray *values;
	GValue *value, val;
	int interactive = FALSE;
	int c;
	struct lu_prompt prompts[7];
	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};
	char **fields;
	size_t fields_len;
	int pcount, i;
	struct passwd *pwd = NULL;

	/* Set up i18n. */
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	/* Parse command-line arguments. */
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

	/* If no user name was specified, or we're running in a setuid
	 * environment, force the user name to be the current user. */
	if ((user == NULL) || (geteuid() != getuid())) {
		pwd = getpwuid(getuid());
		if (pwd != NULL) {
			user = g_strdup(pwd->pw_name);
		} else {
			fprintf(stderr, _("No user name specified, no name "
				"for uid %d.\n"), getuid());
			poptPrintUsage(popt, stderr, 0);
			exit(1);
		}
	}

	/* Give the user some idea of what's going on. */
	g_print(_("Changing finger information for %s.\n"), user);

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

	/* Authenticate the user to the "chfn" service. */
	lu_authenticate_unprivileged(ctx, user, "chfn");

	/* Look up the user's information. */
	ent = lu_ent_new();
	if (lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
		g_print(_("User %s does not exist.\n"), user);
	}

	/* Read the user's GECOS information. */
	values = lu_ent_get(ent, LU_GECOS);
	if (values != NULL) {
		value = g_value_array_get_nth(values, 0);
		gecos = g_value_get_string(value);
	} else {
		gecos = "";
	}

	/* Split the gecos into the prompt structures. */
	fields = g_strsplit(gecos, ",", G_N_ELEMENTS(prompts));

	/* Count the number of fields we got. */
	fields_len = 0;
	if (fields != NULL) {
		while (fields[fields_len] != NULL) {
			fields_len++;
		}
	}

	/* Fill out the prompt structures. */
	memset(&prompts, 0, sizeof(prompts));
	pcount = 0;

	/* The first prompt is for the full name. */
	name = (fields_len > 0) ? fields[0] : NULL;
	prompts[pcount].key = "lchfn/name";
	prompts[pcount].prompt = NAME_KEY;
	prompts[pcount].domain = PACKAGE;
	prompts[pcount].visible = TRUE;
	prompts[pcount].default_value = name;
	pcount++;

	/* If we have it, prompt for the user's surname. */
	values = lu_ent_get(ent, LU_SN);
	if ((values != NULL) && (values->n_values > 0)) {
		value = g_value_array_get_nth(values, 0);
		sn = g_value_get_string(value);
		prompts[pcount].key = SURNAME_KEY;
		prompts[pcount].prompt = N_("Surname");
		prompts[pcount].domain = PACKAGE;
		prompts[pcount].visible = TRUE;
		prompts[pcount].default_value = sn;
		pcount++;
	}

	/* If we have it, prompt for the user's givenname. */
	values = lu_ent_get(ent, LU_GIVENNAME);
	if ((values != NULL) && (values->n_values > 0)) {
		value = g_value_array_get_nth(values, 0);
		gn = g_value_get_string(value);
		prompts[pcount].key = GIVENNAME_KEY;
		prompts[pcount].prompt = N_("Given Name");
		prompts[pcount].domain = PACKAGE;
		prompts[pcount].visible = TRUE;
		prompts[pcount].default_value = gn;
		pcount++;
	}

	/* Prompt for the user's office number. */
	office = (fields_len > 1) ? fields[1] : NULL;
	prompts[pcount].key = OFFICE_KEY;
	prompts[pcount].prompt = N_("Office");
	prompts[pcount].domain = PACKAGE;
	prompts[pcount].visible = TRUE;
	prompts[pcount].default_value = office;
	pcount++;

	/* Prompt for the user's office telephone number. */
	officephone = (fields_len > 2) ? fields[2] : NULL;
	prompts[pcount].key = OFFICEPHONE_KEY;
	prompts[pcount].prompt = N_("Office Phone");
	prompts[pcount].domain = PACKAGE;
	prompts[pcount].visible = TRUE;
	prompts[pcount].default_value = officephone;
	pcount++;

	/* Prompt for the user's home telephone number. */
	homephone = (fields_len > 3) ? fields[3] : NULL;
	prompts[pcount].key = HOMEPHONE_KEY;
	prompts[pcount].prompt = N_("Home Phone");
	prompts[pcount].domain = PACKAGE;
	prompts[pcount].visible = TRUE;
	prompts[pcount].default_value = homephone;
	pcount++;

	/* If we have it, prompt for the user's email. */
	values = lu_ent_get(ent, LU_EMAIL);
	if ((values != NULL) && (values->n_values > 0)) {
		value = g_value_array_get_nth(values, 0);
		email = g_value_get_string(value);
		prompts[pcount].key = EMAIL_KEY;
		prompts[pcount].prompt = N_("E-Mail Address");
		prompts[pcount].domain = PACKAGE;
		prompts[pcount].visible = TRUE;
		prompts[pcount].default_value = email;
		pcount++;
	}

	/* Sanity check. */
	g_assert(pcount <= G_N_ELEMENTS(prompts));

	/* Ask the user for new values. */
	if (lu_prompt_console(prompts, pcount, NULL, &error) == FALSE) {
		g_print(_("Finger information not changed:  input error.\n"));
		exit(1);
	}

	/* Initialize the temporary value variable. */
	memset(&val, 0, sizeof(val));
	g_value_init(&val, G_TYPE_STRING);

	/* Now iterate over the answers and figure things out. */
	for (i = 0; i < pcount; i++) {
		g_value_set_string(&val, prompts[i].value);

		if (strcmp(prompts[i].key, NAME_KEY) == 0) {
			name = prompts[i].value;
			lu_ent_clear(ent, LU_COMMONNAME);
			lu_ent_add(ent, LU_COMMONNAME, &val);
		}

		if (strcmp(prompts[i].key, SURNAME_KEY) == 0) {
			sn = prompts[i].value;
			lu_ent_clear(ent, LU_SN);
			lu_ent_add(ent, LU_SN, &val);
		}

		if (strcmp(prompts[i].key, GIVENNAME_KEY) == 0) {
			gn = prompts[i].value;
			lu_ent_clear(ent, LU_GIVENNAME);
			lu_ent_add(ent, LU_GIVENNAME, &val);
		}

		if (strcmp(prompts[i].key, OFFICE_KEY) == 0) {
			office = prompts[i].value;
			lu_ent_clear(ent, LU_ROOMNUMBER);
			lu_ent_add(ent, LU_ROOMNUMBER, &val);
		}

		if (strcmp(prompts[i].key, OFFICEPHONE_KEY) == 0) {
			officephone = prompts[i].value;
			lu_ent_clear(ent, LU_TELEPHONENUMBER);
			lu_ent_add(ent, LU_TELEPHONENUMBER, &val);
		}

		if (strcmp(prompts[i].key, HOMEPHONE_KEY) == 0) {
			homephone = prompts[i].value;
			lu_ent_clear(ent, LU_HOMEPHONE);
			lu_ent_add(ent, LU_HOMEPHONE, &val);
		}

		if (strcmp(prompts[i].key, EMAIL_KEY) == 0) {
			email = prompts[i].value;
			lu_ent_clear(ent, LU_EMAIL);
			lu_ent_add(ent, LU_EMAIL, &val);
		}

		if (prompts[i].value != NULL) {
			if (prompts[i].free_value != NULL) {
				prompts[i].free_value(prompts[i].value);
				prompts[i].value = NULL;
			}
		}
	}

	/* Build a new gecos string. */
	gecos = g_strjoin(",",
			  name ?: "",
			  office ?: "",
			  officephone ?: "",
			  homephone ?: "",
			  NULL);

	/* Set the GECOS attribute. */
	g_value_set_string(&val, gecos);
	lu_ent_clear(ent, LU_GECOS);
	lu_ent_add(ent, LU_GECOS, &val);

	/* Try to save our changes. */
	if (lu_user_modify(ctx, ent, &error)) {
		g_print(_("Finger information changed.\n"));
		lu_hup_nscd();
	} else {
		if (error && error->string) {
			g_print(_("Finger information not changed: %s.\n"),
				error->string);
		} else {
			g_print(_("Finger information not changed: unknown "
				"error.\n"));
		}
	}

	g_strfreev(fields);

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
