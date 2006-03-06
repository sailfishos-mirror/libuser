/*
 * Copyright (C) 2001, 2002, 2004, 2006 Red Hat, Inc.
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
#include "../lib/user.h"
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
	const char *user, *gecos;
	const char *name, *office, *officephone, *homephone;
	struct lu_context *ctx;
	struct lu_error *error = NULL;
	struct lu_ent *ent;
	GValueArray *values;
	GValue *value, val;
	int interactive = FALSE;
	int c;
	struct lu_prompt prompts[7];
	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		POPT_AUTOHELP POPT_TABLEEND
	};
	char **fields;
	size_t fields_len;
	size_t pcount, i;

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
		struct passwd *pwd;

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

	/* Authenticate the user to the "chfn" service. */
	lu_authenticate_unprivileged(user, "chfn");

	/* Give the user some idea of what's going on. */
	g_print(_("Changing finger information for %s.\n"), user);

	/* Start up the library. */
	ctx = lu_start(user, lu_user, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
		return 1;
	}

	/* Look up the user's information. */
	ent = lu_ent_new();
	if (lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		exit(1);
	}

	/* Read the user's GECOS information. */
	values = lu_ent_get(ent, LU_GECOS);
	if (values != NULL) {
		value = g_value_array_get_nth(values, 0);
		gecos = lu_value_strdup(value);
	} else {
		gecos = "";
	}

	/* Split the gecos into the prompt structures. */
	fields = g_strsplit(gecos, ",", G_N_ELEMENTS(prompts));

	/* Count the number of fields we got. */
	fields_len = g_strv_length(fields);

	/* Fill out the prompt structures. */
	memset(prompts, 0, sizeof(prompts));
	pcount = 0;

	/* The first prompt is for the full name. */
	name = (fields_len > 0) ? fields[0] : NULL;
	prompts[pcount].key = NAME_KEY;
	prompts[pcount].prompt = N_("Full Name");
	prompts[pcount].domain = PACKAGE;
	prompts[pcount].visible = TRUE;
	prompts[pcount].default_value = name;
	pcount++;

	/* If we have it, prompt for the user's surname. */
	values = lu_ent_get(ent, LU_SN);
	if (values != NULL) {
		const char *sn;

		value = g_value_array_get_nth(values, 0);
		sn = lu_value_strdup(value);
		prompts[pcount].key = SURNAME_KEY;
		prompts[pcount].prompt = N_("Surname");
		prompts[pcount].domain = PACKAGE;
		prompts[pcount].visible = TRUE;
		prompts[pcount].default_value = sn;
		pcount++;
	}

	/* If we have it, prompt for the user's givenname. */
	values = lu_ent_get(ent, LU_GIVENNAME);
	if (values != NULL) {
		const char *gn;

		value = g_value_array_get_nth(values, 0);
		gn = lu_value_strdup(value);
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
	if (values != NULL) {
		const char *email;

		value = g_value_array_get_nth(values, 0);
		email = lu_value_strdup(value);
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
		fprintf(stderr,
			_("Finger information not changed:  input error.\n"));
		exit(1);
	}

	/* Initialize the temporary value variable. */
	memset(&val, 0, sizeof(val));
	g_value_init(&val, G_TYPE_STRING);

	/* Now iterate over the answers and figure things out. */
	for (i = 0; i < pcount; i++) {
		const char *filtered;

		if (prompts[i].value == NULL) {
			filtered = "";
		} else
		if (strcmp(prompts[i].value, ".") == 0) {
			filtered = "";
		} else {
			filtered = prompts[i].value;
		}
		g_value_set_string(&val, filtered);

#define ATTR__(KEY, EXTRA, ATTR)				\
		if (strcmp(prompts[i].key, KEY) == 0) {		\
			EXTRA;					\
			lu_ent_clear(ent, ATTR);		\
			if (strlen(filtered) > 0)		\
				lu_ent_add(ent, ATTR, &val);	\
		}
#define ATTR(KEY, ATTR_) ATTR__(KEY, , ATTR_)
#define NAMED_ATTR(KEY, NAME, ATTR_) ATTR__(KEY, NAME = filtered, ATTR_)

		NAMED_ATTR(NAME_KEY, name, LU_COMMONNAME);
		ATTR(SURNAME_KEY, LU_SN);
		ATTR(GIVENNAME_KEY, LU_GIVENNAME);
		NAMED_ATTR(OFFICE_KEY, office, LU_ROOMNUMBER);
		NAMED_ATTR(OFFICEPHONE_KEY, officephone, LU_TELEPHONENUMBER);
		NAMED_ATTR(HOMEPHONE_KEY, homephone, LU_HOMEPHONE);
		ATTR(EMAIL_KEY, LU_EMAIL);
#undef NAMED_ATTR
#undef ATTR
#undef ATTR__
	}

	g_value_reset(&val);

	/* Build a new gecos string. */
	gecos = g_strjoin(",",
			  name ?: "",
			  office ?: "",
			  officephone ?: "",
			  homephone ?: "",
			  NULL);

	/* Now we can free the answers. */
	for (i = 0; i < pcount; i++) {
		if (prompts[i].value != NULL) {
			if (prompts[i].free_value != NULL) {
				prompts[i].free_value(prompts[i].value);
				prompts[i].value = NULL;
			}
		}
	}

	/* Set the GECOS attribute. */
	g_value_set_string(&val, gecos);
	lu_ent_clear(ent, LU_GECOS);
	lu_ent_add(ent, LU_GECOS, &val);
	g_value_reset(&val);

	/* Try to save our changes. */
	if (lu_user_modify(ctx, ent, &error)) {
		g_print(_("Finger information changed.\n"));
		lu_hup_nscd();
	} else {
		fprintf(stderr, _("Finger information not changed: %s.\n"),
			lu_strerror(error));
		return 1;
	}

	g_value_unset(&val);

	g_strfreev(fields);

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
