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
#include "../config.h"
#endif
#include <sys/time.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include <glib.h>
#include "../lib/user.h"
#include "apputil.h"

/* Parse the first element of a value array for a count of days, and return
 * the value.  If the array is empty, or invalid somehow, return the default
 * of -1.  */
static gint
read_ndays(GValueArray *array)
{
	const char *s;
	char *p;
	GValue *value;
	gint n_days = -1;
	/* If we have a non-empty array, check its first element. */
	if ((array != NULL) && (array->n_values > 0)) {
		value = g_value_array_get_nth(array, 0);
		if (value != NULL) {
			/* If it's a string, use strtol to read it. */
			if (G_VALUE_HOLDS_STRING(value)) {
				s = g_value_get_string(value);
				n_days = strtol(s, &p, 10);
				if (*p != '\0') {
					n_days = -1;
				}
			} else
			/* If it's a long, read it directly. */
			if (G_VALUE_HOLDS_LONG(value)) {
				n_days = g_value_get_long(value);
			} else {
				g_assert_not_reached();
			}
		}
	}
	return n_days;
}

/* Format a count of days into a string that's intelligible to a user. */
static void
date_to_string(gint n_days, char *buf, size_t len)
{
	GDate *date;

	if ((n_days >= 0) && (n_days < 99999)) {
		date = g_date_new_dmy(1, G_DATE_JANUARY, 1970);
		g_date_add_days(date, n_days);
		g_date_strftime(buf, len, "%x", date);
		g_date_free(date);
	}
}

int
main(int argc, const char **argv)
{
	char buf[LINE_MAX];
	long shadowMin = INVALID, shadowMax = INVALID,
	     shadowLastChange = INVALID, shadowInactive = INVALID,
	     shadowExpire = INVALID, shadowWarning = INVALID;
	const char *user = NULL;
	struct lu_context *ctx = NULL;
	struct lu_ent *ent = NULL;
	struct lu_error *error = NULL;
	GValueArray *values, *values2, *values3;
	GValue value;
	int interactive = FALSE;
	int list_only = FALSE;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		{"list", 'l', POPT_ARG_NONE, &list_only, 0,
		 "list aging parameters for the user", NULL},
		{"mindays", 'm', POPT_ARG_LONG, &shadowMin, 0,
		 "minimum days between password changes", "NUM"},
		{"maxdays", 'M', POPT_ARG_LONG, &shadowMax, 0,
		 "maximum days between password changes", "NUM"},
		{"date", 'd', POPT_ARG_LONG, &shadowLastChange, 0,
		 "date of last password change, relative to days since "
		 "1/1/70", "NUM"},
		{"inactive", 'I', POPT_ARG_LONG, &shadowInactive, 0,
		 "number of days after expiration date when account "
		 "is considered inactive", "NUM"},
		{"expire", 'E', POPT_ARG_LONG, &shadowInactive, 0,
		 "password expiration date", "NUM"},
		{"warndays", 'W', POPT_ARG_LONG, &shadowInactive, 0,
		 "days before expiration to begin warning user", "NUM"},
		POPT_AUTOHELP
		{NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	/* Set up i18n. */
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	/* Parse arguments. */
	popt = poptGetContext("lchage", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}
	user = poptGetArg(popt);

	/* We need exactly one argument, and that's the user's name. */
	if (user == NULL) {
		fprintf(stderr, _("No user name specified.\n"));
		poptPrintUsage(popt, stderr, 0);
		return 1;
	}

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

	ent = lu_ent_new();

	/* Look up information about the user. */
	if (lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		return 2;
	}

	if (list_only) {
		/* Just print out what we can find out, in a format similar
		 * to the chage(1) utility from the shadow suite. */
		if (lu_user_islocked(ctx, ent, &error)) {
			printf(_("Account is locked.\n"));
		} else {
			printf(_("Account is not locked.\n"));
		}

		values = lu_ent_get(ent, LU_SHADOWMIN);
		if (values && (values->n_values > 0)) {
			printf(_("Minimum:\t%d\n"), read_ndays(values));
		}

		values = lu_ent_get(ent, LU_SHADOWMAX);
		if (values && (values->n_values > 0)) {
			printf(_("Maximum:\t%d\n"), read_ndays(values));
		}

		values = lu_ent_get(ent, LU_SHADOWWARNING);
		if (values && (values->n_values > 0)) {
			printf(_("Warning:\t%d\n"), read_ndays(values));
		}

		values = lu_ent_get(ent, LU_SHADOWINACTIVE);
		if (values && (values->n_values > 0)) {
			printf(_("Inactive:\t%d\n"), read_ndays(values));
		}

		values = lu_ent_get(ent, LU_SHADOWLASTCHANGE);
		if (values && (values->n_values > 0)) {
			strcpy(buf, _("Never"));
			date_to_string(read_ndays(values), buf, sizeof(buf));
			printf(_("Last Change:\t%s\n"), buf);
		}

		values2 = lu_ent_get(ent, LU_SHADOWMAX);
		if (values && (values->n_values > 0) &&
		    values2 && (values2->n_values > 0)) {
			strcpy(buf, _("Never"));
			date_to_string(read_ndays(values) +
				       read_ndays(values2),
				       buf, sizeof(buf));
			printf(_("Password Expires:\t%s\n"), buf);
		}

		values3 = lu_ent_get(ent, LU_SHADOWINACTIVE);
		if (values && (values->n_values > 0) &&
		    values2 && (values2->n_values > 0) &&
		    values3 && (values3->n_values > 0)) {
			strcpy(buf, _("Never"));
			date_to_string(read_ndays(values) +
				       read_ndays(values2) +
				       read_ndays(values3),
				       buf, sizeof(buf));
			printf(_("Password Inactive:\t%s\n"), buf);
		}

		values = lu_ent_get(ent, LU_SHADOWEXPIRE);
		if (values && (values->n_values > 0)) {
			strcpy(buf, _("Never"));
			date_to_string(read_ndays(values), buf, sizeof(buf));
			printf(_("Account Expires:\t%s\n"), buf);
		}
	} else {
		/* Set values using parameters given on the command-line. */
		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_LONG);
		if (shadowLastChange != INVALID) {
			g_value_set_long(&value, shadowLastChange);
			lu_ent_clear(ent, LU_SHADOWLASTCHANGE);
			lu_ent_add(ent, LU_SHADOWLASTCHANGE, &value);
			g_value_reset(&value);
		}
		if (shadowMin != INVALID) {
			g_value_set_long(&value, shadowMin);
			lu_ent_clear(ent, LU_SHADOWMIN);
			lu_ent_add(ent, LU_SHADOWMIN, &value);
			g_value_reset(&value);
		}
		if (shadowMax != INVALID) {
			g_value_set_long(&value, shadowMax);
			lu_ent_clear(ent, LU_SHADOWMAX);
			lu_ent_add(ent, LU_SHADOWMAX, &value);
			g_value_reset(&value);
		}
		if (shadowWarning != INVALID) {
			g_value_set_long(&value, shadowWarning);
			lu_ent_clear(ent, LU_SHADOWWARNING);
			lu_ent_add(ent, LU_SHADOWWARNING, &value);
			g_value_reset(&value);
		}
		if (shadowInactive != INVALID) {
			g_value_set_long(&value, shadowInactive);
			lu_ent_clear(ent, LU_SHADOWINACTIVE);
			lu_ent_add(ent, LU_SHADOWINACTIVE, &value);
			g_value_reset(&value);
		}
		if (shadowExpire != INVALID) {
			g_value_set_long(&value, shadowExpire);
			lu_ent_clear(ent, LU_SHADOWEXPIRE);
			lu_ent_add(ent, LU_SHADOWEXPIRE, &value);
			g_value_reset(&value);
		}
		g_value_unset(&value);

		/* Now actually modify the user's data in the system
		 * information store. */
		if (lu_user_modify(ctx, ent, &error) == FALSE) {
			fprintf(stderr, _("Failed to modify aging information "
				"for %s.\n"), user);
			return 3;
		}

		lu_hup_nscd();
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
