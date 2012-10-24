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
#include <sys/time.h>
#include <errno.h>
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

#define INVALID_LONG LONG_MIN

/* Parse the first element of a (non-NULL, non-empty) value array for a count
 * of days in G_TYPE_LONG, and return the value.  If the array is invalid,
 * return the default of -1. */
static glong
read_ndays(GValueArray *array)
{
	GValue *value;

	value = g_value_array_get_nth(array, 0);
	if (value != NULL) {
		g_assert(G_VALUE_HOLDS_LONG(value));
		return g_value_get_long(value);
	} else
		return -1;
}

/* Format a count of days into a string that's intelligible to a user. */
static void
date_to_string(glong n_days, char *buf, size_t len)
{
	if ((n_days >= 0) && (n_days < 99999)) {
		GDate *date;

		date = g_date_new_dmy(1, G_DATE_JANUARY, 1970);
		g_date_add_days(date, n_days);
		g_date_strftime(buf, len, "%x", date);
		g_date_free(date);
	}
}

int
main(int argc, const char **argv)
{
	long shadowMin = INVALID_LONG, shadowMax = INVALID_LONG,
	     shadowLastChange = INVALID_LONG, shadowInactive = INVALID_LONG,
	     shadowExpire = INVALID_LONG, shadowWarning = INVALID_LONG;
	const char *user;
	struct lu_context *ctx;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	int interactive = FALSE;
	int list_only = FALSE;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 N_("prompt for all information"), NULL},
		{"list", 'l', POPT_ARG_NONE, &list_only, 0,
		 N_("list aging parameters for the user"), NULL},
		{"mindays", 'm', POPT_ARG_LONG, &shadowMin, 0,
		 N_("minimum days between password changes"), N_("DAYS")},
		{"maxdays", 'M', POPT_ARG_LONG, &shadowMax, 0,
		 N_("maximum days between password changes"), N_("DAYS")},
		{"date", 'd', POPT_ARG_LONG, &shadowLastChange, 0,
		 N_("date of last password change in days since 1/1/70"),
		 N_("DAYS")},
		{"inactive", 'I', POPT_ARG_LONG, &shadowInactive, 0,
		 N_("number of days after password expiration date when "
		    "account is considered inactive"), N_("DAYS")},
		{"expire", 'E', POPT_ARG_LONG, &shadowExpire, 0,
		 N_("password expiration date in days since 1/1/70"),
		 N_("DAYS")},
		{"warndays", 'W', POPT_ARG_LONG, &shadowWarning, 0,
		 N_("days before expiration to begin warning user"),
		 N_("DAYS")},
		POPT_AUTOHELP
		POPT_TABLEEND
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

	poptFreeContext(popt);

	/* Start up the library. */
	ctx = lu_start(user, lu_user, NULL, NULL,
		       interactive ? lu_prompt_console :
		       lu_prompt_console_quiet, NULL, &error);
	if (ctx == NULL) {
		fprintf(stderr, _("Error initializing %s: %s.\n"), PACKAGE,
			lu_strerror(error));
		return 1;
	}

	ent = lu_ent_new();

	/* Look up information about the user. */
	if (lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		return 2;
	}

	if (list_only) {
		char buf[LINE_MAX];
		GValueArray *values, *values2, *values3;

		/* Just print out what we can find out, in a format similar
		 * to the chage(1) utility from the shadow suite. */
		if (lu_user_islocked(ctx, ent, &error)) {
			printf(_("Account is locked.\n"));
		} else {
			printf(_("Account is not locked.\n"));
		}

		values = lu_ent_get(ent, LU_SHADOWMIN);
		if (values != NULL)
			printf(_("Minimum:\t%ld\n"), read_ndays(values));

		values = lu_ent_get(ent, LU_SHADOWMAX);
		if (values != NULL)
			printf(_("Maximum:\t%ld\n"), read_ndays(values));

		values = lu_ent_get(ent, LU_SHADOWWARNING);
		if (values != NULL)
			printf(_("Warning:\t%ld\n"), read_ndays(values));

		values = lu_ent_get(ent, LU_SHADOWINACTIVE);
		if (values != NULL)
			printf(_("Inactive:\t%ld\n"), read_ndays(values));

		values = lu_ent_get(ent, LU_SHADOWLASTCHANGE);
		if (values != NULL) {
			strcpy(buf, _("Never"));
			date_to_string(read_ndays(values), buf, sizeof(buf));
			printf(_("Last Change:\t%s\n"), buf);
		}

		values2 = lu_ent_get(ent, LU_SHADOWMAX);
		if (values != NULL && values2 != NULL) {
			strcpy(buf, _("Never"));
			date_to_string(read_ndays(values) +
				       read_ndays(values2),
				       buf, sizeof(buf));
			printf(_("Password Expires:\t%s\n"), buf);
		}

		values3 = lu_ent_get(ent, LU_SHADOWINACTIVE);
		if (values != NULL && values2 != NULL && values3 != NULL) {
			strcpy(buf, _("Never"));
			date_to_string(read_ndays(values) +
				       read_ndays(values2) +
				       read_ndays(values3),
				       buf, sizeof(buf));
			printf(_("Password Inactive:\t%s\n"), buf);
		}

		values = lu_ent_get(ent, LU_SHADOWEXPIRE);
		if (values != NULL) {
			strcpy(buf, _("Never"));
			date_to_string(read_ndays(values), buf, sizeof(buf));
			printf(_("Account Expires:\t%s\n"), buf);
		}
	} else {
		GValue value;

		/* Set values using parameters given on the command-line. */
		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_LONG);
		if (shadowLastChange != INVALID_LONG) {
			g_value_set_long(&value, shadowLastChange);
			lu_ent_clear(ent, LU_SHADOWLASTCHANGE);
			lu_ent_add(ent, LU_SHADOWLASTCHANGE, &value);
			g_value_reset(&value);
		}
		if (shadowMin != INVALID_LONG) {
			g_value_set_long(&value, shadowMin);
			lu_ent_clear(ent, LU_SHADOWMIN);
			lu_ent_add(ent, LU_SHADOWMIN, &value);
			g_value_reset(&value);
		}
		if (shadowMax != INVALID_LONG) {
			g_value_set_long(&value, shadowMax);
			lu_ent_clear(ent, LU_SHADOWMAX);
			lu_ent_add(ent, LU_SHADOWMAX, &value);
			g_value_reset(&value);
		}
		if (shadowWarning != INVALID_LONG) {
			g_value_set_long(&value, shadowWarning);
			lu_ent_clear(ent, LU_SHADOWWARNING);
			lu_ent_add(ent, LU_SHADOWWARNING, &value);
			g_value_reset(&value);
		}
		if (shadowInactive != INVALID_LONG) {
			g_value_set_long(&value, shadowInactive);
			lu_ent_clear(ent, LU_SHADOWINACTIVE);
			lu_ent_add(ent, LU_SHADOWINACTIVE, &value);
			g_value_reset(&value);
		}
		if (shadowExpire != INVALID_LONG) {
			g_value_set_long(&value, shadowExpire);
			lu_ent_clear(ent, LU_SHADOWEXPIRE);
			lu_ent_add(ent, LU_SHADOWEXPIRE, &value);
			g_value_reset(&value);
		}
		g_value_unset(&value);

		/* Now actually modify the user's data in the system
		 * information store. */
		if (lu_user_modify(ctx, ent, &error) == FALSE) {
			fprintf(stderr,
				_("Failed to modify aging information for %s: "
				  "%s\n"), user, lu_strerror(error));
			return 3;
		}

		lu_nscd_flush_cache(LU_NSCD_CACHE_PASSWD);
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
