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
#include <sys/time.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include "../include/libuser/user.h"
#include "apputil.h"

static gint
read_ndays(const char *days)
{
	char *p;
	gint n_days;
	n_days = strtol(days, &p, 10);
	if((strlen(days) == 0) || (n_days == -1) || (p == NULL) || *p) {
		n_days = -1;
	}
	return n_days;
}

static void
date_to_string(gint n_days, char *buf, size_t len)
{
	GDate *date;

	if((n_days >= 0) && (n_days < 99999)) {
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
	long shadowMin = -2, shadowMax = -2, shadowLastChange = -2,
             shadowInactive = -2, shadowExpire = -2, shadowWarning = -2;
	const char  *user = NULL;
	struct lu_context *ctx = NULL;
	struct lu_ent *ent = NULL;
	struct lu_error *error = NULL;
	GList *values, *values2, *values3;
	int interactive = FALSE;
	int list_only = FALSE;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0, "prompt for all information", NULL},
		{"list", 'l', POPT_ARG_NONE, &list_only, 0, "list aging parameters for the user", NULL},
		{"mindays", 'm', POPT_ARG_LONG, &shadowMin, 0, "minimum days between password changes", "NUM"},
		{"maxdays", 'M', POPT_ARG_LONG, &shadowMax, 0, "maximum days between password changes", "NUM"},
		{"date", 'd', POPT_ARG_LONG, &shadowLastChange, 0, "date of last password change, relative to days since "
		 "1/1/70", "NUM"}, {"inactive", 'I', POPT_ARG_LONG, &shadowInactive, 0,
		 "number of days after expiration date when account " "is considered inactive", "NUM"},
		{"expire", 'E', POPT_ARG_LONG, &shadowInactive, 0, "password expiration date", "NUM"},
		{"warndays", 'W', POPT_ARG_LONG, &shadowInactive, 0, "days before expiration to begin warning user", "NUM"},
		POPT_AUTOHELP
	       	{NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lchage", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	g_return_val_if_fail(c == -1, 0);
	user = poptGetArg(popt);

	if(user == NULL) {
		fprintf(stderr, _("No user name specified.\n"));
		return 1;
	}

	ctx = lu_start(user, lu_user, NULL, NULL, interactive ? lu_prompt_console:lu_prompt_console_quiet, NULL, &error);
	g_return_val_if_fail(ctx != NULL, 1);

	ent = lu_ent_new();

	if(lu_user_lookup_name(ctx, user, ent, &error) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		return 2;
	}

	if(list_only) {
		if(lu_user_islocked(ctx, ent, &error)) {
			printf(_("Account is locked.\n"));
		} else {
			printf(_("Account is not locked.\n"));
		}
		values = lu_ent_get(ent, LU_SHADOWMIN);
		if(values && values->data) {
			printf(_("Minimum:\t%d\n"), read_ndays(values->data));
		}
		values = lu_ent_get(ent, LU_SHADOWMAX);
		if(values && values->data) {
			printf(_("Maximum:\t%d\n"), read_ndays(values->data));
		}
		values = lu_ent_get(ent, LU_SHADOWWARNING);
		if(values && values->data) {
			printf(_("Warning:\t%d\n"), read_ndays(values->data));
		}
		values = lu_ent_get(ent, LU_SHADOWINACTIVE);
		if(values && values->data) {
			printf(_("Inactive:\t%d\n"), read_ndays(values->data));
		}
		values = lu_ent_get(ent, LU_SHADOWLASTCHANGE);
		if(values && values->data) {
			strcpy(buf, _("Never"));
			date_to_string(read_ndays(values->data),
				       buf, sizeof(buf));
			printf(_("Last Change:\t%s\n"), buf);
		}

		values2 = lu_ent_get(ent, LU_SHADOWMAX);
		if(values && values->data && values2 && values2->data) {
			strcpy(buf, _("Never"));
			date_to_string(read_ndays(values->data) + read_ndays(values2->data), buf, sizeof(buf));
			printf(_("Password Expires:\t%s\n"), buf);
		}

		values3 = lu_ent_get(ent, LU_SHADOWINACTIVE);
		if(values && values->data && values2 &&
		   values2->data && values3 && values3->data) {
			strcpy(buf, _("Never"));
			date_to_string(read_ndays(values->data) + read_ndays(values2->data) + read_ndays(values3->data),
				       buf, sizeof(buf));
			printf(_("Password Inactive:\t%s\n"), buf);
		}

		values = lu_ent_get(ent, LU_SHADOWEXPIRE);
		if(values && values->data) {
			strcpy(buf, _("Never"));
			date_to_string(read_ndays(values->data), buf, sizeof(buf));
			printf(_("Account Expires:\t%s\n"), buf);
		}
	} else {
		if(shadowLastChange != -2) {
			snprintf(buf, sizeof(buf), "%ld", shadowLastChange);
			lu_ent_set(ent, LU_SHADOWLASTCHANGE, buf);
		}
		if(shadowMin != -2) {
			snprintf(buf, sizeof(buf), "%ld", shadowMin);
			lu_ent_set(ent, LU_SHADOWMIN, buf);
		}
		if(shadowMax != -2) {
			snprintf(buf, sizeof(buf), "%ld", shadowMax);
			lu_ent_set(ent, LU_SHADOWMAX, buf);
		}
		if(shadowWarning != -2) {
			snprintf(buf, sizeof(buf), "%ld", shadowWarning);
			lu_ent_set(ent, LU_SHADOWWARNING, buf);
		}
		if(shadowInactive != -2) {
			snprintf(buf, sizeof(buf), "%ld", shadowInactive);
			lu_ent_set(ent, LU_SHADOWINACTIVE, buf);
		}
		if(shadowExpire != -2) {
			snprintf(buf, sizeof(buf), "%ld", shadowExpire);
			lu_ent_set(ent, LU_SHADOWEXPIRE, buf);
		}

		if(lu_user_modify(ctx, ent, &error) == FALSE) {
			fprintf(stderr, _("Failed to modify aging information for %s.\n"), user);
			return 3;
		}
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
