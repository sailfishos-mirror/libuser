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
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <popt.h>
#include <stdlib.h>
#include <string.h>
#include "../include/libuser/user.h"
#include "apputil.h"

int
main(int argc, const char **argv)
{
	struct lu_context *ctx = NULL;
	struct lu_error *error = NULL;
	struct lu_ent *ent = NULL, *groupEnt = NULL;
	int interactive = FALSE, nocreatehome = FALSE;
	int c;
	char *file = NULL, **fields;
	FILE *fp = stdin;
	GList *values = NULL;
	char buf[LINE_MAX];
	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		{"file", 'f', POPT_ARG_STRING, &file, 0,
		 "file with user information records", "STDIN"},
		{"nocreatehome", 'M', POPT_ARG_NONE, &nocreatehome, 0,
		 "don't create home directories", NULL},
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lnewusers", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...]"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}

	ctx =
	    lu_start(NULL, lu_user, NULL, NULL,
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

	if (file != NULL) {
		fp = fopen(file, "r");
		if (fp == NULL) {
			fprintf(stderr, _("Error opening `%s': %s.\n"),
				file, strerror(errno));
			return 2;
		}
	}

	ent = lu_ent_new();
	groupEnt = lu_ent_new();

	while (fgets(buf, sizeof(buf), fp)) {
		if (strchr(buf, '\r')) {
			char *p = strchr(buf, '\r');
			*p = '\0';
		}
		if (strchr(buf, '\n')) {
			char *p = strchr(buf, '\n');
			*p = '\0';
		}
		fields = g_strsplit(buf, ":", 7);
		if (fields && fields[0] && fields[1] && fields[2]
		    && fields[3] && fields[4] && fields[5] && fields[6]) {
			char *homedir, *gidstring;
			uid_t uid;
			gid_t gid;
			long gid_tmp;
			char *p;

			/* Sorry, but we're bastards here. */
			uid = atol(fields[2]);
			if (uid == 0) {
				g_print(_
					("Refusing to create account with UID 0.\n"));
				g_strfreev(fields);
				continue;
			}

			/* Try to figure out if the field is the name of a group, or a gid. */
			if (strlen(fields[3]) > 0) {
				gidstring = fields[3];
			} else {
				gidstring = fields[0];
			}

			/* Try to convert the field to a number. */
			p = NULL;
			gid_tmp = strtol(gidstring, &p, 10);
			if ((p == NULL) || (*p != '\0')) {
				/* It's not a number, so it's a group name -- see if it's being used. */
				if (lu_group_lookup_name
				    (ctx, gidstring, ent, &error)) {
					/* Retrieve the group's GID. */
					values =
					    lu_ent_get(ent, LU_GIDNUMBER);
					gid =
					    strtol((char *) values->data,
						   &p, 10);
				} else {
					/* No such group -- create it. */
					if (error) {
						lu_error_free(&error);
					}
					lu_group_default(ctx, gidstring,
							 FALSE, ent);
					if (lu_group_add(ctx, ent, &error)) {
						/* Save the GID. */
						values =
						    lu_ent_get(ent,
							       LU_GIDNUMBER);
						gid =
						    strtol((char *)
							   values->data,
							   &p, 10);
						lu_hup_nscd();
					} else {
						/* Aargh!  Abandon all hope. */
						g_print(_
							("Error creating group `%s'.\n"),
							gidstring);
						if (error) {
							lu_error_free
							    (&error);
						}
						g_strfreev(fields);
						continue;
					}
				}
			} else {
				/* It's a group number -- see if it's being used. */
				if (lu_group_lookup_id
				    (ctx, gid_tmp, ent, &error)) {
					/* Retrieve the group's GID. */
					values =
					    lu_ent_get(ent, LU_GIDNUMBER);
					gid =
					    strtol((char *) values->data,
						   &p, 10);
				} else {
					/* No such group -- create one with the user's name. */
					if (error) {
						lu_error_free(&error);
					}
					lu_group_default(ctx, fields[0],
							 FALSE, ent);
					lu_ent_set_numeric(ent,
							   LU_GIDNUMBER,
							   gid_tmp);
					if (lu_group_add(ctx, ent, &error)) {
						/* Save the GID. */
						gid = gid_tmp;
						lu_hup_nscd();
					} else {
						/* Aargh!  Abandon all hope. */
						g_print(_
							("Error creating group `%s' with GID %ld.\n"),
							fields[0],
							gid_tmp);
						if (error) {
							lu_error_free
							    (&error);
						}
						g_strfreev(fields);
						continue;
					}
				}
			}

			lu_user_default(ctx, fields[0], FALSE, ent);
			lu_ent_set(ent, LU_USERNAME, fields[0]);
			lu_ent_set(ent, LU_UIDNUMBER, fields[2]);
			lu_ent_set_numeric(ent, LU_GIDNUMBER, gid);

			if (strlen(fields[4])) {
				lu_ent_set(ent, LU_GECOS, fields[4]);
			}
			if (strlen(fields[5])) {
				homedir = g_strdup(fields[5]);
				lu_ent_set(ent, LU_HOMEDIRECTORY,
					   fields[5]);
			} else {
				GList *values =
				    lu_ent_get(ent, LU_HOMEDIRECTORY);
				if (values) {
					homedir =
					    g_strdup((char *) values->
						     data);
				} else {
					homedir =
					    g_strdup_printf("/home/%s",
							    fields[0]);
				}
			}
			if (strlen(fields[6])) {
				lu_ent_set(ent, LU_LOGINSHELL, fields[6]);
			}

			if (lu_user_add(ctx, ent, &error)) {
				lu_hup_nscd();
				if (!lu_user_setpass
				    (ctx, ent, fields[1], &error)) {
					g_print(_
						("Error setting initial password for %s: %s\n"),
						fields[0],
						error ? error->
						string :
						_("unknown error"));
					if (error) {
						lu_error_free(&error);
					}
				}
				if (!nocreatehome) {
					if (lu_homedir_populate
					    ("/etc/skel", homedir, uid,
					     gid, 0700, &error) == FALSE) {
						g_print(_
							("Error creating home directory for %s: %s\n"),
							fields[0],
							error ? error->
							string :
							_
							("unknown error"));
						if (error) {
							lu_error_free
							    (&error);
						}
					}
				}
			} else {
				g_print(_
					("Error creating user account for %s: %s\n"),
					fields[0],
					error ? error->
					string : _("unknown error"));
				if (error) {
					lu_error_free(&error);
				}
			}

			g_free(homedir);
		} else {
			g_print(_
				("Error creating account for `%s': line improperly formatted.\n"),
				buf);
		}
		if (fields) {
			g_strfreev(fields);
		}
		lu_ent_clear_all(ent);
		lu_ent_clear_all(groupEnt);
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
