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
#include "../config.h"
#endif
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <popt.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/user.h"
#include "apputil.h"

int
main(int argc, const char **argv)
{
	struct lu_context *ctx = NULL;
	struct lu_error *error = NULL;
	struct lu_ent *ent = NULL, *groupEnt = NULL;
	int interactive = FALSE, nocreatehome = FALSE, creategroup = FALSE;
	int c;
	char *file = NULL, **fields;
	FILE *fp = stdin;
	uid_t uid;
	gid_t gid;
	char *homedir, *gidstring;
	const char *skeleton;
	long gid_tmp;
	char *p;
	GValueArray *values = NULL;
	GValue *value, val;
	char buf[LINE_MAX];
	poptContext popt;
	struct poptOption options[] = {
		{"interactive", 'i', POPT_ARG_NONE, &interactive, 0,
		 "prompt for all information", NULL},
		{"file", 'f', POPT_ARG_STRING, &file, 0,
		 "file with user information records", "STDIN"},
		{"nocreatehome", 'M', POPT_ARG_NONE, &nocreatehome, 0,
		 "don't create home directories", NULL},
		POPT_AUTOHELP
		{NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	/* Initialize i18n support. */
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	/* Parse arguments. */
	popt = poptGetContext("lnewusers", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...]"));
	c = poptGetNextOpt(popt);
	if (c != -1) {
		fprintf(stderr, _("Error parsing arguments: %s.\n"),
			poptStrerror(c));
		poptPrintUsage(popt, stderr, 0);
		exit(1);
	}

	/* Start up the library. */
	ctx = lu_start(NULL, lu_user, NULL, NULL,
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

	/* Open the file we're going to look at. */
	if (file != NULL) {
		fp = fopen(file, "r");
		if (fp == NULL) {
			fprintf(stderr, _("Error opening `%s': %s.\n"),
				file, strerror(errno));
			return 2;
		}
	} else {
		fp = stdin;
	}

	ent = lu_ent_new();
	groupEnt = lu_ent_new();

	while (fgets(buf, sizeof(buf), fp)) {
		/* Strip off the end-of-line terminators. */
		if (strchr(buf, '\r')) {
			char *p = strchr(buf, '\r');
			*p = '\0';
		}
		if (strchr(buf, '\n')) {
			char *p = strchr(buf, '\n');
			*p = '\0';
		}

		/* Make sure the line splits into *exactly* seven fields. */
		fields = g_strsplit(buf, ":", 7);
		if ((fields == NULL) ||
		    (fields[0] == NULL) ||
		    (fields[1] == NULL) ||
		    (fields[2] == NULL) ||
		    (fields[3] == NULL) ||
		    (fields[4] == NULL) ||
		    (fields[5] == NULL) ||
		    (fields[6] == NULL) ||
		    (fields[7] != NULL)) {
			g_print(_("Error creating account for `%s': line "
				"improperly formatted.\n"), buf);
		}

		/* Sorry, but we're bastards here.  No root accounts. */
		uid = atol(fields[2]);
		if (uid == 0) {
			g_print(_("Refusing to create account with UID 0.\n"));
			g_strfreev(fields);
			continue;
		}

		/* Try to figure out if the field is the name of a group, or
		 * a gid.  If it's just empty, make it the same as the user's
		 * name.  FIXME: provide some way to set a default other than
		 * the user's own name, like "users" or something. */
		if (strlen(fields[3]) > 0) {
			gidstring = fields[3];
		} else {
			gidstring = fields[0];
		}

		/* Try to convert the field to a number. */
		p = NULL;
		gid_tmp = strtol(gidstring, &p, 10);
		gid = INVALID;
		if (*p != '\0') {
			/* It's not a number, so it's a group name --
			 * see if it's being used. */
			if (lu_group_lookup_name(ctx, gidstring, ent, &error)) {
				/* Retrieve the group's GID. */
				values = lu_ent_get(ent, LU_GIDNUMBER);
				if (values != NULL) {
					value = g_value_array_get_nth(values,
								      0);
					if (G_VALUE_HOLDS_LONG(value)) {
						gid = g_value_get_long(value);
					} else
					if (G_VALUE_HOLDS_STRING(value)) {
						gid = atol(g_value_get_string(value));
					} else {
						g_assert_not_reached();
					}
				}
				creategroup = FALSE;
			} else {
				/* Mark that we need to create a group for the
				 * user to be in. */
				creategroup = TRUE;
			}
		} else {
			/* It's a group number -- see if it's being used. */
			gid = gid_tmp;
			if (lu_group_lookup_id(ctx, gid_tmp, ent, &error)) {
				/* Retrieve the group's GID. */
				values = lu_ent_get(ent, LU_GIDNUMBER);
				if (values != NULL) {
					value = g_value_array_get_nth(values,
								      0);
					if (G_VALUE_HOLDS_LONG(value)) {
						gid = g_value_get_long(value);
					} else
					if (G_VALUE_HOLDS_STRING(value)) {
						gid = atol(g_value_get_string(value));
					} else {
						g_assert_not_reached();
					}
				}
				creategroup = FALSE;
			} else {
				/* Mark that we need to create a group for the
				 * user to be in. */
				creategroup = TRUE;
			}
		}
		/* If we need to create a group, create a template group and
		 * try to apply what the user has asked us to. */
		if (creategroup) {
			/* If we got a GID, then we need to use the user's name,
			 * otherwise we need to use the default group name. */
			if (gid != INVALID) {
				lu_group_default(ctx, fields[0], FALSE, ent);
				memset(&val, 0, sizeof(val));
				g_value_init(&val, G_TYPE_LONG);
				g_value_set_long(&val, gid);
				lu_ent_clear(ent, LU_GIDNUMBER);
				lu_ent_add(ent, LU_GIDNUMBER, &val);
				g_value_unset(&val);
			} else {
				lu_group_default(ctx, "users", FALSE, ent);
			}
			/* Try to create the group, and if it works, get its
			 * GID, which we need to give to this user. */
			if (lu_group_add(ctx, ent, &error)) {
				values = lu_ent_get(ent, LU_GIDNUMBER);
				value = g_value_array_get_nth(values, 0);
				if (G_VALUE_HOLDS_LONG(value)) {
					gid = g_value_get_long(value);
				} else
				if (G_VALUE_HOLDS_STRING(value)) {
					gid = atol(g_value_get_string(value));
				} else {
					g_assert_not_reached();
				}
			} else {
				/* Aargh!  Abandon all hope. */
				g_print(_("Error creating group for `%s' with "
					"GID %ld.\n"), fields[0], gid_tmp);
				g_strfreev(fields);
				continue;
			}
		}

		/* Create a new user record, and set the user's primary GID. */
		lu_user_default(ctx, fields[0], FALSE, ent);
		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_LONG);
		g_value_set_long(&val, gid);
		lu_ent_clear(ent, LU_GIDNUMBER);
		lu_ent_add(ent, LU_GIDNUMBER, &val);
		g_value_unset(&val);

		/* Set other fields if we've got them. */
		memset(&val, 0, sizeof(val));
		g_value_init(&val, G_TYPE_STRING);
		if (strlen(fields[4]) > 0) {
			g_value_set_string(&val, fields[4]);
			lu_ent_clear(ent, LU_GECOS);
			lu_ent_add(ent, LU_GECOS, &val);
		}
		if (strlen(fields[5]) > 0) {
			homedir = g_strdup(fields[5]);
			g_value_set_string(&val, homedir);
			lu_ent_clear(ent, LU_HOMEDIRECTORY);
			lu_ent_add(ent, LU_HOMEDIRECTORY, &val);
		} else {
			if (values != NULL) {
				value = g_value_array_get_nth(values,
							      0);
				homedir = g_strdup(g_value_get_string(value));
			} else {
				homedir = g_strdup_printf("/home/%s",
							  fields[0]);
			}
		}
		if (strlen(fields[6]) > 0) {
			g_value_set_string(&val, fields[6]);
			lu_ent_clear(ent, LU_LOGINSHELL);
			lu_ent_add(ent, LU_LOGINSHELL, &val);
		}

		g_value_unset(&val);

		/* Now try to add the user's account. */
		if (lu_user_add(ctx, ent, &error)) {
			lu_hup_nscd();
			if (!lu_user_setpass(ctx, ent, fields[1], &error)) {
				g_print(_("Error setting initial password for "
					"%s: %s\n"),
					fields[0],
					error ?
					error->string :
					_("unknown error"));
				if (error) {
					lu_error_free(&error);
				}
			}
			/* Unless the nocreatehomedirs flag was given, attempt
			 * to create the user's home directory. */
			if (!nocreatehome) {
				skeleton = lu_cfg_read_single(ctx,
							      "defaults/skeleton",
							      "/etc/skel");
				if (lu_homedir_populate(skeleton,
							homedir,
							uid,
							gid,
							0700,
							&error) == FALSE) {
					g_print(_("Error creating home "
						"directory for %s: %s\n"),
						fields[0],
						error ?
						error->string :
						_("unknown error"));
					if (error) {
						lu_error_free(&error);
					}
				}
			}
		} else {
			g_print(_("Error creating user account for %s: "
				"%s\n"), fields[0],
				error ?
				error->string :
				_("unknown error"));
			if (error) {
				lu_error_free(&error);
			}
		}

		g_free(homedir);
		if (fields != NULL) {
			g_strfreev(fields);
		}
		lu_ent_clear_all(ent);
		lu_ent_clear_all(groupEnt);
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
