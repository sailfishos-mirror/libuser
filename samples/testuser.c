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
#include <libintl.h>
#include <locale.h>
#include <stdlib.h>
#include "../include/libuser/user_private.h"

static void
dump_attribute(const char *attribute, struct lu_ent *ent)
{
	GValueArray *array;
	GValue *value;
	int i;
	g_print("%s\n", attribute);
	array = lu_ent_get(ent, attribute);
	if (array != NULL) {
		for (i = 0; i < array->n_values; i++) {
			value = g_value_array_get_nth(array, i);
			g_print(" %s = %s\n", attribute,
				g_value_get_string(value));
		}
	}
}

int
main(int argc, char **argv)
{
	struct lu_context *ctx;
	struct lu_ent *ent, *tmp, *temp;
	struct lu_error *error = NULL;
	GList *ret = NULL;
	int i;
	void *control = NULL;

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	control = g_malloc0(65536);

	ctx =
	    lu_start(NULL, 0, NULL, NULL, lu_prompt_console, NULL, &error);

	if (ctx == NULL) {
		g_print(gettext("Error initializing %s: %s.\n"), PACKAGE,
			error->string);
		exit(1);
	}

	g_print(gettext("Default user object classes:\n"));
	ret = lu_cfg_read(ctx, "userdefaults/objectclass", "bar");
	for (i = 0; i < g_list_length(ret); i++) {
		g_print(" %s\n", (char *) g_list_nth(ret, i)->data);
	}

	g_print(gettext("Default user attribute names:\n"));
	ret = lu_cfg_read_keys(ctx, "userdefaults");
	for (i = 0; i < g_list_length(ret); i++) {
		g_print(" %s\n", (char *) g_list_nth(ret, i)->data);
	}

	g_print(gettext("Getting default user attributes:\n"));
	ent = lu_ent_new();
	lu_user_default(ctx, "newuser", FALSE, ent);
	lu_ent_dump(ent, stdout);

	dump_attribute(LU_UIDNUMBER, ent);

	g_print(gettext("Copying user structure:\n"));
	tmp = lu_ent_new();
	lu_ent_copy(ent, tmp);
	temp = lu_ent_new();
	lu_ent_copy(tmp, temp);
	lu_ent_dump(temp, stdout);

	lu_ent_free(ent);
	lu_ent_free(tmp);
	lu_ent_free(temp);

	lu_end(ctx);

	g_free(control);

	return 0;
}
