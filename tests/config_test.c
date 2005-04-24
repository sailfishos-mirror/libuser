/* Copyright (C) 2000-2002, 2005 Red Hat, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/user.h"
#undef NDEBUG
#include <assert.h>

int
main(void)
{
	struct lu_context *ctx;
	struct lu_error *error;
	GList *list;
	
	setenv("LIBUSER_CONF", g_strconcat(getenv("srcdir"),
					   "/tests/config.conf",
					   (const gchar *)NULL), 1);
	error = NULL;
	ctx = lu_start(NULL, 0, NULL, NULL, lu_prompt_console_quiet, NULL,
		       &error);
	if (ctx == NULL) {
		fprintf(stderr, "Error initializing %s: %s.\n", PACKAGE,
			lu_strerror(error));
		return 1;
	}


	list = lu_cfg_read(ctx, "test/name", NULL);
	assert(g_list_length(list) == 2);
	assert(strcmp(list->data, "value1") == 0);
	assert(strcmp(list->next->data, "value2") == 0);

	list = lu_cfg_read(ctx, "test/nonexistent", "default");
	assert(g_list_length(list) == 1);
	assert(strcmp(list->data, "default") == 0);

	list = lu_cfg_read(ctx, "test/nonexistent", NULL);
	assert(g_list_length(list) == 0);
	
	assert(strcmp(lu_cfg_read_single(ctx, "test/name", NULL), "value1")
	       == 0);
	assert(strcmp(lu_cfg_read_single(ctx, "test/nonexistent", "default"),
		      "default") == 0);
	assert(lu_cfg_read_single(ctx, "test/nonexistent", NULL) == NULL);
	
	list = lu_cfg_read_keys(ctx, "test");
	assert(g_list_length(list) == 2);
	assert(strcmp(list->data, "name") == 0);
	assert(strcmp(list->next->data, "name2") == 0);

	list = lu_cfg_read_keys(ctx, "invalid");
	assert(g_list_length(list) == 0);
	
	lu_end(ctx);

	return 0;
}
