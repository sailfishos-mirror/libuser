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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/libuser/user_private.h"
#include "modules.h"
#include "misc.h"

void
lu_set_prompter(struct lu_context *context, lu_prompt_fn * prompter,
		gpointer prompter_data)
{
	g_assert(prompter != NULL);
	context->prompter = prompter;
	context->prompter_data = prompter_data;
}

void
lu_get_prompter(struct lu_context *context, lu_prompt_fn **prompter,
		gpointer *prompter_data)
{
	if (prompter != NULL) {
		*prompter = context->prompter;
	}
	if (prompter_data != NULL) {
		*prompter_data = context->prompter_data;
	}
}

gboolean
lu_set_modules(struct lu_context * context, const char *list,
	       struct lu_error ** error)
{
	return lu_modules_load(context, list, &context->module_names, error);
}

const char *
lu_get_modules(struct lu_context *context)
{
	char *tmp = NULL, *ret = NULL;
	GValue *value;
	int i;

	for (i = 0; i < context->module_names->n_values; i++) {
		value = g_value_array_get_nth(context->module_names, i);
		if (tmp) {
			char *p;
			p = g_strconcat(tmp, " ",
					g_value_get_string(value), NULL);
			g_free(tmp);
			tmp = p;
		} else {
			tmp = g_value_dup_string(value);
		}
	}

	if (tmp) {
		ret = context->scache->cache(context->scache, tmp);
		g_free(tmp);
	}

	return ret;
}
