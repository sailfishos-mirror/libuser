/* Copyright (C) 2000-2002, 2004 Red Hat, Inc.
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "user_private.h"
#include "modules.h"

char *
lu_value_strdup(const GValue *value)
{
	char *ret;
	
	if (G_VALUE_HOLDS_STRING(value))
		ret = g_value_dup_string(value);
	else if (G_VALUE_HOLDS_LONG(value))
		ret = g_strdup_printf("%ld", g_value_get_long(value));
	else if (G_VALUE_HOLDS_INT64(value))
		ret = g_strdup_printf("%lld",
				      (long long)g_value_get_int64(value));
	else {
		g_assert_not_reached();
		ret = NULL;
	}
	return ret;
}

int
lu_values_equal(const GValue *a, const GValue *b)
{
	g_return_val_if_fail(G_VALUE_TYPE(a) == G_VALUE_TYPE(b), FALSE);
	if (G_VALUE_HOLDS_STRING(a))
		return strcmp(g_value_get_string(a), g_value_get_string(b))
			== 0;
	else if (G_VALUE_HOLDS_LONG(a))
		return g_value_get_long(a) == g_value_get_long(b);
	else if (G_VALUE_HOLDS_INT64(a))
		return g_value_get_int64(a) == g_value_get_int64(b);
	else {
		g_assert_not_reached();
		return FALSE;
	}
}

void
lu_value_init_set_id(GValue *value, id_t id)
{
	/* Don't unnecessarily change behavior when long is enough. Only when
	   long isn't enough, we fail in more interesting ways instead of
	   silently corrupting data.

	   The (intmax_t) casts are needed to handle the (Linux) case when id_t
	   is "unsigned long', otherwise the comparison would be
	   (unsigned long)(long)id == id, which is always true. */
	if ((intmax_t)(long)id == (intmax_t)id) {
		g_value_init(value, G_TYPE_LONG);
		g_value_set_long(value, id);
	} else {
		/* FIXME: check that int64 is enough */
		g_value_init(value, G_TYPE_INT64);
		g_value_set_int64(value, id);
	}
	
}

id_t
lu_value_get_id(const GValue *value)
{
	long long val;
	
	if (G_VALUE_HOLDS_LONG(value))
		val = g_value_get_long(value);
	else if (G_VALUE_HOLDS_INT64(value))
		val = g_value_get_int64(value);
	else if (G_VALUE_HOLDS_STRING(value)) {
		const char *src;
		char *end;

		src = g_value_get_string(value);
		errno = 0;
		val = strtoll(src, &end, 10);
		if (errno != 0 || *end != 0 || end == src) {
			g_error("lu_value_get_id(): invalid id_t value '%s'",
				 src);
			return LU_VALUE_INVALID_ID;
		}
	} else {
		g_error("lu_value_get_id(): invalid GValue type");
		return LU_VALUE_INVALID_ID;
	}
	if ((id_t)val != val) {
		g_error("lu_value_get_id(): value %lld out of range", val);
		return LU_VALUE_INVALID_ID;
	}
	return val;
}

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
	size_t i;

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
