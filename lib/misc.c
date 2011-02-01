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

#include <config.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "user_private.h"
#include "internal.h"

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
		if (errno != 0 || *end != 0 || end == src)
			g_return_val_if_reached(LU_VALUE_INVALID_ID);
	} else
		g_return_val_if_reached(LU_VALUE_INVALID_ID);
	g_return_val_if_fail((id_t)val == val, LU_VALUE_INVALID_ID);
	g_return_val_if_fail(val != LU_VALUE_INVALID_ID, LU_VALUE_INVALID_ID);
	return val;
}

/* Check whether NAME is within LIST, which is a NUL-separated sequence of
   strings, terminated by double NUL. */
static gboolean
attr_in_list(const char *attr, const char *list)
{
	size_t attr_len;

	attr_len = strlen(attr);
	while (*list != '\0') {
		size_t s_len;

		s_len = strlen(list);
		if (attr_len == s_len && strcmp(attr, list) == 0)
			return TRUE;
		list += s_len + 1;
	}
	return FALSE;
}

/* The error messages returned from this function don't contain the input
   string, to allow the caller to output at least partially usable error
   message without disclosing the invalid string in e.g. /etc/shadow, which
   might be somebody's misplaced password. */
gboolean
lu_value_init_set_attr_from_string(GValue *value, const char *attr,
				   const char *string, lu_error_t **error)
{
	LU_ERROR_CHECK(error);
#define A(NAME) NAME "\0"
	if (attr_in_list(attr, A(LU_USERNAME) A(LU_USERPASSWORD) A(LU_GECOS)
			 A(LU_HOMEDIRECTORY) A(LU_LOGINSHELL) A(LU_GROUPNAME)
			 A(LU_GROUPPASSWORD) A(LU_MEMBERNAME)
			 A(LU_ADMINISTRATORNAME) A(LU_SHADOWNAME)
			 A(LU_SHADOWPASSWORD) A(LU_COMMONNAME) A(LU_GIVENNAME)
			 A(LU_SN) A(LU_ROOMNUMBER) A(LU_TELEPHONENUMBER)
			 A(LU_HOMEPHONE) A(LU_EMAIL))) {
		g_value_init(value, G_TYPE_STRING);
		g_value_set_string(value, string);
	} else if (attr_in_list(attr, A(LU_SHADOWLASTCHANGE) A(LU_SHADOWMIN)
				A(LU_SHADOWMAX) A(LU_SHADOWWARNING)
				A(LU_SHADOWINACTIVE) A(LU_SHADOWEXPIRE)
				A(LU_SHADOWFLAG))) {
		long l;
		char *p;

		errno = 0;
		l = strtol(string, &p, 10);
		if (errno != 0 || *p != 0 || p == string) {
			lu_error_new(error, lu_error_invalid_attribute_value,
				     _("invalid number"));
			return FALSE;
		}
		g_value_init(value, G_TYPE_LONG);
		g_value_set_long(value, l);
	} else if (attr_in_list(attr, A(LU_UIDNUMBER) A(LU_GIDNUMBER))) {
		intmax_t imax;
		char *p;

		errno = 0;
		imax = strtoimax(string, &p, 10);
		if (errno != 0 || *p != 0 || p == string
		    || (id_t)imax != imax || imax == LU_VALUE_INVALID_ID) {
			lu_error_new(error, lu_error_invalid_attribute_value,
				     _("invalid ID"));
			return FALSE;
		}
		lu_value_init_set_id(value, imax);
	} else {
		*error = NULL;
		return FALSE;
	}
#undef A
	return TRUE;
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
	size_t i;

	for (i = 0; i < context->module_names->n_values; i++) {
		GValue *value;

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
