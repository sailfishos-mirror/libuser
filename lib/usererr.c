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

#define _(String) gettext(String)

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <execinfo.h>
#include <libintl.h>
#include <stdarg.h>
#include <string.h>
#include "../include/libuser/user.h"

static const char *
lu_strerror(enum lu_error_code code)
{
	switch(code) {
		case lu_error_success:
			return _("success");
		case lu_error_generic:
			return _("generic error");
		case lu_error_privilege:
			return _("not enough privileges");
		case lu_error_access_denied:
			return _("access denied");
		case lu_error_name_bad:
			return _("bad user/group name");
		case lu_error_id_bad:
			return _("bad user/group id");
		case lu_error_name_used:
			return _("user/group name in use");
		case lu_error_id_used:
			return _("user/group id in use");
		default:
			return _("unknown error");
	};
	return _("unknown error");
}

/**
 * lu_error_new:
 * error: A pointer to a pointer to a #lu_error_t which will be used to hold information about this error.
 * code: An #lu_error_code describing the error.
 * desc: A format string (followed by arguments) giving a more detailed description of the error.  May be #NULL.
 *
 * This function sets an #lu_error_t pointer to a value which can be passed up to a calling function.
 *
 * Returns: nothing.
 **/
void
lu_error_new(struct lu_error **error, enum lu_error_code code, const char *desc, ...)
{
	struct lu_error *ret;
	va_list args;
	void *stack[128];
	int depth;

	if(error != NULL) {
		g_assert(*error == NULL);
		ret = g_malloc0(sizeof(struct lu_error));
		ret->code = code;
		va_start(args, desc);
		ret->string = desc ?  g_strdup_vprintf(desc, args) : g_strdup(lu_strerror(code));
		depth = backtrace(stack, sizeof(stack) / sizeof(stack[0]));
		ret->stack = backtrace_symbols(stack, depth);
		va_end(args);
		*error = ret;
	}
}

/**
 * lu_error_free:
 * error: A pointer to a pointer to a #lu_error_t which must be cleared.
 *
 * This function clears an #lu_error_t pointer.
 *
 * Returns: nothing.
 **/
void
lu_error_free(struct lu_error **error)
{
	if(error != NULL) {
		if((*error)->string != NULL) {
			g_free((*error)->string);
		}
		memset(*error, 0, sizeof(**error));
		g_free(*error);
		*error = NULL;
	}
}
