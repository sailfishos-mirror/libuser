/* Copyright (C) 2000-2002 Red Hat, Inc.
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
#include <sys/types.h>
#include <errno.h>
#include <execinfo.h>
#include <libintl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "user.h"
#include "user_private.h"

const char *
lu_strerror(struct lu_error *error)
{
	if (error != NULL) {
		if (error->string != NULL) {
			return error->string;
		}
		switch (error->code) {
			case lu_success:
				return _("success");
			case lu_warning_config_disabled:
				return _("module disabled by configuration");
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
			case lu_error_terminal:
				return _("error manipulating terminal attributes");
			case lu_error_open:
				return _("error opening file");
			case lu_error_lock:
				return _("error locking file");
			case lu_error_stat:
				return _("error statting file");
			case lu_error_read:
				return _("error reading file");
			case lu_error_write:
				return _("error writing to file");
			case lu_error_search:
				return _("data not found in file");
			case lu_error_init:
				return _("internal initialization error");
			case lu_error_module_load:
				return _("error loading module");
			case lu_error_module_sym:
				return _("error resolving symbol in module");
			case lu_error_module_version:
				return _("library/module version mismatch");
			default:
				break;
		}
	}
	return _("unknown error");
}

gboolean
lu_error_is_success(enum lu_status code)
{
	switch (code) {
		case lu_success:
			return TRUE;
		default:
			return FALSE;
	}
	return FALSE;
}

gboolean
lu_error_is_warning(enum lu_status code)
{
	switch (code) {
		case lu_warning_config_disabled:
			return TRUE;
		default:
			return FALSE;
	}
	return FALSE;
}

gboolean
lu_error_is_error(enum lu_status code)
{
	switch (code) {
		case lu_error_generic:
		case lu_error_privilege:
		case lu_error_access_denied:
		case lu_error_name_bad:
		case lu_error_id_bad:
		case lu_error_name_used:
		case lu_error_id_used:
		case lu_error_terminal:
		case lu_error_open:
		case lu_error_lock:
		case lu_error_stat:
		case lu_error_read:
		case lu_error_write:
		case lu_error_search:
		case lu_error_init:
		case lu_error_module_load:
		case lu_error_module_sym:
		case lu_error_module_version:
			return TRUE;
		default:
			return FALSE;
	}
	return FALSE;
}

void
lu_error_new(struct lu_error **error, enum lu_status code,
	     const char *fmt, ...)
{
	struct lu_error *ret;
	va_list args;

	if (error != NULL) {
		g_assert(*error == NULL);
		ret = g_malloc0(sizeof(struct lu_error));
		ret->code = code;
		va_start(args, fmt);
		ret->string = fmt ?
			g_strdup_vprintf(fmt, args) :
			g_strdup_printf(lu_strerror(ret), strerror(errno));
		va_end(args);
		*error = ret;
	}
}

void
lu_error_free(struct lu_error **error)
{
	if (error != NULL) {
		if ((*error)->string != NULL) {
			g_free((*error)->string);
		}
		memset(*error, 0, sizeof(**error));
		g_free(*error);
		*error = NULL;
	}
}
