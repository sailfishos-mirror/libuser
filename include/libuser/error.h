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

#ifndef libuser_error_h
#define libuser_error_h

/** @file error.h */

#include <sys/types.h>
#include <errno.h>
#include <glib.h>

enum lu_error_code {
	lu_error_success = 0,	/** No error. */
	lu_error_generic,	/** Generic error. */
	lu_error_privilege,	/** We know we don't have enough privileges. */
	lu_error_access_denied,	/** Denied access. */
	lu_error_name_bad,	/** Name bad. */
	lu_error_id_bad,	/** ID bad. */
	lu_error_name_used,	/** Name is in use. */
	lu_error_id_used,	/** ID is in use. */
	lu_error_module_load,	/** Error loading module. */
	lu_error_module_sym,	/** Error finding address of symbol in module. */
	lu_error_version,	/** Library/module version mismatch. */
	lu_error_terminal,	/** Error manipulating terminal attributes. */
	lu_error_open,		/** Error opening file. */
	lu_error_lock,		/** Error locking file. */
	lu_error_stat,		/** Error getting information about file. */
	lu_error_read,		/** Error reading from file. */
	lu_error_write,		/** Error writing to file. */
	lu_error_search,	/** Data not found in file. */
	lu_error_init,		/** Internal initialization error. */
};

typedef struct lu_error {
	enum lu_error_code code;
	char *string;
} lu_error_t;

void lu_error_set(struct lu_error **error, enum lu_error_code code,
		  const char *fmt, ...);
void lu_error_free(struct lu_error **error);

#endif
