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

#ifndef util_h
#define util_h

#include <glib.h>

gint lu_str_case_equal(gconstpointer v1, gconstpointer v2);

gint lu_str_equal(gconstpointer v1, gconstpointer v2);

gint lu_strcasecmp(gconstpointer v1, gconstpointer v2);

gint lu_strcmp(gconstpointer v1, gconstpointer v2);

const char *lu_make_crypted(const char *plain, const char *previous);

gboolean lu_util_lock_obtain(int fd, struct lu_error ** error);

void lu_util_lock_free(int fd);

char *lu_util_line_get_matchingx(int fd, const char *part, int field,
				 struct lu_error **error);

char *lu_util_line_get_matching1(int fd, const char *part,
				 struct lu_error **error);

char *lu_util_line_get_matching3(int fd, const char *part,
				 struct lu_error **error);

char *lu_util_field_read(int fd, const char *first, unsigned int field,
			 struct lu_error **error);

gboolean lu_util_field_write(int fd, const char *first, unsigned int field,
			     const char *value, struct lu_error ** error);

char *lu_util_shadow_current_date(struct lu_string_cache *cache);

#endif
