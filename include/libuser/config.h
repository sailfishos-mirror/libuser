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

#ifndef libuser_config_h
#define libuser_config_h

#include <sys/types.h>
#include <glib.h>

struct lu_context;

GList *lu_cfg_read(struct lu_context *context,
		   const char *key, const char *default_value);

const char *lu_cfg_read_single(struct lu_context *context,
			       const char *key, const char *default_value);

GList *lu_cfg_read_keys(struct lu_context *context, const char *parent_key);

#endif
