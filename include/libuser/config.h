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

/** @file config.h */

#include <sys/types.h>
#include <glib.h>

struct lu_context;

/**
 * Read the value of a potentially multi-valued key in the configuration file.
 * @param context A valid library context.
 * @param key The path to the value in the configuration file.
 * @param default_value The value to return if the key is not found in the file.
 * @return A list of values on success.
 * @return The default value on failure.
 **/
GList *lu_cfg_read(struct lu_context *context,
		   const char *key, const char *default_value);

/**
 * Read the value of a single-valued key in the configuration file.
 * @param context A valid library context.
 * @param key The path to the value in the configuration file.
 * @param default_value The value to return if the key is not found in the file.
 * @return A single value on success.
 * @return The default value on failure.
 */
const char *lu_cfg_read_single(struct lu_context *context,
			       const char *key, const char *default_value);

/**
 * Read the list of keys in a section of the file.
 * @param context A valid library context.
 * @param parent_key A path beneath which keys should be searched for.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
GList *lu_cfg_read_keys(struct lu_context *context, const char *parent_key);

#endif
