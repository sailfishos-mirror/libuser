/*
 * Copyright (C) 2000-2002, 2005 Red Hat, Inc.
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

/* gtkdoc: private_header */

#ifndef internal_h
#define internal_h

#include <glib.h>

/* Configuration initialization and shutdown. */
gboolean lu_cfg_init(struct lu_context *context, struct lu_error **error)
	G_GNUC_INTERNAL;
void lu_cfg_done(struct lu_context *context) G_GNUC_INTERNAL;

/* Set the sources of record for a given entity structure. */
void lu_ent_add_module(struct lu_ent *ent, const char *source) G_GNUC_INTERNAL;
void lu_ent_clear_modules(struct lu_ent *ent) G_GNUC_INTERNAL;

gboolean lu_modules_load(struct lu_context *ctx, const char *module_list,
			 GValueArray **names, struct lu_error **error)
	G_GNUC_INTERNAL;
int lu_module_unload(gpointer key, gpointer value, gpointer data)
	G_GNUC_INTERNAL;

gint lu_strcasecmp(gconstpointer v1, gconstpointer v2) G_GNUC_INTERNAL;
gint lu_strcmp(gconstpointer v1, gconstpointer v2) G_GNUC_INTERNAL;

#endif