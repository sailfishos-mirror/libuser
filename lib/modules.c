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

#define SEPARATORS "\t ,"

gboolean
lu_modules_load(struct lu_context *ctx, const char *module_list,
	       	GValueArray **names, struct lu_error **error)
{
	char *p, *q, *tmp, *symbol, *modlist, *module_file = NULL;
	int i;
	GModule *handle = NULL;
	const char *module_dir = NULL, *ctmp;
	lu_module_init_t module_init = NULL;
	struct lu_module *module = NULL;

	LU_ERROR_CHECK(error);

	g_assert(ctx != NULL);
	g_assert(module_list != NULL);
	g_assert(names != NULL);

	/* Build a GValueArray for the module names. */
	if (*names != NULL) {
		g_value_array_free(*names);
	}
	*names = g_value_array_new(0);

	/* Iterate over the list, broken out into actual names, and add them
	 * to the array. */
	modlist = g_strdup(module_list);
	for (p = strtok_r(modlist, SEPARATORS, &q);
	     p != NULL;
	     p = strtok_r(NULL, SEPARATORS, &q)) {
		char *cached;
		GValue value;
		tmp = g_strndup(p, q ? q - p : strlen(p));
		cached = ctx->scache->cache(ctx->scache, tmp);
		g_free(tmp);

		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_STRING);	
		g_value_set_string(&value, cached);	
		g_value_array_append(*names, &value);
		g_value_unset(&value);
	}
	g_free(modlist);

	/* Figure out where the modules would be. */
	module_dir = lu_cfg_read_single(ctx, "defaults/moduledir", MODULEDIR);

	/* Load the modules. */
	for (i = 0; i < (*names)->n_values; i++) {
		ctmp = g_value_get_string(g_value_array_get_nth(*names, i));
		tmp = ctx->scache->cache(ctx->scache, ctmp);
		/* Only load the module if it's not already loaded. */
		if (g_tree_lookup(ctx->modules, tmp) == NULL) {
			/* Generate the file name. */
			tmp = g_strconcat(PACKAGE "_", ctmp, NULL);
			module_file = g_module_build_path(module_dir, tmp);
			g_free(tmp);
			tmp = module_file;
			module_file = ctx->scache->cache(ctx->scache, tmp);
			g_free(tmp);

			/* Open the module. */
			handle = g_module_open(module_file, 0);
			if (handle == NULL) {
				/* If the open failed, we return an error. */
				lu_error_new(error, lu_error_module_load,
					     "%s", g_module_error());
				return FALSE;
			}

			/* Determine the name of the module's initialization
			 * function and try to find it. */
			tmp = g_strconcat(PACKAGE "_", ctmp, "_init", NULL);
			symbol = ctx->scache->cache(ctx->scache, tmp);
			g_free(tmp);
			g_module_symbol(handle, symbol,
					(gpointer *)&module_init);

			/* If we couldn't find the entry point, error out. */
			if (module_init == NULL) {
				lu_error_new(error, lu_error_module_sym,
					     _("no initialization function %s "
					       "in `%s'"),
					     symbol, module_file);
				g_module_close(handle);
				return FALSE;
			}

			/* Ask the module to allocate the a module structure
			 * and hand it back to us. */
			module = module_init(ctx, error);

			if (module == NULL) {
				/* The module initializer sets the error, but
				 * we need to ignore warnings. */
				if (lu_error_is_warning((*error)->code)) {
					lu_error_free(error);
				} else {
					g_module_close(handle);
					return FALSE;
				}
			} else {
				/* Check that the module interface version
				 * is right, too. */
				if (module->version != LU_MODULE_VERSION) {
					lu_error_new(error,
						     lu_error_module_version,
						     _("module version "
						       "mismatch in `%s'"),
						     module_file);
					g_module_close(handle);
					return FALSE;
				}

				/* Initialize the last two fields in the
				 * module structure, add it to the module
				 * tree, and return. */
				module->lu_context = ctx;
				module->module_handle = handle;
				tmp = ctx->scache->cache(ctx->scache, ctmp);
				g_tree_insert(ctx->modules, tmp, module);
			}

			/* For safety's sake, make sure that all functions
			 * provided by the module exist.  This can often mean
			 * a useless round trip, but it simplifies the logic
			 * of the library greatly. */
			g_return_val_if_fail(module->uses_elevated_privileges != NULL,
					     FALSE);
			g_return_val_if_fail(module->user_lookup_name != NULL,
					     FALSE);
			g_return_val_if_fail(module->user_lookup_id != NULL,
					     FALSE);
			g_return_val_if_fail(module->user_add != NULL, FALSE);
			g_return_val_if_fail(module->user_mod != NULL, FALSE);
			g_return_val_if_fail(module->user_del != NULL, FALSE);
			g_return_val_if_fail(module->user_lock != NULL, FALSE);
			g_return_val_if_fail(module->user_unlock != NULL,
					     FALSE);
			g_return_val_if_fail(module->user_is_locked != NULL,
					     FALSE);
			g_return_val_if_fail(module->user_setpass != NULL,
					     FALSE);
			g_return_val_if_fail(module->users_enumerate != NULL,
					     FALSE);
			g_return_val_if_fail(module->users_enumerate_by_group != NULL,
					     FALSE);
			g_return_val_if_fail(module->users_enumerate_full != NULL,
					     FALSE);
			g_return_val_if_fail(module->users_enumerate_by_group_full != NULL,
					     FALSE);

			g_return_val_if_fail(module->group_lookup_name != NULL,
					     FALSE);
			g_return_val_if_fail(module->group_lookup_id != NULL,
					     FALSE);
			g_return_val_if_fail(module->group_add != NULL, FALSE);
			g_return_val_if_fail(module->group_mod != NULL, FALSE);
			g_return_val_if_fail(module->group_del != NULL, FALSE);
			g_return_val_if_fail(module->group_lock != NULL, FALSE);
			g_return_val_if_fail(module->group_unlock != NULL,
					     FALSE);
			g_return_val_if_fail(module->group_is_locked != NULL,
					     FALSE);
			g_return_val_if_fail(module->group_setpass != NULL,
					     FALSE);
			g_return_val_if_fail(module->groups_enumerate != NULL,
					     FALSE);
			g_return_val_if_fail(module->groups_enumerate_by_user != NULL,
					     FALSE);
			g_return_val_if_fail(module->groups_enumerate_full != NULL,
					     FALSE);
			g_return_val_if_fail(module->groups_enumerate_by_user_full != NULL,
					     FALSE);

			g_return_val_if_fail(module->close != NULL, FALSE);
		}
	}
	return TRUE;
}

/* Unload a given module, implemented as a callback for a GTree where the
 * module's name is a key, and the module structure is the value. */
int
lu_module_unload(gpointer key, gpointer value, gpointer data)
{
	struct lu_module *module;
	GModule *handle = NULL;
	/* Give the module a chance to clean itself up. */
	if (value != NULL) {
		module = (struct lu_module *) value;
		handle = module->module_handle;
		module->close(module);
	}
	/* Unload the module. */
	if (handle != NULL) {
		g_module_close(handle);
	}
	return 0;
}
