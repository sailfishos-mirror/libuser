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
#include "config.h"
#endif
#include <libuser/user_private.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define WHITESPACE "\t "

enum lu_dispatch_id {
	user_lookup_name,
	group_lookup_name,
	user_lookup_id,
	group_lookup_id,
	user_add,
	user_mod,
	user_del,
	user_lock,
	user_unlock,
	user_setpass,
	group_add,
	group_mod,
	group_del,
	group_lock,
	group_unlock,
	group_setpass,
};

static void
lu_module_unload(gpointer key, gpointer value, gpointer data)
{
	struct lu_module *module;
	GModule *handle = NULL;
	if(value != NULL) {
		module = (struct lu_module*) value;
		handle = module->module_handle;
		module->close(module);
	}
	if(handle != NULL) {
		g_module_close(handle);
	}
}

static void
lu_module_load(struct lu_context *ctx, const gchar *list, GList **names)
{
	char *p, *q, *tmp, *wlist, *sym;
	GModule *handle = NULL;
	const gchar *module_dir = NULL, *module_file = NULL;
	lu_module_init_t module_init = NULL;
	struct lu_module *module = NULL;

	g_return_if_fail(ctx != NULL);
	g_return_if_fail(list != NULL);

	if(names) {
		g_list_free(*names);
		*names = NULL;
	}

	module_dir = lu_cfg_read_single(ctx, "defaults/moduledir", MODULEDIR);

	wlist = g_strdup(ctx->scache->cache(ctx->scache, list));

	for(p = strtok_r(wlist, WHITESPACE, &q);
	    p != NULL;
	    p = strtok_r(NULL, WHITESPACE, &q)) {
		if(g_hash_table_lookup(ctx->modules, p) == NULL) {
			tmp = g_strconcat(module_dir, "/libuser_", p, ".so",
					  NULL);
			module_file = ctx->scache->cache(ctx->scache, tmp);
			g_free(tmp);

			handle = g_module_open(module_file, 0);
			if(handle == NULL) {
				g_warning(_("error loading libuser module "
					    "'%s': %s."), module_file,
					  g_module_error());
				exit(1);
			} else {
				tmp = g_strconcat("lu_", p, "_init", NULL);
				sym = ctx->scache->cache(ctx->scache, tmp);
				g_free(tmp);

				g_module_symbol(handle, sym,
						(gpointer*) &module_init);
			}
			if(module_init == NULL) {
				g_warning(_("no initialization function %s "
					    "in '%s'."), sym, module_file);
				exit(1);
			} else {
				module = module_init(ctx);
			}
			if(module == NULL) {
				g_warning(_("error initializing '%s'."),
					  module_file);
				exit(1);
			} else {
				char *key = ctx->scache->cache(ctx->scache, p);
				module->lu_context = ctx;
				module->module_handle = handle;
				g_hash_table_insert(ctx->modules, key, module);
				*names = g_list_append(*names, key);
			}
			if(module->version != LU_MODULE_VERSION) {
				g_warning(_("module version mismatch in %s"),
					  module_file);
				exit(1);
			}
		} else {
			char *key = ctx->scache->cache(ctx->scache, p);
			*names = g_list_append(*names, key);
		}
	}

	g_free(wlist);
}

void
lu_set_info_modules(struct lu_context *context, const char *list)
{
	g_return_if_fail(list != NULL);
	lu_module_load(context, list, &context->info_module_names);
}

void
lu_set_auth_modules(struct lu_context *context, const char *list)
{
	g_return_if_fail(list != NULL);
	lu_module_load(context, list, &context->auth_module_names);
}

struct lu_context *
lu_start(const char *auth_name, enum lu_type auth_type,
	 const char *info_modules, const char *auth_modules,
	 lu_prompt_fn *prompter, gpointer prompter_data)
{
	struct lu_context *ctx = NULL;

	ctx = g_malloc0(sizeof(struct lu_context));

	if(lu_cfg_init(ctx) == FALSE) {
		g_free(ctx);
		return NULL;
	}

	ctx->scache = lu_string_cache_new(TRUE);

	ctx->prompter = prompter;
	ctx->prompter_data = prompter_data;
	ctx->auth_name = ctx->scache->cache(ctx->scache, auth_name);
	ctx->auth_type = auth_type;

	ctx->modules = g_hash_table_new(g_str_hash, lu_str_case_equal);

	if(info_modules == NULL) {
		info_modules = lu_cfg_read_single(ctx, "defaults/info_modules",
						  "");
	}
	lu_module_load(ctx, info_modules, &ctx->info_module_names);

	if(auth_modules == NULL) {
		auth_modules = lu_cfg_read_single(ctx, "defaults/auth_modules",
						  "");
	}
	lu_module_load(ctx, auth_modules, &ctx->auth_module_names);

	return ctx;
}

void
lu_end(struct lu_context *context)
{
	g_return_if_fail(context != NULL);

	g_hash_table_foreach(context->modules, lu_module_unload, NULL);
	g_hash_table_destroy(context->modules);

	lu_cfg_done(context);

	context->scache->free(context->scache);

	memset(context, 0, sizeof(struct lu_context));

	g_free(context);
}

static gboolean
run_single(struct lu_context *context, struct lu_module *module,
	   enum lu_module_type type, enum lu_dispatch_id id,
	   struct lu_ent *ent, gpointer data)
{
	gboolean success = FALSE;
	g_return_val_if_fail(context != NULL, FALSE);
	g_return_val_if_fail(module != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);
	switch(id) {
		case user_lookup_name:
#ifdef DEBUG
			g_print("Looking up user %s using %s.\n",
				data, module->name);
#endif
			success = module->user_lookup_name(module,
							   data,
							   ent);
			break;
		case user_lookup_id:
#ifdef DEBUG
			g_print("Looking up uid %d using %s.\n",
				GPOINTER_TO_INT(data), module->name);
#endif
			success = module->user_lookup_id(module,
							 data,
							 ent);
			break;
		case group_lookup_name:
#ifdef DEBUG
			g_print("Looking up group %s using %s.\n",
				data, module->name);
#endif
			success = module->group_lookup_name(module,
							    data,
							    ent);
			break;
		case group_lookup_id:
#ifdef DEBUG
			g_print("Looking up gid %d using %s.\n",
				GPOINTER_TO_INT(data), module->name);
#endif
			success = module->group_lookup_id(module,
							  data,
							  ent);
			break;
		case user_add:
#ifdef DEBUG
			g_print("Adding user to %s.\n", module->name);
#endif
			success = module->user_add(module, ent);
			break;
		case group_add:
#ifdef DEBUG
			g_print("Adding group to %s.\n", module->name);
#endif
			success = module->group_add(module, ent);
			break;
		case user_mod:
#ifdef DEBUG
			g_print("Modifying user in %s.\n", module->name);
#endif
			success = module->user_mod(module, ent);
			break;
		case group_mod:
#ifdef DEBUG
			g_print("Modifying group in %s.\n", module->name);
#endif
			success = module->group_mod(module, ent);
			break;
		case user_del:
#ifdef DEBUG
			g_print("Removing user from %s.\n", module->name);
#endif
			success = module->user_del(module, ent);
			break;
		case group_del:
#ifdef DEBUG
			g_print("Removing group from %s.\n", module->name);
#endif
			success = module->group_del(module, ent);
			break;
		case user_lock:
#ifdef DEBUG
			g_print("Locking user in %s.\n", module->name);
#endif
			success = module->user_lock(module, ent);
			break;
		case group_lock:
#ifdef DEBUG
			g_print("Locking group in %s.\n", module->name);
#endif
			success = module->group_lock(module, ent);
			break;
		case user_unlock:
#ifdef DEBUG
			g_print("Unlocking user in %s.\n", module->name);
#endif
			success = module->user_unlock(module, ent);
			break;
		case group_unlock:
#ifdef DEBUG
			g_print("Unlocking group in %s.\n", module->name);
#endif
			success = module->group_unlock(module, ent);
			break;
		case user_setpass:
			if(module->user_setpass) {
#ifdef DEBUG
				g_print("Setting password for user in %s.\n",
					module->name);
#endif
				success = module->user_setpass(module, ent,
							       data);
			} else {
#ifdef DEBUG
				g_print("Unable to set password for user in "
					"%s.\n", module->name);
#endif
			}
			break;
		case group_setpass:
			if(module->group_setpass) {
#ifdef DEBUG
				g_print("Setting password for group in %s.\n",
					module->name);
#endif
				success = module->group_setpass(module, ent,
								data);
			} else {
#ifdef DEBUG
				g_print("Unable to set password for group in "
					"%s.\n", module->name);
#endif
			}
			break;
	}
	if(success) {
		if(type == auth) {
			lu_ent_set_source_auth(ent, module->name);
		}
		if(type == info) {
			lu_ent_set_source_info(ent, module->name);
		}
#ifdef DEBUG
		g_print("...%s succeeded for %s.\n", module->name,
			type == auth ? "auth" : "info");
	} else {
		g_print("...%s failed for %s.\n", module->name,
			type == auth ? "auth" : "info");
#endif
	}
	return success;
}

static gboolean
run_list(struct lu_context *context, GList *modules, enum lu_module_type type,
	 enum lu_dispatch_id id, struct lu_ent *ent, gpointer data)
{
	struct lu_module *module;
	GList *c;
	gboolean success;
	int i;

	g_return_val_if_fail(context != NULL, FALSE);
	g_return_val_if_fail(modules != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);

	for(i = 0, success = FALSE;
	    (c = g_list_nth(modules, i)) != NULL;
	    i++) {
		module = g_hash_table_lookup(context->modules, (char*)c->data);
		g_assert(module != NULL);
		success = run_single(context, module, type, id, ent, data);
		if(success) {
			break;
		}
	}

	return success;
}

static gboolean
lu_dispatch(struct lu_context *context, enum lu_dispatch_id id,
	    gpointer data, struct lu_ent *ent)
{
	struct lu_ent *tmp;
	struct lu_module *auth_module, *info_module;
	gboolean success = FALSE;

	g_return_val_if_fail(context != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);

	tmp = lu_ent_new();
	lu_ent_copy(ent, tmp);

	switch(id) {
		case user_lookup_id:
		case group_lookup_id:
			if(run_list(context, context->info_module_names,
				    info, id, tmp, data)) {
				/* Got a match on that ID, convert it to a
				 * name and look it up by name. */
				GList *value = NULL;
				const char *attr = NULL;
				g_assert((id == user_lookup_id) ||
					 (id == group_lookup_id));
				if(id == user_lookup_id) {
					attr = LU_USERNAME;
					id = user_lookup_name;
				}
				if(id == group_lookup_id) {
					attr = LU_GROUPNAME;
					id = group_lookup_name;
				}
				value = lu_ent_get_original(tmp, attr);
				if(value && value->data) {
					data = ent->vcache->cache(ent->vcache,
								  value->data);
				} else {
					break;
				}
			} else {
				/* No match on that ID. */
				break;
			}
		case user_lookup_name:
		case group_lookup_name:
			g_assert((id == user_lookup_name) ||
				 (id == group_lookup_name));
			if(run_list(context, context->info_module_names, info, id, tmp, data) &&
			   run_list(context, context->auth_module_names, auth, id, tmp, data)) {
				lu_ent_copy(tmp, ent);
				lu_ent_revert(ent);
				success = TRUE;
			}
			break;
		case user_add:
		case group_add:
			if(run_list(context, context->auth_module_names, auth, id, tmp, data) &&
			   run_list(context, context->info_module_names, info, id, tmp, data)) {
				success = TRUE;
			}
			break;
		case user_mod:
		case user_del:
		case group_mod:
		case group_del:
			auth_module = g_hash_table_lookup(context->modules,
							  tmp->source_auth);
			info_module = g_hash_table_lookup(context->modules,
							  tmp->source_info);
			g_assert(auth_module != NULL);
			g_assert(info_module != NULL);
			if(run_single(context, auth_module, auth, id, tmp, data) &&
			   run_single(context, info_module, info, id, tmp, data)) {
				success = TRUE;
			}
			break;
		case user_lock:
		case user_unlock:
		case user_setpass:
		case group_lock:
		case group_unlock:
		case group_setpass:
			auth_module = g_hash_table_lookup(context->modules,
							  tmp->source_auth);
			g_assert(auth_module != NULL);
			success = run_single(context, auth_module, auth,
					     id, tmp, data);
			break;
	}
	lu_ent_free(tmp);

	if(success) {
		switch(id) {
			case user_lookup_id:
			case user_lookup_name:
				ent->type = lu_user;
				break;
			case group_lookup_name:
			case group_lookup_id:
				ent->type = lu_group;
				break;
			default:
		}
	}

	return success;
}

gboolean
lu_user_lookup_name(struct lu_context *context, const char *name,
		    struct lu_ent *ent)
{
	return lu_dispatch(context,
			   user_lookup_name,
			   (gpointer)name,
			   ent);
}

gboolean
lu_group_lookup_name(struct lu_context *context, const char *name,
		     struct lu_ent *ent)
{
	return lu_dispatch(context,
			   group_lookup_name,
			   (gpointer)name,
			   ent);
}

gboolean
lu_user_lookup_id(struct lu_context *context, uid_t uid, struct lu_ent *ent)
{
	return lu_dispatch(context,
			   user_lookup_id,
			   (gpointer)uid,
			   ent);
}

gboolean
lu_group_lookup_id(struct lu_context *context, gid_t gid, struct lu_ent *ent)
{
	return lu_dispatch(context,
			   group_lookup_id,
			   (gpointer)gid,
			   ent);
}

gboolean
lu_user_add(struct lu_context *context, struct lu_ent *ent)
{
	return lu_dispatch(context,
			   user_add,
			   NULL,
			   ent);
}

gboolean
lu_group_add(struct lu_context *context, struct lu_ent *ent)
{
	return lu_dispatch(context,
			   group_add,
			   NULL,
			   ent);
}

gboolean
lu_user_modify(struct lu_context *context, struct lu_ent *ent)
{
	return lu_dispatch(context,
			   user_mod,
			   NULL,
			   ent);
}

gboolean
lu_group_modify(struct lu_context *context, struct lu_ent *ent)
{
	return lu_dispatch(context,
			   group_mod,
			   NULL,
			   ent);
}

gboolean
lu_user_delete(struct lu_context *context, struct lu_ent *ent)
{
	return lu_dispatch(context,
			   user_del,
			   NULL,
			   ent);
}

gboolean
lu_group_delete(struct lu_context *context, struct lu_ent *ent)
{
	return lu_dispatch(context,
			   group_del,
			   NULL,
			   ent);
}

gboolean
lu_user_lock(struct lu_context *context, struct lu_ent *ent)
{
	return lu_dispatch(context,
			   user_lock,
			   NULL,
			   ent);
}

gboolean
lu_user_unlock(struct lu_context *context, struct lu_ent *ent)
{
	return lu_dispatch(context,
			   user_unlock,
			   NULL,
			   ent);
}

gboolean
lu_user_setpass(struct lu_context *context, struct lu_ent *ent,
		const char *password)
{
	return lu_dispatch(context,
			   user_setpass,
			   password,
			   ent);
}

gboolean
lu_group_lock(struct lu_context *context, struct lu_ent *ent)
{
	return lu_dispatch(context,
			   group_lock,
			   NULL,
			   ent);
}

gboolean
lu_group_unlock(struct lu_context *context, struct lu_ent *ent)
{
	return lu_dispatch(context,
			   group_unlock,
			   NULL,
			   ent);
}

gboolean
lu_group_setpass(struct lu_context *context, struct lu_ent *ent,
		 const char *password)
{
	return lu_dispatch(context,
			   group_setpass,
			   password,
			   ent);
}
