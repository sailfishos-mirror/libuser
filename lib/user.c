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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/libuser/user_private.h"

#define SEPARATOR "\t ,"

enum lu_dispatch_id {
	user_lookup_name = 0x4b82,
	group_lookup_name,
	user_lookup_id,
	group_lookup_id,
	user_add,
	user_mod,
	user_del,
	user_lock,
	user_unlock,
	user_islocked,
	user_setpass,
	group_add,
	group_mod,
	group_del,
	group_lock,
	group_unlock,
	group_islocked,
	group_setpass,
};

/**
 * lu_module_unload:
 * @key: A string representation of the module's name.
 * @value: A pointer to the module's #lu_module_t structure.
 *
 * Unloads a libuser module from memory.
 *
 * Returns: nothing.
 **/
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

static gboolean
lu_module_load(struct lu_context *ctx, const gchar *list, GList **names, struct lu_error **error)
{
	char *p, *q, *tmp, *wlist, *sym;
	GModule *handle = NULL;
	const gchar *module_dir = NULL, *module_file = NULL;
	lu_module_init_t module_init = NULL;
	struct lu_module *module = NULL;

	LU_ERROR_CHECK(error);

	g_assert(ctx != NULL);
	g_assert(list != NULL);

	if(names) {
		g_list_free(*names);
		*names = NULL;
	}

	module_dir = lu_cfg_read_single(ctx, "defaults/moduledir", MODULEDIR);

	wlist = g_strdup(ctx->scache->cache(ctx->scache, list));

	for(p = strtok_r(wlist, SEPARATOR, &q);
	    p != NULL;
	    p = strtok_r(NULL, SEPARATOR, &q)) {
		if(g_hash_table_lookup(ctx->modules, p) == NULL) {
			tmp = g_strconcat(module_dir, "/libuser_", p, ".so", NULL);
			module_file = ctx->scache->cache(ctx->scache, tmp);
			g_free(tmp);

			handle = g_module_open(module_file, 0);

			if(handle == NULL) {
				lu_error_new(error, lu_error_module_load, "%s", g_module_error());
				g_free(wlist);
				return FALSE;
			} else {
				tmp = g_strconcat("lu_", p, "_init", NULL);
				sym = ctx->scache->cache(ctx->scache, tmp);
				g_free(tmp);

				g_module_symbol(handle, sym, (gpointer*) &module_init);
			}

			if(module_init == NULL) {
				lu_error_new(error, lu_error_module_sym, _("no initialization function %s in `%s'"),
					     sym, module_file);
				g_module_close(handle);
				g_free(wlist);
				return FALSE;
			} else {
				module = module_init(ctx, error);
			}

			if(module == NULL) {
				/* module initializer sets the error */
				if((*error)->code == lu_error_config_disabled) {
					lu_error_free(error);
				} else {
					g_module_close(handle);
					g_free(wlist);
					return FALSE;
				}
			} else {
				char *key;
				if(module->version != LU_MODULE_VERSION) {
					lu_error_new(error, lu_error_version, _("module version mismatch in `%s'"),
						     module_file);
					g_module_close(handle);
					g_free(wlist);
					return FALSE;
				}
				key = ctx->scache->cache(ctx->scache, p);
				module->lu_context = ctx;
				module->module_handle = handle;
				g_hash_table_insert(ctx->modules, key, module);
				*names = g_list_append(*names, key);
			}
		} else {
			char *key = ctx->scache->cache(ctx->scache, p);
			*names = g_list_append(*names, key);
		}
	}

	g_free(wlist);

	return TRUE;
}

/**
 * lu_set_info_modules:
 * @context: A valid library context, initialized by calling lu_start().
 * @list: A string containing a comma-separated or whitespace-separated list of modules to search in.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * Sets the list of modules which will be queried when looking up information
 * about users and groups.  The first module in the list which admits to having
 * some idea of who the user or group is will be deemed authoritative for
 * general information for that user or group.
 *
 * Returns: TRUE on success, FALSE on failure, with @error set.
 **/
gboolean
lu_set_info_modules(struct lu_context *context, const char *list, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	g_assert(list != NULL);
	return lu_module_load(context, list, &context->info_module_names, error);
}

/**
 * lu_set_auth_modules:
 * @context: A valid library context, initialized by calling lu_start().
 * @list: A string containing a comma-separated or whitespace-separated list of modules to search in.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * Sets the list of modules which will be queried when looking up authentication
 * information about users and groups.  The first module in the list which
 * admits to having some idea of who the user or group is will be deemed
 * authoritative for authentication information for that user or group.
 *
 * Returns: TRUE on success, FALSE on failure, with @error set.
 **/
gboolean
lu_set_auth_modules(struct lu_context *context, const char *list, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	g_assert(list != NULL);
	return lu_module_load(context, list, &context->auth_module_names, error);
}

/**
 * lu_set_prompter:
 * @context: A valid library context, initialized by calling lu_start().
 * @prompter: The address of a function with the same prototype as lu_prompt_console().
 * @prompter_data: Data which will be passed to @prompter as its @callback_data parameter.
 *
 * Sets the function modules loaded by libuser will use to ask the application's user for information.  This typically includes
 * login and password information when the module needs access to network services.  The default prompter is #lu_prompt_console,
 * but an application can (and if it's a graphical application, definitely should) replace it with its own version.
 *
 * Returns: void
 **/
void
lu_set_prompter(struct lu_context *context, lu_prompt_fn *prompter, gpointer prompter_data)
{
	g_assert(prompter != NULL);
	context->prompter = prompter;
	context->prompter_data = prompter_data;
}

/**
 * lu_start:
 * @auth_name: A suggested name to use when initializing modules.
 * @auth_type: Whether &auth_name; is a user or group.
 * @info_modules: An initial list of modules to use.  If the application intends to cause modules to be added or removed during
 * the course of its operation, it should pass an initial string here, and pass in #NULL otherwise.
 * @info_modules: An initial list of modules to use.  If the application intends to cause modules to be added or removed during
 * the course of its operation, it should pass an initial string here, and pass in #NULL otherwise.
 * @prompter: A function which modules will be able to call to interact with the application's user.
 * @prompter_data: Data to be passed to @prompter when it is called.
 *
 * Initializes the library.
 *
 * Returns: A library context.
 **/
struct lu_context *
lu_start(const char *auth_name, enum lu_type auth_type, const char *info_modules, const char *auth_modules,
	 lu_prompt_fn *prompter, gpointer prompter_data, struct lu_error **error)
{
	struct lu_context *ctx = NULL;

	LU_ERROR_CHECK(error);

	ctx = g_malloc0(sizeof(struct lu_context));

	if(lu_cfg_init(ctx, error) == FALSE) {
		/* lu_cfg_init sets error */
		g_free(ctx);
		return NULL;
	}

	ctx->scache = lu_string_cache_new(TRUE);

#ifdef DEBUG
	g_message("prompter = <%p>, data = <%p>\n", prompter, prompter_data);
#endif
	ctx->prompter = prompter;
	ctx->prompter_data = prompter_data;
	ctx->auth_name = ctx->scache->cache(ctx->scache, auth_name);
	ctx->auth_type = auth_type;

	ctx->modules = g_hash_table_new(g_str_hash, lu_str_case_equal);

	if(info_modules == NULL) {
		info_modules = lu_cfg_read_single(ctx, "defaults/info_modules", "files");
	}
	if(!lu_module_load(ctx, info_modules, &ctx->info_module_names, error)) {
		/* lu_module_load sets errors */
		g_free(ctx);
		return NULL;
	}

	if(auth_modules == NULL) {
		auth_modules = lu_cfg_read_single(ctx, "defaults/auth_modules", "files shadow");
	}
	if(!lu_module_load(ctx, auth_modules, &ctx->auth_module_names, error)) {
		/* lu_module_load sets errors */
		g_free(ctx);
		return NULL;
	}

	return ctx;
}

/**
 * lu_end:
 * @context: A library context.
 *
 * Shuts down the library.
 *
 * Returns: void
 */
void
lu_end(struct lu_context *context)
{
	g_assert(context != NULL);

	if(context->modules != NULL) {
		g_hash_table_foreach(context->modules, lu_module_unload, NULL);
		g_hash_table_destroy(context->modules);
	}

	lu_cfg_done(context);

	if(context->scache != NULL) {
		context->scache->free(context->scache);
	}

	memset(context, 0, sizeof(struct lu_context));

	g_free(context);
}

static gboolean
run_single(struct lu_context *context, struct lu_module *module, enum lu_module_type type, enum lu_dispatch_id id,
	   struct lu_ent *ent, gconstpointer data, struct lu_error **error)
{
	gboolean success = FALSE;
	g_assert(context != NULL);
	g_assert(module != NULL);
	g_assert(ent != NULL);

	LU_ERROR_CHECK(error);

	switch(id) {
		case user_lookup_name:
#ifdef DEBUG
			g_print("Looking up user %s using %s.\n", data, module->name);
#endif
			success = module->user_lookup_name(module, data, ent, error);
			break;
		case user_lookup_id:
#ifdef DEBUG
			g_print("Looking up uid %d using %s.\n", GPOINTER_TO_INT(data), module->name);
#endif
			success = module->user_lookup_id(module, data, ent, error);
			break;
		case group_lookup_name:
#ifdef DEBUG
			g_print("Looking up group %s using %s.\n", data, module->name);
#endif
			success = module->group_lookup_name(module, data, ent, error);
			break;
		case group_lookup_id:
#ifdef DEBUG
			g_print("Looking up gid %d using %s.\n", GPOINTER_TO_INT(data), module->name);
#endif
			success = module->group_lookup_id(module, data, ent, error);
			break;
		case user_add:
#ifdef DEBUG
			g_print("Adding user to %s.\n", module->name);
#endif
			success = module->user_add(module, ent, error);
			break;
		case group_add:
#ifdef DEBUG
			g_print("Adding group to %s.\n", module->name);
#endif
			success = module->group_add(module, ent, error);
			break;
		case user_mod:
#ifdef DEBUG
			g_print("Modifying user in %s.\n", module->name);
#endif
			success = module->user_mod(module, ent, error);
			break;
		case group_mod:
#ifdef DEBUG
			g_print("Modifying group in %s.\n", module->name);
#endif
			success = module->group_mod(module, ent, error);
			break;
		case user_del:
#ifdef DEBUG
			g_print("Removing user from %s.\n", module->name);
#endif
			success = module->user_del(module, ent, error);
			break;
		case group_del:
#ifdef DEBUG
			g_print("Removing group from %s.\n", module->name);
#endif
			success = module->group_del(module, ent, error);
			break;
		case user_lock:
#ifdef DEBUG
			g_print("Locking user in %s.\n", module->name);
#endif
			success = module->user_lock(module, ent, error);
			break;
		case group_lock:
#ifdef DEBUG
			g_print("Locking group in %s.\n", module->name);
#endif
			success = module->group_lock(module, ent, error);
			break;
		case user_unlock:
#ifdef DEBUG
			g_print("Unlocking user in %s.\n", module->name);
#endif
			success = module->user_unlock(module, ent, error);
			break;
		case group_unlock:
#ifdef DEBUG
			g_print("Unlocking group in %s.\n", module->name);
#endif
			success = module->group_unlock(module, ent, error);
			break;
		case user_islocked:
#ifdef DEBUG
			g_print("Checking if user is locked in %s.\n", module->name);
#endif
			success = module->user_islocked(module, ent, error);
			break;
		case group_islocked:
#ifdef DEBUG
			g_print("Checking if group is locked in %s.\n", module->name);
#endif
			success = module->group_islocked(module, ent, error);
			break;
		case user_setpass:
			if(module->user_setpass) {
#ifdef DEBUG
				g_print("Setting password for user in %s.\n", module->name);
#endif
				success = module->user_setpass(module, ent, data, error);
			} else {
#ifdef DEBUG
				g_print("Unable to set password for user in %s.\n", module->name);
#endif
			}
			break;
		case group_setpass:
			if(module->group_setpass) {
#ifdef DEBUG
				g_print("Setting password for group in %s.\n", module->name);
#endif
				success = module->group_setpass(module, ent, data, error);
			} else {
#ifdef DEBUG
				g_print("Unable to set password for group in %s.\n", module->name);
#endif
			}
			break;
	}
#ifdef DEBUG
	g_print("...%s returned %s for %s.\n",
		module->name,
		success ? "TRUE" : "FALSE",
		type == auth ? "auth" : "info");
#endif
	return success;
}

static gboolean
run_list(struct lu_context *context, GList *modules, enum lu_module_type type,
	 enum lu_dispatch_id id, struct lu_ent *ent, gconstpointer data,
	 struct lu_error **error)
{
	struct lu_module *module;
	GList *c;
	gboolean success;
	int i;

	LU_ERROR_CHECK(error);

	g_assert(context != NULL);
	g_assert(modules != NULL);
	g_assert(ent != NULL);
	g_assert((id == user_lookup_name) ||
		 (id == user_lookup_id) ||
		 (id == group_lookup_name) ||
		 (id == group_lookup_id) ||
		 (id == user_add) ||
		 (id == group_add));

	for(i = 0, success = FALSE;
	    (c = g_list_nth(modules, i)) != NULL;
	    i++) {
		module = g_hash_table_lookup(context->modules, (char*)c->data);
		g_assert(module != NULL);
		success = run_single(context, module, type, id, ent, data, error);
		if(success) {
			if(type == auth) {
				lu_ent_set_source_auth(ent, module->name);
			}
			if(type == info) {
				lu_ent_set_source_info(ent, module->name);
			}
			break;
		} else {
			if(g_list_nth(modules, i + 1) != NULL) {
				if(*error != NULL) {
					lu_error_free(error);
				}
			}
		}
	}

	return success;
}

static gboolean
lu_dispatch(struct lu_context *context, enum lu_dispatch_id id, gconstpointer data, struct lu_ent *ent, struct lu_error **error)
{
	struct lu_ent *tmp;
	struct lu_module *auth_module, *info_module;
	gboolean success = FALSE;

	LU_ERROR_CHECK(error);

	g_assert(context != NULL);
	g_assert(ent != NULL);

	tmp = lu_ent_new();
	lu_ent_copy(ent, tmp);

	switch(id) {
		case user_lookup_id:
		case group_lookup_id:
			if(run_list(context, context->info_module_names, info, id, tmp, data, error)) {
				/* Got a match on that ID, convert it to a
				 * name and look it up by name. */
				GList *value = NULL;
				const char *attr = NULL;
				g_assert((id == user_lookup_id) || (id == group_lookup_id));
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
					data = ent->vcache->cache(ent->vcache, value->data);
				} else {
					break;
				}
			} else {
				/* No match on that ID. */
				break;
			}
		case user_lookup_name:
		case group_lookup_name:
			g_assert((id == user_lookup_name) || (id == group_lookup_name));
			if(run_list(context, context->info_module_names, info, id, tmp, data, error) &&
			   run_list(context, context->auth_module_names, auth, id, tmp, data, error)) {
				lu_ent_copy(tmp, ent);
				lu_ent_revert(ent);
				success = TRUE;
			}
			break;
		case user_add:
		case group_add:
			if(run_list(context, context->auth_module_names, auth, id, tmp, data, error) &&
			   run_list(context, context->info_module_names, info, id, tmp, data, error)) {
				success = TRUE;
			}
			if(success) {
				g_assert(tmp->source_info != NULL);
				g_assert(tmp->source_auth != NULL);
				lu_ent_copy(tmp, ent);
			}
			break;
		case user_mod:
		case user_del:
		case group_mod:
		case group_del:
		case user_setpass:
		case group_setpass:
			auth_module = g_hash_table_lookup(context->modules, tmp->source_auth);
			info_module = g_hash_table_lookup(context->modules, tmp->source_info);
			g_assert(auth_module != NULL);
			g_assert(info_module != NULL);
			if(run_single(context, auth_module, auth, id, tmp, data, error) &&
			   run_single(context, info_module, info, id, tmp, data, error)) {
				success = TRUE;
			}
			break;
		case user_lock:
		case user_unlock:
		case user_islocked:
		case group_lock:
		case group_unlock:
		case group_islocked:
			auth_module = g_hash_table_lookup(context->modules, tmp->source_auth);
			g_assert(auth_module != NULL);
			success = run_single(context, auth_module, auth, id, tmp, data, error);
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

/**
 * lu_user_lookup_name:
 * @context: A library context.
 * @name: A user name.
 * @ent: An entity structure.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function can be used to look up information about a user given only the user's @name.  All loaded modules are queried,
 * first for information about how the user is authenticated, and then for general information about the user (UID, home
 * directory, and so on).  If a match is found, information about the user is stored in @ent.
 *
 * Returns: TRUE if the user is found, FALSE if the user is not found, with @error filled in.
 **/
gboolean
lu_user_lookup_name(struct lu_context *context, const char *name, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_lookup_name, (gpointer)name, ent, error);
}

/**
 * lu_group_lookup_name:
 * @context: A library context.
 * @name: A group name.
 * @ent: An entity structure.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function can be used to look up information about a group given only the group's @name.  All loaded modules are queried,
 * first for information about how the group is authenticated, and then for general information about the group (GID, members,
 * and so on).  If a match is found, information about the group is stored in @ent.
 *
 * Returns: TRUE if the user is found, FALSE if the user is not found.
 **/
gboolean
lu_group_lookup_name(struct lu_context *context, const char *name, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_lookup_name, (gpointer)name, ent, error);
}

/**
 * lu_user_lookup_id:
 * @context: A library context.
 * @uid: A numeric user ID.
 * @ent: An entity structure.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function can be used to look up information about a user given only the user's UID.  All loaded modules are queried,
 * first for information about how the user is authenticated, and then for general information about the user (UID, home
 * directory, and so on).  If a match is found, information about the user is stored in @ent.
 *
 * Returns: TRUE if the user is found, FALSE if the user is not found.
 **/
gboolean
lu_user_lookup_id(struct lu_context *context, uid_t uid, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_lookup_id, (gpointer)uid, ent, error);
}

/**
 * lu_group_lookup_id:
 * @context: A library context.
 * @gid: A numeric group ID.
 * @ent: An entity structure.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function can be used to look up information about a group given only the group's #GID.  All loaded modules are queried,
 * first for information about how the group is authenticated, and then for general information about the group (GID, members,
 * and so on).  If a match is found, information about the group is stored in @ent.
 *
 * Returns: TRUE if the user is found, FALSE if the user is not found.
 **/
gboolean
lu_group_lookup_id(struct lu_context *context, gid_t gid, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_lookup_id, (gpointer)gid, ent, error);
}

/**
 * lu_user_add:
 * @context: A library context.
 * @ent: Information about the user about whom information should be stored in the user information databases.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function adds information about the user given in the @ent structure to the system databases.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
gboolean
lu_user_add(struct lu_context *context, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_add, NULL, ent, error);
}

/**
 * lu_group_add:
 * @context: A library context.
 * @ent: Information about the group about which information should be stored in the group information databases.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function adds information about the group given in the @ent structure to the system databases.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
gboolean
lu_group_add(struct lu_context *context, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_add, NULL, ent, error);
}

/**
 * lu_user_modify:
 * @context: A library context.
 * @ent: Information about the user about whom information should be modified in the user information databases.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function modifies information about the user given in the @ent structure in the system databases so that they match
 * the data stored in the structure.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
gboolean
lu_user_modify(struct lu_context *context, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_mod, NULL, ent, error);
}

/**
 * lu_group_modify:
 * @context: A library context.
 * @ent: Information about the group about which information should be modified in the group information databases.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function modifies information about the group given in the @ent structure in the system databases so that they match
 * the data stored in the structure.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
gboolean
lu_group_modify(struct lu_context *context, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_mod, NULL, ent, error);
}

/**
 * lu_user_delete:
 * @context: A library context.
 * @ent: Information about the user about whom information should be removed from the user information databases.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function removes information about the user given in the @ent structure from the system databases.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
gboolean
lu_user_delete(struct lu_context *context, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_del, NULL, ent, error);
}

/**
 * lu_group_delete:
 * @context: A library context.
 * @ent: Information about the group about which information should be removed from the group information databases.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function removes information about the group given in the @ent structure from the system databases.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
gboolean
lu_group_delete(struct lu_context *context, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_del, NULL, ent, error);
}

/**
 * lu_user_lock:
 * @context: A library context.
 * @ent: A structure containing information describing the user whose account should be locked.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function disables access to the given account without removing it from the system database.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
gboolean
lu_user_lock(struct lu_context *context, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_lock, NULL, ent, error);
}

/**
 * lu_user_unlock:
 * @context: A library context.
 * @ent: A structure describing the user account which should be unlocked.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function can be used to undo the effects of the lu_user_lock() function.  Access to the account will be made again
 * possible.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
gboolean
lu_user_unlock(struct lu_context *context, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_unlock, NULL, ent, error);
}

gboolean
lu_user_islocked(struct lu_context *context, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_islocked, NULL, ent, error);
}

/**
 * lu_user_setpass:
 * @context: A library context.
 * @ent: A structure describing the user account which should have its password changed.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function can be used to set or reset the password on a user account.  It may use the default prompter, or a prompter
 * function which the calling application has specified when calling lu_start() or lu_set_prompter().
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
gboolean
lu_user_setpass(struct lu_context *context, struct lu_ent *ent, const char *password, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_setpass, password, ent, error);
}

/**
 * lu_group_lock:
 * @context: A library context.
 * @ent: A structure containing information describing the group account which should be locked.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function disables access to the given group account without removing it from the system database.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
gboolean
lu_group_lock(struct lu_context *context, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_lock, NULL, ent, error);
}

/**
 * lu_group_unlock:
 * @context: A library context.
 * @ent: A structure describing the group account which should be unlocked.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function can be used to undo the effects of the lu_group_lock() function.  Access to the account will be made again
 * possible.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
gboolean
lu_group_unlock(struct lu_context *context, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_unlock, NULL, ent, error);
}

gboolean
lu_group_islocked(struct lu_context *context, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_islocked, NULL, ent, error);
}

/**
 * lu_group_setpass:
 * @context: A library context.
 * @ent: A structure describing the group account which should have its password changed.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * This function can be used to set or reset the password on a group account.  It may use the default prompter, or a prompter
 * function which the calling application has specified when calling lu_start() or lu_set_prompter().  Note that whether or not
 * group passwords are supported at all depends entirely on which authentication modules are being used.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
gboolean
lu_group_setpass(struct lu_context *context, struct lu_ent *ent, const char *password, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_setpass, password, ent, error);
}

struct enumerate_data {
	GList *list;
	const char *pattern;
	struct lu_error **error;
};

static void
lu_enumerate_users(gpointer key, gpointer value, gpointer data)
{
	struct lu_module *mod = (struct lu_module *)value;
	struct enumerate_data *en = (struct enumerate_data*) data;
	if((en->error == NULL) || (*(en->error) == NULL))
	en->list = g_list_concat(en->list, mod->users_enumerate(mod, en->pattern, en->error));
}

static void
lu_enumerate_groups(gpointer key, gpointer value, gpointer data)
{
	struct lu_module *mod = (struct lu_module *)value;
	struct enumerate_data *en = (struct enumerate_data*) data;
	if((en->error == NULL) || (*(en->error) == NULL))
	en->list = g_list_concat(en->list, mod->groups_enumerate(mod, en->pattern, en->error));
}

static GList *
lu_enumerate(struct lu_context *context, enum lu_type type, const char *pattern, const char *module, struct lu_error **error)
{
	struct enumerate_data data;
	struct lu_module *mod;
	char *module_rw;

	LU_ERROR_CHECK(error);

	g_assert((type == lu_user) || (type == lu_group));

	data.list = NULL;
	data.pattern = pattern ?: "*";
	data.error = error;

	if(module) {
		module_rw = g_strdup(module);
		mod = g_hash_table_lookup(context->modules, module);
		if(mod != NULL) {
			if(type == lu_user) {
				lu_enumerate_users(module_rw, mod, &data);
			} else {
				lu_enumerate_groups(module_rw, mod, &data);
			}
		}
		g_free(module_rw);
	} else {
		if(type == lu_user) {
			g_hash_table_foreach(context->modules, lu_enumerate_users, &data);
		} else {
			g_hash_table_foreach(context->modules, lu_enumerate_groups, &data);
		}
	}
	return data.list;
}

/**
 * lu_users_enumerate:
 * @context: A library context.
 * @pattern: A glob-style pattern which the library will match user names against before returning them.
 * @module: The name of a module which will be queried specifically.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * The lu_users_enumerate() function will query loaded modules for a list of users who match the given @pattern and return
 * the answers as a #GList.
 *
 * Returns: A #GList which must be freed by calling g_list_free().
 **/
GList *
lu_users_enumerate(struct lu_context *context, const char *pattern, const char *module, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_enumerate(context, lu_user, pattern, module, error);
}

/**
 * lu_groups_enumerate:
 * @context: A library context.
 * @pattern: A glob-style pattern which the library will match group names against before returning them.
 * @module: The name of a module which will be queried specifically.
 * @error: A pointer to a pointer to an #lu_error_t structure to hold information about any errors which might occur.
 *
 * The lu_groups_enumerate() function will query loaded modules for a list of groups who match the given @pattern and return
 * the answers as a #GList.
 *
 * Returns: A #GList which must be freed by calling g_list_free().
 */
GList *
lu_groups_enumerate(struct lu_context *context, const char *pattern, const char *module, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_enumerate(context, lu_group, pattern, module, error);
}
