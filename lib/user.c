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
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/libuser/user_private.h"
#include "misc.h"
#include "modules.h"
#include "util.h"

#define INVALID (-0x80000000)

enum lu_dispatch_id {
	uses_elevated_privileges = 0x0003,
	user_lookup_name,
	user_lookup_id,
	user_add,
	user_add_prep,
	user_mod,
	user_del,
	user_lock,
	user_unlock,
	user_is_locked,
	user_setpass,
	users_enumerate,
	users_enumerate_by_group,
	users_enumerate_full,
	users_enumerate_by_group_full,
	group_lookup_name,
	group_lookup_id,
	group_add,
	group_add_prep,
	group_mod,
	group_del,
	group_lock,
	group_unlock,
	group_is_locked,
	group_setpass,
	groups_enumerate,
	groups_enumerate_full,
	groups_enumerate_by_user,
	groups_enumerate_by_user_full,
};

struct lu_context *
lu_start(const char *auth_name, enum lu_entity_type auth_type,
	 const char *modules, const char *create_modules,
	 lu_prompt_fn *prompter, gpointer prompter_data,
	 struct lu_error **error)
{
	struct lu_context *ctx = NULL;

	LU_ERROR_CHECK(error);

	/* Register our message domain with gettext. */
	bindtextdomain(PACKAGE, LOCALEDIR);

	/* Initialize the gtype system if it's not already initialized. */
	g_type_init();

	/* Allocate space for the context. */
	ctx = g_malloc0(sizeof(struct lu_context));

	/* Create a configuration structure. */
	if (lu_cfg_init(ctx, error) == FALSE) {
		/* If there's an error, lu_cfg_init() sets it. */
		g_free(ctx);
		return NULL;
	}

	/* Initialize the rest of the fields. */
	ctx->scache = lu_string_cache_new(TRUE);

	ctx->auth_name = ctx->scache->cache(ctx->scache, auth_name);
	ctx->auth_type = auth_type;

	ctx->prompter = prompter;
	ctx->prompter_data = prompter_data;

	ctx->modules = g_tree_new(lu_strcasecmp);

	/* Read the list of default modules, if the application didn't specify
	 * any that we should be using. */
	if (modules == NULL) {
		modules = lu_cfg_read_single(ctx, "defaults/modules",
					     "files shadow");
	}
	if (create_modules == NULL) {
		create_modules = lu_cfg_read_single(ctx, "defaults/modules",
						    "files shadow");
	}

	/* Load the modules. */
	if (!lu_modules_load(ctx, modules, &ctx->module_names, error)) {
		/* lu_module_load sets errors */
		g_free(ctx);
		return NULL;
	}
	if (!lu_modules_load(ctx, create_modules, &ctx->create_module_names,
			     error)) {
		/* lu_module_load sets errors */
		g_free(ctx);
		return NULL;
	}

	return ctx;
}

void
lu_end(struct lu_context *context)
{
	g_assert(context != NULL);

	if (context->modules != NULL) {
		g_tree_foreach(context->modules, lu_module_unload, NULL);
		g_tree_destroy(context->modules);
	}

	lu_cfg_done(context);

	if (context->scache != NULL) {
		context->scache->free(context->scache);
	}

	memset(context, 0, sizeof(struct lu_context));

	g_free(context);
}

static const char *
extract_name(struct lu_ent *ent)
{
	GValueArray *array;
	GValue *value;
	g_return_val_if_fail(ent != NULL, NULL);
	array = lu_ent_get(ent,
			   ent->type == lu_user ? LU_USERNAME : LU_GROUPNAME);
	g_return_val_if_fail(array != NULL, NULL);
	value = g_value_array_get_nth(array, 0);
	g_return_val_if_fail(value != NULL, NULL);
	return g_value_get_string(value);
}

static long
extract_id(struct lu_ent *ent)
{
	GValueArray *array;
	GValue *value;
	const char *idstring;
	char *p;
	long ret;
	g_return_val_if_fail(ent != NULL, INVALID);
	array = lu_ent_get(ent,
			   ent->type == lu_user ? LU_UIDNUMBER : LU_GIDNUMBER);
	g_return_val_if_fail(array != NULL, INVALID);
	value = g_value_array_get_nth(array, 0);
	g_return_val_if_fail(value != NULL, INVALID);
	ret = INVALID;
	if (G_VALUE_HOLDS_LONG(value)) {
		ret = g_value_get_long(value);
	} else
	if (G_VALUE_HOLDS_STRING(value)) {
		idstring = g_value_get_string(value);
		ret = strtol(idstring, &p, 0);
		if ((p == NULL) || (*p != '\0')) {
			ret = INVALID;
		}
	}
	return ret;
}

static long
convert_user_name_to_id(struct lu_context *context, const char *sdata)
{
	struct lu_ent *ent;
	long ret = INVALID;
	char buf[LINE_MAX * 4];
	struct passwd *err, passwd;
	struct lu_error *error = NULL;
	if ((getpwnam_r(sdata, &passwd, buf, sizeof(buf), &err) == 0) &&
	    (err == &passwd)) {
		ret = passwd.pw_uid;
		return ret;
	}
	ent = lu_ent_new();
	if (lu_user_lookup_name(context, sdata, ent, &error) == TRUE) {
		ret = extract_id(ent);
	}
	lu_ent_free(ent);
	return ret;
}

static long
convert_group_name_to_id(struct lu_context *context, const char *sdata)
{
	struct lu_ent *ent;
	long ret = INVALID;
	char buf[LINE_MAX * 4];
	struct group *err, group;
	struct lu_error *error = NULL;
	if ((getgrnam_r(sdata, &group, buf, sizeof(buf), &err) == 0) &&
	    (err == &group)) {
		ret = group.gr_gid;
		return ret;
	}
	ent = lu_ent_new();
	if (lu_group_lookup_name(context, sdata, ent, &error) == TRUE) {
		ret = extract_id(ent);
	}
	lu_ent_free(ent);
	return ret;
}

static gboolean
run_single(struct lu_context *context,
	   struct lu_module *module,
	   enum lu_dispatch_id id,
	   const char *sdata, long ldata,
	   struct lu_ent *entity,
	   gpointer *ret,
	   struct lu_error **error)
{
	g_assert(context != NULL);
	g_assert(module != NULL);

	LU_ERROR_CHECK(error);

	switch (id) {
	case user_lookup_name:
		g_return_val_if_fail(sdata != NULL, FALSE);
		g_return_val_if_fail(strlen(sdata) > 0, FALSE);
		g_return_val_if_fail(entity != NULL, FALSE);
		if (module->user_lookup_name(module, sdata, entity, error)) {
			lu_ent_add_module(entity, module->name);
			return TRUE;
		}
		return FALSE;
	case user_lookup_id:
		g_return_val_if_fail(entity != NULL, FALSE);
		if (module->user_lookup_id(module, ldata, entity, error)) {
			lu_ent_add_module(entity, module->name);
			return TRUE;
		}
		return FALSE;
	case user_add:
		g_return_val_if_fail(entity != NULL, FALSE);
		if (module->user_add(module, entity, error)) {
			lu_ent_add_module(entity, module->name);
			return TRUE;
		}
		return FALSE;
	case user_add_prep:
		g_return_val_if_fail(entity != NULL, FALSE);
		if (module->user_add_prep(module, entity, error)) {
			lu_ent_add_module(entity, module->name);
			return TRUE;
		}
		return FALSE;
	case user_mod:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->user_mod(module, entity, error);
	case user_del:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->user_del(module, entity, error);
	case user_lock:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->user_lock(module, entity, error);
	case user_unlock:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->user_unlock(module, entity, error);
	case user_is_locked:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->user_is_locked(module, entity, error);
	case user_setpass:
		g_return_val_if_fail(entity != NULL, FALSE);
		g_return_val_if_fail(sdata != NULL, FALSE);
		return module->user_setpass(module, entity, sdata, error);
	case users_enumerate:
		g_return_val_if_fail(ret != NULL, FALSE);
		*ret = module->users_enumerate(module, sdata, error);
		return TRUE;
	case users_enumerate_by_group:
		g_return_val_if_fail(sdata != NULL, FALSE);
		g_return_val_if_fail(strlen(sdata) > 0, FALSE);
		g_return_val_if_fail(ret != NULL, FALSE);
		*ret = module->users_enumerate_by_group(module,
							sdata,
							ldata,
							error);
		return TRUE;
	case users_enumerate_full:
		g_return_val_if_fail(ret != NULL, FALSE);
		*ret = module->users_enumerate_full(module, sdata, error);
		return TRUE;
	case users_enumerate_by_group_full:
		g_return_val_if_fail(sdata != NULL, FALSE);
		g_return_val_if_fail(strlen(sdata) > 0, FALSE);
		g_return_val_if_fail(ret != NULL, FALSE);
		*ret = module->users_enumerate_by_group_full(module,
							     sdata,
							     ldata,
							     error);
		return TRUE;
	case group_lookup_name:
		g_return_val_if_fail(sdata != NULL, FALSE);
		g_return_val_if_fail(strlen(sdata) > 0, FALSE);
		g_return_val_if_fail(entity != NULL, FALSE);
		if (module->group_lookup_name(module, sdata, entity, error)) {
			lu_ent_add_module(entity, module->name);
			return TRUE;
		}
		return FALSE;
	case group_lookup_id:
		g_return_val_if_fail(entity != NULL, FALSE);
		if (module->group_lookup_id(module, ldata, entity, error)) {
			lu_ent_add_module(entity, module->name);
			return TRUE;
		}
		return FALSE;
	case group_add:
		g_return_val_if_fail(entity != NULL, FALSE);
		if (module->group_add(module, entity, error)) {
			lu_ent_add_module(entity, module->name);
			return TRUE;
		}
		return FALSE;
	case group_add_prep:
		g_return_val_if_fail(entity != NULL, FALSE);
		if (module->group_add_prep(module, entity, error)) {
			lu_ent_add_module(entity, module->name);
			return TRUE;
		}
		return FALSE;
	case group_mod:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->group_mod(module, entity, error);
	case group_del:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->group_del(module, entity, error);
	case group_lock:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->group_lock(module, entity, error);
	case group_unlock:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->group_unlock(module, entity, error);
	case group_is_locked:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->group_is_locked(module, entity, error);
	case group_setpass:
		g_return_val_if_fail(entity != NULL, FALSE);
		g_return_val_if_fail(sdata != NULL, FALSE);
		return module->group_setpass(module, entity,
					     sdata, error);
	case groups_enumerate:
		g_return_val_if_fail(ret != NULL, FALSE);
		*ret = module->groups_enumerate(module, sdata, error);
		return TRUE;
	case groups_enumerate_by_user:
		g_return_val_if_fail(sdata != NULL, FALSE);
		g_return_val_if_fail(strlen(sdata) > 0, FALSE);
		g_return_val_if_fail(ret != NULL, FALSE);
		*ret = module->groups_enumerate_by_user(module,
							sdata,
							ldata,
							error);
		return TRUE;
	case groups_enumerate_full:
		g_return_val_if_fail(ret != NULL, FALSE);
		*ret = module->groups_enumerate_full(module, sdata, error);
		return TRUE;
	case groups_enumerate_by_user_full:
		g_return_val_if_fail(sdata != NULL, FALSE);
		g_return_val_if_fail(strlen(sdata) > 0, FALSE);
		g_return_val_if_fail(ret != NULL, FALSE);
		*ret = module->groups_enumerate_by_user_full(module,
							     sdata,
							     ldata,
							     error);
		return TRUE;
	case uses_elevated_privileges:
		return module->uses_elevated_privileges(module);
	default:
		g_assert(0);	/* not reached */
	}
	return FALSE;
}

static gboolean
logic_and(gboolean a, gboolean b)
{
	return a && b;
}

static gboolean
logic_or(gboolean a, gboolean b)
{
	return a || b;
}

static void
remove_duplicate_values(GValueArray *array)
{
	int i, j;
	GValue *ivalue, *jvalue;
	gboolean same;
	for (i = 0; i < array->n_values; i++) {
		ivalue = g_value_array_get_nth(array, i);
		for (j = i + 1; j < array->n_values; j++) {
			jvalue = g_value_array_get_nth(array, j);
			if (G_VALUE_TYPE(ivalue) == G_VALUE_TYPE(jvalue)) {
				same = FALSE;
				switch (G_VALUE_TYPE(ivalue)) {
				case G_TYPE_LONG:
					same =
						g_value_get_long(ivalue) ==
						g_value_get_long(jvalue);
					break;
				case G_TYPE_STRING:
					same =
						g_quark_from_string(g_value_get_string(ivalue)) ==
						g_quark_from_string(g_value_get_string(jvalue));
					break;
				}
				if (same) {
					g_value_array_remove(array, j);
					j--;
					continue;
				}
			}
		}
	}
}

static gboolean
run_list(struct lu_context *context,
	 GValueArray *list,
	 gboolean (*logic_function)(gboolean a, gboolean b),
	 enum lu_dispatch_id id,
	 const char *sdata, long ldata,
	 struct lu_ent *entity,
	 gpointer *ret,
	 struct lu_error **error)
{
	struct lu_module *module;
	GPtrArray *ptr_array = NULL, *tmp_ptr_array = NULL;
	GValueArray *value_array = NULL, *tmp_value_array = NULL;
	GValue *value;
	gpointer scratch;
	struct lu_ent *tmp_ent;
	char *name;
	gboolean success, tsuccess;
	int i, j;

	LU_ERROR_CHECK(error);

	g_assert(context != NULL);
	g_assert(context->module_names != NULL);
	g_assert(context->modules != NULL);
	g_assert(entity != NULL);
	g_assert(logic_function != NULL);
	g_assert((id == user_lookup_name) ||
		 (id == user_lookup_id) ||
		 (id == user_add_prep) ||
		 (id == user_add) ||
		 (id == user_mod) ||
		 (id == user_del) ||
		 (id == user_lock) ||
		 (id == user_unlock) ||
		 (id == user_is_locked) ||
		 (id == users_enumerate) ||
		 (id == users_enumerate_by_group) ||
		 (id == users_enumerate_full) ||
		 (id == users_enumerate_by_group_full) ||
		 (id == group_lookup_name) ||
		 (id == group_lookup_id) ||
		 (id == group_add_prep) ||
		 (id == group_add) ||
		 (id == group_mod) ||
		 (id == group_del) ||
		 (id == group_lock) ||
		 (id == group_unlock) ||
		 (id == group_is_locked) ||
		 (id == users_enumerate) ||
		 (id == groups_enumerate) ||
		 (id == groups_enumerate_by_user) ||
		 (id == groups_enumerate_full) ||
		 (id == groups_enumerate_by_user_full) ||
		 (id == uses_elevated_privileges));

	success = FALSE;
	for (i = 0; i < list->n_values; i++) {
		value = g_value_array_get_nth(list, i);
		name = g_value_dup_string(value);
		module = g_tree_lookup(context->modules, name);
		g_free(name);
		g_assert(module != NULL);
		scratch = NULL;
		tsuccess = run_single(context, module, id,
				      sdata, ldata, entity, &scratch, error);
		if (scratch != NULL) switch (id) {
			case users_enumerate:
			case users_enumerate_by_group:
			case groups_enumerate:
			case groups_enumerate_by_user:
				tmp_value_array = scratch;
				value_array = *ret;
				if (value_array == NULL) {
					value_array = g_value_array_new(0);
				}
				if (tmp_value_array != NULL) {
					for (j = 0; j < tmp_value_array->n_values; j++) {
						value = g_value_array_get_nth(tmp_value_array,
									      j);
						g_value_array_append(value_array,
								     value);
					}
					g_value_array_free(tmp_value_array);
				}
				remove_duplicate_values(value_array);
				*ret = value_array;
				break;
			case users_enumerate_full:
			case users_enumerate_by_group_full:
			case groups_enumerate_full:
			case groups_enumerate_by_user_full:
				tmp_ptr_array = scratch;
				ptr_array = *ret;
				if (ptr_array == NULL) {
					ptr_array = g_ptr_array_new();
				}
				if (tmp_ptr_array != NULL) {
					for (j = 0; j < tmp_ptr_array->len; j++) {
						tmp_ent = g_ptr_array_index(tmp_ptr_array,
									    j);
						g_ptr_array_add(ptr_array, tmp_ent);
					}
					g_ptr_array_free(tmp_ptr_array, TRUE);
				}
				/* remove_duplicate_ptrs(ptr_array); */
				*ret = ptr_array;
				break;
			case user_lookup_name:
			case user_lookup_id:
			case user_add:
			case user_add_prep:
			case user_mod:
			case user_del:
			case group_lookup_name:
			case group_lookup_id:
			case group_add:
			case group_add_prep:
			case group_mod:
			case group_del:
			case uses_elevated_privileges:
				break;
			default:
				g_assert_not_reached();	/* never reached */
				break;
		}
		if (i == 0) {
			success = tsuccess;
		} else {
			success = logic_function(success, tsuccess);
		}
	}

	return success;
}

static gboolean
lu_dispatch(struct lu_context *context,
	    enum lu_dispatch_id id,
	    const char *sdata, long ldata,
	    struct lu_ent *entity,
	    gpointer *ret,
	    struct lu_error **error)
{
	struct lu_ent *tmp = NULL;
	gboolean success;
	GValueArray *values = NULL;
	GPtrArray *ptrs = NULL;
	GValue *value = NULL;
	gpointer scratch = NULL;

	LU_ERROR_CHECK(error);

	g_assert(context != NULL);

	tmp = lu_ent_new();
	if (entity != NULL) {
		lu_ent_copy(entity, tmp);
	}

	success = FALSE;

	switch (id) {
	case user_lookup_id:
	case group_lookup_id:
		/* Make sure data items are right for this call. */
		sdata = NULL;
		g_assert(ldata != INVALID);
		/* Run the list. */
		if (run_list(context, context->module_names,
			    logic_or, id,
			    sdata, ldata, tmp, &scratch, error)) {
			/* Got a match on that ID, convert it to a
			 * name and look it up by name. */
			const char *attr = NULL;
			if (id == user_lookup_id) {
				attr = LU_USERNAME;
				id = user_lookup_name;
			}
			if (id == group_lookup_id) {
				attr = LU_GROUPNAME;
				id = group_lookup_name;
			}
			values = lu_ent_get_current(tmp, attr);
			if ((values != NULL) && (values->n_values > 0)) {
				value = g_value_array_get_nth(values, 0);
				attr = g_value_get_string(value);
				sdata = tmp->cache->cache(tmp->cache, attr);
			} else {
				/* No values for the right attribute. */
				break;
			}
		} else {
			/* No match on that ID. */
			break;
		}
		/* fall through on successful ID->name conversion */
	case user_lookup_name:
	case group_lookup_name:
		/* Make sure data items are right for this call. */
		g_assert(sdata != NULL);
		ldata = INVALID;
		/* Run the list. */
		if (run_list(context, context->module_names,
			    logic_or, id,
			    sdata, ldata, tmp, &scratch, error)) {
			if (entity != NULL) {
				lu_ent_copy(tmp, entity);
				lu_ent_revert(entity);
			}
			success = TRUE;
		}
		break;
	case user_add_prep:
	case group_add_prep:
		/* Make sure we have both name and ID here. */
		sdata = sdata ?: extract_name(tmp);
		ldata = (ldata != INVALID) ? ldata : extract_id(tmp);
		g_return_val_if_fail(sdata != NULL, FALSE);
		g_return_val_if_fail(ldata != INVALID, FALSE);
		/* Run the checks and preps. */
		if (run_list(context, context->create_module_names,
			    logic_and, id,
			    sdata, ldata, tmp, &scratch, error)) {
			if (entity != NULL) {
				lu_ent_copy(tmp, entity);
			}
			success = TRUE;
		}
		break;
	case user_add:
	case group_add:
		/* Make sure we have both name and ID here. */
		sdata = sdata ?: extract_name(tmp);
		ldata = (ldata != INVALID) ? ldata : extract_id(tmp);
		g_return_val_if_fail(sdata != NULL, FALSE);
		g_return_val_if_fail(ldata != INVALID, FALSE);
		/* Add the account. */
		if (run_list(context, context->create_module_names,
			    logic_and, id,
			    sdata, ldata, tmp, &scratch, error)) {
			if (entity != NULL) {
				lu_ent_copy(tmp, entity);
				lu_ent_commit(entity);
			}
			success = TRUE;
		}
		break;
	case user_mod:
	case user_del:
	case user_lock:
	case user_unlock:
	case user_setpass:
	case group_mod:
	case group_del:
	case group_setpass:
	case group_lock:
	case group_unlock:
		/* Make sure we have both name and ID here. */
		sdata = sdata ?: extract_name(tmp);
		ldata = (ldata != INVALID) ? ldata : extract_id(tmp);
		g_return_val_if_fail(sdata != NULL, FALSE);
		g_return_val_if_fail(ldata != INVALID, FALSE);
		/* Make the changes. */
		g_assert(entity != NULL);
		if (run_list(context, entity->modules,
			    logic_and, id,
			    sdata, ldata, tmp, &scratch, error)) {
			lu_ent_copy(tmp, entity);
			switch (id) {
				case user_mod:
				case group_mod:
					lu_ent_commit(entity);
					break;
				default:
					break;
			}
			success = TRUE;
		}
		break;
	case user_is_locked:
	case group_is_locked:
		/* Make sure we have both name and ID here. */
		sdata = sdata ?: extract_name(tmp);
		ldata = (ldata != INVALID) ? ldata : extract_id(tmp);
		g_return_val_if_fail(sdata != NULL, FALSE);
		g_return_val_if_fail(ldata != INVALID, FALSE);
		/* Run the checks. */
		g_assert(entity != NULL);
		if (run_list(context, entity->modules,
			    logic_or, id,
			    sdata, ldata, tmp, &scratch, error)) {
			lu_ent_copy(tmp, entity);
			success = TRUE;
		}
		break;
	case users_enumerate_by_group:
	case groups_enumerate_by_user:
		/* Make sure we have both name and ID here. */
		g_return_val_if_fail(sdata != NULL, FALSE);
		if (id == users_enumerate_by_group) {
			ldata = convert_group_name_to_id(context, sdata);
		} else
		if (id == groups_enumerate_by_user) {
			ldata = convert_user_name_to_id(context, sdata);
		} else {
			g_assert_not_reached();
		}
		g_return_val_if_fail(ldata != INVALID, FALSE);
		/* fall through */
	case users_enumerate:
	case groups_enumerate:
		/* Get the lists. */
		if (run_list(context, context->module_names,
			    logic_or, id,
			    sdata, ldata, tmp, (gpointer*)&values, error)) {
			*ret = values;
			success = TRUE;
		}
		break;
	case users_enumerate_by_group_full:
	case groups_enumerate_by_user_full:
		/* Make sure we have both name and ID here. */
		g_return_val_if_fail(sdata != NULL, FALSE);
		if (id == users_enumerate_by_group_full) {
			ldata = convert_group_name_to_id(context, sdata);
		} else
		if (id == groups_enumerate_by_user_full) {
			ldata = convert_user_name_to_id(context, sdata);
		} else {
			g_assert_not_reached();
		}
		g_return_val_if_fail(ldata != INVALID, FALSE);
		/* fall through */
	case users_enumerate_full:
	case groups_enumerate_full:
		/* Get the lists. */
		if (run_list(context, context->module_names,
			    logic_or, id,
			    sdata, ldata, tmp, (gpointer*)&ptrs, error)) {
			*ret = ptrs;
			success = TRUE;
		}
		break;
	case uses_elevated_privileges:
		if (run_list(context, context->module_names,
			    logic_or, id,
			    sdata, ldata, tmp, &scratch, error)) {
			success = TRUE;
		}
		break;
	default:
		g_assert(0);	/* not reached */
		break;
	}
	lu_ent_free(tmp);

	if (success) {
		switch (id) {
			case user_lookup_id:
			case user_lookup_name:
				g_assert(entity != NULL);
				entity->type = lu_user;
				break;
			case group_lookup_name:
			case group_lookup_id:
				g_assert(entity != NULL);
				entity->type = lu_group;
				break;
			default:
				break;
		}
	}

	return success;
}

gboolean
lu_uses_elevated_privileges (struct lu_context *context)
{
	struct lu_error *error = NULL;
	gboolean ret = lu_dispatch(context, uses_elevated_privileges, NULL, 0,
				   NULL, NULL, &error);
	if (error != NULL) {
		lu_error_free(&error);
	}
	return ret;
}

gboolean
lu_user_lookup_name(struct lu_context * context, const char *name,
		    struct lu_ent * ent, struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_lookup_name, name, 0,
			   ent, NULL, error);
}

gboolean
lu_group_lookup_name(struct lu_context * context, const char *name,
		     struct lu_ent * ent, struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_lookup_name, name, 0,
			   ent, NULL, error);
}

gboolean
lu_user_lookup_id(struct lu_context * context, uid_t uid,
		  struct lu_ent * ent, struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_lookup_id, NULL, uid,
			   ent, NULL, error);
}

gboolean
lu_group_lookup_id(struct lu_context * context, gid_t gid,
		   struct lu_ent * ent, struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_lookup_id, NULL, gid,
			   ent, NULL, error);
}

gboolean
lu_user_add(struct lu_context * context, struct lu_ent * ent,
	    struct lu_error ** error)
{
	gboolean ret = FALSE;
	LU_ERROR_CHECK(error);
	
	if (lu_dispatch(context, user_add_prep, NULL, INVALID,
			ent, NULL, error)) {
		ret = lu_dispatch(context, user_add, NULL, INVALID,
				  ent, NULL, error);
	}
	return ret;
}

gboolean
lu_group_add(struct lu_context * context, struct lu_ent * ent,
	     struct lu_error ** error)
{
	gboolean ret = FALSE;
	LU_ERROR_CHECK(error);
	if (lu_dispatch(context, group_add_prep, NULL, INVALID,
			ent, NULL, error)) {
		ret = lu_dispatch(context, group_add, NULL, INVALID,
				  ent, NULL, error);
	}
	return ret;
}

gboolean
lu_user_modify(struct lu_context * context, struct lu_ent * ent,
	       struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_mod, NULL, INVALID, ent, NULL, error);
}

gboolean
lu_group_modify(struct lu_context * context, struct lu_ent * ent,
		struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_mod, NULL, INVALID, ent, NULL, error);
}

gboolean
lu_user_delete(struct lu_context * context, struct lu_ent * ent,
	       struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_del, NULL, INVALID, ent, NULL, error);
}

gboolean
lu_group_delete(struct lu_context * context, struct lu_ent * ent,
		struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_del, NULL, INVALID, ent, NULL, error);
}

gboolean
lu_user_lock(struct lu_context * context, struct lu_ent * ent,
	     struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_lock, NULL, INVALID, ent, NULL, error);
}

gboolean
lu_user_unlock(struct lu_context * context, struct lu_ent * ent,
	       struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_unlock, NULL, INVALID,
			   ent, NULL, error);
}

gboolean
lu_user_islocked(struct lu_context * context, struct lu_ent * ent,
		 struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, user_is_locked, NULL, INVALID,
			   ent, NULL, error);
}

gboolean
lu_user_setpass(struct lu_context * context, struct lu_ent * ent,
		const char *password, struct lu_error ** error)
{
	gboolean ret;
	LU_ERROR_CHECK(error);
	ret = lu_dispatch(context, user_setpass, password, INVALID,
			  ent, NULL, error);
	if (ret) {
		GValue value;
		lu_ent_clear(ent, LU_SHADOWLASTCHANGE);
		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_STRING);
		g_value_set_string(&value,
				   lu_util_shadow_current_date(ent->cache));
		lu_ent_add(ent, LU_SHADOWLASTCHANGE, &value);
		g_value_unset(&value);
	}
	return ret;
}

gboolean
lu_group_lock(struct lu_context * context, struct lu_ent * ent,
	      struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_lock, NULL, INVALID,
			   ent, NULL, error);
}

gboolean
lu_group_unlock(struct lu_context * context, struct lu_ent * ent,
		struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_unlock, NULL, INVALID,
			   ent, NULL, error);
}

gboolean
lu_group_islocked(struct lu_context * context, struct lu_ent * ent,
		  struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	return lu_dispatch(context, group_is_locked, NULL, INVALID,
			   ent, NULL, error);
}

gboolean
lu_group_setpass(struct lu_context * context, struct lu_ent * ent,
		 const char *password, struct lu_error ** error)
{
	gboolean ret;
	LU_ERROR_CHECK(error);
	ret = lu_dispatch(context, group_setpass, password, INVALID,
			  ent, NULL, error);
	if (ret) {
		GValue value;
		lu_ent_clear(ent, LU_SHADOWLASTCHANGE);
		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_STRING);
		g_value_set_string(&value,
				   lu_util_shadow_current_date(ent->cache));
		lu_ent_add(ent, LU_SHADOWLASTCHANGE, &value);
		g_value_unset(&value);
	}
	return ret;
}

GValueArray *
lu_users_enumerate(struct lu_context * context, const char *pattern,
		   struct lu_error ** error)
{
	GValueArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, users_enumerate, pattern, INVALID,
		    NULL, (gpointer*)&ret, error);
	return ret;
}

GValueArray *
lu_groups_enumerate(struct lu_context * context, const char *pattern,
		    struct lu_error ** error)
{
	GValueArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, groups_enumerate, pattern, INVALID,
		    NULL, (gpointer*) &ret, error);
	return ret;
}

GValueArray *
lu_users_enumerate_by_group(struct lu_context * context, const char *group,
			    struct lu_error ** error)
{
	GValueArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, users_enumerate_by_group, group, INVALID,
		    NULL, (gpointer*) &ret, error);
	return ret;
}

GValueArray *
lu_groups_enumerate_by_user(struct lu_context * context, const char *user,
			    struct lu_error ** error)
{
	GValueArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, groups_enumerate_by_user, user, INVALID,
		    NULL, (gpointer*) &ret, error);
	return ret;
}

GPtrArray *
lu_users_enumerate_full(struct lu_context * context, const char *pattern,
		        struct lu_error ** error)
{
	GPtrArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, users_enumerate_full, pattern, INVALID,
		    NULL, (gpointer*) &ret, error);
	return ret;
}

GPtrArray *
lu_groups_enumerate_full(struct lu_context * context, const char *pattern,
			 struct lu_error ** error)
{
	GPtrArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, groups_enumerate_full, pattern, INVALID,
		    NULL, (gpointer*) &ret, error);
	return ret;
}

GPtrArray *
lu_users_enumerate_by_group_full(struct lu_context * context,
				 const char *pattern,
				 struct lu_error ** error)
{
	GPtrArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, users_enumerate_by_group_full, pattern, INVALID,
		    NULL, (gpointer*) &ret, error);
	return ret;
}

GPtrArray *
lu_groups_enumerate_by_user_full(struct lu_context * context,
				 const char *pattern,
				 struct lu_error ** error)
{
	GPtrArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, groups_enumerate_by_user_full, pattern, INVALID,
		    NULL, (gpointer*) &ret, error);
	return ret;
}
