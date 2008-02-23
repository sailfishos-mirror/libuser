/* Copyright (C) 2000-2002, 2004, 2005, 2006, 2007 Red Hat, Inc.
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

#include <config.h>
#include <sys/types.h>
#include <errno.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utmp.h>
#include "user_private.h"
#include "internal.h"

#define DEFAULT_ID 500

enum lu_dispatch_id {
	uses_elevated_privileges = 0x0003,
	user_lookup_name,
	user_lookup_id,
	user_default,
	user_add_prep,
	user_add,
	user_mod,
	user_del,
	user_lock,
	user_unlock,
	user_unlock_nonempty,
	user_is_locked,
	user_setpass,
	user_removepass,
	users_enumerate,
	users_enumerate_by_group,
	users_enumerate_full,
	users_enumerate_by_group_full,
	group_lookup_name,
	group_lookup_id,
	group_default,
	group_add_prep,
	group_add,
	group_mod,
	group_del,
	group_lock,
	group_unlock,
	group_unlock_nonempty,
	group_is_locked,
	group_setpass,
	group_removepass,
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
	struct lu_context *ctx;

	LU_ERROR_CHECK(error);

	/* Register our message domain with gettext. */
	bindtextdomain(PACKAGE, LOCALEDIR);

	/* Initialize the gtype system if it's not already initialized. */
	g_type_init();

	/* Allocate space for the context. */
	ctx = g_malloc0(sizeof(struct lu_context));

	ctx->scache = lu_string_cache_new(TRUE);

	/* Create a configuration structure. */
	if (lu_cfg_init(ctx, error) == FALSE)
		/* If there's an error, lu_cfg_init() sets it. */
		goto err_scache;

	ctx->auth_name = ctx->scache->cache(ctx->scache, auth_name);
	ctx->auth_type = auth_type;

	ctx->prompter = prompter;
	ctx->prompter_data = prompter_data;

	ctx->modules = g_tree_new(lu_strcasecmp);

	/* Read the list of default modules, if the application didn't specify
	 * any that we should be using. */
	if (modules == NULL) {
		modules = lu_cfg_read_single(ctx,
					     "defaults/modules",
					     "files shadow");
	}
	if (create_modules == NULL) {
		create_modules = lu_cfg_read_single(ctx,
						    "defaults/create_modules",
						    "files shadow");
	}

	/* Load the modules. */
	if (!lu_modules_load(ctx, modules, &ctx->module_names, error))
		goto err_modules; /* lu_module_load sets errors */
	if (!lu_modules_load(ctx, create_modules, &ctx->create_module_names,
			     error))
		goto err_module_names; /* lu_module_load sets errors */

	return ctx;

err_module_names:
	g_value_array_free(ctx->module_names);
	g_tree_foreach(ctx->modules, lu_module_unload, NULL);
err_modules:
	g_tree_destroy(ctx->modules);
err_scache:
	ctx->scache->free(ctx->scache);
	g_free(ctx);
	return NULL;
}

void
lu_end(struct lu_context *context)
{
	g_assert(context != NULL);

	g_tree_foreach(context->modules, lu_module_unload, NULL);
	g_tree_destroy(context->modules);

	g_value_array_free(context->create_module_names);
	g_value_array_free(context->module_names);

	lu_cfg_done(context);

	context->scache->free(context->scache);

	memset(context, 0, sizeof(struct lu_context));

	g_free(context);
}

static const char *
extract_name(struct lu_ent *ent)
{
	GValueArray *array;
	GValue *value;
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail((ent->type == lu_user) || (ent->type == lu_group), NULL);
	array = lu_ent_get(ent,
			   ent->type == lu_user ? LU_USERNAME : LU_GROUPNAME);
	if (array == NULL) {
		array = lu_ent_get_current(ent,
					   ent->type == lu_user ? LU_USERNAME : LU_GROUPNAME);
		if (array == NULL)
			return NULL;
	}
	value = g_value_array_get_nth(array, 0);
	g_return_val_if_fail(value != NULL, NULL);
	return ent->cache->cache(ent->cache, g_value_get_string(value));
}

static gboolean
lu_name_allowed(struct lu_ent *ent, struct lu_error **error)
{
	const char *sdata;
	size_t len, i;

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail((ent->type == lu_user) || (ent->type == lu_group),
			     FALSE);
	sdata = extract_name(ent);
	if (sdata == NULL) {
		lu_error_new(error, lu_error_name_bad, _("name is not set"));
		return FALSE;
	}
	len = strlen(sdata);
	if (len == 0) {
		lu_error_new(error, lu_error_name_bad, _("name is too short"));
		return FALSE;
	}
	if (len > UT_NAMESIZE - 1) {
		lu_error_new(error, lu_error_name_bad,
			     _("name is too long (%zu > %d)"), len,
			     UT_NAMESIZE - 1);
		return FALSE;
	}
	for (i = 0; sdata[i] != '\0'; i++) {
		if ((sdata[i] & 0x80) != 0) {
			lu_error_new(error, lu_error_name_bad,
				     _("name contains non-ASCII characters"));
			return FALSE;
		}
	}
	for (i = 0; sdata[i] != '\0'; i++) {
		if ((sdata[i] == 0x7f) || (sdata[i] < 0x20)) {
			lu_error_new(error, lu_error_name_bad,
				     _("name contains control characters"));
			return FALSE;
		}
	}
	for (i = 0; sdata[i] != '\0'; i++) {
		if (g_ascii_isspace(sdata[i])) {
			lu_error_new(error, lu_error_name_bad,
				     _("name contains whitespace"));
			return FALSE;
		}
	}
	/* SUSv3 (3.426) says "To be portable across ..., the value is composed
	   of characters from the portable filename character set. The hyphen
	   should not be used as the first character of a portable user name.

	   Note: "the value _is_ composed", not "should be" composed.  We don't
	   have to allow more. */
	if (sdata[0] == '-') {
		lu_error_new(error, lu_error_name_bad,
			     _("name starts with a hyphen"));
		return FALSE;
	}
	for (i = 0; sdata[i] != '\0'; i++) {
		if (!((sdata[i] >= 'a' && sdata[i] <= 'z')
		      || (sdata[i] >= 'A' && sdata[i] <= 'Z')
		      || (sdata[i] >= '0' && sdata[i] <= '9')
		      || sdata[i] == '.' || sdata[i] ==  '-' || sdata[i] == '_'
		      /* Allow trailing $ for samba machine accounts. */
		      || (sdata[i] == '$' && sdata[i + 1] == '\0'))) {
			lu_error_new(error, lu_error_name_bad,
				     _("name contains invalid char `%c'"),
				     sdata[i]);
			return FALSE;
		}
	}
	return TRUE;
}

static id_t
extract_id(struct lu_ent *ent)
{
	GValueArray *array;
	GValue *value;

	g_return_val_if_fail(ent != NULL, LU_VALUE_INVALID_ID);
	g_return_val_if_fail((ent->type == lu_user) || (ent->type == lu_group),
			     LU_VALUE_INVALID_ID);
	array = lu_ent_get(ent,
			   ent->type == lu_user ? LU_UIDNUMBER : LU_GIDNUMBER);
	if (array == NULL) {
		array = lu_ent_get_current(ent,
					   ent->type == lu_user ? LU_UIDNUMBER : LU_GIDNUMBER);
		if (array == NULL)
			return LU_VALUE_INVALID_ID;
	}
	value = g_value_array_get_nth(array, 0);
	g_return_val_if_fail(value != NULL, LU_VALUE_INVALID_ID);
	return lu_value_get_id(value);
}

static uid_t
convert_user_name_to_id(struct lu_context *context, const char *sdata,
			struct lu_error **error)
{
	struct lu_ent *ent;
	uid_t ret = LU_VALUE_INVALID_ID;
	char buf[LINE_MAX * 4];
	struct passwd *err, passwd;

	if ((getpwnam_r(sdata, &passwd, buf, sizeof(buf), &err) == 0) &&
	    (err == &passwd))
		return passwd.pw_uid;
	ent = lu_ent_new();
	if (lu_user_lookup_name(context, sdata, ent, error) == TRUE) {
		ret = extract_id(ent);
		if (ret == LU_VALUE_INVALID_ID)
			lu_error_new(error, lu_error_generic,
				     _("user %s has no UID"), sdata);
	}
	lu_ent_free(ent);
	return ret;
}

static gid_t
convert_group_name_to_id(struct lu_context *context, const char *sdata,
			 struct lu_error **error)
{
	struct lu_ent *ent;
	gid_t ret = LU_VALUE_INVALID_ID;
	char buf[LINE_MAX * 4];
	struct group *err, group;

	if ((getgrnam_r(sdata, &group, buf, sizeof(buf), &err) == 0) &&
	    (err == &group))
		return group.gr_gid;
	ent = lu_ent_new();
	if (lu_group_lookup_name(context, sdata, ent, error) == TRUE) {
		ret = extract_id(ent);
		if (ret == LU_VALUE_INVALID_ID)
			lu_error_new(error, lu_error_generic,
				     _("group %s has no GID"), sdata);
	}
	lu_ent_free(ent);
	return ret;
}

static gboolean ent_has_name_and_id(struct lu_ent *ent,
				    struct lu_error **error)
{
	const char *name;
	id_t id;

	g_return_val_if_fail(ent->type == lu_user || ent->type == lu_group,
			     FALSE);
	name = extract_name(ent);
	id = extract_id(ent);
	if (name != NULL && id != LU_VALUE_INVALID_ID)
		return TRUE;
	if (id != LU_VALUE_INVALID_ID)
		lu_error_new(error, lu_error_generic,
			     ent->type == lu_user ? _("user %jd has no name")
			     : _("group %jd has no name"),
			     (intmax_t)id);
	else if (name != NULL)
		lu_error_new(error, lu_error_generic, ent->type == lu_user
			     ? _("user %s has no UID")
			     : _("group %s has no GID"), name);
	else
		lu_error_new(error, lu_error_generic, ent->type == lu_user
			     ? _("user has neither a name nor an UID")
			     : _("group has neither a name nor a GID"));
	return FALSE;
}

static gboolean lu_refresh_int(struct lu_context *context,
			       struct lu_ent *entity,
			       struct lu_error **error);

static gboolean
lu_refresh_user(struct lu_context *context, struct lu_ent *entity,
		struct lu_error **error)
{
	g_return_val_if_fail(entity->type == lu_user, FALSE);
	return lu_refresh_int(context, entity, error);
}

static gboolean
lu_refresh_group(struct lu_context *context, struct lu_ent *entity,
		 struct lu_error **error)
{
	g_return_val_if_fail(entity->type == lu_group, FALSE);
	return lu_refresh_int(context, entity, error);
}

static gboolean
run_single(struct lu_context *context,
	   struct lu_module *module,
	   enum lu_dispatch_id id,
	   const char *sdata, id_t ldata,
	   struct lu_ent *entity,
	   gpointer *ret,
	   struct lu_error **error)
{
	GPtrArray *ptrs;
	size_t i;

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
	case user_default:
		g_return_val_if_fail(entity != NULL, FALSE);
		if (module->user_default(module, sdata, ldata, entity, error)) {
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
		if (lu_name_allowed(entity, error) == FALSE) {
			return FALSE;
		} else if (module->user_add_prep(module, entity, error)) {
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
	case user_unlock_nonempty:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->user_unlock_nonempty(module, entity, error);
	case user_is_locked:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->user_is_locked(module, entity, error);
	case user_setpass:
		g_return_val_if_fail(entity != NULL, FALSE);
		g_return_val_if_fail(sdata != NULL, FALSE);
		return module->user_setpass(module, entity, sdata, error);
	case user_removepass:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->user_removepass(module, entity, error);
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
		if (*ret) {
			ptrs = *ret;
			for (i = 0; i < ptrs->len; i++) {
				lu_ent_add_module(g_ptr_array_index(ptrs, i),
						  module->name);
			}
		}
		return TRUE;
	case users_enumerate_by_group_full:
		g_return_val_if_fail(sdata != NULL, FALSE);
		g_return_val_if_fail(strlen(sdata) > 0, FALSE);
		g_return_val_if_fail(ret != NULL, FALSE);
		*ret = module->users_enumerate_by_group_full(module,
							     sdata,
							     ldata,
							     error);
		if (*ret) {
			ptrs = *ret;
			for (i = 0; i < ptrs->len; i++) {
				lu_ent_add_module(g_ptr_array_index(ptrs, i),
						  module->name);
			}
		}
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
	case group_default:
		g_return_val_if_fail(entity != NULL, FALSE);
		if (module->group_default(module, sdata, ldata, entity, error)) {
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
		if (lu_name_allowed(entity, error) == FALSE) {
			return FALSE;
		} else if (module->group_add_prep(module, entity, error)) {
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
	case group_unlock_nonempty:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->group_unlock_nonempty(module, entity, error);
	case group_is_locked:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->group_is_locked(module, entity, error);
	case group_setpass:
		g_return_val_if_fail(entity != NULL, FALSE);
		g_return_val_if_fail(sdata != NULL, FALSE);
		return module->group_setpass(module, entity, sdata, error);
	case group_removepass:
		g_return_val_if_fail(entity != NULL, FALSE);
		return module->group_removepass(module, entity, error);
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
		if (*ret) {
			ptrs = *ret;
			for (i = 0; i < ptrs->len; i++) {
				lu_ent_add_module(g_ptr_array_index(ptrs, i),
						  module->name);
			}
		}
		return TRUE;
	case groups_enumerate_by_user_full:
		g_return_val_if_fail(sdata != NULL, FALSE);
		g_return_val_if_fail(strlen(sdata) > 0, FALSE);
		g_return_val_if_fail(ret != NULL, FALSE);
		*ret = module->groups_enumerate_by_user_full(module,
							     sdata,
							     ldata,
							     error);
		if (*ret) {
			ptrs = *ret;
			for (i = 0; i < ptrs->len; i++) {
				lu_ent_add_module(g_ptr_array_index(ptrs, i),
						  module->name);
			}
		}
		return TRUE;
	case uses_elevated_privileges:
		return module->uses_elevated_privileges(module);
	default:
		g_assert_not_reached();	/* not reached */
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
	size_t i;

	for (i = 0; i < array->n_values; i++) {
		size_t j;
		GValue *ivalue;

		ivalue = g_value_array_get_nth(array, i);
		for (j = i + 1; j < array->n_values; j++) {
			GValue *jvalue;

			jvalue = g_value_array_get_nth(array, j);
			if (G_VALUE_TYPE(ivalue) == G_VALUE_TYPE(jvalue)
			    && lu_values_equal(ivalue, jvalue)) {
				g_value_array_remove(array, j);
				j--;
			}
		}
	}
}

static int
compare_strings(gconstpointer a, gconstpointer b, gpointer data)
{
	(void)data;
	return strcmp(a, b);
}

static GPtrArray *
merge_ent_array_duplicates(GPtrArray *array)
{
	GPtrArray *ret;
	size_t i;
	GTree *users, *groups;

	g_return_val_if_fail(array != NULL, NULL);
	users = g_tree_new_full(compare_strings, NULL, g_free, NULL);
	groups = g_tree_new_full(compare_strings, NULL, g_free, NULL);
	/* A structure to hold the new list. */
	ret = g_ptr_array_new();
	/* Iterate over every entity in the incoming list. */
	for (i = 0; i < array->len; i++) {
		struct lu_ent *current, *saved;
		char *key;
		GValueArray *values;
		GValue *value;
		GTree *tree;

		current = g_ptr_array_index(array, i);
		key = NULL;
		values = NULL;
		tree = NULL;
		/* Get the name of the user or group. */
		if (current->type == lu_user) {
			values = lu_ent_get(current, LU_USERNAME);
			tree = users;
		} else if (current->type == lu_group) {
			values = lu_ent_get(current, LU_GROUPNAME);
			tree = groups;
		} else {
			g_warning("Unknown entity(%zu) type: %d.\n",
				  i, current->type);
			g_assert_not_reached();
		}
		value = g_value_array_get_nth(values, 0);
		key = lu_value_strdup(value);
		/* Check if there's already an entity with that name. */
		saved = g_tree_lookup(tree, key);
		/* If it's not in there, add this one. */
		if (saved == NULL) {
			g_tree_insert(tree, key, current);
			g_ptr_array_add(ret, current);
		} else {
			GList *attributes, *list;
			const char *attr;
			size_t j;

			g_free (key);
			/* Merge all of its data into the existing one; first,
			 * the current data. */
			attributes = lu_ent_get_attributes_current(current);
			list = attributes;
			while (attributes != NULL) {
				attr = (const char *)attributes->data;
				values = lu_ent_get_current(current, attr);
				for (j = 0; j < values->n_values; j++) {
					value = g_value_array_get_nth(values,
								      j);
					lu_ent_add_current(saved, attr, value);
				}
				attributes = g_list_next(attributes);
			}
			g_list_free(list);
			/* Merge the pending data. */
			attributes = lu_ent_get_attributes(current);
			list = attributes;
			while (attributes != NULL) {
				attr = (const char *)attributes->data;
				values = lu_ent_get(current, attr);
				for (j = 0; j < values->n_values; j++) {
					value = g_value_array_get_nth(values,
								      j);
					lu_ent_add(saved, attr, value);
				}
				attributes = g_list_next(attributes);
			}
			g_list_free(list);
			/* Now merge the entity's list of modules. */
			for (j = 0; j < current->modules->n_values; j++) {
				value = g_value_array_get_nth(current->modules,
							      j);
				g_value_array_append(saved->modules, value);
			}
			remove_duplicate_values(saved->modules);
			lu_ent_free(current);
		}
	}
	g_tree_destroy(users);
	g_tree_destroy(groups);
	g_ptr_array_free(array, TRUE);
	return ret;
}

static gboolean
run_list(struct lu_context *context,
	 GValueArray *list,
	 gboolean (*logic_function)(gboolean a, gboolean b),
	 enum lu_dispatch_id id,
	 const char *sdata, id_t ldata,
	 struct lu_ent *entity,
	 gpointer ret,
	 struct lu_error **firsterror)
{
	gboolean success;
	struct lu_error *lasterror = NULL;
	size_t i;

	LU_ERROR_CHECK(firsterror);

	g_assert(context != NULL);
	g_assert(context->module_names != NULL);
	g_assert(context->modules != NULL);
	g_assert(entity != NULL);
	g_assert(logic_function != NULL);
	g_assert((id == user_lookup_name) ||
		 (id == user_lookup_id) ||
		 (id == user_default) ||
		 (id == user_add_prep) ||
		 (id == user_add) ||
		 (id == user_mod) ||
		 (id == user_del) ||
		 (id == user_lock) ||
		 (id == user_unlock) ||
		 (id == user_unlock_nonempty) ||
		 (id == user_is_locked) ||
		 (id == user_setpass) ||
		 (id == user_removepass) ||
		 (id == users_enumerate) ||
		 (id == users_enumerate_by_group) ||
		 (id == users_enumerate_full) ||
		 (id == users_enumerate_by_group_full) ||
		 (id == group_lookup_name) ||
		 (id == group_lookup_id) ||
		 (id == group_default) ||
		 (id == group_add_prep) ||
		 (id == group_add) ||
		 (id == group_mod) ||
		 (id == group_del) ||
		 (id == group_lock) ||
		 (id == group_unlock) ||
		 (id == group_unlock_nonempty) ||
		 (id == group_is_locked) ||
		 (id == group_setpass) ||
		 (id == group_removepass) ||
		 (id == groups_enumerate) ||
		 (id == groups_enumerate_by_user) ||
		 (id == groups_enumerate_full) ||
		 (id == groups_enumerate_by_user_full) ||
		 (id == uses_elevated_privileges));

	success = FALSE;
	for (i = 0; i < list->n_values; i++) {
		struct lu_module *module;
		gpointer scratch;
		GValue *value;
		gboolean tsuccess;

		value = g_value_array_get_nth(list, i);
		module = g_tree_lookup(context->modules,
				       g_value_get_string(value));
		g_assert(module != NULL);
		scratch = NULL;
		tsuccess = run_single(context, module, id,
				      sdata, ldata, entity, &scratch,
				      &lasterror);
		if (scratch != NULL) switch (id) {
			GPtrArray *ptr_array, *tmp_ptr_array;
			GValueArray *value_array, *tmp_value_array;
			size_t j;

			case users_enumerate:
			case users_enumerate_by_group:
			case groups_enumerate:
			case groups_enumerate_by_user:
				tmp_value_array = scratch;
				value_array = *(GValueArray **)ret;
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
				*(GValueArray **)ret = value_array;
				break;
			case users_enumerate_full:
			case users_enumerate_by_group_full:
			case groups_enumerate_full:
			case groups_enumerate_by_user_full:
				/* FIXME: do some kind of merging here. */
				tmp_ptr_array = scratch;
				ptr_array = *(GPtrArray **)ret;
				if (ptr_array == NULL) {
					ptr_array = g_ptr_array_new();
				}
				if (tmp_ptr_array != NULL) {
					for (j = 0; j < tmp_ptr_array->len; j++) {
						struct lu_ent *tmp_ent;

						tmp_ent = g_ptr_array_index(tmp_ptr_array,
									    j);
						g_ptr_array_add(ptr_array, tmp_ent);
					}
					g_ptr_array_free(tmp_ptr_array, TRUE);
				}
				/* remove_duplicate_ptrs(ptr_array); */
				*(GPtrArray **)ret = ptr_array;
				break;
			case user_lookup_name:
			case user_lookup_id:
			case user_default:
			case user_add_prep:
			case user_add:
			case user_mod:
			case user_del:
			case group_lookup_name:
			case group_lookup_id:
			case group_default:
			case group_add_prep:
			case group_add:
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
		if (firsterror != NULL) {
			if (*firsterror == NULL) {
				/* Make this the error we report. */
				*firsterror = lasterror;
				lasterror = NULL;
			} else {
				/* Already have an error, discard. */
				if (lasterror != NULL) {
					lu_error_free(&lasterror);
				}
			}
		} else {
			/* Can't report this error. */
			if (lasterror != NULL) {
				lu_error_free(&lasterror);
			}
		}
	}

	return success;
}

static gboolean
lu_refresh_int(struct lu_context *context, struct lu_ent *entity,
	       struct lu_error **error)
{
	enum lu_dispatch_id id = 0;
	const char *sdata;
	gpointer scratch = NULL;
	g_return_val_if_fail((entity->type == lu_user) ||
			     (entity->type == lu_group),
			     FALSE);
	if (entity->type == lu_user) {
		id = user_lookup_name;
	} else
	if (entity->type == lu_group) {
		id = group_lookup_name;
	} else {
		g_assert_not_reached();
	}
	sdata = extract_name(entity);
	if (sdata == NULL)
		return FALSE;
	if (run_list(context, entity->modules, logic_and, id,
		     sdata, LU_VALUE_INVALID_ID, entity, &scratch, error)) {
		lu_ent_revert(entity);
		return TRUE;
	}
	return FALSE;
}

static gboolean
lu_dispatch(struct lu_context *context,
	    enum lu_dispatch_id id,
	    const char *sdata, id_t ldata,
	    struct lu_ent *entity,
	    gpointer ret,
	    struct lu_error **error)
{
	struct lu_ent *tmp;
	gboolean success;
	GValueArray *values = NULL;
	GPtrArray *ptrs = NULL;
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
		g_assert(ldata != LU_VALUE_INVALID_ID);
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
			if (values != NULL) {
				GValue *value;

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
		/* Run the list. */
		if (run_list(context, context->module_names, logic_or, id,
			     sdata, LU_VALUE_INVALID_ID, tmp, &scratch,
			     error)) {
			if (entity != NULL) {
				lu_ent_revert(tmp);
				lu_ent_copy(tmp, entity);
			}
			success = TRUE;
		}
		break;
	case user_default:
	case group_default:
		/* Make sure we have both name and boolean here. */
		g_return_val_if_fail(sdata != NULL, FALSE);
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
	case user_add_prep:
	case group_add_prep:
		/* Make sure we have both name and ID here. */
		if (ent_has_name_and_id(tmp, error) == FALSE)
			break;
		/* Run the checks and preps. */
		if (run_list(context, context->create_module_names, logic_and,
			     id, NULL, LU_VALUE_INVALID_ID, tmp, &scratch,
			     error)) {
			if (entity != NULL) {
				lu_ent_copy(tmp, entity);
			}
			success = TRUE;
		}
		break;
	case user_add:
	case group_add:
		/* Make sure we have both name and ID here. */
		if (ent_has_name_and_id(tmp, error) == FALSE)
			break;
		/* Add the account. */
		if (run_list(context, context->create_module_names,
			     logic_and, id, NULL, LU_VALUE_INVALID_ID,
			     tmp, &scratch, error)) {
			if (entity != NULL) {
				lu_ent_copy(tmp, entity);
			}
			success = TRUE;
		}
		break;
	case user_mod:
	case group_mod:
		/* Make sure we have both name and ID here. */
		/* FIXME: this checks current, not pending values */
		if (ent_has_name_and_id(tmp, error) == FALSE)
			break;
		/* Make the changes. */
		g_assert(entity != NULL);
		if (run_list(context, entity->modules, logic_and, id, NULL,
			     LU_VALUE_INVALID_ID, tmp, &scratch, error)) {
			lu_ent_commit(tmp);
			lu_ent_copy(tmp, entity);
			success = TRUE;
		}
		break;
	case user_del:
	case user_lock:
	case user_unlock:
	case user_unlock_nonempty:
	case group_del:
	case group_lock:
	case group_unlock:
	case group_unlock_nonempty:
		/* Make sure we have both name and ID here. */
		if (ent_has_name_and_id(tmp, error) == FALSE)
			break;
		/* Make the changes. */
		g_assert(entity != NULL);
		if (run_list(context, entity->modules, logic_and, id, NULL,
			     LU_VALUE_INVALID_ID, tmp, &scratch, error)) {
			lu_ent_revert(tmp);
			lu_ent_copy(tmp, entity);
			success = TRUE;
		}
		break;
	case user_setpass:
	case group_setpass:
		/* Make sure we have a valid password. */
		g_return_val_if_fail(sdata != NULL, FALSE);
		/* fall through */
	case user_removepass:
	case group_removepass:
		/* Make the changes. */
		g_assert(entity != NULL);
		if (run_list(context, entity->modules, logic_and, id, sdata,
			     LU_VALUE_INVALID_ID, tmp, &scratch, error)) {
			lu_ent_revert(tmp);
			lu_ent_copy(tmp, entity);
			success = TRUE;
		}
		break;
	case user_is_locked:
	case group_is_locked:
		/* Make sure we have both name and ID here. */
		if (ent_has_name_and_id(tmp, error) == FALSE)
			break;
		/* Run the checks. */
		g_assert(entity != NULL);
		if (run_list(context, entity->modules, logic_or, id, NULL,
			     LU_VALUE_INVALID_ID, tmp, &scratch, error)) {
			lu_ent_copy(tmp, entity);
			success = TRUE;
		}
		break;
	case users_enumerate_by_group:
	case groups_enumerate_by_user:
		/* Make sure we have both name and ID here. */
		g_return_val_if_fail(sdata != NULL, FALSE);
		if (id == users_enumerate_by_group)
			ldata = convert_group_name_to_id(context, sdata,
							 error);
		else if (id == groups_enumerate_by_user)
			ldata = convert_user_name_to_id(context, sdata, error);
		else
			g_assert_not_reached();
		if (ldata == LU_VALUE_INVALID_ID)
			break;
		/* fall through */
	case users_enumerate:
	case groups_enumerate:
		/* Get the lists. */
		if (run_list(context, context->module_names,
			    logic_or, id,
			    sdata, ldata, tmp, &values, error)) {
			*(GValueArray **)ret = values;
			success = TRUE;
		}
		break;
	case users_enumerate_by_group_full:
	case groups_enumerate_by_user_full:
		/* Make sure we have both name and ID here. */
		g_return_val_if_fail(sdata != NULL, FALSE);
		if (id == users_enumerate_by_group)
			ldata = convert_group_name_to_id(context, sdata,
							 error);
		else if (id == groups_enumerate_by_user)
			ldata = convert_user_name_to_id(context, sdata, error);
		else
			g_assert_not_reached();
		if (ldata == LU_VALUE_INVALID_ID)
			break;
		/* fall through */
	case users_enumerate_full:
	case groups_enumerate_full:
		/* Get the lists. */
		if (run_list(context, context->module_names,
			    logic_or, id,
			    sdata, ldata, tmp, &ptrs, error)) {
			if (ptrs != NULL) {
				size_t i;

				for (i = 0; i < ptrs->len; i++) {
					struct lu_ent *ent;
					ent = g_ptr_array_index(ptrs, i);
					lu_ent_revert(ent);
				}
			}
			*(GPtrArray **)ret = ptrs;
			success = TRUE;
		}
		/* Clean up results. */
		if (*(GPtrArray **)ret != NULL) {
			*(GPtrArray **)ret
				= merge_ent_array_duplicates(*(GPtrArray **)ret);
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
		g_assert_not_reached();
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
		if ((error != NULL) && (*error != NULL)) {
			lu_error_free(error);
		}
	}

	return success;
}

/* FIXME: error status, if any, is not reported to the caller */
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
	g_return_val_if_fail(name != NULL, FALSE);
	return lu_dispatch(context, user_lookup_name, name, 0,
			   ent, NULL, error);
}

gboolean
lu_group_lookup_name(struct lu_context * context, const char *name,
		     struct lu_ent * ent, struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	g_return_val_if_fail(name != NULL, FALSE);
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

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_user, FALSE);

	if (lu_dispatch(context, user_add_prep, NULL, LU_VALUE_INVALID_ID,
			ent, NULL, error)) {
		ret = lu_dispatch(context, user_add, NULL, LU_VALUE_INVALID_ID,
				  ent, NULL, error) &&
		      lu_refresh_user(context, ent, error);
	}
	return ret;
}

gboolean
lu_group_add(struct lu_context * context, struct lu_ent * ent,
	     struct lu_error ** error)
{
	gboolean ret = FALSE;
	LU_ERROR_CHECK(error);

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_group, FALSE);

	if (lu_dispatch(context, group_add_prep, NULL, LU_VALUE_INVALID_ID,
			ent, NULL, error)) {
		ret = lu_dispatch(context, group_add, NULL,
				  LU_VALUE_INVALID_ID, ent, NULL, error) &&
		      lu_refresh_group(context, ent, error);
	}
	return ret;
}

gboolean
lu_user_modify(struct lu_context * context, struct lu_ent * ent,
	       struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_user, FALSE);
	return lu_dispatch(context, user_mod, NULL, LU_VALUE_INVALID_ID, ent,
			   NULL, error) &&
	       lu_refresh_user(context, ent, error);
}

gboolean
lu_group_modify(struct lu_context * context, struct lu_ent * ent,
		struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_group, FALSE);
	return lu_dispatch(context, group_mod, NULL, LU_VALUE_INVALID_ID, ent,
			   NULL, error) &&
	       lu_refresh_group(context, ent, error);
}

gboolean
lu_user_delete(struct lu_context * context, struct lu_ent * ent,
	       struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_user, FALSE);
	return lu_dispatch(context, user_del, NULL, LU_VALUE_INVALID_ID, ent,
			   NULL, error);
}

gboolean
lu_group_delete(struct lu_context * context, struct lu_ent * ent,
		struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_group, FALSE);
	return lu_dispatch(context, group_del, NULL, LU_VALUE_INVALID_ID, ent,
			   NULL, error);
}

gboolean
lu_user_lock(struct lu_context * context, struct lu_ent * ent,
	     struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_user, FALSE);
	return lu_dispatch(context, user_lock, NULL, LU_VALUE_INVALID_ID, ent,
			   NULL, error) &&
	       lu_refresh_user(context, ent, error);
}

gboolean
lu_user_unlock(struct lu_context * context, struct lu_ent * ent,
	       struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_user, FALSE);
	return lu_dispatch(context, user_unlock, NULL, LU_VALUE_INVALID_ID,
			   ent, NULL, error) &&
	       lu_refresh_user(context, ent, error);
}

gboolean
lu_user_unlock_nonempty(struct lu_context * context, struct lu_ent * ent,
			struct lu_error ** error)
{
	LU_ERROR_CHECK(error);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_user, FALSE);
	return lu_dispatch(context, user_unlock_nonempty, NULL,
			   LU_VALUE_INVALID_ID, ent, NULL, error) &&
	       lu_refresh_user(context, ent, error);
}

gboolean
lu_user_islocked(struct lu_context * context, struct lu_ent * ent,
		 struct lu_error ** error)
{
	LU_ERROR_CHECK(error);

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_user, FALSE);

	return lu_dispatch(context, user_is_locked, NULL, LU_VALUE_INVALID_ID,
			   ent, NULL, error);
}

gboolean
lu_user_setpass(struct lu_context * context, struct lu_ent * ent,
		const char *password, gboolean is_crypted,
		struct lu_error ** error)
{
	gboolean ret;
	char *tmp;
	LU_ERROR_CHECK(error);

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_user, FALSE);

	if (is_crypted) {
		tmp = g_strconcat(LU_CRYPTED, password, NULL);
	} else {
		tmp = g_strdup(password);
	}
	ret = lu_dispatch(context, user_setpass, tmp, LU_VALUE_INVALID_ID,
			  ent, NULL, error);
	g_free(tmp);
	if (ret)
		ret = lu_refresh_user(context, ent, error);
	if (ret) {
		lu_util_update_shadow_last_change(ent);
		ret = lu_user_modify(context, ent, error);
	}
	return ret;
}

gboolean
lu_user_removepass(struct lu_context * context, struct lu_ent * ent,
		   struct lu_error ** error)
{
	gboolean ret;
	LU_ERROR_CHECK(error);

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_user, FALSE);

	ret = lu_dispatch(context, user_removepass, NULL, LU_VALUE_INVALID_ID,
			  ent, NULL, error);
	if (ret)
		ret = lu_refresh_user(context, ent, error);
	if (ret) {
		lu_util_update_shadow_last_change(ent);
		ret = lu_user_modify(context, ent, error);
	}
	return ret;
}

gboolean
lu_group_lock(struct lu_context * context, struct lu_ent * ent,
	      struct lu_error ** error)
{
	LU_ERROR_CHECK(error);

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_group, FALSE);

	return lu_dispatch(context, group_lock, NULL, LU_VALUE_INVALID_ID,
			   ent, NULL, error) &&
	       lu_refresh_group(context, ent, error);
}

gboolean
lu_group_unlock(struct lu_context * context, struct lu_ent * ent,
		struct lu_error ** error)
{
	LU_ERROR_CHECK(error);

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_group, FALSE);

	return lu_dispatch(context, group_unlock, NULL, LU_VALUE_INVALID_ID,
			   ent, NULL, error) &&
	       lu_refresh_group(context, ent, error);
}

gboolean
lu_group_unlock_nonempty(struct lu_context * context, struct lu_ent * ent,
			 struct lu_error ** error)
{
	LU_ERROR_CHECK(error);

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_group, FALSE);

	return lu_dispatch(context, group_unlock_nonempty, NULL,
			   LU_VALUE_INVALID_ID, ent, NULL, error) &&
	       lu_refresh_group(context, ent, error);
}

gboolean
lu_group_islocked(struct lu_context * context, struct lu_ent * ent,
		  struct lu_error ** error)
{
	LU_ERROR_CHECK(error);

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_group, FALSE);

	return lu_dispatch(context, group_is_locked, NULL, LU_VALUE_INVALID_ID,
			   ent, NULL, error);
}

gboolean
lu_group_setpass(struct lu_context * context, struct lu_ent * ent,
		 const char *password, gboolean is_crypted,
		 struct lu_error ** error)
{
	gboolean ret;
	char *tmp;
	LU_ERROR_CHECK(error);

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_group, FALSE);

	if (is_crypted) {
		tmp = g_strconcat(LU_CRYPTED, password, NULL);
	} else {
		tmp = g_strdup(password);
	}
	ret = lu_dispatch(context, group_setpass, tmp, LU_VALUE_INVALID_ID,
			  ent, NULL, error);
	g_free(tmp);
	if (ret)
		ret = lu_refresh_group(context, ent, error);
	return ret;
}

gboolean
lu_group_removepass(struct lu_context * context, struct lu_ent * ent,
		    struct lu_error ** error)
{
	gboolean ret;
	LU_ERROR_CHECK(error);

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->type == lu_group, FALSE);

	ret = lu_dispatch(context, group_removepass, NULL, LU_VALUE_INVALID_ID,
			  ent, NULL, error);
	if (ret)
		ret = lu_refresh_group(context, ent, error);
	return ret;
}

GValueArray *
lu_users_enumerate(struct lu_context * context, const char *pattern,
		   struct lu_error ** error)
{
	GValueArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, users_enumerate, pattern, LU_VALUE_INVALID_ID,
		    NULL, &ret, error);
	return ret;
}

GValueArray *
lu_groups_enumerate(struct lu_context * context, const char *pattern,
		    struct lu_error ** error)
{
	GValueArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, groups_enumerate, pattern, LU_VALUE_INVALID_ID,
		    NULL, &ret, error);
	return ret;
}

GValueArray *
lu_users_enumerate_by_group(struct lu_context * context, const char *group,
			    struct lu_error ** error)
{
	GValueArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, users_enumerate_by_group, group,
		    LU_VALUE_INVALID_ID, NULL, &ret, error);
	return ret;
}

GValueArray *
lu_groups_enumerate_by_user(struct lu_context * context, const char *user,
			    struct lu_error ** error)
{
	GValueArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, groups_enumerate_by_user, user,
		    LU_VALUE_INVALID_ID, NULL, &ret, error);
	return ret;
}

GPtrArray *
lu_users_enumerate_full(struct lu_context * context, const char *pattern,
		        struct lu_error ** error)
{
	GPtrArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, users_enumerate_full, pattern,
		    LU_VALUE_INVALID_ID, NULL, &ret, error);
	return ret;
}

GPtrArray *
lu_groups_enumerate_full(struct lu_context * context, const char *pattern,
			 struct lu_error ** error)
{
	GPtrArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, groups_enumerate_full, pattern,
		    LU_VALUE_INVALID_ID, NULL, &ret, error);
	return ret;
}

#if 0
GPtrArray *
lu_users_enumerate_by_group_full(struct lu_context * context,
				 const char *pattern,
				 struct lu_error ** error)
{
	GPtrArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, users_enumerate_by_group_full, pattern,
		    LU_VALUE_INVALID_ID, NULL, (gpointer*) &ret, error);
	return ret;
}

GPtrArray *
lu_groups_enumerate_by_user_full(struct lu_context * context,
				 const char *pattern,
				 struct lu_error ** error)
{
	GPtrArray *ret = NULL;
	LU_ERROR_CHECK(error);
	lu_dispatch(context, groups_enumerate_by_user_full, pattern,
		    LU_VALUE_INVALID_ID, NULL, (gpointer*) &ret, error);
	return ret;
}
#endif

id_t
lu_get_first_unused_id(struct lu_context *ctx,
		       enum lu_entity_type type,
		       id_t id)
{
	struct lu_ent *ent;
	char buf[LINE_MAX * 4];

	g_return_val_if_fail(ctx != NULL, (id_t)-1);

	ent = lu_ent_new();
	if (type == lu_user) {
		struct lu_error *error = NULL;
		do {
			struct passwd pwd, *err;

			/* There may be read-only sources of user information
			 * on the system, and we want to avoid allocating an ID
			 * that's already in use by a service we can't write
			 * to, so check with NSS first.  FIXME: use growing
			 * buffers here. */
			if ((getpwuid_r(id, &pwd, buf, sizeof(buf), &err) == 0) &&
			    (err == &pwd)) {
				id++;
				continue;
			}
			if (lu_user_lookup_id(ctx, id, ent, &error)) {
				lu_ent_free(ent);
				ent = lu_ent_new();
				id++;
				continue;
			}
			if (error) {
				lu_error_free(&error);
			}
			break;
		} while (id != (id_t)-1);
	} else if (type == lu_group) {
		struct lu_error *error = NULL;
		do {
			struct group grp, *err;

			/* There may be read-only sources of user information
			 * on the system, and we want to avoid allocating an ID
			 * that's already in use by a service we can't write
			 * to, so check with NSS first. */
			getgrgid_r(id, &grp, buf, sizeof(buf), &err);
			if (err == &grp) {
				id++;
				continue;
			}
			if (lu_group_lookup_id(ctx, id, ent, &error)) {
				lu_ent_free(ent);
				ent = lu_ent_new();
				id++;
				continue;
			}
			if (error) {
				lu_error_free(&error);
			}
			break;
		} while (id != (id_t)-1);
	}
	if (id == (id_t)-1)
		id = 0;
	lu_ent_free(ent);
	return id;
}

/* Replace all instances of OLD in g_malloc()'ed STRING by NEW. */
static char *
replace_all(char *string, const char *old, const char *new)
{
	char *pos;

	pos = strstr(string, old);
	if (pos != NULL) {
		size_t old_len;

		old_len = strlen(old);
		do {
			char *p, *prefix;

			prefix = g_strndup(string, pos - string);
			p = g_strconcat(prefix, new, pos + old_len, NULL);
			g_free(prefix);
			g_free(string);
			string = p;
			pos = strstr(string, old);
		} while (pos != NULL);
	}
	return string;
}

static gboolean
lu_default_int(struct lu_context *context, const char *name,
	       enum lu_entity_type type, gboolean is_system, struct lu_ent *ent)
{
	GList *keys, *p;
	GValue value;
	char *cfgkey;
	const char *top, *idkey, *idkeystring, *val;
	id_t id = DEFAULT_ID;
	struct group grp, *err;
	struct lu_error *error = NULL;
	gpointer macguffin = NULL;
	size_t i;

	g_return_val_if_fail(context != NULL, FALSE);
	g_return_val_if_fail(name != NULL, FALSE);
	g_return_val_if_fail(strlen(name) > 0, FALSE);
	g_return_val_if_fail((type == lu_user) || (type == lu_group), FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);

	/* Clear out and initialize the record. */
	lu_ent_clear_all(ent);
	lu_ent_clear_modules(ent);
	ent->type = type;

	/* Set the name of the user/group. */
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);
	g_value_set_string(&value, name);
	if (ent->type == lu_user) {
		char buf[LINE_MAX * 4];

		lu_ent_clear(ent, LU_USERNAME);
		lu_ent_add(ent, LU_USERNAME, &value);
		/* Additionally, pick a default default group. */
		g_value_unset(&value);
		/* FIXME: handle arbitrarily long lines. */
		if ((getgrnam_r("users", &grp, buf, sizeof(buf), &err) == 0) &&
		    (err == &grp))
			lu_value_init_set_id(&value, grp.gr_gid);
		else {
			g_value_init(&value, G_TYPE_LONG);
			g_value_set_long(&value, -1);
		}
		lu_ent_clear(ent, LU_GIDNUMBER);
		lu_ent_add(ent, LU_GIDNUMBER, &value);
	} else if (ent->type == lu_group) {
		lu_ent_clear(ent, LU_GROUPNAME);
		lu_ent_add(ent, LU_GROUPNAME, &value);
	}
	g_value_unset(&value);

	/* Figure out which part of the configuration we need to iterate over
	 * to initialize the structure. */
	if (type == lu_user) {
		top = "userdefaults";
		idkey = LU_UIDNUMBER;
		idkeystring = G_STRINGIFY_ARG(LU_UIDNUMBER);
	} else {
		top = "groupdefaults";
		idkey = LU_GIDNUMBER;
		idkeystring = G_STRINGIFY_ARG(LU_GIDNUMBER);
	}

	/* The system flag determines where we will start searching for
	 * unused IDs to assign to this entity. */
	if (is_system) {
		id = 1;
	} else {
		cfgkey = g_strconcat(top, "/", idkey, (const gchar *)NULL);
		val = lu_cfg_read_single(context, cfgkey, NULL);
		g_free(cfgkey);
		if (val == NULL) {
			cfgkey = g_strconcat(top, "/", idkeystring,
					     (const gchar *)NULL);
			val = lu_cfg_read_single(context, cfgkey, NULL);
			g_free(cfgkey);
		}
		if (val != NULL) {
			intmax_t imax;
			char *end;

			errno = 0;
			imax = strtoimax(val, &end, 10);
			if (errno == 0 && *end == 0 && end != val
			    && (id_t)imax == imax)
				id = imax;
			else
				id = DEFAULT_ID;
		}
	}

	/* Search for a free ID. */
	id = lu_get_first_unused_id(context, type, id);

	/* Add this ID to the entity. */
	lu_value_init_set_id(&value, id);
	lu_ent_add(ent, idkey, &value);
	g_value_unset(&value);

	/* Now iterate to find the rest. */
	keys = lu_cfg_read_keys(context, top);
	for (p = keys; p && p->data; p = g_list_next(p)) {
		static const struct {
			const char *realkey, *configkey;
		} keymap[] = {
			{LU_USERNAME, G_STRINGIFY_ARG(LU_USERNAME)},
			{LU_USERPASSWORD, G_STRINGIFY_ARG(LU_USERPASSWORD)},
			{LU_UIDNUMBER, G_STRINGIFY_ARG(LU_UIDNUMBER)},
			{LU_GIDNUMBER, G_STRINGIFY_ARG(LU_GIDNUMBER)},
			{LU_GECOS, G_STRINGIFY_ARG(LU_GECOS)},
			{LU_HOMEDIRECTORY, G_STRINGIFY_ARG(LU_HOMEDIRECTORY)},
			{LU_LOGINSHELL, G_STRINGIFY_ARG(LU_LOGINSHELL)},

			{LU_GROUPNAME, G_STRINGIFY_ARG(LU_GROUPNAME)},
			{LU_GROUPPASSWORD, G_STRINGIFY_ARG(LU_GROUPPASSWORD)},
			{LU_MEMBERNAME, G_STRINGIFY_ARG(LU_MEMBERNAME)},
			{LU_ADMINISTRATORNAME,
				G_STRINGIFY_ARG(LU_ADMINISTRATORNAME)},

			{LU_SHADOWNAME, G_STRINGIFY_ARG(LU_SHADOWNAME)},
			{LU_SHADOWPASSWORD, G_STRINGIFY_ARG(LU_SHADOWPASSWORD)},
			{LU_SHADOWLASTCHANGE,
				G_STRINGIFY_ARG(LU_SHADOWLASTCHANGE)},
			{LU_SHADOWMIN, G_STRINGIFY_ARG(LU_SHADOWMIN)},
			{LU_SHADOWMAX, G_STRINGIFY_ARG(LU_SHADOWMAX)},
			{LU_SHADOWWARNING, G_STRINGIFY_ARG(LU_SHADOWWARNING)},
			{LU_SHADOWINACTIVE, G_STRINGIFY_ARG(LU_SHADOWINACTIVE)},
			{LU_SHADOWEXPIRE, G_STRINGIFY_ARG(LU_SHADOWEXPIRE)},
			{LU_SHADOWFLAG, G_STRINGIFY_ARG(LU_SHADOWFLAG)},

			{LU_COMMONNAME, G_STRINGIFY_ARG(LU_COMMONNAME)},
			{LU_GIVENNAME, G_STRINGIFY_ARG(LU_GIVENNAME)},
			{LU_SN, G_STRINGIFY_ARG(LU_SN)},
			{LU_ROOMNUMBER, G_STRINGIFY_ARG(LU_ROOMNUMBER)},
			{LU_TELEPHONENUMBER,
				G_STRINGIFY_ARG(LU_TELEPHONENUMBER)},
			{LU_HOMEPHONE, G_STRINGIFY_ARG(LU_HOMEPHONE)},
			{LU_EMAIL, G_STRINGIFY_ARG(LU_EMAIL)},
		};

		char *tmp, replacement[sizeof (intmax_t) * CHAR_BIT + 1];
		const char *key;
		gboolean ok;

		/* Possibly map the key to an internal name. */
		key = p->data;
		for (i = 0; i < G_N_ELEMENTS(keymap); i++) {
			if (strcmp(key, keymap[i].configkey) == 0) {
				key = keymap[i].realkey;
				break;
			}
		}

		/* Skip over the key which represents the user/group ID,
		 * because we only used it as a starting point. */
		if (g_ascii_strcasecmp(idkey, key) == 0) {
			continue;
		}

		/* Generate the key and read the value for the item. */
		cfgkey = g_strconcat(top, "/", (const gchar *)p->data,
				     (const gchar *)NULL);
		val = lu_cfg_read_single(context, cfgkey, NULL);

		/* Create a copy of the value to mess with. */
		g_assert(val != NULL);
		tmp = g_strdup(val);

		tmp = replace_all(tmp, "%n", name);
		sprintf(replacement, "%ld", lu_util_shadow_current_date());
		tmp = replace_all(tmp, "%d", replacement);
		sprintf(replacement, "%jd", (intmax_t)id);
		tmp = replace_all(tmp, "%u", replacement);

		ok = lu_value_init_set_attr_from_string(&value, key, tmp,
							&error);
		if (ok == FALSE) {
			if (error == NULL) {
				/* Whatever this attribute is, default to a
				   string. */
				g_value_init(&value, G_TYPE_STRING);
				g_value_set_string(&value, tmp);
				ok = TRUE;
			} else {
				g_warning(_("Invalid default value of field "
					    "%s: %s"), cfgkey,
					  lu_strerror(error));
				lu_error_free(&error);
			}
		}
		g_free(tmp);
		g_free(cfgkey);

		if (ok != FALSE) {
			/* Add the transformed value. */
			lu_ent_clear(ent, key);
			lu_ent_add(ent, key, &value);
			g_value_unset(&value);
		}
	}
	if (keys != NULL) {
		g_list_free(keys);
	}

	/* Now let the modules do their thing. */
	lu_dispatch(context, (type == lu_user) ? user_default : group_default,
		    name, is_system, ent, &macguffin, &error);
	if (error != NULL) {
		lu_error_free(&error);
	}

	/* Make the pending set be the same as the current set. */
	lu_ent_commit(ent);

	return TRUE;
}

gboolean
lu_user_default(struct lu_context *context, const char *name,
		gboolean system_account, struct lu_ent *ent)
{
	return lu_default_int(context, name, lu_user, system_account, ent);
}

gboolean
lu_group_default(struct lu_context *context, const char *name,
		 gboolean system_account, struct lu_ent *ent)
{
	return lu_default_int(context, name, lu_group, system_account, ent);
}
