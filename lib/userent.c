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
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include "../include/libuser/user_private.h"

#define DEFAULT_ID 100

static int
dump_attribute(gpointer key, gpointer value, gpointer data)
{
	GList *list;
	for(list = (GList*) value; list; list = g_list_next(list))
		g_print(" %s = %s\n", (char*) key, (char*) list->data);
	return 0;
}

static void
lu_ent_dump(struct lu_ent *ent)
{
	g_return_if_fail(ent != NULL);
	g_print(_("dump of struct lu_ent at %p:\n"), ent);
	g_print(_(" magic = %08x\n"), ent->magic);
	g_print(_(" type = %s\n"), ent->type == lu_user ? _("user") : (ent->type == lu_group ? _("group") : _("unknown")));
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_tree_traverse(ent->attributes, dump_attribute, G_IN_ORDER, NULL);
}

/**
 * lu_get_free_id:
 * @ctx: A library context.
 * @type: An indicator of whether the application needs an unused UID or GID.
 * @id: An initial guess at what the returned ID might be.
 *
 * The lu_get_free_id() function returns an unused UID or GID, using @id as a first guess at what a free ID might be.
 *
 * Returns: a UID or GID if one is found, 0 on failure.
 **/
static glong
lu_get_free_id(struct lu_context *ctx, enum lu_type type, glong id)
{
	struct lu_ent *ent;
	char buf[LINE_MAX];

	g_return_val_if_fail(ctx != NULL, -1);

	ent = lu_ent_new();
	if(type == lu_user) {
		struct passwd pwd, *err;
		struct lu_error *error = NULL;
		while((id != 0) && (lu_user_lookup_id(ctx, id, ent, &error) || (getpwuid_r(id, &pwd, buf, sizeof(buf), &err) == 0)))
			id++;
		if(error)
			lu_error_free(&error);
	} else
	if(type == lu_group) {
		struct group grp, *err;
		struct lu_error *error = NULL;
		while((id != 0) && (lu_group_lookup_id(ctx, id, ent, &error) || (getgrgid_r(id, &grp, buf, sizeof(buf), &err) == 0)))
			id++;
		if(error)
			lu_error_free(&error);
	}
	lu_ent_free(ent);
	return id;
}

/**
 * lu_ent_new:
 *
 * This function creates and returns a new entity structure, suitable for passing into other functions provided by the library.
 *
 * Returns: a new entity structure.
 **/
struct lu_ent *
lu_ent_new()
{
	struct lu_ent *ent = NULL;
	ent = g_malloc0(sizeof(struct lu_ent));
	ent->magic = LU_ENT_MAGIC;
	ent->acache = lu_string_cache_new(FALSE);
	ent->vcache = lu_string_cache_new(TRUE);
	ent->original_attributes = g_tree_new(lu_strcasecmp);
	ent->attributes = g_tree_new(lu_strcasecmp);
	return ent;
}

/**
 * lu_ent_set_source_auth:
 * @ent: An entity structure.
 * @source: The name of a module which should be taken as authoritative for authentication information pertaining to the user
 * or group described by the entity structure.
 *
 * This function can be used to override the data store where authentication information for a user or group will subsequently
 * be recorded.  This function should only be used with great care, for careless use will disrupt the integrity of data stores.
 *
 * Returns: void
 **/
void
lu_ent_set_source_auth(struct lu_ent *ent, const char *source)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	if(source) {
		ent->source_auth = ent->vcache->cache(ent->vcache, source);
	} else {
		ent->source_auth = NULL;
	}
}

/**
 * lu_ent_set_source_info:
 * @ent: An entity structure.
 * @source: The name of a module which should be taken as authoritative for information pertaining to the user or group
 * described by the entity structure.
 *
 * This function can be used to override the data store where information for a user or group will subsequently be recorded.
 * This function should only be used with great care, for careless use will disrupt the integrity of data stores.
 *
 * Returns: void
 **/
void
lu_ent_set_source_info(struct lu_ent *ent, const char *source)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	if(source) {
		ent->source_info = ent->vcache->cache(ent->vcache, source);
	} else {
		ent->source_info = NULL;
	}
}

static int
copy_original_list(gpointer key, gpointer value, gpointer data)
{
	struct lu_ent *e = data;
	GList *v = value;
	g_return_val_if_fail(data != NULL, 1);
	g_return_val_if_fail(e->magic == LU_ENT_MAGIC, 1);
	lu_ent_clear_original(e, key);
	while(v) {
		lu_ent_add_original(e, key, v->data);
		v = g_list_next(v);
	}
	return 0;
}

static int
copy_list(gpointer key, gpointer value, gpointer data)
{
	struct lu_ent *dest = data;
	GList *v = value;
	g_return_val_if_fail(data != NULL, 1);
	g_return_val_if_fail(dest->magic == LU_ENT_MAGIC, 1);
	lu_ent_clear(dest, key);
	while(v) {
		lu_ent_add(dest, key, v->data);
		v = g_list_next(v);
	}
	return 0;
}

/**
 * lu_ent_revert:
 * @source: An entity whose attribute values should be reset to those returned by the last lookup performed with the structure
 * or when the structure was first created.
 *
 * This function can be used to undo changes to the in-memory structure which is used for storing information about users and
 * groups.
 *
 * Returns: void
 **/
void
lu_ent_revert(struct lu_ent *source)
{
	g_tree_traverse(source->original_attributes, copy_list, G_IN_ORDER, source);
}

/**
 * lu_ent_copy:
 * @source: An entity object, the contents of which should be copied to @dest.
 * @dest: An entity object which will be modified to resemble the @source object.
 *
 * This function can be used to create a temporary copy of an entity structure which can be manipulated without changes being
 * made the an original.
 *
 * Returns: void
 **/
void
lu_ent_copy(struct lu_ent *source, struct lu_ent *dest)
{
#ifdef DEBUG_USERENT
	g_print(_("\nBefore copy:\n"));
	lu_ent_dump(source);
	lu_ent_dump(dest);
#endif
	g_return_if_fail(source != NULL);
	g_return_if_fail(dest != NULL);
	g_return_if_fail(source->magic == LU_ENT_MAGIC);
	g_return_if_fail(dest->magic == LU_ENT_MAGIC);
	dest->type = source->type;
	lu_ent_set_source_info(dest, source->source_info);
	lu_ent_set_source_auth(dest, source->source_auth);
	g_tree_traverse(source->original_attributes, copy_original_list, G_IN_ORDER, dest);
	g_tree_traverse(source->attributes, copy_list, G_IN_ORDER, dest);
#ifdef DEBUG_USERENT
	g_print(_("\nAfter copy:\n"));
	lu_ent_dump(source);
	lu_ent_dump(dest);
#endif
}

static gboolean
lu_default(struct lu_context *context, const char *name,
	   enum lu_type type, gboolean system, struct lu_ent *ent)
{
	GList *keys, *vals, *p, *q;
	char *top, *key, *idkey, *idval, *tmp;
	gulong id = DEFAULT_ID;

	g_return_val_if_fail(name != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);

	ent->type = type;

	if(ent->type == lu_user) {
		lu_ent_set_original(ent, LU_USERNAME, name);
		lu_ent_set(ent, LU_USERNAME, name);
	} else
	if(ent->type == lu_group) {
		lu_ent_set_original(ent, LU_GROUPNAME, name);
		lu_ent_set(ent, LU_GROUPNAME, name);
	}

	if(type == lu_user) {
		top = ent->acache->cache(ent->acache, "userdefaults");
		idkey = ent->acache->cache(ent->acache, LU_UIDNUMBER);
	} else {
		top = ent->acache->cache(ent->acache, "groupdefaults");
		idkey = ent->acache->cache(ent->acache, LU_GIDNUMBER);
	}

	if(system) { 
		id = 1;
	} else {
		key = g_strdup_printf("%s/%s", top, idkey);
		vals = lu_cfg_read(context, key, NULL);
		g_free(key);
		if(vals && vals->data) {
			id = strtol((char*)vals->data, &idval, 10);
			if(*idval != '\0') {
				id = DEFAULT_ID;
			}
			idval = g_strdup_printf("%ld", id);
			lu_ent_set_original(ent, idkey, idval);
			lu_ent_set(ent, idkey, idval);
			g_free(idval);
		}
		if(vals != NULL) {
			g_list_free(vals);
		}
	}

	id = lu_get_free_id(context, type, id);

	tmp = g_strdup_printf("%ld", id);
	idval = ent->vcache->cache(ent->vcache, tmp);
	g_free(tmp);
	lu_ent_set_original(ent, idkey, idval);
	lu_ent_set(ent, idkey, idval);

	keys = lu_cfg_read_keys(context, top);

	for(p = keys; p && p->data; p = g_list_next(p)) {
		if(lu_str_case_equal(idkey, p->data)) {
			continue;
		}

		key = g_strdup_printf("%s/%s", top, (char*) p->data);
		vals = lu_cfg_read(context, key, NULL);
		g_free(key);

		for(q = vals; q && q->data; q = g_list_next(q)) {
			char *val = (char*) q->data;
			if(strstr(val, "%n")) {
				char *pre = g_strndup(val, strstr(val, "%n") - val);
				char *post = g_strdup(strstr(val, "%n") + 2);
				val = g_strconcat(pre, name, post, NULL);
				g_free(pre);
				g_free(post);
			}
			if(strstr(val, "%u")) {
				char *pre = g_strndup(val, strstr(val, "%u") - val);
				char *post = g_strdup(strstr(val, "%u") + 2);
				val = g_strconcat(pre, idval, post, NULL);
				g_free(pre);
				g_free(post);
			}
			lu_ent_add(ent, (char*) p->data, val);
		}
		if(vals != NULL) {
			g_list_free(vals);
		}
	}
	if(keys != NULL) {
		g_list_free(keys);
	}

	return TRUE;
}

/**
 * lu_user_default:
 * @context: A library context.
 * @name: A name for the new user.
 * @system: Specifies whether or not this will be a "system" account.
 * @ent: An entity structure which will contain information suitable for passing to lu_user_add().
 *
 * This function seeds an entity structure with the given name, allocates an unused UID using lu_get_free_id(), and sets
 * defaults necessary to create a well-formed user account.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
void
lu_user_default(struct lu_context *context, const char *name, gboolean system, struct lu_ent *ent)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	lu_default(context, name, lu_user, system, ent);
}

/**
 * lu_group_default:
 * @context: A library context.
 * @name: A name for the new group.
 * @system: Specifies whether or not this will be a "system" account.
 * @ent: An entity structure which will contain information suitable for passing to lu_group_add().
 *
 * This function seeds an entity structure with the given name, allocates an unused GID using lu_get_free_id(), and sets
 * defaults necessary to create a well-formed group account.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
void
lu_group_default(struct lu_context *context, const char *name, gboolean system, struct lu_ent *ent)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	lu_default(context, name, lu_group, system, ent);
}

/**
 * lu_ent_free:
 * @ent: An entity structure which will be destroyed.
 *
 * This function destroys an entity structure.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
void
lu_ent_free(struct lu_ent *ent)
{
#ifdef DEBUG_USERENT
	g_print(_("freeing lu_ent at %p.\n"), ent);
#endif
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_tree_destroy(ent->original_attributes);
	g_tree_destroy(ent->attributes);
	ent->acache->free(ent->acache);
	ent->vcache->free(ent->vcache);
	memset(ent, 0, sizeof(struct lu_ent));
	g_free(ent);
}

void
lu_ent_set_original(struct lu_ent *ent, const char *attr, const char *val)
{
	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);
	lu_ent_clear_original(ent, attr);
	lu_ent_add_original(ent, attr, val);
}

/**
 * lu_ent_set:
 * @ent: An entity structure which will be modified.
 * @attr: The attribute of the entity structure which will be replaced.
 * @val: A new value for the attribute.
 *
 * This function modifies the given attribute of a structure so that it is equal to @val.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
void
lu_ent_set(struct lu_ent *ent, const char *attr, const char *val)
{
	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);
	lu_ent_clear(ent, attr);
	lu_ent_add(ent, attr, val);
}

static int
get_hash_keys(gpointer key, gpointer value, gpointer data)
{
	GList **list = data;
	*list = g_list_append(*list, key);
	return 0;
}

/**
 * lu_ent_has:
 * @ent: An entity structure which will be queried.
 * @attribute: The attribute which we are checking the entity for values for.
 *
 * This function returns a boolean indicating whether or not the entity has values for a particular attribute.
 *
 * Returns: TRUE if there is a value, FALSE if there is not.
 **/
gboolean
lu_ent_has(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	return g_tree_lookup(ent->attributes, ent->acache->cache(ent->acache, attribute)) != NULL;
}

/**
 * lu_ent_get_attributes:
 * @ent: An entity structure which will be queried.
 *
 * This function returns a list of the attributes for which the entity structure has values defined.
 *
 * Returns: A #GList which should not be freed.
 **/
GList *
lu_ent_get_attributes(struct lu_ent *ent)
{
	GList *ret = NULL;
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	g_tree_traverse(ent->attributes, get_hash_keys, G_IN_ORDER, &ret);
	return ret;
}

/**
 * lu_ent_get:
 * @ent: An entity structure which will be queried.
 * @attr: The attribute of the structure which will be queried.
 *
 * This function returns a list of the values for the named attribute of the entity structure.
 *
 * Returns: A #GList which must be freed by calling g_list_free().
 **/
GList *
lu_ent_get(struct lu_ent *ent, const char *attr)
{
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	return g_tree_lookup(ent->attributes, ent->acache->cache(ent->acache, attr));
}

GList *
lu_ent_get_original(struct lu_ent *ent, const char *attr)
{
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	return g_tree_lookup(ent->original_attributes, ent->acache->cache(ent->acache, attr));
}

typedef GList* (get_fn)(struct lu_ent *, const char *);

static void
lu_ent_addx(struct lu_ent *ent, get_fn *get, GTree *tree,
	    const char *attr, const char *val)
{
	GList *list = NULL, *tmp = NULL;

	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);
	g_assert(get != NULL);
	g_assert(val != NULL);

	attr = ent->acache->cache(ent->acache, attr);

	list = get(ent, (char*)attr);

	for(tmp = list; tmp; tmp = g_list_next(tmp)) {
		if(lu_str_case_equal(tmp->data, val)) {
			return;
		}
	}

	val = ent->vcache->cache(ent->vcache, val);
	list = g_list_append(list, (char*)val);

	g_tree_insert(tree, (char*)attr, list);
}

/**
 * lu_ent_add:
 * @ent: An entity structure which will be queried.
 * @attr: The attribute of the structure which will be modified.
 * @val: The value which will be added to the structure's list of values for the named attribute.
 *
 * This function adds a single value to the list of the values of the named attribute contained in the entity structure.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
void
lu_ent_add(struct lu_ent *ent, const char *attr, const char *val)
{
	lu_ent_addx(ent, lu_ent_get, ent->attributes, attr, val);
}

void
lu_ent_add_original(struct lu_ent *ent, const char *attr, const char *val)
{
	lu_ent_addx(ent, lu_ent_get_original, ent->original_attributes, attr, val);
}

/**
 * lu_ent_del:
 * @ent: An entity structure which will be queried.
 * @attr: The attribute of the structure which will be modified.
 * @val: The value which will be removed from the structure's list of values for the named attribute.
 *
 * This function removes a single value from the list of the values of the named attribute contained in the entity structure.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
void
lu_ent_del(struct lu_ent *ent, const char *attr, const char *val)
{
	GList *list = NULL;

	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);
	g_assert(attr != NULL);
	g_assert(val != NULL);

	attr = ent->acache->cache(ent->acache, attr);

	list = lu_ent_get(ent, (char*)attr);

	val = ent->vcache->cache(ent->vcache, val);
	list = g_list_remove(list, (char*)val);

	g_tree_insert(ent->attributes, (char*)attr, list);
}

/**
 * lu_ent_clear:
 * @ent: An entity structure which will be queried.
 * @attr: The attribute of the structure which will be removed.
 *
 * This function removes all values of the named attribute contained in the entity structure.
 *
 * Returns: TRUE on success, FALSE on failure.
 **/
void
lu_ent_clear(struct lu_ent *ent, const char *attr)
{
	GList *tmp;

	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);
	g_assert(attr != NULL);

	attr = ent->acache->cache(ent->acache, attr);

	tmp = lu_ent_get(ent, attr);

	g_tree_remove(ent->attributes, ent->acache->cache(ent->acache, attr));

	g_list_free(tmp);
}

void
lu_ent_clear_original(struct lu_ent *ent, const char *attr)
{
	GList *tmp;

	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);
	g_assert(attr != NULL);

	attr = ent->acache->cache(ent->acache, attr);

	tmp = lu_ent_get_original(ent, attr);

	g_tree_remove(ent->original_attributes, ent->acache->cache(ent->acache, attr));

	g_list_free(tmp);
}
