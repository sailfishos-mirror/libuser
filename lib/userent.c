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
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>

#define DEFAULT_ID 100

static void
dump_attribute(gpointer key, gpointer value, gpointer data)
{
	GList *list;
	for(list = (GList*) value; list; list = g_list_next(list))
		g_print(" %s = %s\n", (char*) key, (char*) list->data);
}

void
lu_ent_dump(struct lu_ent *ent)
{
	g_return_if_fail(ent != NULL);
	g_print(_("dump of struct lu_ent at %p:\n"), ent);
	g_print(_(" magic = %08x\n"), ent->magic);
	g_print(_(" type = %s\n"), ent->type == lu_user ? _("user") :
		(ent->type == lu_group ? _("group") : _("unknown")));
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_hash_table_foreach(ent->attributes, dump_attribute, NULL);
}

static glong
lu_get_free_id(struct lu_context *ctx, enum lu_type type, glong id)
{
	struct lu_ent *ent;
	char buf[LINE_MAX];

	g_return_val_if_fail(ctx != NULL, -1);

	ent = lu_ent_new();
	if(type == lu_user) {
		struct passwd pwd, *err;
		while((id != 0) && (lu_user_lookup_id(ctx, id, ent) || (getpwuid_r(id, &pwd, buf, sizeof(buf), &err) == 0)))
			id++;
	} else
	if(type == lu_group) {
		struct group grp, *err;
		while((id != 0) && (lu_group_lookup_id(ctx, id, ent) || (getgrgid_r(id, &grp, buf, sizeof(buf), &err) == 0)))
			id++;
	}
	lu_ent_free(ent);
	return id;
}

struct lu_ent *
lu_ent_new()
{
	struct lu_ent *ent = NULL;
	ent = g_malloc0(sizeof(struct lu_ent));
	ent->magic = LU_ENT_MAGIC;
	ent->acache = lu_string_cache_new(FALSE);
	ent->vcache = lu_string_cache_new(TRUE);
	ent->original_attributes = g_hash_table_new(g_str_hash,
						    lu_str_case_equal);
	ent->attributes = g_hash_table_new(g_str_hash,
					   lu_str_case_equal);
	return ent;
}

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

static void
copy_original_list(gpointer key, gpointer value, gpointer data)
{
	struct lu_ent *e = data;
	GList *v = value;
	g_return_if_fail(data != NULL);
	g_return_if_fail(e->magic == LU_ENT_MAGIC);
	lu_ent_clear_original(e, key);
	while(v) {
		lu_ent_add_original(e, key, v->data);
		v = g_list_next(v);
	}
}

static void
copy_list(gpointer key, gpointer value, gpointer data)
{
	struct lu_ent *dest = data;
	GList *v = value;
	g_return_if_fail(data != NULL);
	g_return_if_fail(dest->magic == LU_ENT_MAGIC);
	lu_ent_clear(dest, key);
	while(v) {
		lu_ent_add(dest, key, v->data);
		v = g_list_next(v);
	}
}

void
lu_ent_revert(struct lu_ent *source)
{
	g_hash_table_foreach(source->original_attributes, copy_list, source);
}

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
	g_hash_table_foreach(source->original_attributes,
			     copy_original_list, dest);
	g_hash_table_foreach(source->attributes, copy_list, dest);
#ifdef DEBUG_USERENT
	g_print(_("\nAfter copy:\n"));
	lu_ent_dump(source);
	lu_ent_dump(dest);
#endif
}

/* This function seeds "uid" with the passed-in name, and "uidNumber" or
 * "gidNumber" with the first available uid or gid, depending on whether
 * this is a user or a group.  The rest is all taken from the configuration
 * file's "userdefaults" or "groupdefaults" section. */
gboolean
lu_ent_default(struct lu_context *context, const char *name,
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
				char *pre = g_strndup(val,
						      strstr(val, "%n") - val);
				char *post = g_strdup(strstr(val, "%n") + 2);
				val = g_strconcat(pre, name, post, NULL);
				g_free(pre);
				g_free(post);
			}
			if(strstr(val, "%u")) {
				char *pre = g_strndup(val,
						      strstr(val, "%u") - val);
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

void
lu_ent_user_default(struct lu_context *context, const char *name,
		    gboolean system, struct lu_ent *ent)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	lu_ent_default(context, name, lu_user, system, ent);
}

void
lu_ent_group_default(struct lu_context *context, const char *name,
		     gboolean system, struct lu_ent *ent)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	lu_ent_default(context, name, lu_group, system, ent);
}

void
lu_ent_free(struct lu_ent *ent)
{
#ifdef DEBUG_USERENT
	g_print(_("freeing lu_ent at %p.\n"), ent);
#endif
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_hash_table_destroy(ent->original_attributes);
	g_hash_table_destroy(ent->attributes);
	ent->acache->free(ent->acache);
	ent->vcache->free(ent->vcache);
	memset(ent, 0, sizeof(struct lu_ent));
	g_free(ent);
}

gboolean
lu_ent_set_original(struct lu_ent *ent, const char *attr, const char *val)
{
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	lu_ent_clear_original(ent, attr);
	lu_ent_add_original(ent, attr, val);
	return TRUE;
}

gboolean
lu_ent_set(struct lu_ent *ent, const char *attr, const char *val)
{
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	lu_ent_clear(ent, attr);
	lu_ent_add(ent, attr, val);
	return TRUE;
}

static void
get_hash_keys(gpointer key, gpointer value, gpointer data)
{
	GList **list = data;
	*list = g_list_append(*list, key);
}

GList *
lu_ent_get_attributes(struct lu_ent *ent)
{
	GList *ret = NULL;
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	g_hash_table_foreach(ent->attributes, get_hash_keys, &ret);
	return ret;
}

GList *
lu_ent_get(struct lu_ent *ent, const char *attr)
{
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	attr = ent->acache->cache(ent->acache, attr);
	return g_hash_table_lookup(ent->attributes, (char*)attr);
}

GList *
lu_ent_get_original(struct lu_ent *ent, const char *attr)
{
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	attr = ent->acache->cache(ent->acache, attr);
	return g_hash_table_lookup(ent->original_attributes, (char*)attr);
}

typedef GList* (get_fn)(struct lu_ent *, const char *);

static gboolean
lu_ent_addx(struct lu_ent *ent, get_fn *get, GHashTable *hash,
	    const char *attr, const char *val)
{
	GList *list = NULL, *tmp = NULL;

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	g_return_val_if_fail(get != NULL, FALSE);
	g_return_val_if_fail(val != NULL, FALSE);

	attr = ent->acache->cache(ent->acache, attr);

	list = get(ent, (char*)attr);

	for(tmp = list; tmp; tmp = g_list_next(tmp)) {
		if(lu_str_case_equal(tmp->data, val)) {
			return TRUE;
		}
	}

	val = ent->vcache->cache(ent->vcache, val);
	list = g_list_append(list, (char*)val);

	g_hash_table_insert(hash, (char*)attr, list);

	return TRUE;
}

gboolean
lu_ent_add(struct lu_ent *ent, const char *attr, const char *val)
{
	return lu_ent_addx(ent, lu_ent_get, ent->attributes,
			   attr, val);
}

gboolean
lu_ent_add_original(struct lu_ent *ent, const char *attr, const char *val)
{
	return lu_ent_addx(ent, lu_ent_get_original, ent->original_attributes,
			   attr, val);
}

gboolean
lu_ent_del(struct lu_ent *ent, const char *attr, const char *val)
{
	GList *list = NULL;

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	g_return_val_if_fail(attr != NULL, FALSE);
	g_return_val_if_fail(val != NULL, FALSE);

	attr = ent->acache->cache(ent->acache, attr);

	list = lu_ent_get(ent, (char*)attr);

	val = ent->vcache->cache(ent->vcache, val);
	list = g_list_remove(list, (char*)val);

	g_hash_table_insert(ent->attributes, (char*)attr, list);

	return TRUE;
}

gboolean
lu_ent_clear(struct lu_ent *ent, const char *attr)
{
	GList *tmp;

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	g_return_val_if_fail(attr != NULL, FALSE);

	attr = ent->acache->cache(ent->acache, attr);

	tmp = lu_ent_get(ent, attr);

	g_hash_table_remove(ent->attributes, attr);

	g_list_free(tmp);

	return TRUE;
}

gboolean
lu_ent_clear_original(struct lu_ent *ent, const char *attr)
{
	GList *tmp;

	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	g_return_val_if_fail(attr != NULL, FALSE);

	attr = ent->acache->cache(ent->acache, attr);

	tmp = lu_ent_get_original(ent, attr);

	g_hash_table_remove(ent->original_attributes, attr);

	g_list_free(tmp);

	return TRUE;
}
