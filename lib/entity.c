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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "../include/libuser/user_private.h"
#include "util.h"

#define DEFAULT_ID 500

struct lu_ent *
lu_ent_new()
{
	struct lu_ent *ent = NULL;
	ent = g_malloc0(sizeof(struct lu_ent));
	ent->magic = LU_ENT_MAGIC;
	ent->acache = lu_string_cache_new(FALSE);
	ent->vcache = lu_string_cache_new(TRUE);
	ent->current = g_array_new(FALSE, TRUE, sizeof(struct lu_attribute));
	ent->pending = g_array_new(FALSE, TRUE, sizeof(struct lu_attribute));
	ent->modules = g_value_array_new(1);
	return ent;
}

void
lu_ent_free(struct lu_ent *ent)
{
	int i;
	struct lu_attribute *attr;
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	ent->acache->free(ent->acache);
	ent->vcache->free(ent->vcache);
	for(i = 0; i < ent->current->len; i++) {
		attr = &g_array_index(ent->current, struct lu_attribute, i);
		g_value_array_free(attr->values);
		attr->name = NULL;
		attr->values = NULL;
	}
	g_array_free(ent->current, FALSE);
	for(i = 0; i < ent->pending->len; i++) {
		attr = &g_array_index(ent->pending, struct lu_attribute, i);
		g_value_array_free(attr->values);
		attr->name = NULL;
		attr->values = NULL;
	}
	g_array_free(ent->pending, FALSE);
	g_value_array_free(ent->modules);
	memset(ent, 0, sizeof(struct lu_ent));
	g_free(ent);
}

void
lu_ent_dump(struct lu_ent *ent, FILE *fp)
{
	int i, j;
	struct lu_attribute *attribute;
	g_return_if_fail(ent != NULL);
	fprintf(fp, "dump of struct lu_ent at %p:\n", ent);
	fprintf(fp, " magic = %08x\n", ent->magic);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	switch(ent->type) {
		case lu_user:
			fprintf(fp, " type = user\n");
			break;
		case lu_group:
			fprintf(fp, " type = group\n");
			break;
		default:
			g_return_if_fail((ent->type == lu_user) ||
					 (ent->type == lu_group));
			break;
	}
	for(i = 0; i < ent->current->len; i++) {
		attribute = &g_array_index(ent->current,
					   struct lu_attribute,
					   i);
		for(j = 0; j < attribute->values->n_values; j++) {
			GValue *value;
			value = g_value_array_get_nth(attribute->values, j);
			fprintf(fp, " %s = `%s'\n", attribute->name,
				g_value_get_string(value));
		}
	}
}

static glong
lu_get_first_unused_id(struct lu_context *ctx,
		       enum lu_entity_type type,
		       glong id)
{
	struct lu_ent *ent;
	char buf[LINE_MAX];

	g_return_val_if_fail(ctx != NULL, -1);

	ent = lu_ent_new();
	if (type == lu_user) {
		struct passwd pwd, *err;
		struct lu_error *error = NULL;
		do {
			/* There may be read-only sources of user information
			 * on the system, and we want to avoid allocating an ID
			 * that's already in use by a service we can't write
			 * to, so check with NSS first. */
			getpwuid_r(id, &pwd, buf, sizeof(buf), &err);
			if (err == &pwd) {
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
		} while (id != 0);
	} else if (type == lu_group) {
		struct group grp, *err;
		struct lu_error *error = NULL;
		do {
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
		} while (id != 0);
	}
	lu_ent_free(ent);
	return id;
}

void
lu_ent_add_module(struct lu_ent *ent, const char *source)
{
	GValue value;
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(ent->modules != NULL);
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);
	g_value_set_string(&value, source);
	g_value_array_append(ent->modules, &value);
	g_value_unset(&value);
}

void
lu_ent_clear_modules(struct lu_ent *ent)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_value_array_free(ent->modules);
	ent->modules = g_value_array_new(1);
}

static void
clear_attribute_list(GArray *dest)
{
	int i;
	struct lu_attribute *attr;
	for(i = dest->len - 1; i >= 0; i--) {
		attr = &g_array_index(dest, struct lu_attribute, i);
		g_value_array_free(attr->values);
		attr->values = NULL;
		g_array_remove_index_fast(dest, i);
	}
}

static void
copy_attributes(GArray *source, GArray *dest, struct lu_string_cache *acache)
{
	int i, j;
	struct lu_attribute *attr, newattr;
	GValue *value;
	/* First, clear the list of attributes. */
	clear_attribute_list(dest);
	/* Now copy all of the attributes and their values. */
	for(i = 0; i < source->len; i++) {
		attr = &g_array_index(source, struct lu_attribute, i);
		/* Copy the attribute name, then its values, into the holding
		 * area. */
		memset(&newattr, 0, sizeof(newattr));
		newattr.name = acache->cache(acache, attr->name);
		newattr.values = g_value_array_new(attr->values->n_values);
		for(j = 0; j < attr->values->n_values; j++) {
			value = g_value_array_get_nth(attr->values, j);
			g_value_array_append(newattr.values, value);
		}
		/* Now append the attribute to the array. */
		g_array_append_val(dest, newattr);
	}
}

void
lu_ent_revert(struct lu_ent *entity)
{
	copy_attributes(entity->current, entity->pending, entity->acache);
}

void
lu_ent_copy(struct lu_ent *source, struct lu_ent *dest)
{
	g_return_if_fail(source != NULL);
	g_return_if_fail(dest != NULL);
	g_return_if_fail(source->magic == LU_ENT_MAGIC);
	g_return_if_fail(dest->magic == LU_ENT_MAGIC);
	dest->type = source->type;
	copy_attributes(source->current, dest->current, dest->acache);
	copy_attributes(source->pending, dest->pending, dest->acache);
	g_value_array_free(dest->modules);
	dest->modules = g_value_array_copy(source->modules);
}

static GValueArray *
lu_ent_get_int(GArray *list, const char *attribute)
{
	struct lu_attribute *attr;
	int i;
	for(i = 0; i < list->len; i++) {
		attr = &g_array_index(list, struct lu_attribute, i);
		if(attr != NULL) {
			if(strcasecmp(attr->name, attribute) == 0) {
				return attr->values;
			}
		}
	}
	return NULL;
}

static gboolean
lu_ent_has_int(GArray *list, const char *attribute)
{
	return (lu_ent_get_int(list, attribute) != NULL) ? TRUE : FALSE;
}

static void
lu_ent_set_int(GArray *list, struct lu_string_cache *acache,
	       const char *attr, const GValueArray *values)
{
	GValueArray *dest, *copy;
	struct lu_attribute newattr;
	int i;
	dest = lu_ent_get_int(list, attr);
	if(dest == NULL) {
		memset(&newattr, 0, sizeof(newattr));
		newattr.name = acache->cache(acache, attr);
		newattr.values = g_value_array_new(values->n_values);
		dest = newattr.values;
		g_array_append_val(list, newattr);
	}
	copy = g_value_array_copy(values);
	for(i = 0; i < copy->n_values; i++) {
		g_value_array_append(dest, g_value_array_get_nth(copy, i));
	}
	g_value_array_free(copy);

}

static void
lu_ent_add_int(GArray *list, struct lu_string_cache *acache,
	       const char *attr, const GValue *value)
{
	GValueArray *dest;
	struct lu_attribute newattr;
	dest = lu_ent_get_int(list, attr);
	if(dest == NULL) {
		memset(&newattr, 0, sizeof(newattr));
		newattr.name = acache->cache(acache, attr);
		newattr.values = g_value_array_new(1);
		dest = newattr.values;
		g_array_append_val(list, newattr);
	}
	g_value_array_append(dest, value);
}

static void
lu_ent_clear_int(GArray *list, const char *attribute)
{
	int i;
	struct lu_attribute *attr;
	for(i = list->len - 1; i >= 0; i--) {
		attr = &g_array_index(list, struct lu_attribute, i);
		if(strcasecmp(attr->name, attribute) == 0) {
			break;
		}
	}
	if(i >= 0) {
		g_value_array_free(attr->values);
		attr->values = NULL;
		g_array_remove_index(list, i);
	}
}

static void
lu_ent_clear_all_int(GArray *list)
{
	clear_attribute_list(list);
}

static void
lu_ent_del_int(GArray *list, const char *attr, const GValue *value)
{
	GValueArray *dest;
	GValue *tvalue;
	char *svalue, *tmp;
	int i;
	dest = lu_ent_get_int(list, attr);
	if(dest != NULL) {
		svalue = g_strdup_value_contents(value);
		for(i = 0; i < dest->n_values; i++) {
			tvalue = g_value_array_get_nth(dest, i);
			tmp = g_strdup_value_contents(tvalue);
			if(strcmp(tmp, svalue) == 0) {
				g_free(tmp);
				break;
			}
			g_free(tmp);
		}
		g_free(svalue);
		if(i < dest->n_values) {
			g_value_array_remove(dest, i);
		}
	}
}

static GList *
lu_ent_get_attributes_int(GArray *list)
{
	struct lu_attribute *attr;
	int i;
	GList *ret = NULL;
	for(i = 0; i < list->len; i++) {
		attr = &g_array_index(list, struct lu_attribute, i);
		ret = g_list_prepend(ret, (gpointer)attr->name);
	}
	return g_list_reverse(ret);
}

GValueArray *
lu_ent_get(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	g_return_val_if_fail(attribute != NULL, NULL);
	return lu_ent_get_int(ent->pending, attribute);
}
GValueArray *
lu_ent_get_current(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	g_return_val_if_fail(attribute != NULL, NULL);
	return lu_ent_get_int(ent->current, attribute);
}

gboolean
lu_ent_has(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	g_return_val_if_fail(attribute != NULL, FALSE);
	return lu_ent_has_int(ent->pending, attribute);
}
gboolean
lu_ent_has_current(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	g_return_val_if_fail(attribute != NULL, FALSE);
	return lu_ent_has_int(ent->current, attribute);
}

void
lu_ent_set(struct lu_ent *ent, const char *attribute, const GValueArray *values)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	lu_ent_set_int(ent->pending, ent->acache, attribute, values);
}
void
lu_ent_set_current(struct lu_ent *ent, const char *attribute,
		   const GValueArray *values)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	lu_ent_set_int(ent->current, ent->acache, attribute, values);
}

void
lu_ent_add(struct lu_ent *ent, const char *attribute, const GValue *value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	lu_ent_add_int(ent->pending, ent->acache, attribute, value);
}
void
lu_ent_add_current(struct lu_ent *ent, const char *attribute,
		   const GValue *value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	lu_ent_add_int(ent->current, ent->acache, attribute, value);
}

void
lu_ent_clear(struct lu_ent *ent, const char *attribute)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	lu_ent_clear_int(ent->pending, attribute);
}
void
lu_ent_clear_current(struct lu_ent *ent, const char *attribute)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	lu_ent_clear_int(ent->current, attribute);
}

void
lu_ent_clear_all(struct lu_ent *ent)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	lu_ent_clear_all_int(ent->pending);
}
void
lu_ent_clear_all_current(struct lu_ent *ent)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	lu_ent_clear_all_int(ent->current);
}

void
lu_ent_del(struct lu_ent *ent, const char *attribute, const GValue *value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	lu_ent_del_int(ent->pending, attribute, value);
}
void
lu_ent_del_current(struct lu_ent *ent, const char *attribute,
		   const GValue *value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	lu_ent_del_int(ent->current, attribute, value);
}

GList *
lu_ent_get_attributes(struct lu_ent *ent)
{
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	return lu_ent_get_attributes_int(ent->pending);
}
GList *
lu_ent_get_attributes_current(struct lu_ent *ent)
{
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	return lu_ent_get_attributes_int(ent->current);
}

static gboolean
lu_default_int(struct lu_context *context, const char *name,
	       enum lu_entity_type type, gboolean system, struct lu_ent *ent)
{
	GList *keys, *p;
	GValue value;
	char *top, *key, *idkey, *tmp, *idstring;
	const char *val;
	gulong id = DEFAULT_ID;
	int i;

	g_return_val_if_fail(context != NULL, FALSE);
	g_return_val_if_fail(name != NULL, FALSE);
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
		lu_ent_add(ent, LU_USERNAME, &value);
		lu_ent_add_current(ent, LU_USERNAME, &value);
	} else if (ent->type == lu_group) {
		lu_ent_add(ent, LU_GROUPNAME, &value);
		lu_ent_add_current(ent, LU_GROUPNAME, &value);
	}
	g_value_unset(&value);

	/* Figure out which part of the configuration we need to iterate over
	 * to initialize the structure. */
	if (type == lu_user) {
		top = ent->acache->cache(ent->acache, "userdefaults");
		idkey = ent->acache->cache(ent->acache, LU_UIDNUMBER);
	} else {
		top = ent->acache->cache(ent->acache, "groupdefaults");
		idkey = ent->acache->cache(ent->acache, LU_GIDNUMBER);
	}

	/* The system flag determines where we will start searching for
	 * unused IDs to assign to this entity. */
	if (system) {
		id = 1;
	} else {
		key = g_strdup_printf("%s/%s", top, idkey);
		val = lu_cfg_read_single(context, key, NULL);
		g_free(key);
		if (val != NULL) {
			id = strtol((char *) val, &tmp, 10);
			if (*tmp != '\0') {
				id = DEFAULT_ID;
			}
		}
	}

	/* Search for a free ID. */
	id = lu_get_first_unused_id(context, type, id);

	/* Add this ID to the entity. */
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_LONG);
	g_value_set_long(&value, id);
	idstring = g_strdup_value_contents(&value);
	lu_ent_add_current(ent, idkey, &value);
	lu_ent_add(ent, idkey, &value);

	/* Now iterate to find the rest. */
	keys = lu_cfg_read_keys(context, top);
	for (p = keys; p && p->data; p = g_list_next(p)) {
		struct {
			const char *format, *value;
		} subst[] = {
			{"%n", name},
			{"%d", lu_util_shadow_current_date(context->scache)},
			{"%u", idstring},
		};

		/* Skip over the key which represents the user/group ID,
		 * because we only used it as a starting point. */
		if (lu_str_case_equal(idkey, p->data)) {
			continue;
		}

		/* Generate the key and read the value for the item. */
		key = g_strdup_printf("%s/%s", top, (char *) p->data);
		val = lu_cfg_read_single(context, key, NULL);
		g_free(key);

		/* Create a copy of the value to mess with. */
		g_assert(val != NULL);
		tmp = g_strdup(val);

		/* Perform substitutions. */
		for(i = 0; i < G_N_ELEMENTS(subst); i++) {
			while(strstr(val, subst[i].format) != NULL) {
				char *pre, *post, *tmp2;
				val = strstr(tmp, subst[i].format);
				pre = g_strndup(val, tmp - val);
				post = g_strdup(tmp + strlen(subst[i].format));
				tmp2 = g_strconcat(pre,
						   subst[i].value,
						   post,
						   NULL);
				g_free(tmp);
				tmp = tmp2;
			}
		}

		/* Add the transformed value. */
		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_STRING);
		g_value_set_string(&value, tmp);
		g_free(tmp);
		lu_ent_add(ent, (char *) p->data, &value);
		g_value_unset(&value);
	}
	if (keys != NULL) {
		g_list_free(keys);
	}

	return TRUE;
}

gboolean
lu_user_default(struct lu_context *context, const char *name,
		gboolean system, struct lu_ent *ent)
{
	return lu_default_int(context, name, lu_user, system, ent);
}
gboolean
lu_group_default(struct lu_context *context, const char *name,
		 gboolean system, struct lu_ent *ent)
{
	return lu_default_int(context, name, lu_group, system, ent);
}
