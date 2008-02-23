/*
 * Copyright (C) 2000-2002, 2004, 2005 Red Hat, Inc.
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
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "user_private.h"
#include "internal.h"

/* Create and return a new entity object. */
struct lu_ent *
lu_ent_new()
{
	struct lu_ent *ent;

	ent = g_malloc0(sizeof(struct lu_ent));
	ent->magic = LU_ENT_MAGIC;
	ent->cache = lu_string_cache_new(TRUE);
	ent->current = g_array_new(FALSE, TRUE, sizeof(struct lu_attribute));
	ent->pending = g_array_new(FALSE, TRUE, sizeof(struct lu_attribute));
	ent->modules = g_value_array_new(1);
	return ent;
}

struct lu_ent *
lu_ent_new_typed(enum lu_entity_type entity_type)
{
	struct lu_ent *ret;
	ret = lu_ent_new();
	ret->type = entity_type;
	return ret;
}

/* Free an entity object. */
void
lu_ent_free(struct lu_ent *ent)
{
	size_t i;
	struct lu_attribute *attr;
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	/* Free the cache. */
	ent->cache->free(ent->cache);
	/* Free each current attribute. */
	for (i = 0; i < ent->current->len; i++) {
		attr = &g_array_index(ent->current, struct lu_attribute, i);
		/* Free the values array in this attribute; the array free
		 * will get the rest. */
		g_value_array_free(attr->values);
		attr->name = 0;
		attr->values = NULL;
	}
	g_array_free(ent->current, TRUE);
	/* Free each pending attribute. */
	for (i = 0; i < ent->pending->len; i++) {
		attr = &g_array_index(ent->pending, struct lu_attribute, i);
		/* Free the values array in this attribute; the array free
		 * will get the rest. */
		g_value_array_free(attr->values);
		attr->name = 0;
		attr->values = NULL;
	}
	g_array_free(ent->pending, TRUE);
	/* Free the module list. */
	g_value_array_free(ent->modules);
	memset(ent, 0, sizeof(struct lu_ent));
	g_free(ent);
}

/* Dump a set of attributes */
static void
lu_ent_dump_attributes(GArray *attrs, FILE *fp)
{
	size_t i;

	for (i = 0; i < attrs->len; i++) {
		struct lu_attribute *attribute;
		size_t j;

		attribute = &g_array_index(attrs, struct lu_attribute, i);
		for (j = 0; j < attribute->values->n_values; j++) {
			GValue *value;

			value = g_value_array_get_nth(attribute->values, j);
			fprintf(fp, " %s = ",
				g_quark_to_string(attribute->name));
			if (G_VALUE_HOLDS_STRING(value))
				fprintf(fp, "`%s'\n",
					g_value_get_string(value));
			else if (G_VALUE_HOLDS_LONG(value))
				fprintf(fp, "%ld\n", g_value_get_long(value));
			else if (G_VALUE_HOLDS_INT64(value))
				fprintf(fp, "%lld\n",
					(long long)g_value_get_int64(value));
			else
				fprintf(fp, "???\n");
		}
	}
}

/* Dump the contents of an entity structure.  This is primarily for
 * debugging. */
void
lu_ent_dump(struct lu_ent *ent, FILE *fp)
{
	size_t i;

	g_return_if_fail(ent != NULL);
	fprintf(fp, "dump of struct lu_ent at %p:\n", ent);
	fprintf(fp, " magic = %08x\n", ent->magic);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail((ent->type == lu_user) || (ent->type == lu_group));
	switch (ent->type) {
		case lu_invalid:
			fprintf(fp, " type = invalid\n");
			break;
		case lu_user:
			fprintf(fp, " type = user\n");
			break;
		case lu_group:
			fprintf(fp, " type = group\n");
			break;
		default:
			fprintf(fp, " type = UNKNOWN\n");
			break;
	}
	/* Print the module list. */
	fprintf(fp, " modules = (");
	for (i = 0; i < ent->modules->n_values; i++) {
		GValue *value;

		value = g_value_array_get_nth(ent->modules, i);
		if (i > 0)
			fprintf(fp, ", ");
		if (G_VALUE_HOLDS_STRING(value))
			fprintf(fp, "`%s'", g_value_get_string(value));
		else
			fprintf(fp, "?");
	}
	fprintf(fp, ")\n");
	/* Print the current data values. */
	lu_ent_dump_attributes(ent->current, fp);
	fprintf(fp, "\n");
	lu_ent_dump_attributes(ent->pending, fp);
}

/* Add a module to the list of modules kept for this entity. */
void
lu_ent_add_module(struct lu_ent *ent, const char *source)
{
	size_t i;

	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(ent->modules != NULL);
	for (i = 0; i < ent->modules->n_values; i++) {
		GValue *val;

		val = g_value_array_get_nth(ent->modules, i);
		/* We only add strings, so there had better be only strings
		 * in this list, otherwise someone is messing with us. */
		g_assert(G_VALUE_HOLDS_STRING(val));
		if (strcmp(g_value_get_string(val), source) == 0)
			break;
	}
	/* If we fell of the end of the array, then the new value is not
	 * in there, so we should add it. */
	if (i >= ent->modules->n_values) {
		GValue value;

		/* Initialize a value with the string. */
		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_STRING);
		g_value_set_string(&value, source);
		g_value_array_append(ent->modules, &value);
		g_value_unset(&value);
	}
}

/* Clear the list of modules which affect this module, by freeing the array
 * we use to keep track of them and allocating a new one. */
void
lu_ent_clear_modules(struct lu_ent *ent)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_value_array_free(ent->modules);
	ent->modules = g_value_array_new(1);
}

/* Remove all attributes from an object.  This function takes the address
 * of whichever list we want cleared. */
static void
clear_attribute_list(GArray *dest)
{
	int i;

	for (i = dest->len - 1; i >= 0; i--) {
		struct lu_attribute *attr;

		attr = &g_array_index(dest, struct lu_attribute, i);
		g_value_array_free(attr->values);
		attr->values = NULL;
		g_array_remove_index_fast(dest, i);
	}
}

/* Copy all attributes from source to dest, wiping out whatever was already
 * in the destination array. */
static void
copy_attributes(GArray *source, GArray *dest)
{
	size_t i;

	/* First, clear the destination list of all attributes. */
	clear_attribute_list(dest);
	/* Now copy all of the attributes and their values. */
	for (i = 0; i < source->len; i++) {
		struct lu_attribute *attr, newattr;

		attr = &g_array_index(source, struct lu_attribute, i);
		/* Copy the attribute name, then its values, into the holding
		 * area. */
		memset(&newattr, 0, sizeof(newattr));
		newattr.name = attr->name;
		newattr.values = g_value_array_copy(attr->values);
		/* Now append the attribute to the array. */
		g_array_append_val(dest, newattr);
	}
}

void
lu_ent_revert(struct lu_ent *entity)
{
	copy_attributes(entity->current, entity->pending);
}

void
lu_ent_commit(struct lu_ent *entity)
{
	copy_attributes(entity->pending, entity->current);
}

void
lu_ent_copy(struct lu_ent *source, struct lu_ent *dest)
{
	g_return_if_fail(source != NULL);
	g_return_if_fail(dest != NULL);
	g_return_if_fail(source->magic == LU_ENT_MAGIC);
	g_return_if_fail(dest->magic == LU_ENT_MAGIC);
	dest->type = source->type;
	copy_attributes(source->current, dest->current);
	copy_attributes(source->pending, dest->pending);
	g_value_array_free(dest->modules);
	dest->modules = g_value_array_copy(source->modules);
}

/* Return a GQark for lower-cased attribute */
static GQuark
quark_from_attribute(const char *attribute)
{
	GQuark quark;
	char *lower;

	lower = g_ascii_strdown(attribute, -1);
	quark = g_quark_from_string(lower);
	g_free(lower);
	return quark;
}

static GValueArray *
lu_ent_get_int(GArray *list, const char *attribute)
{
	GQuark aquark;
	size_t i;

	g_return_val_if_fail(list != NULL, NULL);
	g_return_val_if_fail(attribute != NULL, NULL);
	g_return_val_if_fail(strlen(attribute) > 0, NULL);
	aquark = quark_from_attribute(attribute);
	for (i = 0; i < list->len; i++) {
		struct lu_attribute *attr;

		attr = &g_array_index(list, struct lu_attribute, i);
		if (attr != NULL) {
			if (attr->name == aquark) {
				g_assert(attr->values != NULL);
				g_assert(attr->values->n_values > 0);
				return attr->values;
			}
		}
	}
	return NULL;
}

static gboolean
lu_ent_has_int(GArray *list, const char *attribute)
{
	g_return_val_if_fail(list != NULL, FALSE);
	g_return_val_if_fail(attribute != NULL, FALSE);
	g_return_val_if_fail(strlen(attribute) > 0, FALSE);
	return (lu_ent_get_int(list, attribute) != NULL) ? TRUE : FALSE;
}

static void
lu_ent_clear_int(GArray *list, const char *attribute)
{
	int i;
	struct lu_attribute *attr = NULL;
	GQuark aquark;

	g_return_if_fail(list != NULL);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	aquark = quark_from_attribute(attribute);
	for (i = list->len - 1; i >= 0; i--) {
		attr = &g_array_index(list, struct lu_attribute, i);
		if (attr->name == aquark)
			break;
	}
	if (i >= 0) {
		g_value_array_free(attr->values);
		attr->values = NULL;
		g_array_remove_index(list, i);
	}
}

static void
lu_ent_set_int(GArray *list, const char *attr, const GValueArray *values)
{
	GValueArray *dest, *copy;
	size_t i;

	g_return_if_fail(list != NULL);
	g_return_if_fail(attr != NULL);
	g_return_if_fail(strlen(attr) > 0);
	if (values->n_values == 0) {
		lu_ent_clear_int(list, attr);
		return;
	}
	dest = lu_ent_get_int(list, attr);
	if (dest == NULL) {
		struct lu_attribute newattr;

		memset(&newattr, 0, sizeof(newattr));
		newattr.name = quark_from_attribute(attr);
		newattr.values = g_value_array_new(0);
		dest = newattr.values;
		g_array_append_val(list, newattr);
	}
	while (dest->n_values > 0)
		g_value_array_remove(dest, dest->n_values - 1);
	copy = g_value_array_copy(values);
	for (i = 0; i < copy->n_values; i++)
		g_value_array_append(dest, g_value_array_get_nth(copy, i));
	g_value_array_free(copy);
}

static void
lu_ent_add_int(GArray *list, const char *attr, const GValue *value)
{
	GValueArray *dest;
	size_t i;

	g_return_if_fail(list != NULL);
	g_return_if_fail(value != NULL);
	g_return_if_fail(attr != NULL);
	g_return_if_fail(strlen(attr) > 0);
	dest = lu_ent_get_int(list, attr);
	if (dest == NULL) {
		struct lu_attribute newattr;

		memset(&newattr, 0, sizeof(newattr));
		newattr.name = quark_from_attribute(attr);
		newattr.values = g_value_array_new(1);
		dest = newattr.values;
		g_array_append_val(list, newattr);
	}
	for (i = 0; i < dest->n_values; i++) {
		GValue *current;

		current = g_value_array_get_nth(dest, i);
		if (G_VALUE_TYPE(value) == G_VALUE_TYPE(current)
		    && lu_values_equal(value, current))
			break;
	}
	if (i >= dest->n_values)
		g_value_array_append(dest, value);
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
	size_t i;
	g_return_if_fail(list != NULL);
	g_return_if_fail(value != NULL);
	g_return_if_fail(attr != NULL);
	g_return_if_fail(strlen(attr) > 0);
	dest = lu_ent_get_int(list, attr);
	if (dest != NULL) {
		for (i = 0; i < dest->n_values; i++) {
			GValue *tvalue;

			tvalue = g_value_array_get_nth(dest, i);
			if (G_VALUE_TYPE(value) == G_VALUE_TYPE(tvalue)
			    && lu_values_equal(value, tvalue))
				break;
		}
		if (i < dest->n_values) {
			g_value_array_remove(dest, i);
			if (dest->n_values == 0)
				lu_ent_clear_int(list, attr);
		}
	}
}

static GList *
lu_ent_get_attributes_int(GArray *list)
{
	size_t i;
	GList *ret = NULL;
	g_return_val_if_fail(list != NULL, NULL);
	for (i = 0; i < list->len; i++) {
		struct lu_attribute *attr;

		attr = &g_array_index(list, struct lu_attribute, i);
		ret = g_list_prepend(ret, (char*)g_quark_to_string(attr->name));
	}
	return g_list_reverse(ret);
}

GValueArray *
lu_ent_get(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	g_return_val_if_fail(attribute != NULL, NULL);
	g_return_val_if_fail(strlen(attribute) > 0, NULL);
	return lu_ent_get_int(ent->pending, attribute);
}

GValueArray *
lu_ent_get_current(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	g_return_val_if_fail(attribute != NULL, NULL);
	g_return_val_if_fail(strlen(attribute) > 0, NULL);
	return lu_ent_get_int(ent->current, attribute);
}

gboolean
lu_ent_has(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	g_return_val_if_fail(attribute != NULL, FALSE);
	g_return_val_if_fail(strlen(attribute) > 0, FALSE);
	return lu_ent_has_int(ent->pending, attribute);
}
gboolean
lu_ent_has_current(struct lu_ent *ent, const char *attribute)
{
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	g_return_val_if_fail(attribute != NULL, FALSE);
	g_return_val_if_fail(strlen(attribute) > 0, FALSE);
	return lu_ent_has_int(ent->current, attribute);
}

void
lu_ent_set(struct lu_ent *ent, const char *attribute, const GValueArray *values)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	lu_ent_set_int(ent->pending, attribute, values);
}
void
lu_ent_set_current(struct lu_ent *ent, const char *attribute,
		   const GValueArray *values)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	lu_ent_set_int(ent->current, attribute, values);
}

void
lu_ent_add(struct lu_ent *ent, const char *attribute, const GValue *value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	lu_ent_add_int(ent->pending, attribute, value);
}
void
lu_ent_add_current(struct lu_ent *ent, const char *attribute,
		   const GValue *value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	lu_ent_add_int(ent->current, attribute, value);
}

void
lu_ent_clear(struct lu_ent *ent, const char *attribute)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	lu_ent_clear_int(ent->pending, attribute);
}
void
lu_ent_clear_current(struct lu_ent *ent, const char *attribute)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
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
	g_return_if_fail(strlen(attribute) > 0);
	g_return_if_fail(value != NULL);
	lu_ent_del_int(ent->pending, attribute, value);
}
void
lu_ent_del_current(struct lu_ent *ent, const char *attribute,
		   const GValue *value)
{
	g_return_if_fail(ent != NULL);
	g_return_if_fail(ent->magic == LU_ENT_MAGIC);
	g_return_if_fail(attribute != NULL);
	g_return_if_fail(strlen(attribute) > 0);
	g_return_if_fail(value != NULL);
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
