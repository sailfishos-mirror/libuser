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
#include <string.h>
#include "../include/libuser/user_private.h"

/* Cache a string.  We do this so that we only have to keep track of one
   pointer to it, and we have a well-defined time when it will be freed.
   This may all be replaced by GQuark-based stuff when glib-2.0 is released. */
static char *
lu_string_cache_cache(struct lu_string_cache *cache, const char *string)
{
	char *ret = NULL;
	if(string == NULL) {
		return NULL;
	}
	if((ret = g_tree_lookup(cache->tree, (char*)string)) == NULL) {
		ret = g_strdup(string);
		g_tree_insert(cache->tree, ret, ret);
	}
	return ret;
}

/* Add each key to the list passed in through data. */
static int
get_keys(gpointer key, gpointer value, gpointer data)
{
	GList **list = data;
	if(key) {
		*list = g_list_append(*list, key);
	}
	return 0;
}

/* Free all of the keys in the cache.  All of the items are keys. */
static void
lu_string_cache_free(struct lu_string_cache *cache)
{
	GList *list = NULL, *i;
	char *tmp;

	g_return_if_fail(cache != NULL);
	g_tree_traverse(cache->tree, get_keys, G_IN_ORDER, &list);
	g_tree_destroy(cache->tree);

	for(i = list; i; i = g_list_next(i)) {
		if((tmp = i->data) != NULL) {
			memset(tmp, '\0', strlen(tmp));
			g_free(tmp);
		}
	}
	g_list_free(list);

	memset(cache, 0, sizeof(struct lu_string_cache));

	g_free(cache);
}

/**
 * lu_string_cache_new:
 * case_sensitive: A #boolean indicating whether or not the new cache should be sensitive to case.
 *
 * Creates and returns a new string cache, which may or may not be case-sensitive.
 *
 **/
struct lu_string_cache *
lu_string_cache_new(gboolean case_sensitive)
{
	struct lu_string_cache *cache;
	cache = g_malloc0(sizeof(struct lu_string_cache));
	if(case_sensitive) {
		cache->tree = g_tree_new(lu_strcmp);
	} else {
		cache->tree = g_tree_new(lu_strcasecmp);
	}
	cache->cache = lu_string_cache_cache;
	cache->free = lu_string_cache_free;
	return cache;
}
