/* Copyright (C) 2000-2002 Red Hat, Inc.
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
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "user_private.h"
#include "util.h"

#ifdef HAVE___SECURE_GETENV
#define getenv(string) __secure_getenv(string)
#endif

/* We read the configuration file at startup only, so we need to keep a
 * copy of it around. */
struct config_config {
	struct lu_string_cache *cache;
	GTree *sections; /* GList of "struct config_key" for each section */
};

/* A (key, values) pair. */
struct config_key {
	char *key;
	GList *values;
};

/* Compare two section names */
static int
compare_section_names(gconstpointer a, gconstpointer b)
{
	return g_ascii_strcasecmp(a, b);
}

/* Compare a struct config_key to a string */
static int
compare_key_string(gconstpointer xa, gconstpointer b)
{
	const struct config_key *a;

	a = xa;
	return g_ascii_strcasecmp(a->key, b);
}

/* Process a line, and assuming it contains a value, return the key and value
 * it provides us.  If we encounter a section start, change the section. */
static void
process_line(char *line, struct lu_string_cache *cache,
	     char **section, char **key, char **value)
{
	char *p, *tmp;

	g_return_if_fail(line != NULL);
	g_return_if_fail(cache != NULL);
	g_return_if_fail(section != NULL);
	g_return_if_fail(key != NULL);
	g_return_if_fail(value != NULL);

	/* By default, return that we found nothing. */
	*key = NULL;
	*value = NULL;

	/* Skip initial whitespace. */
	while (isspace(*line) && (*line != '\0')) {
		line++;
	}

	/* If it's a comment, bail. */
	if (*line == '#') {
		return;
	}

	/* If it's the beginning of a section, process it and clear the key
	 * and value values. */
	if (*line == '[') {
		line++;
		p = strchr(line, ']');
		if (p) {
			tmp = g_strndup(line, p - line);
			*section = cache->cache(cache, tmp);
			g_free(tmp);
			*key = NULL;
			*value = NULL;
		}
		return;
	}

	/* If the line contains a value, split the key and the value, trim off
	 * any additional whitespace, and return them. */
	if (strchr(line, '=')) {
		p = strchr(line, '=');

		/* Trim any trailing whitespace off the key name. */
		p--;
		while (isspace(*p) && (p > line)) {
			p--;
		}

		/* Save the key. */
		tmp = g_strndup(line, p - line + 1);
		*key = cache->cache(cache, tmp);
		g_free(tmp);

		/* Skip over any whitespace after the equal sign. */
		line = strchr(line, '=');
		line++;
		while (isspace(*line) && (*line != '\0')) {
			line++;
		}

		/* Trim off any trailing whitespace. */
		p = line + strlen(line);
		p--;
		while (isspace(*p) && (p > line)) {
			p--;
		}

		/* Save the value. */
		tmp = g_strndup(line, p - line + 1);
		*value = cache->cache(cache, tmp);
		g_free(tmp);
	}
}

/* Initialize the configuration structure. */
gboolean
lu_cfg_init(struct lu_context *context, struct lu_error **error)
{
	int fd;
	struct stat st;
	const char *filename = SYSCONFDIR "/libuser.conf";
	struct config_config *config = NULL;
	char *data, *line, *xstrtok_ptr, *section = NULL;
	const char *t;

	g_assert(context != NULL);

	/* Allow the LIBUSER_CONF environment variable to override where
	 * we get the configuration file is, but only if we can trust the
	 * environment. */
	if ((getuid() == geteuid()) && (getgid() == getegid())) {
		t = getenv("LIBUSER_CONF");
		if (t != NULL) {
			filename = t;
		}
	}

	/* Try to open the file. */
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("could not open configuration file `%s': %s"),
			     filename, strerror(errno));
		goto err;
	}

	/* Create a new structure to save the data. */
	config = g_malloc0(sizeof(struct config_config));
	if (fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat,
			     _("could not stat configuration file `%s': %s"),
			     filename, strerror(errno));
		goto err_config;
	} 
	/* Read the file's contents in. */
	data = g_malloc0(st.st_size + 1);
	if (read(fd, data, st.st_size) != st.st_size) {
		lu_error_new(error, lu_error_read,
			     _("could not read configuration file `%s': %s"),
			     filename, strerror(errno));
		goto err_data;
	}
	close(fd);

	config->cache = lu_string_cache_new(FALSE);
	config->sections = g_tree_new(compare_section_names);
	context->config = config;

	for (line = strtok_r(data, "\n", &xstrtok_ptr); line != NULL;
	     line = strtok_r(NULL, "\n", &xstrtok_ptr)) {
		char *key = NULL, *value = NULL;

		/* See what this line contains. */
		process_line(line, config->cache, &section, &key, &value);

		/* If we have a valid line, */
		if (section && key && value &&
		    strlen(section) && strlen(key)) {
			GList *sect, *k;
			struct config_key *ck;

			/* NULL (empty list) if not found */
			sect = g_tree_lookup(config->sections, section);
			k = g_list_find_custom(sect, key,
					       compare_key_string);
			if (k != NULL)
				ck = k->data;
			else {
				ck = g_malloc(sizeof (*ck));
				ck->key = key;
				ck->values = NULL;
				sect = g_list_append(sect, ck);
				g_tree_insert(config->sections, section, sect);
			}
			/* add the value to the list if it's not
			 * already in the list. */
			if (g_list_index(ck->values, value) == -1)
				ck->values = g_list_append(ck->values, value);
		}

	}
	g_free(data);

	return TRUE;


 err_data:
	g_free(data);
 err_config:
	g_free(config);
	close(fd);
 err:
	return FALSE;
}

static gboolean
gather_values(gpointer key, gpointer value, gpointer xdata)
{
	GList **data;

	data = xdata;
	*data = g_list_append(*data, value);
	return FALSE;
}

/* Free a configuration context structure. */
void
lu_cfg_done(struct lu_context *context)
{
	struct config_config *config = NULL;
	GList *sections, *sect;

	g_assert(context != NULL);
	g_assert(context->config != NULL);

	config = (struct config_config *) context->config;

	sections = NULL;
	g_tree_foreach(config->sections, gather_values, &sections);
	g_tree_destroy(config->sections);
	for (sect = sections; sect != NULL; sect = sect->next) {
		GList *key;

		for (key = sect->data; key != NULL; key = key->next) {
			struct config_key *ck;
			
			ck = key->data;
			g_list_free(ck->values);
			g_free(ck);
		}
		g_list_free(sect->data);
	}
	g_list_free(sections);
	/* Free the cache, the file contents, and finally the config structure
	 * itself. */
	config->cache->free(config->cache);
	g_free(config);
	context->config = NULL;
}

/* Read a specific key from the stored configuration, and return a list of
 * the values.  The list must be freed. */
GList *
lu_cfg_read(struct lu_context *context, const char *key,
	    const char *default_value)
{
	struct config_config *config;
	char *section, *slash, *def;
	GList *sect, *ret = NULL, *k;

	g_assert(context != NULL);
	g_assert(context->config != NULL);
	g_assert(key != NULL);
	g_assert(strlen(key) > 0);

	config = (struct config_config *) context->config;

	slash = strchr(key, '/');
	if (slash == NULL)
		goto end;

	section = g_strndup(key, slash - key);
	/* NULL (empty list) if not found */
	sect = g_tree_lookup(config->sections, section);
	g_free(section);
	k = g_list_find_custom(sect, slash + 1, compare_key_string);
	if (k != NULL) {
		struct config_key *ck;

		ck = k->data;
		ret = g_list_copy(ck->values);
	}
	
 end:
	/* If we still don't have data, return the default answer. */
	if (ret == NULL) {
		if (default_value != NULL) {
			def = context->scache->cache(context->scache,
						     default_value);
			ret = g_list_append(ret, def);
		}
	}

	return ret;
}

/* Read the list of keys in a particular section of the file. */
GList *
lu_cfg_read_keys(struct lu_context * context, const char *parent_key)
{
	struct config_config *config;
	GList *sect, *ret = NULL;

	g_assert(context != NULL);
	g_assert(context->config != NULL);
	g_assert(parent_key != NULL);
	g_assert(strlen(parent_key) > 0);

	config = (struct config_config *) context->config;

	/* NULL (empty list) if not found */
	for (sect = g_tree_lookup(config->sections, parent_key); sect != NULL;
	     sect = sect->next) {
		struct config_key *ck;

		ck = sect->data;
		ret = g_list_append(ret, ck->key);
	}

	return ret;
}

/* Read a configuration entry, and return no more than one value. */
const char *
lu_cfg_read_single(struct lu_context *context, const char *key,
		   const char *default_value)
{
	GList *answers = NULL;
	const char *ret = NULL;

	g_assert(context != NULL);
	g_assert(context->config != NULL);

	ret = context->scache->cache(context->scache, default_value);

	/* Read the whole list. */
	answers = lu_cfg_read(context, key, NULL);
	if (answers && answers->data) {
		/* Save the first value, and free the list. */
		ret = context->scache->cache(context->scache, answers->data);
		g_list_free(answers);
	}

	return ret;
}
