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
	char *data;
};

/* Initialize the configuration structure. */
gboolean
lu_cfg_init(struct lu_context *context, struct lu_error **error)
{
	int fd;
	struct stat st;
	const char *filename = SYSCONFDIR "/libuser.conf";
	struct config_config *config = NULL;
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
	config->data = g_malloc0(st.st_size + 1);
	if (read(fd, config->data, st.st_size) != st.st_size) {
		lu_error_new(error, lu_error_read,
			     _("could not read configuration file `%s': %s"),
			     filename, strerror(errno));
		goto err_data;
	}
	close(fd);

	/* Finish up. */
	config->cache = lu_string_cache_new(FALSE);
	context->config = config;

	return TRUE;


 err_data:
	g_free(config->data);
 err_config:
	g_free(config);
	close(fd);
 err:
	return FALSE;
}

/* Free a configuration context structure. */
void
lu_cfg_done(struct lu_context *context)
{
	struct config_config *config = NULL;

	g_assert(context != NULL);
	g_assert(context->config != NULL);

	config = (struct config_config *) context->config;

	/* Free the cache, the file contents, and finally the config structure
	 * itself. */
	config->cache->free(config->cache);
	g_free(config->data);
	g_free(config);
	context->config = NULL;
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

/* Read a specific key from the stored configuration, and return a list of
 * the values.  The list must be freed. */
GList *
lu_cfg_read(struct lu_context *context, const char *key,
	    const char *default_value)
{
	struct config_config *config;
	char *data = NULL, *line, *xstrtok_ptr, *def;
	char *section = NULL, *k = NULL, *value = NULL, *tmp;
	GList *ret = NULL;

	g_assert(context != NULL);
	g_assert(context->config != NULL);
	g_assert(key != NULL);
	g_assert(strlen(key) > 0);

	config = (struct config_config *) context->config;

	/* If we have no configuration, just return the default value
	 * in a list of its own. */
	if (config->data == NULL) {
		if (default_value != NULL) {
			def = context->scache->cache(context->scache,
						     default_value);
			return g_list_append(NULL, def);
		} else {
			return NULL;
		}
	}

	/* Create a copy of the stored configuration with which we can mess. */
	data = g_strdup(config->data);

	/* Break the pool up line by line to process it. */
	for (line = strtok_r(data, "\n", &xstrtok_ptr);
	     line != NULL;
	     line = strtok_r(NULL, "\n", &xstrtok_ptr)) {
		/* See what this line contains. */
		process_line(line, config->cache, &section, &k, &value);

		/* If we have a valid line, */
		if (section && k && value &&
		    strlen(section) && strlen(k) && strlen(value)) {
			/* format the section and key as a path and if the
			 * result matches the requested key, */
			tmp = g_strconcat(section, "/", k, NULL);
			if (g_ascii_strcasecmp(tmp, key) == 0) {
				/* add the value to the list if it's not
				 * already in the list. */
				if (g_list_index(ret, value) == -1) {
					ret = g_list_append(ret, value);
				}
			}
			g_free(tmp);
		}
	}

	/* Free the working copy. */
	g_free(data);

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
	char *data = NULL, *line, *xstrtok_ptr;
	char *section = NULL, *key = NULL, *value = NULL;
	GList *ret = NULL;

	g_assert(context != NULL);
	g_assert(context->config != NULL);
	g_assert(parent_key != NULL);
	g_assert(strlen(parent_key) > 0);

	config = (struct config_config *) context->config;

	if (config->data) {
		/* Create a working copy of the memory pool which we can
		 * modify safely. */
		data = g_strdup(config->data);
		for (line = strtok_r(data, "\n", &xstrtok_ptr);
		     line != NULL;
		     line = strtok_r(NULL, "\n", &xstrtok_ptr)) {
			/* Process this line. */
			process_line(line, config->cache,
				     &section, &key, &value);
			/* If we have a section and a key, */
			if (section && key && strlen(section) && strlen(key)) {
				/* and the parent key matches the one which the
				 * application asked us to list, */
				if (g_ascii_strcasecmp(section, parent_key) == 0) {
					/* and it's not already in the list, */
					if (g_list_index(ret, key) == -1) {
						/* add it to the list. */
						ret = g_list_append(ret, key);
					}
				}
			}
		}
		/* Free the pool. */
		g_free(data);
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
