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
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/libuser/user_private.h"
#include "util.h"

#ifdef HAVE___SECURE_GETENV
#define getenv(string) __secure_getenv(string)
#endif

struct config_config {
	struct lu_string_cache *cache;
	char *data;
};

gboolean
lu_cfg_init(struct lu_context *context, struct lu_error **error)
{
	int fd;
	struct stat st;
	const char *filename = SYSCONFDIR "/libuser.conf";
	struct config_config *config = NULL;

	g_assert(context != NULL);

	if ((getuid() == geteuid()) && (getgid() == getegid())) {
		const char *t = getenv("LIBUSER_CONF");
		if (t != NULL) {
			filename = t;
		}
	}

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("could not open configuration file `%s': %s"),
			     filename, strerror(errno));
		return FALSE;
	}

	config = g_malloc0(sizeof(struct config_config));
	if (fstat(fd, &st) != -1) {
		config->data = g_malloc0(st.st_size + 1);
		read(fd, config->data, st.st_size);
	}
	close(fd);

	config->cache = lu_string_cache_new(FALSE);
	context->config = config;

	return TRUE;
}

void
lu_cfg_done(struct lu_context *context)
{
	struct config_config *config = NULL;

	g_assert(context != NULL);
	g_assert(context->config != NULL);

	config = (struct config_config *) context->config;
	config->cache->free(config->cache);
	g_free(config->data);
	g_free(config);
	context->config = NULL;
}

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

	while (isspace(*line) && (*line != '\0')) {
		line++;
	}
	if (*line == '#') {
		return;
	}
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
	if (strchr(line, '=')) {
		p = strchr(line, '=');

		p--;
		while (isspace(*p) && (p > line)) {
			p--;
		}

		tmp = g_strndup(line, p - line + 1);
		*key = cache->cache(cache, tmp);
		g_free(tmp);

		line = strchr(line, '=');
		line++;
		while (isspace(*line) && (*line != '\0')) {
			line++;
		}

		p = line + strlen(line);

		p--;
		while (isspace(*p) && (p > line)) {
			p--;
		}

		tmp = g_strndup(line, p - line + 1);
		*value = cache->cache(cache, tmp);
		g_free(tmp);
	}
}

GList *
lu_cfg_read(struct lu_context *context, const char *key,
	    const char *default_value)
{
	struct config_config *config;
	char *data = NULL, *line, *xstrtok_ptr;
	char *section = NULL, *k = NULL, *value = NULL, *tmp;
	GList *ret = NULL;

	g_assert(context != NULL);
	g_assert(context->config != NULL);
	g_assert(key != NULL);
	g_assert(strlen(key) > 0);

	config = (struct config_config *) context->config;

	if (config->data == NULL) {
		if (default_value != NULL) {
			return g_list_append(NULL, (char *) default_value);
		} else {
			return NULL;
		}
	} else {
		data = g_strdup(config->data);
		for (line = strtok_r(data, "\n", &xstrtok_ptr);
		     line != NULL;
		     line = strtok_r(NULL, "\n", &xstrtok_ptr)) {
			process_line(line, config->cache, &section, &k,
				     &value);
			if (section && key && value && strlen(section)
			    && strlen(key) && strlen(value)) {
				tmp = g_strconcat(section, "/", k, NULL);
				if (g_ascii_strcasecmp(tmp, key) == 0) {
					if (g_list_index(ret, value) == -1) {
						ret =
						    g_list_append(ret,
								  value);
					}
				}
				g_free(tmp);
			}
		}
		g_free(data);
		if (ret == NULL) {
			if (default_value != NULL) {
				ret =
				    g_list_append(ret,
						  (char *) default_value);
			}
		}
	}

	return ret;
}

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
		data = g_strdup(config->data);
		for (line = strtok_r(data, "\n", &xstrtok_ptr);
		     line != NULL;
		     line = strtok_r(NULL, "\n", &xstrtok_ptr)) {
			process_line(line, config->cache, &section,
				     &key, &value);
			if (section && key && strlen(section)
			    && strlen(key)) {
				if (g_ascii_strcasecmp(section, parent_key) == 0) {
					if (g_list_index(ret, key) == -1) {
						ret =
						    g_list_append(ret,
								  key);
					}
				}
			}
		}
		g_free(data);
	}
	return ret;
}

const char *
lu_cfg_read_single(struct lu_context *context, const char *key,
		   const char *default_value)
{
	GList *answers = NULL;
	const char *ret = NULL;

	g_assert(context != NULL);
	g_assert(context->config != NULL);

	ret = context->scache->cache(context->scache, default_value);

	answers = lu_cfg_read(context, key, NULL);
	if (answers && answers->data) {
		ret =
		    context->scache->cache(context->scache, answers->data);
		g_list_free(answers);
	}

	return ret;
}
