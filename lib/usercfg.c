#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <libuser/user_private.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

struct config_config {
	struct lu_string_cache *cache;
	char *data;
};

gboolean
lu_cfg_init(struct lu_context *context)
{
	int fd;
	struct stat st;
	const char *filename = SYSCONFDIR "/libuser.conf";
	struct config_config *config = NULL;

	g_return_val_if_fail(context != NULL, FALSE);

	config = g_malloc0(sizeof(struct config_config));
	config->cache = lu_string_cache_new(TRUE);

#ifdef DEBUG
	if(getenv("LIBUSER_CONF")) {
		filename = getenv("LIBUSER_CONF");
	}
#endif

	fd = open(filename, O_RDONLY);
	if(fd != -1) {
		if(fstat(fd, &st) != -1) {
			config->data = g_malloc0(st.st_size + 1);
			read(fd, config->data, st.st_size);
		}
		close(fd);
	}

	context->config = config;

	return TRUE;
}

gboolean
lu_cfg_done(struct lu_context *context)
{
	struct config_config *config = NULL;

	g_return_val_if_fail(context != NULL, FALSE);

	if(context->config) {
		config = (struct config_config*) context->config;
		config->cache->free(config->cache);
		g_free(config->data);
		g_free(config);
		context->config = NULL;
		return TRUE;
	}

	return FALSE;
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

	while(isspace(*line) && (*line != '\0')) {
		line++;
	}
	if(*line == '#') {
		return;
	}
	if(*line == '[') {
		line++;
		p = strchr(line, ']');
		if(p) {
			tmp = g_strndup(line, p - line);
			*section = cache->cache(cache, tmp);
			g_free(tmp);
			*key = NULL;
			*value = NULL;
		}
		return;
	}
	if(strchr(line, '=')) {
		p = strchr(line, '=');

		p--;
		while(isspace(*p) && (p > line)) {
			p--;
		}

		tmp = g_strndup(line, p - line + 1);
		*key = cache->cache(cache, tmp);
		g_free(tmp);

		line = strchr(line, '=');
		line++;
		while(isspace(*line) && (*line != '\0')) {
			line++;
		}

		p = line + strlen(line);

		p--;
		while(isspace(*p) && (p > line)) {
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

	g_return_val_if_fail(context != NULL, NULL);
	g_return_val_if_fail(context->config != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);
	g_return_val_if_fail(strlen(key) > 0, NULL);

	config = (struct config_config*) context->config;

	if(config->data == NULL) {
		if(default_value) {
			return g_list_append(NULL, (char*)default_value);
		} else {
			return NULL;
		}
	} else {
		data = g_strdup(config->data);
		for(line = strtok_r(data, "\n", &xstrtok_ptr);
		    line;
		    line = strtok_r(NULL, "\n", &xstrtok_ptr)) {
			process_line(line, config->cache, &section, &k, &value);
			if(section && key && value &&
			   strlen(section) && strlen(key) && strlen(value)) {
				tmp = g_strconcat(section, "/", k, NULL);
				if(g_strcasecmp(tmp, key) == 0) {
					if(g_list_index(ret, value) == -1) {
						ret = g_list_append(ret, value);
					}
				}
				g_free(tmp);
			}
		}
		if(ret == NULL) {
			if(default_value) {
				ret = g_list_append(ret, (char*)default_value);
			}
		}
	}

	return ret;
}

GList *
lu_cfg_read_keys(struct lu_context *context, const char *parent_key)
{
	struct config_config *config;
	char *data = NULL, *line, *xstrtok_ptr;
	char *section = NULL, *key = NULL, *value = NULL;
	GList *ret = NULL;

	g_return_val_if_fail(context != NULL, NULL);
	g_return_val_if_fail(context->config != NULL, NULL);
	g_return_val_if_fail(parent_key != NULL, NULL);
	g_return_val_if_fail(strlen(parent_key) > 0, NULL);

	config = (struct config_config*) context->config;

	if(config->data) {
		data = g_strdup(config->data);
		for(line = strtok_r(data, "\n", &xstrtok_ptr);
		    line;
		    line = strtok_r(NULL, "\n", &xstrtok_ptr)) {
			process_line(line, config->cache,
				     &section, &key, &value);
			if(section && key && strlen(section) && strlen(key)) {
				if(g_strcasecmp(section, parent_key) == 0) {
					if(g_list_index(ret, key) == -1) {
						ret = g_list_append(ret, key);
					}
				}
			}
		}
		g_free(data);
	}
	return ret;
}
