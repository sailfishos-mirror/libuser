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
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../include/libuser/user_private.h"

/* Global symbols. */
struct lu_module *
lu_files_init(struct lu_context *context, struct lu_error **error);

struct lu_module *
lu_shadow_init(struct lu_context *context, struct lu_error **error);

/* Guides for parsing and formatting entries in the files we're looking at.  For formatting purposes, these are all arranged
 * in order of ascending positions. */
struct format_specifier {
	int position;
	const char *attribute;
	const char *prefix;
	const char *def;
	gboolean multiple, suppress;
};

static const struct format_specifier
format_passwd[] = {
	{1, LU_USERNAME, NULL, NULL, FALSE, FALSE},
	{2, LU_USERPASSWORD, "{crypt}", "*", FALSE, TRUE},
	{3, LU_UIDNUMBER, NULL, NULL, FALSE, FALSE},
	{4, LU_GIDNUMBER, NULL, NULL, FALSE, FALSE},
	{5, LU_GECOS, NULL, NULL, FALSE, FALSE},
	{6, LU_HOMEDIRECTORY, NULL, NULL, FALSE, FALSE},
	{7, LU_LOGINSHELL, NULL, NULL, FALSE, FALSE},
};
static const size_t
format_passwd_elts = sizeof(format_passwd) / sizeof(format_passwd[0]);

static const struct format_specifier
format_group[] = {
	{1, LU_GROUPNAME, NULL, NULL, FALSE, FALSE},
	{2, LU_USERPASSWORD, "{crypt}", "*", FALSE, TRUE},
	{3, LU_GIDNUMBER, NULL, NULL, TRUE, FALSE},
	{4, LU_MEMBERUID, NULL, NULL, TRUE, FALSE},
};
static const size_t
format_group_elts = sizeof(format_group) / sizeof(format_group[0]);

static const struct format_specifier
format_shadow[] = {
	{1, LU_USERNAME, NULL, NULL, FALSE, FALSE},
	{2, LU_USERPASSWORD, "{crypt}", "*", FALSE, TRUE},
	{3, LU_SHADOWLASTCHANGE, NULL, NULL, FALSE, FALSE},
	{4, LU_SHADOWMIN, NULL, NULL, FALSE, FALSE},
	{5, LU_SHADOWMAX, NULL, NULL, FALSE, FALSE},
	{6, LU_SHADOWWARNING, NULL, NULL, FALSE, FALSE},
	{7, LU_SHADOWINACTIVE, NULL, NULL, FALSE, FALSE},
	{8, LU_SHADOWEXPIRE, NULL, NULL, FALSE, FALSE},
	{9, LU_SHADOWFLAG, NULL, NULL, FALSE, FALSE},
};
static const size_t
format_shadow_elts = sizeof(format_shadow) / sizeof(format_shadow[0]);

static const struct format_specifier
format_gshadow[] = {
	{1, LU_GROUPNAME, NULL, NULL, FALSE, FALSE},
	{2, LU_USERPASSWORD, "{crypt}", "*", FALSE, TRUE},
	{3, LU_ADMINISTRATORUID, NULL, NULL, TRUE, FALSE},
	{4, LU_MEMBERUID, NULL, NULL, TRUE, FALSE},
};
static const size_t
format_gshadow_elts = sizeof(format_gshadow) / sizeof(format_gshadow[0]);

/* Create a backup copy of "filename" named "filename-". */
static gboolean
lu_files_create_backup(const char *filename, struct lu_error **error)
{
	int ifd, ofd;
	char *backupname;
	struct stat ist, ost;
	gpointer ilock, olock;
	char buf[2048];
	size_t len;

	g_assert(filename != NULL);
	g_assert(strlen(filename) > 0);

	ifd = open(filename, O_RDWR);
	if(ifd == -1) {
		lu_error_new(error, lu_error_open, _("couldn't open `%s'"), filename);
		return FALSE;
	}
	
	ilock = lu_util_lock_obtain(ifd, error);
	if(ilock == NULL) {
		return FALSE;
	}

	if(fstat(ifd, &ist) == -1) {
		close(ifd);
		lu_util_lock_free(ifd, ilock);
		close(ifd);
		lu_error_new(error, lu_error_stat, NULL);
		return FALSE;
	}

	backupname = g_strconcat(filename, "-", NULL);
	ofd = open(backupname, O_WRONLY | O_CREAT, ist.st_mode);
	if(ofd == -1) {
		lu_error_new(error, lu_error_open, _("error creating `%s'"), backupname);
		g_free(backupname);
		lu_util_lock_free(ifd, ilock);
		close(ifd);
		return FALSE;
	}

	if((fstat(ofd, &ost) == -1) || !S_ISREG(ost.st_mode)) {
		struct stat st;
		if((stat(backupname, &st) == -1) || !S_ISREG(st.st_mode) || (st.st_dev != ost.st_dev) || (st.st_ino != ost.st_ino)) {
			lu_error_new(error, lu_error_open, _("backup file `%s' was a symlink"), backupname);
			g_free(backupname);
			lu_util_lock_free(ifd, ilock);
			close(ifd);
			close(ofd);
			return FALSE;
		}
		lu_error_new(error, lu_error_stat, NULL);
		g_free(backupname);
		lu_util_lock_free(ifd, ilock);
		close(ifd);
		close(ofd);
		return FALSE;
	}

	olock = lu_util_lock_obtain(ofd, error);
	if(olock == NULL) {
		g_free(backupname);
		lu_util_lock_free(ifd, ilock);
		close(ifd);
		lu_util_lock_free(ofd, olock);
		close(ofd);
		return FALSE;
	}

	fchown(ofd, ist.st_uid, ist.st_gid);
	fchmod(ofd, ist.st_mode);

	do {
		len = read(ifd, buf, sizeof(buf));
		if(len >= 0) {
			write(ofd, buf, len);
		}
	} while(len == sizeof(buf));
	fsync(ofd);
	ftruncate(ofd, lseek(ofd, 0, SEEK_CUR));

	if(fstat(ofd, &ost) == -1) {
		lu_error_new(error, lu_error_stat, NULL);
		g_free(backupname);
		lu_util_lock_free(ifd, ilock);
		close(ifd);
		lu_util_lock_free(ofd, olock);
		close(ofd);
		return FALSE;
	}

	lu_util_lock_free(ifd, ilock);
	close(ifd);
	lu_util_lock_free(ofd, olock);
	close(ofd);

	g_assert(ist.st_size == ost.st_size);

	g_free(backupname);

	return TRUE;
}

/** Parse a string into an ent structure using the elements in the format specifier array. */
static gboolean
parse_generic(const gchar *line, const struct format_specifier *formats, size_t format_count, struct lu_ent *ent)
{
	int i;
	int minimum = 1;
	gchar **v = NULL;

	/* Make sure the line is properly formatted, meaning that it has enough fields in it for us to parse. */
	for(i = 0; i < format_count; i++) {
		minimum = MAX(minimum, formats[i].position);
	}
	v = g_strsplit(line, ":", format_count);
	if(lu_strv_len(v) < minimum - 1) {
		g_warning("entry is incorrectly formatted");
		return FALSE;
	}

	/* Now parse out the fields. */
	for(i = 0; i < format_count; i++) {
		/* Some things we NEVER read. */
		if(formats[i].suppress) {
			continue;
		}
		if(formats[i].multiple) {
			/* Multiple comma-separated values. */
			gchar **w;
			int j;
			lu_ent_clear(ent, formats[i].attribute);
			w = g_strsplit(v[formats[i].position - 1] ?: "", ",", 0);
			lu_ent_clear(ent, formats[i].attribute);
			lu_ent_clear_original(ent, formats[i].attribute);
			for(j = 0; (w != NULL) && (w[j] != NULL); j++) {
				if(formats[i].prefix) {
					char *p;
					p = g_strconcat(formats[i].prefix, w[j], NULL);
					lu_ent_add(ent, formats[i].attribute, p);
					lu_ent_add_original(ent, formats[i].attribute, p);
					g_free(p);
				} else {
					lu_ent_add(ent, formats[i].attribute, w[j]);
					lu_ent_add_original(ent, formats[i].attribute, w[j]);
				}
			}
			g_strfreev(w);
		} else {
			/* This is a single-value field. */
			if(formats[i].prefix) {
				char *p;
				p = g_strconcat(formats[i].prefix, v[formats[i].position - 1], NULL);
				lu_ent_set_original(ent, formats[i].attribute, p);
				lu_ent_set(ent, formats[i].attribute, p);
				g_free(p);
			} else {
				lu_ent_set_original(ent, formats[i].attribute, v[formats[i].position - 1] ?: "");
				lu_ent_set(ent, formats[i].attribute, v[formats[i].position - 1] ?: "");
			}
		}
	}
	return TRUE;
}

/* Parse an entry from /etc/passwd into an ent structure, using the attribute names we know. */
static gboolean
lu_files_parse_user_entry(const gchar *line, struct lu_ent *ent)
{
	return parse_generic(line, format_passwd, format_passwd_elts, ent);
}

/* Parse an entry from /etc/group into an ent structure, using the attribute names we know. */
static gboolean
lu_files_parse_group_entry(const gchar *line, struct lu_ent *ent)
{
	return parse_generic(line, format_group, format_group_elts, ent);
}

/* Parse an entry from /etc/shadow into an ent structure, using the attribute names we know. */
static gboolean
lu_shadow_parse_user_entry(const gchar *line, struct lu_ent *ent)
{
	return parse_generic(line, format_shadow, format_shadow_elts, ent);
}

/* Parse an entry from /etc/shadow into an ent structure, using the attribute names we know. */
static gboolean
lu_shadow_parse_group_entry(const gchar *line, struct lu_ent *ent)
{
	return parse_generic(line, format_gshadow, format_gshadow_elts, ent);
}

typedef gboolean (*parse_fn)(const gchar *line, struct lu_ent *ent);

static gboolean
generic_lookup(struct lu_module *module, const char *base_name, gconstpointer name,
	       parse_fn parser, int field, struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = FALSE;
	gpointer lock;
	const char *dir;
	int fd = -1;
	char *line, *filename, *key;

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(name != NULL);
	g_assert(parser != NULL);
	g_assert(field > 0);
	g_assert(ent != NULL);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	fd = open(filename, O_RDWR);
	if(fd == -1) {
		lu_error_new(error, lu_error_open, NULL);
		return FALSE;
	}

	lock = lu_util_lock_obtain(fd, error);
	if(lock == NULL) {
		return FALSE;
	}

	line = lu_util_line_get_matchingx(fd, (char*) name, field, error);
	if(line == NULL) {
		return FALSE;
	}

	if(line != NULL) {
		ret = parser(line, ent);
		g_free(line);
	}
	lu_util_lock_free(fd, lock);
	close(fd);

	g_free(filename);

	return ret;
}

static gboolean
lu_files_user_lookup_name(struct lu_module *module, gconstpointer name, struct lu_ent *ent, struct lu_error **error)
{
	return generic_lookup(module, "passwd", name, lu_files_parse_user_entry, 1, ent, error);
}

static gboolean
lu_files_user_lookup_id(struct lu_module *module, gconstpointer id, struct lu_ent *ent, struct lu_error **error)
{
	char *key;
	gboolean ret = FALSE;
	key = g_strdup_printf("%d", GPOINTER_TO_INT(id));
	ret = generic_lookup(module, "passwd", key, lu_files_parse_user_entry, 3, ent, error);
	g_free(key);
	return ret;
}

static gboolean
lu_shadow_user_lookup_name(struct lu_module *module, gconstpointer name, struct lu_ent *ent, struct lu_error **error)
{
	return generic_lookup(module, "shadow", name, lu_shadow_parse_user_entry, 1, ent, error);
}

static gboolean
lu_shadow_user_lookup_id(struct lu_module *module, gconstpointer id, struct lu_ent *ent, struct lu_error **error)
{
	char *key;
	GList *values;
	gboolean ret = FALSE;
	key = g_strdup_printf("%d", GPOINTER_TO_INT(id));
	ret = lu_files_user_lookup_id(module, id, ent, error);
	if(ret) {
		values = lu_ent_get(ent, LU_USERNAME);
		if(values && values->data) {
			ret = generic_lookup(module, "shadow", values->data, lu_shadow_parse_user_entry, 1, ent, error);
		}
	}
	g_free(key);
	return ret;
}

static gboolean
lu_files_group_lookup_name(struct lu_module *module, gconstpointer name, struct lu_ent *ent, struct lu_error **error)
{
	return generic_lookup(module, "group", name, lu_files_parse_group_entry, 1, ent, error);
}

static gboolean
lu_files_group_lookup_id(struct lu_module *module, gconstpointer id, struct lu_ent *ent, struct lu_error **error)
{
	char *key;
	gboolean ret = FALSE;
	key = g_strdup_printf("%d", GPOINTER_TO_INT(id));
	ret = generic_lookup(module, "group", key, lu_files_parse_group_entry, 3, ent, error);
	g_free(key);
	return ret;
}

static gboolean
lu_shadow_group_lookup_name(struct lu_module *module, gconstpointer name, struct lu_ent *ent, struct lu_error **error)
{
	return generic_lookup(module, "gshadow", name, lu_shadow_parse_group_entry, 1, ent, error);
}

static gboolean
lu_shadow_group_lookup_id(struct lu_module *module, gconstpointer id, struct lu_ent *ent, struct lu_error **error)
{
	char *key;
	GList *values;
	gboolean ret = FALSE;
	key = g_strdup_printf("%d", GPOINTER_TO_INT(id));
	ret = lu_files_group_lookup_id(module, id, ent, error);
	if(ret) {
		values = lu_ent_get(ent, LU_GROUPNAME);
		if(values && values->data) {
			ret = generic_lookup(module, "gshadow", values->data, lu_shadow_parse_group_entry, 1, ent, error);
		}
	}
	g_free(key);
	return ret;
}

/* Format a line for the user/group, using the information in ent, using formats to guide the formatting. */
static char *
format_generic(struct lu_ent *ent, const struct format_specifier *formats, size_t format_count)
{
	GList *l;
	char *ret = NULL, *p;
	int i, j;

	g_return_val_if_fail(ent != NULL, NULL);

	for(i = 0; i < format_count; i++) {
		/* Add a separator if we need to. */
		if(i > 0) {
			j = formats[i].position - formats[i - 1].position;
			while(j-- > 0) {
				p = g_strconcat(ret, ":", NULL);
				if(ret) {
					g_free(ret);
				}
				ret = p;
			}
		}
		/* Get the attribute data. */
		l = lu_ent_get(ent, formats[i].attribute);
		if(l == NULL) {
			/* Check for a default value. */
			if(formats[i].def != NULL) {
				/* Use the default listed in the format
				 * specifier. */
				l = g_list_append(g_list_alloc(), ent->vcache->cache(ent->vcache, formats[i].def));
			}
		}
		if(!formats[i].multiple) {
			/* It's a single-item entry, add it. */
			if(l != NULL) {
				p = l ? (char*)l->data : NULL;
				if(p == NULL) {
					p = "";
				}
				/* If there's a prefix, strip it. */
				if(formats[i].prefix) {
					if(strncmp(p, formats[i].prefix, strlen(formats[i].prefix)) == 0) {
						p += strlen(formats[i].prefix);
					}
				}
				/* Tack the data onto the end. */
				p = g_strconcat(ret ?: "", p, NULL);
				if(ret) {
					g_free(ret);
				}
				ret = p;
			}
		} else {
			/* Separate data with a comma after the first datum. */
			gboolean postfirst = FALSE;
			while(l != NULL) {
				p = (char*)l->data;
				if(p == NULL) {
					p = "";
				}
				/* If there's a prefix, strip it. */
				if(formats[i].prefix) {
					if(strncmp(p, formats[i].prefix, strlen(formats[i].prefix)) == 0) {
						p += strlen(formats[i].prefix);
					}
				}
				/* Tack the data onto the end. */
				p = g_strconcat(ret ?: "", postfirst ? "," : "", p, NULL);
				if(ret) {
					g_free(ret);
				}
				ret = p;

				/* Go on to the next data item. */
				l = g_list_next(l);
				postfirst = TRUE;
			}
		}
	}
	p = g_strconcat(ret, "\n", NULL);
	if(ret) {
		g_free(ret);
	}
	ret = p;

	return ret;
}

/* Create a line for /etc/passwd using data in the lu_ent structure. */
static char *
lu_files_format_user(struct lu_ent *ent)
{
	return format_generic(ent, format_passwd, format_passwd_elts);
}

/* Create a line for /etc/group using data in the lu_ent structure. */
static char *
lu_files_format_group(struct lu_ent *ent)
{
	return format_generic(ent, format_group, format_group_elts);
}

/* Create a line for /etc/shadow using data in the lu_ent structure. */
static char *
lu_shadow_format_user(struct lu_ent *ent)
{
	return format_generic(ent, format_shadow, format_shadow_elts);
}

/* Create a line for /etc/gshadow using data in the lu_ent structure. */
static char *
lu_shadow_format_group(struct lu_ent *ent)
{
	return format_generic(ent, format_gshadow, format_gshadow_elts);
}

typedef char * (*format_fn)(struct lu_ent *ent);

static gboolean
generic_add(struct lu_module *module, const char *base_name, format_fn formatter, struct lu_ent *ent, struct lu_error **error)
{
	const char *dir;
	char *key, *line, *filename, *contents;
	int fd;
	struct stat st;
	off_t offset;
	gpointer lock;
	gboolean ret = FALSE;

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(formatter != NULL);
	g_assert(ent != NULL);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if(lu_files_create_backup(filename, error) == FALSE) {
		g_free(filename);
		return FALSE;
	}

	fd = open(filename, O_RDWR);
	if(fd == -1) {
		lu_error_new(error, lu_error_open, NULL);
		g_free(filename);
		return FALSE;
	}

	lock = lu_util_lock_obtain(fd, error);
	if(lock == NULL) {
		close(fd);
		g_free(filename);
		return FALSE;
	}

	if(fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat, NULL);
		lu_util_lock_free(fd, lock);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	line = formatter(ent);
	contents = g_malloc0(st.st_size + 1 + strlen(line) + 1);

	if(line && strchr(line, ':')) {
		char *fragment1, *fragment2;
		fragment1 = g_strndup(line, strchr(line, ':') - line + 1);
		fragment2 = g_strconcat("\n", fragment1, NULL);
		if(read(fd, contents, st.st_size) != st.st_size) {
			lu_error_new(error, lu_error_read, NULL);
			lu_util_lock_free(fd, lock);
			close(fd);
			g_free(fragment1);
			g_free(fragment2);
			g_free(contents);
			g_free(filename);
			return FALSE;
		}
		if(strncmp(contents, fragment1, strlen(fragment1)) == 0) {
			lu_error_new(error, lu_error_generic, _("entry already present in file"));
			lu_util_lock_free(fd, lock);
			close(fd);
			g_free(fragment1);
			g_free(fragment2);
			g_free(contents);
			g_free(filename);
			return FALSE;
		} else {
			if(strstr(contents, fragment2) != NULL) {
				lu_error_new(error, lu_error_generic, _("entry already present in file"));
				lu_util_lock_free(fd, lock);
				close(fd);
				g_free(fragment1);
				g_free(fragment2);
				g_free(contents);
				g_free(filename);
				return FALSE;
			} else {
				int r;
				offset = lseek(fd, 0, SEEK_END);
				if(offset == -1) {
					lu_error_new(error, lu_error_write, NULL);
					lu_util_lock_free(fd, lock);
					close(fd);
					g_free(fragment1);
					g_free(fragment2);
					g_free(contents);
					g_free(filename);
					return FALSE;
				}
				r = write(fd, line, strlen(line));
				if(r != strlen(line)) {
					lu_error_new(error, lu_error_write, NULL);
					ftruncate(fd, offset);
					lu_util_lock_free(fd, lock);
					close(fd);
					g_free(fragment1);
					g_free(fragment2);
					g_free(contents);
					g_free(filename);
					return FALSE;
				} else {
					ret = TRUE;
				}
			}
		}
		g_free(fragment1);
		g_free(fragment2);
	}
	g_free(contents);
	lu_util_lock_free(fd, lock);
	close(fd);
	g_free(filename);

	return ret;
}

static gboolean
lu_files_user_add(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = generic_add(module, "passwd", lu_files_format_user, ent, error);
	return ret;
}

static gboolean
lu_shadow_user_add(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = generic_add(module, "shadow", lu_shadow_format_user, ent, error);
	if(ret) {
		lu_ent_set(ent, LU_USERPASSWORD, "{crypt}x");
	}
	return ret;
}

static gboolean
lu_files_group_add(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = generic_add(module, "group", lu_files_format_group, ent, error);
	return ret;
}

static gboolean
lu_shadow_group_add(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = generic_add(module, "gshadow", lu_shadow_format_group, ent, error);
	if(ret) {
		lu_ent_set(ent, LU_USERPASSWORD, "{crypt}x");
	}
	return ret;
}

static gboolean
generic_mod(struct lu_module *module, const char *base_name, const struct format_specifier *formats, size_t format_count,
	    struct lu_ent *ent, struct lu_error **error)
{
	char *filename = NULL, *key = NULL;
	int fd = -1;
	int i;
	const char *dir = NULL;
	char *p, *q, *new_value;
	GList *name = NULL, *values = NULL, *l;
	gboolean ret = FALSE;
	gpointer lock = NULL;

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(formats != NULL);
	g_assert(format_count > 0);
	g_assert(ent != NULL);
	g_assert((ent->type == lu_user) || (ent->type == lu_group));

	if(ent->type == lu_user) {
		name = lu_ent_get_original(ent, LU_USERNAME);
		if(name == NULL) {
			lu_error_new(error, lu_error_generic, _("entity object has no %s attribute"), LU_USERNAME);
			return FALSE;
		}
	}
	if(ent->type == lu_group) {
		name = lu_ent_get_original(ent, LU_GROUPNAME);
		if(name == NULL) {
			lu_error_new(error, lu_error_generic, _("entity object has no %s attribute"), LU_GROUPNAME);
			return FALSE;
		}
	}
	g_assert(name != NULL);
	g_assert(name->data != NULL);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if(lu_files_create_backup(filename, error) == FALSE) {
		g_free(filename);
		return FALSE;
	}

	fd = open(filename, O_RDWR);
	if(fd == -1) {
		lu_error_new(error, lu_error_read, NULL);
		g_free(filename);
		return FALSE;
	}

	lock = lu_util_lock_obtain(fd, error);
	if(lock == NULL) {
		close(fd);
		g_free(filename);
		return FALSE;
	}

	for(i = 0; i < format_count; i++) {
		if(formats[i].suppress) {
			continue;
		}
		values = lu_ent_get(ent, formats[i].attribute);
		new_value = NULL;
		if(!formats[i].multiple) {
			p = (char*)values->data ?: "";
			/* if there's a prefix, strip it */
			if(formats[i].prefix) {
				if(strncmp(p, formats[i].prefix, strlen(formats[i].prefix)) == 0) {
					p += strlen(formats[i].prefix);
				}
			}
			/* make a copy of the data */
			new_value = g_strdup(p);
		} else {
			for(l = values; l && l->data; l = g_list_next(l)) {
				p = l->data;
				/* if there's a prefix, strip it */
				if(formats[i].prefix) {
					if(strncmp(p, formats[i].prefix, strlen(formats[i].prefix)) == 0) {
						p += strlen(formats[i].prefix);
					}
				}
				if(new_value) {
					q = g_strconcat(new_value, ",", NULL);
				} else {
					q = "";
				}
				q = g_strconcat(q, p, NULL);
				if(new_value) {
					g_free(new_value);
				}
				new_value = q;
			}
		}
		ret = lu_util_field_write(fd, (const char*)name->data, formats[i].position, new_value, error);
		g_free(new_value);
		if(ret == FALSE) {
			lu_util_lock_free(fd, lock);
			close(fd);
			g_free(filename);
			return FALSE;
		}
		/* we may have just renamed the account (we're safe assuming
		 * the new name is correct here because if we renamed, we did
		 * it first), so switch to using the account's name */
		if(ent->type == lu_user) {
			name = lu_ent_get(ent, LU_USERNAME);
			if(name == NULL) {
				lu_error_new(error, lu_error_generic, _("entity object has no %s attribute"), LU_USERNAME);
				lu_util_lock_free(fd, lock);
				close(fd);
				g_free(filename);
				return FALSE;
			}
		}
		if(ent->type == lu_group) {
			name = lu_ent_get(ent, LU_GROUPNAME);
			if(name == NULL) {
				lu_error_new(error, lu_error_generic, _("entity object has no %s attribute"), LU_GROUPNAME);
				lu_util_lock_free(fd, lock);
				close(fd);
				g_free(filename);
				return FALSE;
			}
		}
	}

	lu_util_lock_free(fd, lock);
	close(fd);
	g_free(filename);

	return TRUE;
}

static gboolean
lu_files_user_mod(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_mod(module, "passwd", format_passwd, format_passwd_elts, ent, error);
}

static gboolean
lu_files_group_mod(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_mod(module, "group", format_group, format_group_elts, ent, error);
}

static gboolean
lu_shadow_user_mod(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = generic_mod(module, "shadow", format_shadow, format_shadow_elts, ent, error);
	if(ret) {
		lu_ent_set(ent, LU_USERPASSWORD, "{crypt}x");
	}
	return ret;
}

static gboolean
lu_shadow_group_mod(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = generic_mod(module, "gshadow", format_gshadow, format_gshadow_elts, ent, error);
	if(ret) {
		lu_ent_set(ent, LU_USERPASSWORD, "{crypt}x");
	}
	return ret;
}

static gboolean
generic_del(struct lu_module *module, const char *base_name, struct lu_ent *ent, struct lu_error **error)
{
	GList *name = NULL;
	char *contents = NULL, *filename = NULL, *line, *key = NULL, *tmp;
	const char *dir;
	struct stat st;
	int fd = -1;
	gpointer lock = NULL;

	if(ent->type == lu_user)
		name = lu_ent_get_original(ent, LU_USERNAME);
	if(ent->type == lu_group)
		name = lu_ent_get_original(ent, LU_GROUPNAME);
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(ent != NULL);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if(lu_files_create_backup(filename, error) == FALSE) {
		g_free(filename);
		return FALSE;
	}

	fd = open(filename, O_RDWR);
	if(fd == -1) {
		lu_error_new(error, lu_error_open, NULL);
		g_free(filename);
		return FALSE;
	}

	lock = lu_util_lock_obtain(fd, error);
	if(lock == NULL) {
		close(fd);
		g_free(filename);
		return FALSE;
	}

	if(fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat, NULL);
		lu_util_lock_free(fd, lock);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	contents = g_malloc0(st.st_size + 1);
	if(read(fd, contents, st.st_size) != st.st_size) {
		lu_error_new(error, lu_error_read, NULL);
		g_free(contents);
		lu_util_lock_free(fd, lock);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	tmp = g_strdup_printf("%s:", (char*)name->data);
	line = module->scache->cache(module->scache, tmp);
	g_free(tmp);

	if(strncmp(contents, line, strlen(line)) == 0) {
		char *p = strchr(contents, '\n');
		strcpy(contents, p ? (p + 1) : "");
	} else {
		char *p;
		tmp = g_strdup_printf("\n%s:", (char*)name->data);
		line = module->scache->cache(module->scache, tmp);
		g_free(tmp);
		if((p = strstr(contents, line)) != NULL) {
			char *q = strchr(p + 1, '\n');
			strcpy(p + 1, q ? (q + 1) : "");
		}
	}
	if(lseek(fd, 0, SEEK_SET) == -1) {
		lu_error_new(error, lu_error_write, NULL);
		g_free(contents);
		lu_util_lock_free(fd, lock);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	if(write(fd, contents, strlen(contents)) != strlen(contents)) {
		lu_error_new(error, lu_error_write, NULL);
		g_free(contents);
		lu_util_lock_free(fd, lock);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	ftruncate(fd, strlen(contents));
	g_free(contents);
	lu_util_lock_free(fd, lock);
	close(fd);
	g_free(filename);

	return TRUE;
}

static gboolean
lu_files_user_del(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_del(module, "passwd", ent, error);
}

static gboolean
lu_files_group_del(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_del(module, "group", ent, error);
}

static gboolean
lu_shadow_user_del(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = generic_del(module, "shadow", ent, error);
	if(ret) {
		lu_ent_set(ent, LU_USERPASSWORD, "{crypt}x");
	}
	return ret;
}

static gboolean
lu_shadow_group_del(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = generic_del(module, "gshadow", ent, error);
	if(ret) {
		lu_ent_set(ent, LU_USERPASSWORD, "{crypt}x");
	}
	return ret;
}

/** Return the "locked" or "unlocked" version of the cryptedPassword string, depending on whether or not lock is true. */
static char *
lock_process(char *cryptedPassword, gboolean lock, struct lu_ent *ent)
{
	char *ret = NULL;
	if(lock) {
		if(cryptedPassword[0] != '!') {
			cryptedPassword = g_strconcat("!", cryptedPassword, NULL);
			ret = ent->vcache->cache(ent->vcache, cryptedPassword);
			g_free((char*)cryptedPassword);
		} else {
			ret = cryptedPassword;
		}
	} else {
		if(cryptedPassword[0] == '!') {
			ret = ent->vcache->cache(ent->vcache, cryptedPassword + 1);
		} else {
			ret = cryptedPassword;
		}
	}
	return ret;
}

static gboolean
generic_lock(struct lu_module *module, const char *base_name, int field,
	     struct lu_ent *ent, gboolean lock_or_not, struct lu_error **error)
{
	GList *name = NULL;
	char *filename = NULL, *key = NULL;
	const char *dir;
	char *value, *new_value;
	int fd = -1;
	gpointer lock = NULL;
	gboolean ret = FALSE;

	if(ent->type == lu_user)
		name = lu_ent_get_original(ent, LU_USERNAME);
	if(ent->type == lu_group)
		name = lu_ent_get_original(ent, LU_GROUPNAME);
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(ent != NULL);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if(lu_files_create_backup(filename, error) == FALSE) {
		g_free(filename);
		return FALSE;
	}

	fd = open(filename, O_RDWR);
	if(fd == -1) {
		lu_error_new(error, lu_error_open, NULL);
		g_free(filename);
		return FALSE;
	}

	lock = lu_util_lock_obtain(fd, error);
	if(lock == NULL) {
		close(fd);
		g_free(filename);
		return FALSE;
	}

	value = lu_util_field_read(fd, (const char*)name->data, field, error);
	if(value == NULL) {
		lu_util_lock_free(fd, lock);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	new_value = lock_process(value, lock_or_not, ent);
	g_free(value);
	ret = lu_util_field_write(fd, (const char*)name->data, field, new_value, error);
	g_free(new_value);
	if(ret == FALSE) {
		lu_util_lock_free(fd, lock);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	lu_util_lock_free(fd, lock);
	close(fd);
	g_free(filename);

	return TRUE;
}

static gboolean
generic_islocked(struct lu_module *module, const char *base_name, int field,
		 struct lu_ent *ent, gboolean lock_or_not, struct lu_error **error)
{
	GList *name = NULL;
	char *filename = NULL, *key = NULL;
	const char *dir;
	char *value;
	int fd = -1;
	gpointer lock = NULL;
	gboolean ret = FALSE;

	if(ent->type == lu_user)
		name = lu_ent_get_original(ent, LU_USERNAME);
	if(ent->type == lu_group)
		name = lu_ent_get_original(ent, LU_GROUPNAME);
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(ent != NULL);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if(lu_files_create_backup(filename, error) == FALSE) {
		g_free(filename);
		return FALSE;
	}

	fd = open(filename, O_RDWR);
	if(fd == -1) {
		lu_error_new(error, lu_error_open, NULL);
		g_free(filename);
		return FALSE;
	}

	lock = lu_util_lock_obtain(fd, error);
	if(lock == NULL) {
		close(fd);
		g_free(filename);
		return FALSE;
	}

	value = lu_util_field_read(fd, (const char*)name->data, field, error);
	if(value == NULL) {
		lu_util_lock_free(fd, lock);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	ret = value[0] == '!';
	g_free(value);

	return ret;
}

static gboolean
lu_files_user_lock(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_lock(module, "passwd", 2, ent, TRUE, error);
}

static gboolean
lu_files_user_unlock(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_lock(module, "passwd", 2, ent, FALSE, error);
}

static gboolean
lu_files_group_lock(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_lock(module, "group", 2, ent, TRUE, error);
}

static gboolean
lu_files_group_unlock(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_lock(module, "group", 2, ent, FALSE, error);
}

static gboolean
lu_shadow_user_lock(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_lock(module, "shadow", 2, ent, TRUE, error);
}

static gboolean
lu_shadow_user_unlock(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_lock(module, "shadow", 2, ent, FALSE, error);
}

static gboolean
lu_files_user_islocked(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_islocked(module, "passwd", 2, ent, FALSE, error);
}

static gboolean
lu_files_group_islocked(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_islocked(module, "group", 2, ent, FALSE, error);
}

static gboolean
lu_shadow_group_lock(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_lock(module, "gshadow", 2, ent, TRUE, error);
}

static gboolean
lu_shadow_group_unlock(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_lock(module, "gshadow", 2, ent, FALSE, error);
}

static gboolean
lu_shadow_user_islocked(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_islocked(module, "shadow", 2, ent, FALSE, error);
}

static gboolean
lu_shadow_group_islocked(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	return generic_islocked(module, "gshadow", 2, ent, FALSE, error);
}

static gboolean
generic_setpass(struct lu_module *module, const char *base_name, int field,
		struct lu_ent *ent, const char *password, struct lu_error **error)
{
	GList *name = NULL;
	char *filename = NULL, *key = NULL;
	const char *dir;
	int fd = -1;
	gpointer lock = NULL;
	gboolean ret = FALSE;

	if(ent->type == lu_user)
		name = lu_ent_get_original(ent, LU_USERNAME);
	if(ent->type == lu_group)
		name = lu_ent_get_original(ent, LU_GROUPNAME);
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(ent != NULL);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if(lu_files_create_backup(filename, error) == FALSE) {
		g_free(filename);
		return FALSE;
	}

	fd = open(filename, O_RDWR);
	if(fd == -1) {
		lu_error_new(error, lu_error_open, NULL);
		g_free(filename);
		return FALSE;
	}

	lock = lu_util_lock_obtain(fd, error);
	if(lock == NULL) {
		close(fd);
		g_free(filename);
		return FALSE;
	}

	if(strncmp(password, "{crypt}", 7) == 0) {
		password = password + 7;
	} else {
		password = lu_make_crypted(password, NULL);
	}

	ret = lu_util_field_write(fd, (const char*)name->data, field, password, error);
	if(ret == FALSE) {
		lu_util_lock_free(fd, lock);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	lu_util_lock_free(fd, lock);
	close(fd);
	g_free(filename);

	return ret;
}

static gboolean
lu_files_user_setpass(struct lu_module *module, struct lu_ent *ent, const char *password, struct lu_error **error)
{
	return generic_setpass(module, "passwd", 2, ent, password, error);
}

static gboolean
lu_files_group_setpass(struct lu_module *module, struct lu_ent *ent, const char *password, struct lu_error **error)
{
	return generic_setpass(module, "group", 2, ent, password, error);
}

static gboolean
lu_shadow_user_setpass(struct lu_module *module, struct lu_ent *ent, const char *password, struct lu_error **error)
{
	gboolean ret;
	ret = generic_setpass(module, "shadow", 2, ent, password, error);
	if(ret) {
		lu_ent_set(ent, LU_USERPASSWORD, "{crypt}x");
	}
	return ret;
}

static gboolean
lu_shadow_group_setpass(struct lu_module *module, struct lu_ent *ent, const char *password, struct lu_error **error)
{
	gboolean ret;
	ret = generic_setpass(module, "gshadow", 2, ent, password, error);
	if(ret) {
		lu_ent_set(ent, LU_USERPASSWORD, "{crypt}x");
	}
	return ret;
}

static GList *
lu_files_enumerate(struct lu_module *module, const char *base_name, const char *pattern, struct lu_error **error)
{
	int fd;
	gpointer lock;
	GList *ret = NULL;
	char buf[2048];
	char *key = NULL, *filename = NULL, *p;
	const char *dir = NULL;
	FILE *fp;

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(pattern != NULL);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	fd = open(filename, O_RDWR);
	if(fd == -1) {
		lu_error_new(error, lu_error_open, NULL);
		g_free(filename);
		return NULL;
	}
	
	lock = lu_util_lock_obtain(fd, error);
	if(lock == NULL) {
		close(fd);
		g_free(filename);
		return NULL;
	}

	fp = fdopen(fd, "r");
	if(fp == NULL) {
		lu_error_new(error, lu_error_open, NULL);
		lu_util_lock_free(fd, lock);
		close(fd);
		g_free(filename);
		return NULL;
	}

	while(fgets(buf, sizeof(buf), fp) != NULL) {
		p = strchr(buf, ':');
		if(p != NULL) {
			*p = '\0';
			p = module->scache->cache(module->scache, buf);
			if(fnmatch(pattern, p, 0) == 0) {
				ret = g_list_append(ret, p);
			}
		}
	}

	lu_util_lock_free(fd, lock);
	fclose(fp);
	g_free(filename);

	return ret;
}

static GList *
lu_files_users_enumerate(struct lu_module *module, const char *pattern, struct lu_error **error)
{
	return lu_files_enumerate(module, "passwd", pattern, error);
}

static GList *
lu_files_groups_enumerate(struct lu_module *module, const char *pattern, struct lu_error **error)
{
	return lu_files_enumerate(module, "group", pattern, error);
}

static GList *
lu_shadow_users_enumerate(struct lu_module *module, const char *pattern, struct lu_error **error)
{
	return NULL;
}

static GList *
lu_shadow_groups_enumerate(struct lu_module *module, const char *pattern, struct lu_error **error)
{
	return NULL;
}

static gboolean
close_module(struct lu_module *module)
{
	g_return_val_if_fail(module != NULL, FALSE);

	module->scache->free(module->scache);
	memset(module, 0, sizeof(struct lu_module));
	g_free(module);
	return TRUE;
}

struct lu_module *
lu_files_init(struct lu_context *context, struct lu_error **error)
{
	struct lu_module *ret = NULL;

	g_return_val_if_fail(context != NULL, FALSE);

	/* Handle authenticating to the data source. */
#ifndef DEBUG
	if(geteuid() != 0) {
		lu_error_new(error, lu_error_privilege, _("Not executing with superuser privileges."));
		return NULL;
	}
#endif

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, "files");

	/* Set the method pointers. */
	ret->user_lookup_name = lu_files_user_lookup_name;
	ret->user_lookup_id = lu_files_user_lookup_id;

	ret->user_add = lu_files_user_add;
	ret->user_mod = lu_files_user_mod;
	ret->user_del = lu_files_user_del;
	ret->user_lock = lu_files_user_lock;
	ret->user_unlock = lu_files_user_unlock;
	ret->user_islocked = lu_files_user_islocked;
	ret->user_setpass = lu_files_user_setpass;
	ret->users_enumerate = lu_files_users_enumerate;

	ret->group_lookup_name = lu_files_group_lookup_name;
	ret->group_lookup_id = lu_files_group_lookup_id;

	ret->group_add = lu_files_group_add;
	ret->group_mod = lu_files_group_mod;
	ret->group_del = lu_files_group_del;
	ret->group_lock = lu_files_group_lock;
	ret->group_unlock = lu_files_group_unlock;
	ret->group_islocked = lu_files_group_islocked;
	ret->group_setpass = lu_files_group_setpass;
	ret->groups_enumerate = lu_files_groups_enumerate;

	ret->close = close_module;

	/* Done. */
	return ret;
}

struct lu_module *
lu_shadow_init(struct lu_context *context, struct lu_error **error)
{
	struct lu_module *ret = NULL;
	struct stat st;
	char *shadow_file;
	char *key;
	const char *dir;

	g_return_val_if_fail(context != NULL, NULL);

	/* Handle authenticating to the data source. */
#ifndef DEBUG
	if(geteuid() != 0) {
		lu_error_new(error, lu_error_privilege, _("Not executing with superuser privileges."));
		return NULL;
	}
#endif
	/* Get the name of the shadow file. */
	key = g_strconcat("shadow", "/directory", NULL);
	dir = lu_cfg_read_single(context, key, "/etc");
	shadow_file = g_strconcat(dir, "/shadow", NULL);
	g_free(key);

	/* Make sure we're actually using shadow passwords on this system. */
	if((stat(shadow_file, &st) == -1) && (errno == ENOENT)) {
		lu_error_new(error, lu_error_config_disabled, _("No shadow file present -- disabling."));
		g_free(shadow_file);
		return NULL;
	}
	g_free(shadow_file);

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, "shadow");

	/* Set the method pointers. */
	ret->user_lookup_name = lu_shadow_user_lookup_name;
	ret->user_lookup_id = lu_shadow_user_lookup_id;

	ret->user_add = lu_shadow_user_add;
	ret->user_mod = lu_shadow_user_mod;
	ret->user_del = lu_shadow_user_del;
	ret->user_lock = lu_shadow_user_lock;
	ret->user_unlock = lu_shadow_user_unlock;
	ret->user_islocked = lu_shadow_user_islocked;
	ret->user_setpass = lu_shadow_user_setpass;
	ret->users_enumerate = lu_shadow_users_enumerate;

	ret->group_lookup_name = lu_shadow_group_lookup_name;
	ret->group_lookup_id = lu_shadow_group_lookup_id;

	ret->group_add = lu_shadow_group_add;
	ret->group_mod = lu_shadow_group_mod;
	ret->group_del = lu_shadow_group_del;
	ret->group_lock = lu_shadow_group_lock;
	ret->group_unlock = lu_shadow_group_unlock;
	ret->group_islocked = lu_shadow_group_islocked;
	ret->group_setpass = lu_shadow_group_setpass;
	ret->groups_enumerate = lu_shadow_groups_enumerate;

	ret->close = close_module;

	/* Done. */
	return ret;
}
