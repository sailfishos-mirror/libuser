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

#define CHUNK_SIZE (LINE_MAX * 4)

/* Guides for parsing and formatting entries in the files we're looking at.
 * For formatting purposes, these are all arranged in order of ascending
 * positions. */
struct format_specifier {
	int position;
	const char *attribute;
	const char *prefix;
	const char *def;
	gboolean multiple, suppress;
};

static const struct format_specifier format_passwd[] = {
	{1, LU_USERNAME, NULL, NULL, FALSE, FALSE},
	{2, LU_USERPASSWORD, "{crypt}", "*", FALSE, TRUE},
	{3, LU_UIDNUMBER, NULL, NULL, FALSE, FALSE},
	{4, LU_GIDNUMBER, NULL, NULL, FALSE, FALSE},
	{5, LU_GECOS, NULL, NULL, FALSE, FALSE},
	{6, LU_HOMEDIRECTORY, NULL, NULL, FALSE, FALSE},
	{7, LU_LOGINSHELL, NULL, NULL, FALSE, FALSE},
};

static const struct format_specifier format_group[] = {
	{1, LU_GROUPNAME, NULL, NULL, FALSE, FALSE},
	{2, LU_USERPASSWORD, "{crypt}", "*", FALSE, TRUE},
	{3, LU_GIDNUMBER, NULL, NULL, FALSE, FALSE},
	{4, LU_MEMBERUID, NULL, NULL, TRUE, FALSE},
};

static const struct format_specifier format_shadow[] = {
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

static const struct format_specifier format_gshadow[] = {
	{1, LU_GROUPNAME, NULL, NULL, FALSE, FALSE},
	{2, LU_USERPASSWORD, "{crypt}", "*", FALSE, TRUE},
	{3, LU_ADMINISTRATORUID, NULL, NULL, TRUE, FALSE},
	{4, LU_MEMBERUID, NULL, NULL, TRUE, FALSE},
};

/* Create a backup copy of "filename" named "filename-". */
static gboolean
lu_files_create_backup(const char *filename,
		       struct lu_error **error)
{
	int ifd, ofd;
	char *backupname;
	struct stat ist, ost;
	char buf[CHUNK_SIZE];
	size_t len;

	g_assert(filename != NULL);
	g_assert(strlen(filename) > 0);

	ifd = open(filename, O_RDWR);
	if (ifd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		return FALSE;
	}

	if (lu_util_lock_obtain(ifd, error) != TRUE) {
		close(ifd);
		return FALSE;
	}

	if (fstat(ifd, &ist) == -1) {
		close(ifd);
		lu_util_lock_free(ifd);
		close(ifd);
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), filename,
			     strerror(errno));
		return FALSE;
	}

	backupname = g_strconcat(filename, "-", NULL);
	ofd = open(backupname, O_WRONLY | O_CREAT, ist.st_mode);
	if (ofd == -1) {
		lu_error_new(error, lu_error_open,
			     _("error creating `%s': %s"), backupname,
			     strerror(errno));
		g_free(backupname);
		lu_util_lock_free(ifd);
		close(ifd);
		return FALSE;
	}

	if ((fstat(ofd, &ost) == -1) || !S_ISREG(ost.st_mode)) {
		struct stat st;
		if ((stat(backupname, &st) == -1) || !S_ISREG(st.st_mode)
		    || (st.st_dev != ost.st_dev)
		    || (st.st_ino != ost.st_ino)) {
			lu_error_new(error, lu_error_open,
				     _("backup file `%s' was a symlink"),
				     backupname);
			g_free(backupname);
			lu_util_lock_free(ifd);
			close(ifd);
			close(ofd);
			return FALSE;
		}
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), backupname,
			     strerror(errno));
		g_free(backupname);
		lu_util_lock_free(ifd);
		close(ifd);
		close(ofd);
		return FALSE;
	}

	if (lu_util_lock_obtain(ofd, error) != TRUE) {
		g_free(backupname);
		lu_util_lock_free(ifd);
		close(ifd);
		lu_util_lock_free(ofd);
		close(ofd);
		return FALSE;
	}

	fchown(ofd, ist.st_uid, ist.st_gid);
	fchmod(ofd, ist.st_mode);

	do {
		len = read(ifd, buf, sizeof(buf));
		if (len >= 0) {
			write(ofd, buf, len);
		}
	} while (len == sizeof(buf));
	fsync(ofd);
	ftruncate(ofd, lseek(ofd, 0, SEEK_CUR));

	if (fstat(ofd, &ost) == -1) {
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), backupname,
			     strerror(errno));
		g_free(backupname);
		lu_util_lock_free(ifd);
		close(ifd);
		lu_util_lock_free(ofd);
		close(ofd);
		return FALSE;
	}

	lu_util_lock_free(ifd);
	close(ifd);
	lu_util_lock_free(ofd);
	close(ofd);

	g_assert(ist.st_size == ost.st_size);

	g_free(backupname);

	return TRUE;
}

static char *
line_read(FILE * fp)
{
	char *p, *buf;
	size_t buf_size = CHUNK_SIZE;
	p = buf = g_malloc0(buf_size);
	while (fgets(p, buf_size - (p - buf) - 1, fp) != NULL) {
		p = buf + strlen(buf);
		if (p > buf) {
			p--;
		}
		if (*p == '\n') {
			break;
		}

		buf_size += CHUNK_SIZE;
		p = g_malloc0(buf_size);
		strcpy(p, buf);
		g_free(buf);
		buf = p;
		p += strlen(p);
	}
	if (strlen(buf) == 0) {
		g_free(buf);
		return NULL;
	} else {
		return buf;
	}
}

/* Parse a string into an ent structure using the elements in the format
 * specifier array. */
static gboolean
parse_generic(const gchar * line, const struct format_specifier *formats,
	      size_t format_count, struct lu_ent *ent)
{
	int i;
	int minimum = 1;
	gchar **v = NULL;

	/* Make sure the line is properly formatted, meaning that it has enough
	 * fields in it for us to parse. */
	for (i = 0; i < format_count; i++) {
		minimum = MAX(minimum, formats[i].position);
	}
	v = g_strsplit(line, ":", format_count);
	if (lu_strv_len(v) < minimum - 1) {
		g_warning("entry is incorrectly formatted");
		return FALSE;
	}

	/* Now parse out the fields. */
	for (i = 0; i < format_count; i++) {
		GValue value;
		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_STRING);
		/* Some things we NEVER read. */
		if (formats[i].suppress) {
			continue;
		}
		if (formats[i].multiple) {
			/* Multiple comma-separated values. */
			gchar **w;
			int j;
			lu_ent_clear(ent, formats[i].attribute);
			w = g_strsplit(v[formats[i].position - 1] ? : "",
				       ",", 0);
			lu_ent_clear(ent, formats[i].attribute);
			lu_ent_clear_current(ent, formats[i].attribute);
			for (j = 0; (w != NULL) && (w[j] != NULL); j++) {
				if (formats[i].prefix) {
					char *p;
					p = g_strconcat(formats[i].prefix,
							w[j], NULL);
					g_value_set_string(&value, p);
					g_free(p);
				} else {
					g_value_set_string(&value, w[j]);
				}
				lu_ent_add(ent, formats[i].attribute, &value);
				lu_ent_add_current(ent, formats[i].attribute,
						   &value);
			}
			g_strfreev(w);
		} else {
			/* This is a single-value field. */
			if (formats[i].prefix) {
				char *p;
				p = g_strconcat(formats[i].prefix,
						v[formats[i].position - 1],
						NULL);
				g_value_set_string(&value, p);
				g_free(p);
			} else {
				g_value_set_string(&value,
						   v[formats[i].position - 1]);
			}
			lu_ent_clear(ent, formats[i].attribute);
			lu_ent_clear_current(ent, formats[i].attribute);
			lu_ent_add(ent, formats[i].attribute, &value);
			lu_ent_add_current(ent, formats[i].attribute, &value);
		}
		g_value_unset(&value);
	}
	g_strfreev(v);
	return TRUE;
}

/* Parse an entry from /etc/passwd into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_files_parse_user_entry(const gchar * line,
			  struct lu_ent *ent)
{
	gboolean ret;
	ret = parse_generic(line, format_passwd, G_N_ELEMENTS(format_passwd),
			    ent);
	return ret;
}

/* Parse an entry from /etc/group into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_files_parse_group_entry(const gchar * line,
			   struct lu_ent *ent)
{
	gboolean ret;
	ret = parse_generic(line, format_group, G_N_ELEMENTS(format_group),
			    ent);
	return ret;
}

/* Parse an entry from /etc/shadow into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_shadow_parse_user_entry(const gchar * line,
			   struct lu_ent *ent)
{
	gboolean ret;
	ret = parse_generic(line, format_shadow, G_N_ELEMENTS(format_shadow),
			    ent);
	return ret;
}

/* Parse an entry from /etc/shadow into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_shadow_parse_group_entry(const gchar * line,
			    struct lu_ent *ent)
{
	gboolean ret;
	ret = parse_generic(line, format_gshadow, G_N_ELEMENTS(format_gshadow),
			    ent);
	return ret;
}

typedef gboolean(*parse_fn) (const gchar * line,
			     struct lu_ent * ent);

static gboolean
generic_lookup(struct lu_module *module, const char *base_name,
	       gconstpointer name, parse_fn parser, int field,
	       struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = FALSE;
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
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		return FALSE;
	}

	if (lu_util_lock_obtain(fd, error) != TRUE) {
		close(fd);
		return FALSE;
	}

	line = lu_util_line_get_matchingx(fd, (char *) name, field, error);
	if (line == NULL) {
		close(fd);
		return FALSE;
	}

	if (line != NULL) {
		ret = parser(line, ent);
		g_free(line);
	}
	lu_util_lock_free(fd);
	close(fd);

	g_free(filename);

	return ret;
}

static gboolean
lu_files_user_lookup_name(struct lu_module *module,
			  gconstpointer name,
			  struct lu_ent *ent,
			  struct lu_error **error)
{
	gboolean ret;
	ret =
	    generic_lookup(module, "passwd", name,
			   lu_files_parse_user_entry, 1, ent, error);
	return ret;
}

static gboolean
lu_files_user_lookup_id(struct lu_module *module,
			long uid,
			struct lu_ent *ent,
			struct lu_error **error)
{
	char *key;
	gboolean ret = FALSE;
	key = g_strdup_printf("%d", uid);
	ret =
	    generic_lookup(module, "passwd", key,
			   lu_files_parse_user_entry, 3, ent, error);
	g_free(key);
	return ret;
}

static gboolean
lu_shadow_user_lookup_name(struct lu_module *module,
			   gconstpointer name,
			   struct lu_ent *ent,
			   struct lu_error **error)
{
	gboolean ret;
	ret =
	    generic_lookup(module, "shadow", name,
			   lu_shadow_parse_user_entry, 1, ent, error);
	return ret;
}

static gboolean
lu_shadow_user_lookup_id(struct lu_module *module,
			 long uid,
			 struct lu_ent *ent,
			 struct lu_error **error)
{
	char *key;
	GValueArray *values;
	gboolean ret = FALSE;
	key = g_strdup_printf("%d", uid);
	ret = lu_files_user_lookup_id(module, uid, ent, error);
	if (ret) {
		values = lu_ent_get(ent, LU_USERNAME);
		if ((values != NULL) && (values->n_values > 0)) {
			char *p;
			p = g_value_dup_string(g_value_array_get_nth(values,
								     0));
			ret = generic_lookup(module, "shadow", p,
					     lu_shadow_parse_user_entry, 1,
					     ent, error);
			g_free(p);
		}
	}
	g_free(key);
	return ret;
}

static gboolean
lu_files_group_lookup_name(struct lu_module *module,
			   gconstpointer name,
			   struct lu_ent *ent,
			   struct lu_error **error)
{
	gboolean ret;
	ret = generic_lookup(module, "group", name,
			     lu_files_parse_group_entry, 1, ent, error);
	return ret;
}

static gboolean
lu_files_group_lookup_id(struct lu_module *module,
			 long gid,
			 struct lu_ent *ent,
			 struct lu_error **error)
{
	char *key;
	gboolean ret;
	key = g_strdup_printf("%d", gid);
	ret = generic_lookup(module, "group", key,
			     lu_files_parse_group_entry, 3, ent, error);
	g_free(key);
	return ret;
}

static gboolean
lu_shadow_group_lookup_name(struct lu_module *module, gconstpointer name,
			    struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret;
	ret = generic_lookup(module, "gshadow", name,
			     lu_shadow_parse_group_entry, 1, ent, error);
	return ret;
}

static gboolean
lu_shadow_group_lookup_id(struct lu_module *module, long gid,
			  struct lu_ent *ent, struct lu_error **error)
{
	char *key;
	GValueArray *values;
	gboolean ret = FALSE;
	key = g_strdup_printf("%d", gid);
	ret = lu_files_group_lookup_id(module, gid, ent, error);
	if (ret) {
		values = lu_ent_get(ent, LU_GROUPNAME);
		if ((values != NULL) && (values->n_values > 0)) {
			char *p;
			p = g_value_dup_string(g_value_array_get_nth(values,
								     0));
			ret = generic_lookup(module, "gshadow", p,
					     lu_shadow_parse_group_entry, 1,
					     ent, error);
			g_free(p);
		}
	}
	g_free(key);
	return ret;
}

/* Format a line for the user/group, using the information in ent, using
 * formats to guide the formatting. */
static char *
format_generic(struct lu_ent *ent, const struct format_specifier *formats,
	       size_t format_count)
{
	GValueArray *values;
	GValue value;
	char *ret = NULL, *p, *q;
	int i, j;

	g_return_val_if_fail(ent != NULL, NULL);
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);

	for (i = 0; i < format_count; i++) {
		/* Add a separator if we need to. */
		if (i > 0) {
			j = formats[i].position - formats[i - 1].position;
			while (j-- > 0) {
				p = g_strconcat(ret, ":", NULL);
				if (ret) {
					g_free(ret);
				}
				ret = p;
			}
		}
		/* Get the attribute data and store it in a GValue. */
		values = lu_ent_get(ent, formats[i].attribute);
		if ((values != NULL) && (values->n_values > 0)) {
			g_value_copy(g_value_array_get_nth(values, 0),
				     &value);
		} else {
			/* Check for a default value. */
			if (formats[i].def != NULL) {
				/* Use the default listed in the format
				 * specifier. */
				g_value_set_string(&value, formats[i].def);
			}
		}
		/* We now have all the values, and the first or the default. */
		if (!formats[i].multiple) {
			/* It's a single-item entry, use it. */
			p = q = g_value_dup_string(&value);
			/* If there's a prefix, strip it. */
			if (formats[i].prefix) {
				if (strncmp (p, formats[i].prefix,
					     strlen(formats[i].prefix)) == 0) {
					p += strlen(formats[i].prefix);
				}
				/* Tack the data onto the end. */
				p = g_strconcat(ret ? : "", p, NULL);
				if (ret) {
					g_free(ret);
				}
				ret = p;
			}
			g_free(q);
		} else {
			/* Separate data with a comma after the first datum. */
			if (values != NULL)
			for (j = 0; j < values->n_values; j++) {
				g_value_copy(g_value_array_get_nth(values, j),
					     &value);
				p = q = g_value_dup_string(&value);
				/* If there's a prefix, strip it. */
				if (formats[i].prefix) {
					if (strncmp(p, formats[i].prefix,
						    strlen(formats[i].prefix)) == 0) {
						p += strlen(formats[i].
							    prefix);
					}
				}
				/* Tack the data onto the end. */
				p = g_strconcat(ret ? : "",
						(j > 0) ? "," : "", p,
						NULL);
				if (ret) {
					g_free(ret);
				}
				ret = p;
				g_free(q);
			}
		}
	}
	p = g_strconcat(ret, "\n", NULL);
	if (ret) {
		g_free(ret);
	}
	ret = p;

	return ret;
}

/* Create a line for /etc/passwd using data in the lu_ent structure. */
static char *
lu_files_format_user(struct lu_ent *ent)
{
	char *ret;
	ret = format_generic(ent, format_passwd, G_N_ELEMENTS(format_passwd));
	return ret;
}

/* Create a line for /etc/group using data in the lu_ent structure. */
static char *
lu_files_format_group(struct lu_ent *ent)
{
	char *ret;
	ret = format_generic(ent, format_group, G_N_ELEMENTS(format_group));
	return ret;
}

/* Create a line for /etc/shadow using data in the lu_ent structure. */
static char *
lu_shadow_format_user(struct lu_ent *ent)
{
	char *ret;
	ret = format_generic(ent, format_shadow, G_N_ELEMENTS(format_shadow));
	return ret;
}

/* Create a line for /etc/gshadow using data in the lu_ent structure. */
static char *
lu_shadow_format_group(struct lu_ent *ent)
{
	char *ret;
	ret = format_generic(ent, format_gshadow, G_N_ELEMENTS(format_gshadow));
	return ret;
}

typedef char *(*format_fn) (struct lu_ent * ent);

static gboolean
generic_add(struct lu_module *module, const char *base_name,
	    format_fn formatter, struct lu_ent *ent,
	    struct lu_error **error)
{
	const char *dir;
	char *key, *line, *filename, *contents;
	int fd;
	struct stat st;
	off_t offset;
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

	if (lu_files_create_backup(filename, error) == FALSE) {
		g_free(filename);
		return FALSE;
	}

	fd = open(filename, O_RDWR);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		g_free(filename);
		return FALSE;
	}

	if (lu_util_lock_obtain(fd, error) != TRUE) {
		close(fd);
		g_free(filename);
		return FALSE;
	}

	if (fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), filename,
			     strerror(errno));
		lu_util_lock_free(fd);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	line = formatter(ent);
	contents = g_malloc0(st.st_size + 1 + strlen(line) + 1);

	if (line && strchr(line, ':')) {
		char *fragment1, *fragment2;
		fragment1 = g_strndup(line, strchr(line, ':') - line + 1);
		fragment2 = g_strconcat("\n", fragment1, NULL);
		if (read(fd, contents, st.st_size) != st.st_size) {
			lu_error_new(error, lu_error_read,
				     _("couldn't read from `%s': %s"),
				     filename, strerror(errno));
			lu_util_lock_free(fd);
			close(fd);
			g_free(fragment1);
			g_free(fragment2);
			g_free(contents);
			g_free(filename);
			return FALSE;
		}
		if (strncmp(contents, fragment1, strlen(fragment1)) == 0) {
			lu_error_new(error, lu_error_generic,
				     _("entry already present in file"));
			lu_util_lock_free(fd);
			close(fd);
			g_free(fragment1);
			g_free(fragment2);
			g_free(contents);
			g_free(filename);
			return FALSE;
		} else {
			if (strstr(contents, fragment2) != NULL) {
				lu_error_new(error, lu_error_generic,
					     _
					     ("entry already present in file"));
				lu_util_lock_free(fd);
				close(fd);
				g_free(fragment1);
				g_free(fragment2);
				g_free(contents);
				g_free(filename);
				return FALSE;
			} else {
				int r;
				offset = lseek(fd, 0, SEEK_END);
				if (offset == -1) {
					lu_error_new(error, lu_error_write,
						     _
						     ("couldn't write to `%s': %s"),
						     filename,
						     strerror(errno));
					lu_util_lock_free(fd);
					close(fd);
					g_free(fragment1);
					g_free(fragment2);
					g_free(contents);
					g_free(filename);
					return FALSE;
				}
				r = write(fd, line, strlen(line));
				if (r != strlen(line)) {
					lu_error_new(error, lu_error_write,
						     _
						     ("couldn't write to `%s': %s"),
						     filename,
						     strerror(errno));
					ftruncate(fd, offset);
					lu_util_lock_free(fd);
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
	lu_util_lock_free(fd);
	close(fd);
	g_free(filename);

	return ret;
}

static gboolean
lu_files_user_add_prep(struct lu_module *module, struct lu_ent *ent,
		       struct lu_error **error)
{
	return TRUE;
}

static gboolean
lu_files_user_add(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	gboolean ret;
	ret = generic_add(module, "passwd", lu_files_format_user, ent, error);
	return ret;
}

static gboolean
lu_shadow_user_add_prep(struct lu_module *module, struct lu_ent *ent,
		        struct lu_error **error)
{
	return TRUE;
}

static gboolean
lu_shadow_user_add(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	gboolean ret;
	ret = generic_add(module, "shadow", lu_shadow_format_user, ent, error);
	return ret;
}

static gboolean
lu_files_group_add_prep(struct lu_module *module, struct lu_ent *ent,
		        struct lu_error **error)
{
	return TRUE;
}

static gboolean
lu_files_group_add(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	gboolean ret;
	ret = generic_add(module, "group", lu_files_format_group, ent, error);
	return ret;
}

static gboolean
lu_shadow_group_add_prep(struct lu_module *module, struct lu_ent *ent,
		         struct lu_error **error)
{
	return TRUE;
}

static gboolean
lu_shadow_group_add(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	gboolean ret;
	ret = generic_add(module, "gshadow", lu_shadow_format_group, ent, error);
	return ret;
}

static gboolean
generic_mod(struct lu_module *module, const char *base_name,
	    const struct format_specifier *formats, size_t format_count,
	    struct lu_ent *ent, struct lu_error **error)
{
	char *filename = NULL, *key = NULL;
	int fd = -1;
	int i, j;
	const char *dir = NULL;
	char *p, *q, *r, *new_value;
	GValueArray *names = NULL, *values = NULL, *l;
	GValue value;
	gboolean ret = FALSE;

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(formats != NULL);
	g_assert(format_count > 0);
	g_assert(ent != NULL);
	g_assert((ent->type == lu_user) || (ent->type == lu_group));

	if (ent->type == lu_user) {
		names = lu_ent_get_current(ent, LU_USERNAME);
		if (names == NULL) {
			lu_error_new(error, lu_error_generic,
				     _
				     ("entity object has no %s attribute"),
				     LU_USERNAME);
			return FALSE;
		}
	}
	if (ent->type == lu_group) {
		names = lu_ent_get_current(ent, LU_GROUPNAME);
		if (names == NULL) {
			lu_error_new(error, lu_error_generic,
				     _
				     ("entity object has no %s attribute"),
				     LU_GROUPNAME);
			return FALSE;
		}
	}
	g_assert(names != NULL);
	g_assert(names->n_values > 0);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if (lu_files_create_backup(filename, error) == FALSE) {
		g_free(filename);
		return FALSE;
	}

	fd = open(filename, O_RDWR);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		g_free(filename);
		return FALSE;
	}

	if (lu_util_lock_obtain(fd, error) != TRUE) {
		close(fd);
		g_free(filename);
		return FALSE;
	}

	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);

	for (i = 0; i < format_count; i++) {
		if (formats[i].suppress) {
			continue;
		}
		values = lu_ent_get(ent, formats[i].attribute);
		new_value = NULL;
		if (!formats[i].multiple) {
			if (values == NULL) {
				lu_error_new(error, lu_error_generic,
					     _
					     ("entity object has no `%s' attribute"),
					     formats[i].attribute);
				close(fd);
				return FALSE;
			}
			g_value_copy(g_value_array_get_nth(values, 0), &value);
			p = q = g_value_dup_string(&value);
			/* if there's a prefix, strip it */
			if (formats[i].prefix) {
				if (strncmp (p, formats[i].prefix,
					     strlen(formats[i].prefix)) == 0) {
					p += strlen(formats[i].prefix);
				}
			}
			/* make a copy of the data */
			new_value = g_strdup(p);
			g_free(q);
		} else {
			if (values != NULL)
			for (j = 0; j < values->n_values; j++) {
				g_value_copy(g_value_array_get_nth(values, j),
					     &value);
				p = r = g_value_dup_string(&value);
				/* if there's a prefix, strip it */
				if (formats[i].prefix) {
					if (strncmp(p, formats[i].prefix,
						    strlen(formats[i].prefix)) == 0) {
						p += strlen(formats[i].prefix);
					}
				}
				if (new_value) {
					q = g_strconcat(new_value, ",", p,
							NULL);
				} else {
					q = g_strdup(p);
				}
				g_free(r);
				if (new_value) {
					g_free(new_value);
				}
				new_value = q;
			}
		}

		g_value_copy(g_value_array_get_nth(names, 0), &value);

		ret = lu_util_field_write(fd, g_value_get_string(&value),
					  formats[i].position, new_value,
					  error);
		g_free(new_value);
		if (ret == FALSE) {
			lu_util_lock_free(fd);
			close(fd);
			g_free(filename);
			return FALSE;
		}
		/* we may have just renamed the account (we're safe assuming
		 * the new name is correct here because if we renamed, we did
		 * it first), so switch to using the account's name */
		if (ent->type == lu_user) {
			names = lu_ent_get(ent, LU_USERNAME);
			if (names == NULL) {
				lu_error_new(error, lu_error_generic,
					     _
					     ("entity object has no %s attribute"),
					     LU_USERNAME);
				lu_util_lock_free(fd);
				close(fd);
				g_free(filename);
				return FALSE;
			}
		}
		if (ent->type == lu_group) {
			names = lu_ent_get(ent, LU_GROUPNAME);
			if (names == NULL) {
				lu_error_new(error, lu_error_generic,
					     _
					     ("entity object has no %s attribute"),
					     LU_GROUPNAME);
				lu_util_lock_free(fd);
				close(fd);
				g_free(filename);
				return FALSE;
			}
		}
	}
	g_value_unset(&value);

	lu_util_lock_free(fd);
	close(fd);
	g_free(filename);

	return TRUE;
}

static gboolean
lu_files_user_mod(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	gboolean ret;
	ret = generic_mod(module, "passwd", format_passwd,
			  G_N_ELEMENTS(format_passwd), ent, error);
	return ret;
}

static gboolean
lu_files_group_mod(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	gboolean ret;
	ret = generic_mod(module, "group", format_group,
			  G_N_ELEMENTS(format_group), ent, error);
	return ret;
}

static gboolean
lu_shadow_user_mod(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	gboolean ret;
	ret = generic_mod(module, "shadow", format_shadow,
			  G_N_ELEMENTS(format_shadow), ent, error);
	return ret;
}

static gboolean
lu_shadow_group_mod(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	gboolean ret;
	ret =
	    generic_mod(module, "gshadow", format_gshadow,
			G_N_ELEMENTS(format_gshadow), ent, error);
	return ret;
}

static gboolean
generic_del(struct lu_module *module, const char *base_name,
	    struct lu_ent *ent, struct lu_error **error)
{
	GValueArray *name = NULL;
	GValue value;
	char *contents = NULL, *filename = NULL, *line, *key = NULL, *tmp;
	const char *dir;
	struct stat st;
	int fd = -1;

	if (ent->type == lu_user)
		name = lu_ent_get_current(ent, LU_USERNAME);
	if (ent->type == lu_group)
		name = lu_ent_get_current(ent, LU_GROUPNAME);
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(ent != NULL);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if (lu_files_create_backup(filename, error) == FALSE) {
		g_free(filename);
		return FALSE;
	}

	fd = open(filename, O_RDWR);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		g_free(filename);
		return FALSE;
	}

	if (lu_util_lock_obtain(fd, error) != TRUE) {
		close(fd);
		g_free(filename);
		return FALSE;
	}

	if (fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), filename,
			     strerror(errno));
		lu_util_lock_free(fd);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	contents = g_malloc0(st.st_size + 1);
	if (read(fd, contents, st.st_size) != st.st_size) {
		lu_error_new(error, lu_error_read,
			     _("couldn't read from `%s': %s"), filename,
			     strerror(errno));
		g_free(contents);
		lu_util_lock_free(fd);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);
	g_value_copy(g_value_array_get_nth(name, 0), &value);
	tmp = g_strdup_printf("%s:", g_value_get_string(&value));
	line = module->scache->cache(module->scache, tmp);
	g_free(tmp);

	if (strncmp(contents, line, strlen(line)) == 0) {
		char *p = strchr(contents, '\n');
		strcpy(contents, p ? (p + 1) : "");
	} else {
		char *p;
		tmp = g_strdup_printf("\n%s:", g_value_get_string(&value));
		line = module->scache->cache(module->scache, tmp);
		g_free(tmp);
		if ((p = strstr(contents, line)) != NULL) {
			char *q = strchr(p + 1, '\n');
			strcpy(p + 1, q ? (q + 1) : "");
		}
	}

	g_value_unset(&value);

	if (lseek(fd, 0, SEEK_SET) == -1) {
		lu_error_new(error, lu_error_write,
			     _("couldn't write to `%s': %s"), filename,
			     strerror(errno));
		g_free(contents);
		lu_util_lock_free(fd);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	if (write(fd, contents, strlen(contents)) != strlen(contents)) {
		lu_error_new(error, lu_error_write,
			     _("couldn't write to `%s': %s"), filename,
			     strerror(errno));
		g_free(contents);
		lu_util_lock_free(fd);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	ftruncate(fd, strlen(contents));
	g_free(contents);
	lu_util_lock_free(fd);
	close(fd);
	g_free(filename);

	return TRUE;
}

static gboolean
lu_files_user_del(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	gboolean ret;
	ret = generic_del(module, "passwd", ent, error);
	return ret;
}

static gboolean
lu_files_group_del(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	gboolean ret;
	ret = generic_del(module, "group", ent, error);
	return ret;
}

static gboolean
lu_shadow_user_del(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	gboolean ret;
	ret = generic_del(module, "shadow", ent, error);
	return ret;
}

static gboolean
lu_shadow_group_del(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	gboolean ret;
	ret = generic_del(module, "gshadow", ent, error);
	return ret;
}

/** Return the "locked" or "unlocked" version of the cryptedPassword string, depending on whether or not lock is true. */
static char *
lock_process(char *cryptedPassword, gboolean lock, struct lu_ent *ent)
{
	char *ret = NULL;
	if (lock) {
		if (cryptedPassword[0] != '!') {
			cryptedPassword = g_strconcat("!", cryptedPassword,
						      NULL);
			ret = ent->vcache->cache(ent->vcache, cryptedPassword);
			g_free((char *) cryptedPassword);
		} else {
			ret = cryptedPassword;
		}
	} else {
		if (cryptedPassword[0] == '!') {
			ret = ent->vcache->cache(ent->vcache,
						 cryptedPassword + 1);
		} else {
			ret = cryptedPassword;
		}
	}
	return ret;
}

static gboolean
generic_lock(struct lu_module *module, const char *base_name, int field,
	     struct lu_ent *ent, gboolean lock_or_not,
	     struct lu_error **error)
{
	GValueArray *name = NULL;
	char *filename = NULL, *key = NULL;
	const char *dir, *namestring;
	char *value, *new_value;
	int fd = -1;
	gboolean ret = FALSE;

	if (ent->type == lu_user)
		name = lu_ent_get_current(ent, LU_USERNAME);
	if (ent->type == lu_group)
		name = lu_ent_get_current(ent, LU_GROUPNAME);
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(ent != NULL);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if (lu_files_create_backup(filename, error) == FALSE) {
		g_free(filename);
		return FALSE;
	}

	fd = open(filename, O_RDWR);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		g_free(filename);
		return FALSE;
	}

	if (lu_util_lock_obtain(fd, error) != TRUE) {
		close(fd);
		g_free(filename);
		return FALSE;
	}

	namestring = g_value_get_string(g_value_array_get_nth(name, 0));
	value = lu_util_field_read(fd, namestring, field, error);
	if (value == NULL) {
		lu_util_lock_free(fd);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	new_value = lock_process(value, lock_or_not, ent);
	g_free(value);

	ret = lu_util_field_write(fd, namestring, field,
				  new_value, error);
	if (ret == FALSE) {
		lu_util_lock_free(fd);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	lu_util_lock_free(fd);
	close(fd);
	g_free(filename);

	return TRUE;
}

static gboolean
generic_is_locked(struct lu_module *module, const char *base_name,
		  int field, struct lu_ent *ent, gboolean lock_or_not,
		  struct lu_error **error)
{
	GValueArray *name = NULL;
	char *filename = NULL, *key = NULL;
	const char *dir, *namestring;
	char *value;
	int fd = -1;
	gboolean ret = FALSE;

	if (ent->type == lu_user)
		name = lu_ent_get_current(ent, LU_USERNAME);
	if (ent->type == lu_group)
		name = lu_ent_get_current(ent, LU_GROUPNAME);
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(ent != NULL);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if (lu_files_create_backup(filename, error) == FALSE) {
		g_free(filename);
		return FALSE;
	}

	fd = open(filename, O_RDWR);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		g_free(filename);
		return FALSE;
	}

	if (lu_util_lock_obtain(fd, error) != TRUE) {
		close(fd);
		g_free(filename);
		return FALSE;
	}

	namestring = g_value_get_string(g_value_array_get_nth(name, 0));
	value = lu_util_field_read(fd, namestring, field, error);
	if (value == NULL) {
		lu_util_lock_free(fd);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	ret = value[0] == '!';
	g_free(value);

	return ret;
}

static gboolean
lu_files_user_lock(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	gboolean ret;
	ret = generic_lock(module, "passwd", 2, ent, TRUE, error);
	return ret;
}

static gboolean
lu_files_user_unlock(struct lu_module *module, struct lu_ent *ent,
		     struct lu_error **error)
{
	gboolean ret;
	ret = generic_lock(module, "passwd", 2, ent, FALSE, error);
	return ret;
}

static gboolean
lu_files_group_lock(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	gboolean ret;
	ret = generic_lock(module, "group", 2, ent, TRUE, error);
	return ret;
}

static gboolean
lu_files_group_unlock(struct lu_module *module, struct lu_ent *ent,
		      struct lu_error **error)
{
	gboolean ret;
	ret = generic_lock(module, "group", 2, ent, FALSE, error);
	return ret;
}

static gboolean
lu_shadow_user_lock(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	gboolean ret;
	ret = generic_lock(module, "shadow", 2, ent, TRUE, error);
	return ret;
}

static gboolean
lu_shadow_user_unlock(struct lu_module *module, struct lu_ent *ent,
		      struct lu_error **error)
{
	gboolean ret;
	ret = generic_lock(module, "shadow", 2, ent, FALSE, error);
	return ret;
}

static gboolean
lu_files_user_is_locked(struct lu_module *module, struct lu_ent *ent,
		        struct lu_error **error)
{
	gboolean ret;
	ret = generic_is_locked(module, "passwd", 2, ent, FALSE, error);
	return ret;
}

static gboolean
lu_files_group_is_locked(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	gboolean ret;
	ret = generic_is_locked(module, "group", 2, ent, FALSE, error);
	return ret;
}

static gboolean
lu_shadow_group_lock(struct lu_module *module, struct lu_ent *ent,
		     struct lu_error **error)
{
	gboolean ret;
	ret = generic_lock(module, "gshadow", 2, ent, TRUE, error);
	return ret;
}

static gboolean
lu_shadow_group_unlock(struct lu_module *module, struct lu_ent *ent,
		       struct lu_error **error)
{
	gboolean ret;
	ret = generic_lock(module, "gshadow", 2, ent, FALSE, error);
	return ret;
}

static gboolean
lu_shadow_user_is_locked(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	gboolean ret;
	ret = generic_is_locked(module, "shadow", 2, ent, FALSE, error);
	return ret;
}

static gboolean
lu_shadow_group_is_locked(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	gboolean ret;
	ret = generic_is_locked(module, "gshadow", 2, ent, FALSE, error);
	return ret;
}

static gboolean
generic_setpass(struct lu_module *module, const char *base_name, int field,
		struct lu_ent *ent, const char *password,
		struct lu_error **error)
{
	GValueArray *name = NULL;
	char *filename = NULL, *key = NULL;
	const char *dir, *namestring;
	int fd = -1;
	gboolean ret = FALSE;

	if (ent->type == lu_user)
		name = lu_ent_get_current(ent, LU_USERNAME);
	if (ent->type == lu_group)
		name = lu_ent_get_current(ent, LU_GROUPNAME);
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(ent != NULL);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if (lu_files_create_backup(filename, error) == FALSE) {
		g_free(filename);
		return FALSE;
	}

	fd = open(filename, O_RDWR);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		g_free(filename);
		return FALSE;
	}

	if (lu_util_lock_obtain(fd, error) != TRUE) {
		close(fd);
		g_free(filename);
		return FALSE;
	}

	if (strncmp(password, "{crypt}", 7) == 0) {
		password = password + 7;
	} else {
		password = lu_make_crypted(password, NULL);
	}

	namestring = g_value_get_string(g_value_array_get_nth(name, 0));
	ret = lu_util_field_write(fd, namestring, field, password, error);
	if (ret == FALSE) {
		lu_util_lock_free(fd);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	lu_util_lock_free(fd);
	close(fd);
	g_free(filename);

	return ret;
}

static gboolean
lu_files_user_setpass(struct lu_module *module, struct lu_ent *ent,
		      const char *password, struct lu_error **error)
{
	gboolean ret;
	ret = generic_setpass(module, "passwd", 2, ent, password, error);
	return ret;
}

static gboolean
lu_files_group_setpass(struct lu_module *module, struct lu_ent *ent,
		       const char *password, struct lu_error **error)
{
	gboolean ret;
	ret = generic_setpass(module, "group", 2, ent, password, error);
	return ret;
}

static void
set_shadow_last_change(struct lu_module *module, struct lu_ent *ent)
{
	GValue value;
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);
	g_value_set_string(&value, lu_util_shadow_current_date(module->scache));
	lu_ent_clear(ent, LU_SHADOWLASTCHANGE);
	lu_ent_add(ent, LU_SHADOWLASTCHANGE, &value);
	g_value_unset(&value);
}
		       
static gboolean
lu_shadow_user_setpass(struct lu_module *module, struct lu_ent *ent,
		       const char *password, struct lu_error **error)
{
	gboolean ret;
	ret = generic_setpass(module, "shadow", 2, ent, password, error);
	if (ret) {
		set_shadow_last_change(module, ent);
	}
	return ret;
}

static gboolean
lu_shadow_group_setpass(struct lu_module *module, struct lu_ent *ent,
			const char *password, struct lu_error **error)
{
	gboolean ret;
	ret = generic_setpass(module, "gshadow", 2, ent, password, error);
	if (ret) {
		set_shadow_last_change(module, ent);
	}
	return ret;
}

static GValueArray *
lu_files_enumerate(struct lu_module *module, const char *base_name,
		   const char *pattern, struct lu_error **error)
{
	int fd;
	GValueArray *ret = NULL;
	GValue value;
	char *buf;
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
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		g_free(filename);
		return NULL;
	}

	if (lu_util_lock_obtain(fd, error) != TRUE) {
		close(fd);
		g_free(filename);
		return NULL;
	}

	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		lu_util_lock_free(fd);
		close(fd);
		g_free(filename);
		return NULL;
	}

	ret = g_value_array_new(0);
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);
	while ((buf = line_read(fp)) != NULL) {
		p = strchr(buf, ':');
		if (p != NULL) {
			*p = '\0';
			p = module->scache->cache(module->scache, buf);
			if (fnmatch(pattern, p, 0) == 0) {
				g_value_set_string(&value, p);
				g_value_array_append(ret, &value);
			}
		}
		g_free(buf);
	}

	lu_util_lock_free(fd);
	fclose(fp);
	g_free(filename);

	return ret;
}

static GValueArray *
lu_files_users_enumerate(struct lu_module *module, const char *pattern,
			 struct lu_error **error)
{
	GValueArray *ret;
	ret = lu_files_enumerate(module, "passwd", pattern, error);
	return ret;
}

static GValueArray *
lu_files_groups_enumerate(struct lu_module *module, const char *pattern,
			  struct lu_error **error)
{
	GValueArray *ret;
	ret = lu_files_enumerate(module, "group", pattern, error);
	return ret;
}

static GValueArray *
lu_files_users_enumerate_by_group(struct lu_module *module,
				  const char *group, gid_t gid,
				  struct lu_error **error)
{
	int fd;
	GValueArray *ret = NULL;
	GValue value;
	char *buf, grp[CHUNK_SIZE];
	char *key = NULL, *pwdfilename = NULL, *grpfilename = NULL, *p, *q;
	const char *dir = NULL;
	FILE *fp;

	g_assert(module != NULL);
	g_assert(group != NULL);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	pwdfilename = g_strconcat(dir, "/passwd", NULL);
	grpfilename = g_strconcat(dir, "/group", NULL);
	g_free(key);

	fd = open(pwdfilename, O_RDWR);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), pwdfilename,
			     strerror(errno));
		g_free(pwdfilename);
		g_free(grpfilename);
		return NULL;
	}

	if (lu_util_lock_obtain(fd, error) != TRUE) {
		close(fd);
		g_free(pwdfilename);
		g_free(grpfilename);
		return NULL;
	}

	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), pwdfilename,
			     strerror(errno));
		lu_util_lock_free(fd);
		close(fd);
		g_free(pwdfilename);
		g_free(grpfilename);
		return NULL;
	}

	ret = g_value_array_new(0);
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);
	snprintf(grp, sizeof(grp), "%d", gid);
	while ((buf = line_read(fp)) != NULL) {
		p = strchr(buf, ':');
		q = NULL;
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		if (p != NULL) {
			*p = '\0';
			p++;
			q = p;
			p = strchr(p, ':');
		}
		if (q != NULL) {
			if (p != NULL) {
				*p = '\0';
			}
			if (strcmp(q, grp) == 0) {
				g_value_set_string(&value, buf);
				g_value_array_append(ret, &value);
			}
		}
		g_free(buf);
	}
	lu_util_lock_free(fd);
	fclose(fp);

	fd = open(grpfilename, O_RDWR);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), grpfilename,
			     strerror(errno));
		g_free(pwdfilename);
		g_free(grpfilename);
		g_value_array_free(ret);
		return NULL;
	}

	if (lu_util_lock_obtain(fd, error) != TRUE) {
		close(fd);
		g_free(pwdfilename);
		g_free(grpfilename);
		g_value_array_free(ret);
		return NULL;
	}

	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), grpfilename,
			     strerror(errno));
		lu_util_lock_free(fd);
		close(fd);
		g_free(pwdfilename);
		g_free(grpfilename);
		g_value_array_free(ret);
		return NULL;
	}

	while ((buf = line_read(fp)) != NULL) {
		p = strchr(buf, ':');
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		if (strcmp(buf, group) == 0) {
			if (p != NULL) {
				*p = '\0';
				p++;
				p = strchr(p, ':');
			}
			if (p != NULL) {
				*p = '\0';
				p++;
				while ((q = strsep(&p, ",\n")) != NULL) {
					if (strlen(q) > 0) {
						g_value_set_string(&value, buf);
						g_value_array_append(ret,
								     &value);
					}
				}
			}
			g_free(buf);
			break;
		}
		g_free(buf);
	}

	lu_util_lock_free(fd);
	fclose(fp);

	g_free(pwdfilename);
	g_free(grpfilename);

	return ret;
}

static GValueArray *
lu_files_groups_enumerate_by_user(struct lu_module *module,
				  const char *user,
				  uid_t uid,
				  struct lu_error **error)
{
	int fd;
	GValueArray *ret = NULL;
	GValue value;
	char *buf;
	char *key = NULL, *filename = NULL, *p, *q;
	const char *dir = NULL;
	FILE *fp;

	g_assert(module != NULL);
	g_assert(user != NULL);

	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/group", NULL);
	g_free(key);

	fd = open(filename, O_RDWR);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		g_free(filename);
		return NULL;
	}

	if (lu_util_lock_obtain(fd, error) != TRUE) {
		close(fd);
		g_free(filename);
		return NULL;
	}

	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		lu_util_lock_free(fd);
		close(fd);
		g_free(filename);
		return NULL;
	}

	ret = g_value_array_new(0);
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);
	while ((buf = line_read(fp)) != NULL) {
		p = strchr(buf, ':');
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		if (p != NULL) {
			p++;
			while ((q = strsep(&p, ",\n")) != NULL) {
				if (strlen(q) > 0) {
					if (strcmp(q, user) == 0) {
						g_value_set_string(&value, buf);
						g_value_array_append(ret,
								     &value);
					}
				}
			}
		}
		g_free(buf);
	}

	lu_util_lock_free(fd);
	fclose(fp);
	g_free(filename);

	return ret;
}

static GPtrArray *
lu_files_users_enumerate_full(struct lu_module *module,
			      const char *user,
			      struct lu_error **error)
{
	/* FIXME */
	return NULL;
}

static GPtrArray *
lu_files_groups_enumerate_full(struct lu_module *module,
			       const char *user,
			       struct lu_error **error)
{
	/* FIXME */
	return NULL;
}

static GPtrArray *
lu_files_users_enumerate_by_group_full(struct lu_module *module,
				       const char *user,
				       uid_t uid,
				       struct lu_error **error)
{
	/* FIXME */
	return NULL;
}

static GPtrArray *
lu_files_groups_enumerate_by_user_full(struct lu_module *module,
				       const char *user,
				       uid_t uid,
				       struct lu_error **error)
{
	/* FIXME */
	return NULL;
}

static GValueArray *
lu_shadow_users_enumerate(struct lu_module *module,
			  const char *pattern,
			  struct lu_error **error)
{
	return NULL;
}

static GValueArray *
lu_shadow_groups_enumerate(struct lu_module *module,
			   const char *pattern,
			   struct lu_error **error)
{
	return NULL;
}

static GValueArray *
lu_shadow_users_enumerate_by_group(struct lu_module *module,
				   const char *group,
				   gid_t gid,
				   struct lu_error **error)
{
	return NULL;
}

static GValueArray *
lu_shadow_groups_enumerate_by_user(struct lu_module *module,
				   const char *user,
				   uid_t uid,
				   struct lu_error **error)
{
	return NULL;
}

static GPtrArray *
lu_shadow_users_enumerate_full(struct lu_module *module,
			       const char *pattern,
			       struct lu_error **error)
{
	return NULL;
}

static GPtrArray *
lu_shadow_groups_enumerate_full(struct lu_module *module,
				const char *pattern,
				struct lu_error **error)
{
	return NULL;
}

static GPtrArray *
lu_shadow_users_enumerate_by_group_full(struct lu_module *module,
					const char *group,
					gid_t gid,
					struct lu_error **error)
{
	return NULL;
}

static GPtrArray *
lu_shadow_groups_enumerate_by_user_full(struct lu_module *module,
					const char *user,
					uid_t uid,
					struct lu_error **error)
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
libuser_files_init(struct lu_context *context,
		   struct lu_error **error)
{
	struct lu_module *ret = NULL;

	g_return_val_if_fail(context != NULL, FALSE);

	/* Handle authenticating to the data source. */
	if (geteuid() != 0) {
		lu_error_new(error, lu_error_privilege,
			     _("not executing with superuser privileges"));
		return NULL;
	}

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, "files");

	/* Set the method pointers. */
	ret->user_lookup_name = lu_files_user_lookup_name;
	ret->user_lookup_id = lu_files_user_lookup_id;

	ret->user_add_prep = lu_files_user_add_prep;
	ret->user_add = lu_files_user_add;
	ret->user_mod = lu_files_user_mod;
	ret->user_del = lu_files_user_del;
	ret->user_lock = lu_files_user_lock;
	ret->user_unlock = lu_files_user_unlock;
	ret->user_is_locked = lu_files_user_is_locked;
	ret->user_setpass = lu_files_user_setpass;
	ret->users_enumerate_full = lu_files_users_enumerate_full;
	ret->users_enumerate_by_group_full = lu_files_users_enumerate_by_group_full;

	ret->group_lookup_name = lu_files_group_lookup_name;
	ret->group_lookup_id = lu_files_group_lookup_id;

	ret->group_add_prep = lu_files_group_add_prep;
	ret->group_add = lu_files_group_add;
	ret->group_mod = lu_files_group_mod;
	ret->group_del = lu_files_group_del;
	ret->group_lock = lu_files_group_lock;
	ret->group_unlock = lu_files_group_unlock;
	ret->group_is_locked = lu_files_group_is_locked;
	ret->group_setpass = lu_files_group_setpass;
	ret->groups_enumerate = lu_files_groups_enumerate;
	ret->groups_enumerate_by_user = lu_files_groups_enumerate_by_user;
	ret->groups_enumerate_full = lu_files_groups_enumerate_full;
	ret->groups_enumerate_by_user_full = lu_files_groups_enumerate_by_user_full;

	ret->close = close_module;

	/* Done. */
	return ret;
}

struct lu_module *
lu_shadow_init(struct lu_context *context,
	       struct lu_error **error)
{
	struct lu_module *ret = NULL;
	struct stat st;
	char *shadow_file;
	char *key;
	const char *dir;

	g_return_val_if_fail(context != NULL, NULL);

	/* Handle authenticating to the data source. */
	if (geteuid() != 0) {
		lu_error_new(error, lu_error_privilege,
			     _("not executing with superuser privileges"));
		return NULL;
	}

	/* Get the name of the shadow file. */
	key = g_strconcat("shadow", "/directory", NULL);
	dir = lu_cfg_read_single(context, key, "/etc");
	shadow_file = g_strconcat(dir, "/shadow", NULL);
	g_free(key);

	/* Make sure we're actually using shadow passwords on this system. */
	if ((stat(shadow_file, &st) == -1) && (errno == ENOENT)) {
		lu_error_new(error, lu_warning_config_disabled,
			     _("no shadow file present -- disabling"));
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

	ret->user_add_prep = lu_shadow_user_add_prep;
	ret->user_add = lu_shadow_user_add;
	ret->user_mod = lu_shadow_user_mod;
	ret->user_del = lu_shadow_user_del;
	ret->user_lock = lu_shadow_user_lock;
	ret->user_unlock = lu_shadow_user_unlock;
	ret->user_is_locked = lu_shadow_user_is_locked;
	ret->user_setpass = lu_shadow_user_setpass;
	ret->users_enumerate = lu_shadow_users_enumerate;
	ret->users_enumerate_by_group = lu_shadow_users_enumerate_by_group;
	ret->users_enumerate_full = lu_shadow_users_enumerate_full;
	ret->users_enumerate_by_group_full = lu_shadow_users_enumerate_by_group_full;

	ret->group_lookup_name = lu_shadow_group_lookup_name;
	ret->group_lookup_id = lu_shadow_group_lookup_id;

	ret->group_add_prep = lu_shadow_group_add_prep;
	ret->group_add = lu_shadow_group_add;
	ret->group_mod = lu_shadow_group_mod;
	ret->group_del = lu_shadow_group_del;
	ret->group_lock = lu_shadow_group_lock;
	ret->group_unlock = lu_shadow_group_unlock;
	ret->group_is_locked = lu_shadow_group_is_locked;
	ret->group_setpass = lu_shadow_group_setpass;
	ret->groups_enumerate = lu_shadow_groups_enumerate;
	ret->groups_enumerate_by_user = lu_shadow_groups_enumerate_by_user;
	ret->groups_enumerate_full = lu_shadow_groups_enumerate_full;
	ret->groups_enumerate_by_user_full = lu_shadow_groups_enumerate_by_user_full;

	ret->close = close_module;

	/* Done. */
	return ret;
}
