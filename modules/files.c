/*
 * Copyright (C) 2000-2002 Red Hat, Inc.
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
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#else
typedef char security_context_t; /* "Something" */
#endif
#include "../lib/user_private.h"
#include "default.-c"

#define CHUNK_SIZE	(LINE_MAX * 4)

LU_MODULE_INIT(libuser_files_init)
LU_MODULE_INIT(libuser_shadow_init)

/* Guides for parsing and formatting entries in the files we're looking at.
 * For formatting purposes, these are all arranged in order of ascending
 * positions. */
struct format_specifier {
	int position;
	const char *attribute;
	GType type;
	const char *def;
	gboolean multiple, suppress_if_def;
};

static const struct format_specifier format_passwd[] = {
	{1, LU_USERNAME, G_TYPE_STRING, NULL, FALSE, FALSE},
	{2, LU_USERPASSWORD, G_TYPE_STRING, DEFAULT_PASSWORD, FALSE, FALSE},
	{3, LU_UIDNUMBER, G_TYPE_LONG, NULL, FALSE, FALSE},
	{4, LU_GIDNUMBER, G_TYPE_LONG, NULL, FALSE, FALSE},
	{5, LU_GECOS, G_TYPE_STRING, NULL, FALSE, FALSE},
	{6, LU_HOMEDIRECTORY, G_TYPE_STRING, NULL, FALSE, FALSE},
	{7, LU_LOGINSHELL, G_TYPE_STRING, DEFAULT_SHELL, FALSE, FALSE},
};

static const struct format_specifier format_group[] = {
	{1, LU_GROUPNAME, G_TYPE_STRING, NULL, FALSE, FALSE},
	{2, LU_GROUPPASSWORD, G_TYPE_STRING, DEFAULT_PASSWORD, FALSE, FALSE},
	{3, LU_GIDNUMBER, G_TYPE_LONG, NULL, FALSE, FALSE},
	{4, LU_MEMBERNAME, G_TYPE_STRING, NULL, TRUE, FALSE},
};

static const struct format_specifier format_shadow[] = {
	{1, LU_SHADOWNAME, G_TYPE_STRING, NULL, FALSE, FALSE},
	{2, LU_SHADOWPASSWORD, G_TYPE_STRING, DEFAULT_PASSWORD, FALSE, FALSE},
	{3, LU_SHADOWLASTCHANGE, G_TYPE_LONG, NULL, FALSE, FALSE},
	{4, LU_SHADOWMIN, G_TYPE_LONG, "0", FALSE, FALSE},
	{5, LU_SHADOWMAX, G_TYPE_LONG, "99999", FALSE, FALSE},
	{6, LU_SHADOWWARNING, G_TYPE_LONG, "7", FALSE, FALSE},
	{7, LU_SHADOWINACTIVE, G_TYPE_LONG, "-1", FALSE, TRUE},
	{8, LU_SHADOWEXPIRE, G_TYPE_LONG, "-1", FALSE, TRUE},
	{9, LU_SHADOWFLAG, G_TYPE_LONG, "-1", FALSE, TRUE},
};

static const struct format_specifier format_gshadow[] = {
	{1, LU_GROUPNAME, G_TYPE_STRING, NULL, FALSE, FALSE},
	{2, LU_SHADOWPASSWORD, G_TYPE_STRING, DEFAULT_PASSWORD, FALSE, FALSE},
	{3, LU_ADMINISTRATORNAME, G_TYPE_STRING, NULL, TRUE, FALSE},
	{4, LU_MEMBERNAME, G_TYPE_STRING, NULL, TRUE, FALSE},
};

static gboolean
set_default_context(const char *filename, security_context_t *prev_context,
		    struct lu_error **error)
{
	(void)filename;
	(void)prev_context;
	(void)error;
#ifdef WITH_SELINUX
	if (is_selinux_enabled() > 0) {
		security_context_t scontext;

		if (getfilecon(filename, &scontext) < 0) {
			/* FIXME: STRING_FREEZE */
			lu_error_new(error, lu_error_stat, "couldn't get "
				     "security context of `%s': %s", filename,
				     strerror(errno));
			return FALSE;
		}
		if (getfscreatecon(prev_context) < 0) {
			/* FIXME: STRING_FREEZE */
			lu_error_new(error, lu_error_stat, "couldn't set "
				     "default security context: %s",
				     strerror(errno));
			freecon(scontext);
			return FALSE;
		}
		if (setfscreatecon(scontext) < 0) {
			/* FIXME: STRING_FREEZE */
			lu_error_new(error, lu_error_stat, "couldn't set "
				     "default security context to `%s': %s",
				     scontext, strerror(errno));
			freecon(scontext);
			return FALSE;
		}
		freecon(scontext);
	}
#endif
	return TRUE;
}

static void
reset_default_context(security_context_t prev_context, struct lu_error **error)
{
	(void)prev_context;
	(void)error;
#ifdef WITH_SELINUX
	if (setfscreatecon(prev_context) < 0)
		/* FIXME: STRING_FREEZE */
		lu_error_new(error, lu_error_stat,
			     "couldn't reset default security context to "
			     "`%s': %s", prev_context, strerror(errno));
	if (prev_context) {
		freecon(prev_context);
	}
#endif
}

/* Create a backup copy of "filename" named "filename-". */
static gboolean
lu_files_create_backup(const char *filename,
		       struct lu_error **error)
{
	int ifd, ofd;
	gpointer ilock, olock;
	char *backupname;
	struct stat ist, ost;
	char buf[CHUNK_SIZE];
	ssize_t len;

	g_assert(filename != NULL);
	g_assert(strlen(filename) > 0);

	/* Open the original file. */
	ifd = open(filename, O_RDONLY);
	if (ifd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		return FALSE;
	}

	/* Lock the input file. */
	if ((ilock = lu_util_lock_obtain(ifd, error)) == NULL) {
		close(ifd);
		return FALSE;
	}

	/* Read the input file's size. */
	if (fstat(ifd, &ist) == -1) {
		lu_util_lock_free(ilock);
		close(ifd);
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), filename,
			     strerror(errno));
		return FALSE;
	}

	/* Generate the backup file's name and open it, creating it if it
	 * doesn't already exist. */
	backupname = g_strconcat(filename, "-", NULL);
	ofd = open(backupname, O_WRONLY | O_CREAT, ist.st_mode);
	if (ofd == -1) {
		lu_error_new(error, lu_error_open,
			     _("error creating `%s': %s"), backupname,
			     strerror(errno));
		g_free(backupname);
		lu_util_lock_free(ilock);
		close(ifd);
		return FALSE;
	}

	/* If we can't read its size, or it's not a normal file, bail. */
	if ((fstat(ofd, &ost) == -1) || !S_ISREG(ost.st_mode)) {
		struct stat st;
		if ((stat(backupname, &st) == -1) ||
		    !S_ISREG(st.st_mode) ||
		    (st.st_dev != ost.st_dev) ||
		    (st.st_ino != ost.st_ino)) {
			lu_error_new(error, lu_error_open,
				     _("backup file `%s' exists and is not a regular file"),
				     backupname);
			g_free(backupname);
			lu_util_lock_free(ilock);
			close(ifd);
			close(ofd);
			return FALSE;
		}
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), backupname,
			     strerror(errno));
		g_free(backupname);
		lu_util_lock_free(ilock);
		close(ifd);
		close(ofd);
		return FALSE;
	}

	/* Now lock the output file. */
	if ((olock = lu_util_lock_obtain(ofd, error)) == NULL) {
		g_free(backupname);
		lu_util_lock_free(ilock);
		close(ifd);
		close(ofd);
		return FALSE;
	}

	/* Set the permissions on the new file to match the old one. */
	fchown(ofd, ist.st_uid, ist.st_gid);
	fchmod(ofd, ist.st_mode);

	/* Copy the data, block by block. */
	do {
		len = read(ifd, buf, sizeof(buf));
		if (len >= 0) {
			write(ofd, buf, len);
		}
	} while (len == sizeof(buf));

	/* Flush data to disk, and truncate at the current offset.  This is
	 * necessary if the file existed before we opened it. */
	fsync(ofd);
	ftruncate(ofd, lseek(ofd, 0, SEEK_CUR));

	/* Re-read data about the output file. */
	if (fstat(ofd, &ost) == -1) {
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), backupname,
			     strerror(errno));
		g_free(backupname);
		lu_util_lock_free(ilock);
		close(ifd);
		lu_util_lock_free(olock);
		close(ofd);
		return FALSE;
	}

	/* We can close the files now. */
	lu_util_lock_free(ilock);
	close(ifd);
	lu_util_lock_free(olock);
	close(ofd);

	/* Complain if the files are somehow not the same. */
	g_return_val_if_fail(ist.st_size == ost.st_size, FALSE);

	g_free(backupname);

	return TRUE;
}

/* Read a line from the file, no matter how long it is, and return it as a
 * newly-allocated string, with the terminator intact. */
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
parse_generic(const gchar *line, const struct format_specifier *formats,
	      size_t format_count, struct lu_ent *ent)
{
	size_t i;
	int field, minimum = 1;
	gchar **v = NULL;
	GValue value;

	/* Make sure the line is properly formatted, meaning that it has enough
	 * fields in it for us to parse out all the fields we want, allowing for
	 * the last one to be empty. */
	for (i = 0; i < format_count; i++) {
		minimum = MAX(minimum, formats[i].position);
	}
	v = g_strsplit(line, ":", format_count);
	if (lu_strv_len(v) < (size_t)(minimum - 1)) {
		g_warning("entry is incorrectly formatted");
		return FALSE;
	}

	/* Now parse out the fields. */
	memset(&value, 0, sizeof(value));
	for (i = 0; i < format_count; i++) {
		field = formats[i].position - 1;
		/* Clear out old values in the destination structure. */
		lu_ent_clear_current(ent, formats[i].attribute);
		if (formats[i].multiple) {
			/* Field contains multiple comma-separated values. */
			gchar **w;
			int j;
			/* Split up the field. */
			w = g_strsplit(v[field] ?: "", ",", 0);
			/* Clear out old values. */
			for (j = 0; (w != NULL) && (w[j] != NULL); j++) {
				/* Skip over empty strings. */
				if (strlen(w[j]) == 0) {
					continue;
				}
				/* Initialize the value to the right type. */
				g_value_init(&value, formats[i].type);
				/* Set the value. */
				if (G_VALUE_HOLDS_STRING(&value)) {
					g_value_set_string(&value, w[j]);
				} else
				if (G_VALUE_HOLDS_LONG(&value)) {
					g_value_set_long(&value, atol(w[j]));
				} else {
					g_assert_not_reached();
				}
				/* Add it to the current values list. */
				lu_ent_add_current(ent, formats[i].attribute,
						   &value);
				g_value_unset(&value);
			}
			g_strfreev(w);
		} else {
			/* Initialize the value to the right type. */
			g_value_init(&value, formats[i].type);
			/* Check if we need to supply the default value. */
			if ((formats[i].def != NULL) &&
			    (strlen(v[field]) == 0)) {
				/* Convert the default to the right type. */
				if (G_VALUE_HOLDS_STRING(&value)) {
					g_value_set_string(&value,
							   formats[i].def);
				} else
				if (G_VALUE_HOLDS_LONG(&value)) {
					/* Make sure we're not doing something
					 * potentially-dangerous here. */
					g_assert(strlen(formats[i].def) > 0);
					g_value_set_long(&value,
							 atol(formats[i].def));
				} else {
					g_assert_not_reached();
				}
			} else {
				/* Use the value itself. */
				if (G_VALUE_HOLDS_STRING(&value)) {
					g_value_set_string(&value, v[field]);
				} else
				if (G_VALUE_HOLDS_LONG(&value)) {
					/* Make sure the field contains an
					 * actual (I'd say "real", but that's
					 * a loaded word) number. */
					char *p;
					long l;
					l = strtol(v[field], &p, 0);
					g_assert(p != NULL);
					if (*p != '\0') {
						g_warning("entry is incorrectly formatted");
						g_value_unset(&value);
						continue;
					}
					g_value_set_long(&value, l);
				} else {
					g_assert_not_reached();
				}
			}
			/* If we recovered a value, add it to the current
			 * values list for the entity. */
			lu_ent_add_current(ent, formats[i].attribute, &value);
			g_value_unset(&value);
		}
	}
	g_strfreev(v);
	return TRUE;
}

/* Parse an entry from /etc/passwd into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_files_parse_user_entry(const gchar * line, struct lu_ent *ent)
{
	gboolean ret;
	ent->type = lu_user;
	lu_ent_clear_all(ent);
	ret = parse_generic(line, format_passwd, G_N_ELEMENTS(format_passwd),
			    ent);
	return ret;
}

/* Parse an entry from /etc/group into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_files_parse_group_entry(const gchar * line, struct lu_ent *ent)
{
	gboolean ret;
	ent->type = lu_group;
	lu_ent_clear_all(ent);
	ret = parse_generic(line, format_group, G_N_ELEMENTS(format_group),
			    ent);
	return ret;
}

/* Parse an entry from /etc/shadow into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_shadow_parse_user_entry(const gchar * line, struct lu_ent *ent)
{
	gboolean ret;
	ent->type = lu_user;
	lu_ent_clear_all(ent);
	ret = parse_generic(line, format_shadow, G_N_ELEMENTS(format_shadow),
			    ent);
	return ret;
}

/* Parse an entry from /etc/shadow into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_shadow_parse_group_entry(const gchar * line, struct lu_ent *ent)
{
	gboolean ret;
	ent->type = lu_group;
	lu_ent_clear_all(ent);
	ret = parse_generic(line, format_gshadow, G_N_ELEMENTS(format_gshadow),
			    ent);
	return ret;
}

typedef gboolean(*parse_fn) (const gchar * line, struct lu_ent * ent);

/* Look up an entry in the named file, using the string stored in "name" as
 * a key, looking for it in the field'th field, using the given parsing
 * function to load any results we find into the entity structure. */
static gboolean
generic_lookup(struct lu_module *module, const char *base_name,
	       const char *name, int field, parse_fn parser,
	       struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = FALSE;
	const char *dir;
	int fd = -1;
	gpointer lock;
	char *line, *filename, *key;

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(name != NULL);
	g_assert(parser != NULL);
	g_assert(field > 0);
	g_assert(ent != NULL);

	/* Determine the name of the file we're going to read. */
	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	/* Open the file and lock it. */
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		g_free(filename);
		return FALSE;
	}
	g_free(filename);

	if ((lock = lu_util_lock_obtain(fd, error)) == NULL) {
		close(fd);
		return FALSE;
	}

	/* Search for the entry in this file. */
	line = lu_util_line_get_matchingx(fd, name, field, error);
	if (line == NULL) {
		lu_util_lock_free(lock);
		close(fd);
		return FALSE;
	}

	/* If we found data, parse it and then free the data. */
	ret = parser(line, ent);
	g_free(line);
	lu_util_lock_free(lock);
	close(fd);

	return ret;
}

/* Look up a user by name in /etc/passwd. */
static gboolean
lu_files_user_lookup_name(struct lu_module *module,
			  const char *name,
			  struct lu_ent *ent,
			  struct lu_error **error)
{
	gboolean ret;
	ret = generic_lookup(module, "passwd", name, 1,
			     lu_files_parse_user_entry, ent, error);
	return ret;
}

/* Look up a user by ID in /etc/passwd. */
static gboolean
lu_files_user_lookup_id(struct lu_module *module,
			uid_t uid,
			struct lu_ent *ent,
			struct lu_error **error)
{
	char *key;
	gboolean ret = FALSE;
	key = g_strdup_printf("%ld", (long)uid);
	ret = generic_lookup(module, "passwd", key, 3,
			     lu_files_parse_user_entry, ent, error);
	g_free(key);
	return ret;
}

/* Look up a user by name in /etc/shadow. */
static gboolean
lu_shadow_user_lookup_name(struct lu_module *module,
			   const char *name,
			   struct lu_ent *ent,
			   struct lu_error **error)
{
	gboolean ret;
	ret = generic_lookup(module, "shadow", name, 1,
			     lu_shadow_parse_user_entry, ent, error);
	return ret;
}

/* Look up a user by ID in /etc/shadow.  This becomes a bit tricky because
 * the shadow file doesn't contain UIDs, so we need to scan the passwd file
 * to convert the ID to a name first. */
static gboolean
lu_shadow_user_lookup_id(struct lu_module *module,
			 uid_t uid,
			 struct lu_ent *ent,
			 struct lu_error **error)
{
	char *key, *p = NULL;
	GValueArray *values;
	GValue *value;
	gboolean ret = FALSE;
	/* First look the user up by ID. */
	key = g_strdup_printf("%ld", (long)uid);
	ret = lu_files_user_lookup_id(module, uid, ent, error);
	if (ret) {
		/* Now use the user's name to search the shadow file. */
		values = lu_ent_get(ent, LU_USERNAME);
		if ((values != NULL) && (values->n_values > 0)) {
			value = g_value_array_get_nth(values, 0);
			if (G_VALUE_HOLDS_STRING(value)) {
				/* Generate a temporary string containing the
				 * user's name. */
				p = g_value_dup_string(value);
			} else
			if (G_VALUE_HOLDS_LONG(value)) {
				/* So very, very wrong. */
				p = g_strdup_printf("%ld",
						    g_value_get_long(value));
			} else {
				g_assert_not_reached();
			}
			ret = generic_lookup(module, "shadow", p, 1,
					     lu_shadow_parse_user_entry,
					     ent, error);
			g_free(p);
		}
	}
	g_free(key);
	return ret;
}

/* Look a group up by name in /etc/group. */
static gboolean
lu_files_group_lookup_name(struct lu_module *module,
			   const char *name,
			   struct lu_ent *ent,
			   struct lu_error **error)
{
	gboolean ret;
	ret = generic_lookup(module, "group", name, 1,
			     lu_files_parse_group_entry, ent, error);
	return ret;
}

/* Look a group up by ID in /etc/group. */
static gboolean
lu_files_group_lookup_id(struct lu_module *module,
			 gid_t gid,
			 struct lu_ent *ent,
			 struct lu_error **error)
{
	char *key;
	gboolean ret;
	key = g_strdup_printf("%ld", (long)gid);
	ret = generic_lookup(module, "group", key, 3,
			     lu_files_parse_group_entry, ent, error);
	g_free(key);
	return ret;
}

/* Look a group up by name in /etc/gshadow. */
static gboolean
lu_shadow_group_lookup_name(struct lu_module *module, const char *name,
			    struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret;
	ret = generic_lookup(module, "gshadow", name, 1,
			     lu_shadow_parse_group_entry, ent, error);
	return ret;
}

/* Look up a group by ID in /etc/gshadow.  This file doesn't contain any
 * GIDs, so we have to use /etc/group to convert the GID to a name first. */
static gboolean
lu_shadow_group_lookup_id(struct lu_module *module, gid_t gid,
			  struct lu_ent *ent, struct lu_error **error)
{
	char *key;
	GValueArray *values;
	GValue *value;
	gboolean ret = FALSE;
	key = g_strdup_printf("%ld", (long)gid);
	ret = lu_files_group_lookup_id(module, gid, ent, error);
	if (ret) {
		values = lu_ent_get(ent, LU_GROUPNAME);
		if ((values != NULL) && (values->n_values > 0)) {
			char *p = NULL;
			value = g_value_array_get_nth(values, 0);
			if (G_VALUE_HOLDS_STRING(value)) {
				/* Generate a copy of the group's name. */
				p = g_value_dup_string(value);
			} else
			if (G_VALUE_HOLDS_LONG(value)) {
				/* So very, very wrong.... */
				p = g_strdup_printf("%ld",
					            g_value_get_long(value));
			} else {
				g_assert_not_reached();
			}
			ret = generic_lookup(module, "gshadow", p, 1,
					     lu_shadow_parse_group_entry,
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
	GValue value, *val;
	char *ret = NULL, *p, *tmp;
	size_t i, j;

	g_return_val_if_fail(ent != NULL, NULL);
	memset(&value, 0, sizeof(value));

	for (i = 0; i < format_count; i++) {
		/* Add a separator, if we need to, before advancing to
		 * this field.  This way we ensure that the correct number
		 * of fields will result, even if they're empty.  Note that
		 * this implies that position values are always in ascending
		 * order. */
		if (i > 0) {
			g_assert(formats[i].position - formats[i - 1].position >= 0);
			j = formats[i].position - formats[i - 1].position;
			while (j-- > 0) {
				tmp = g_strconcat(ret ?: "", ":", NULL);
				if (ret) {
					g_free(ret);
				}
				ret = tmp;
			}
		}
		/* Retrieve the values for this attribute. */
		values = lu_ent_get(ent, formats[i].attribute);
		if ((values != NULL) && (values->n_values > 0)) {
			/* Iterate over all of the data items we can, prepending
			 * a comma to all but the first. */
			j = 0;
			do {
				/* Get a string representation of this value. */
				val = g_value_array_get_nth(values, j);
				p = NULL;
				if (G_VALUE_HOLDS_STRING(val)) {
					p = g_value_dup_string(val);
				} else
				if (G_VALUE_HOLDS_LONG(val)) {
					p = g_strdup_printf("%ld",
							    g_value_get_long(val));
				} else {
					g_assert_not_reached();
				}
				/* Add it to the end, prepending a comma if we
				 * need to separate it from another value,
				 * unless this is the default value for the
				 * field and we need to suppress it. */
				if ((formats[i].def != NULL) &&
				    (formats[i].multiple == FALSE) &&
				    (strcmp(formats[i].def, p) == 0) &&
				    (formats[i].suppress_if_def == TRUE)) {
					tmp = g_strdup(ret);
				} else {
					tmp = g_strconcat(ret ?: "",
							  (j > 0) ? "," : "",
							  p,
							  NULL);
				}
				g_free(p);
				if (ret != NULL) {
					g_free(ret);
				}
				ret = tmp;
				j++;
			} while (formats[i].multiple && (j < values->n_values));
		} else {
			/* We have no values, so check for a default value,
			 * unless we're suppressing it. */
			if ((formats[i].def != NULL) &&
			    (formats[i].suppress_if_def == FALSE)) {
				/* Use the default listed in the format
				 * specifier. */
				tmp = g_strconcat(ret ?: "",
						  formats[i].def,
						  NULL);
				if (ret != NULL) {
					g_free(ret);
				}
				ret = tmp;
			}
		}
	}
	/* Add an end-of-line terminator. */
	p = g_strconcat(ret ?: "", "\n", NULL);
	if (ret) {
		g_free(ret);
	}
	ret = p;

	return ret;
}

/* Construct a line for /etc/passwd using data in the lu_ent structure. */
static char *
lu_files_format_user(struct lu_ent *ent)
{
	char *ret;
	ret = format_generic(ent, format_passwd, G_N_ELEMENTS(format_passwd));
	return ret;
}

/* Construct a line for /etc/group using data in the lu_ent structure. */
static char *
lu_files_format_group(struct lu_ent *ent)
{
	char *ret;
	ret = format_generic(ent, format_group, G_N_ELEMENTS(format_group));
	return ret;
}

/* Construct a line for /etc/shadow using data in the lu_ent structure. */
static char *
lu_shadow_format_user(struct lu_ent *ent)
{
	char *ret;
	ret = format_generic(ent, format_shadow, G_N_ELEMENTS(format_shadow));
	return ret;
}

/* Construct a line for /etc/gshadow using data in the lu_ent structure. */
static char *
lu_shadow_format_group(struct lu_ent *ent)
{
	char *ret;
	ret = format_generic(ent, format_gshadow, G_N_ELEMENTS(format_gshadow));
	return ret;
}

typedef char *(*format_fn) (struct lu_ent * ent);

/* Add an entity to a given flat file, using a given formatting functin to
 * construct the proper text data. */
static gboolean
generic_add(struct lu_module *module, const char *base_name,
	    format_fn formatter, struct lu_ent *ent,
	    struct lu_error **error)
{
	security_context_t prev_context;
	const char *dir;
	char *key, *line, *filename, *contents;
	char *fragment1, *fragment2;
	int fd;
	int r;
	gpointer lock;
	struct stat st;
	off_t offset;
	gboolean ret = FALSE;

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(formatter != NULL);
	g_assert(ent != NULL);

	/* Generate the name of a file to open. */
	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if (!set_default_context(filename, &prev_context, error)) {
		g_free(filename);
		return FALSE;
	}

	/* Create a backup copy of the file we're about to modify. */
	if (lu_files_create_backup(filename, error) == FALSE)
		goto err_filename;

	/* Open the file. */
	fd = open(filename, O_RDWR);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		goto err_filename;
	}

	/* Lock the file. */
	if ((lock = lu_util_lock_obtain(fd, error)) == NULL)
		goto err_fd;

	/* Read the file's size. */
	if (fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), filename,
			     strerror(errno));
		goto err_lock;
	}

	/* Generate a new line with the right data in it, and allocate space
	 * for the contents of the file. */
	line = formatter(ent); /* FIXME: free? */
	contents = g_malloc0(st.st_size + 1);

	/* We sanity-check here to make sure that the entity isn't already
	 * listed in the file by name by searching for the initial part of
	 * the line. */
	if (line && strchr(line, ':')) {
		fragment1 = g_strndup(line, strchr(line, ':') - line + 1);
	} else {
		if (line && strchr(line, '\n')) {
			fragment1 = g_strndup(line,
					      strchr(line, '\n') - line + 1);
		} else {
			fragment1 = g_strdup(line);
		}
	}
	fragment2 = g_strconcat("\n", fragment1, NULL);

	/* Read the entire file in.  There's some room for improvement here,
	 * but at least we still have the lock, so it's not going to get
	 * funky on us. */
	if (read(fd, contents, st.st_size) != st.st_size) {
		lu_error_new(error, lu_error_read,
			     _("couldn't read from `%s': %s"),
			     filename, strerror(errno));
		goto err_fragment2;
	}

	/* Check if the beginning of the file is the same as the beginning
	 * of the entry. */
	if (strncmp(contents, fragment1, strlen(fragment1)) == 0) {
		lu_error_new(error, lu_error_generic,
			     _("entry already present in file"));
		goto err_fragment2;
	} else
	/* If not, search for a newline followed by the beginning of
	 * the entry. */
	if (strstr(contents, fragment2) != NULL) {
		lu_error_new(error, lu_error_generic,
			     _("entry already present in file"));
		goto err_fragment2;
	}
	/* Hooray, we can add this entry at the end of the file. */
	offset = lseek(fd, 0, SEEK_END);
	if (offset == -1) {
		lu_error_new(error, lu_error_write,
			     _("couldn't write to `%s': %s"),
			     filename, strerror(errno));
		goto err_fragment2;
	}
	/* If the last byte in the file isn't a newline, add one, and silently
	 * curse people who use text editors (which shall remain unnamed) which
	 * allow saving of the file without a final line terminator. */
	if ((st.st_size > 0) && (contents[st.st_size - 1] != '\n')) {
		write(fd, "\n", 1);
	}
	/* Attempt to write the entire line to the end. */
	r = write(fd, line, strlen(line));
	if ((size_t)r != strlen(line)) {
		/* Oh, come on! */
		lu_error_new(error, lu_error_write,
			     _("couldn't write to `%s': %s"),
			     filename,
			     strerror(errno));
		/* Truncate off whatever we actually managed to write and
		 * give up. */
		ftruncate(fd, offset);
		goto err_fragment2;
	}
	/* Hey, it succeeded. */
	ret = TRUE;
	/* Fall through */

 err_fragment2:
	g_free(fragment2);
	g_free(fragment1);
	g_free(contents);
 err_lock:
	lu_util_lock_free(lock);
 err_fd:
	close(fd);
 err_filename:
	g_free(filename);
	reset_default_context(prev_context, error);
	return ret;
}

/* Make last-minute changes to the structures before adding them. */
static gboolean
lu_files_user_add_prep(struct lu_module *module, struct lu_ent *ent,
		       struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return TRUE;
}

/* Add the user record to the passwd file. */
static gboolean
lu_files_user_add(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	gboolean ret;
	ret = generic_add(module, "passwd", lu_files_format_user, ent, error);
	return ret;
}

/* Make last-minute changes to the record before adding it to /etc/shadow. */
static gboolean
lu_shadow_user_add_prep(struct lu_module *module, struct lu_ent *ent,
		        struct lu_error **error)
{
	GValue svalue;

	(void)module;
	(void)error;
	/* Make sure the regular password says "shadow!" */
	memset(&svalue, 0, sizeof(svalue));
	g_value_init(&svalue, G_TYPE_STRING);
	g_value_set_string(&svalue, "x");
	lu_ent_clear(ent, LU_USERPASSWORD);
	lu_ent_add(ent, LU_USERPASSWORD, &svalue);
	g_value_unset(&svalue);

	return TRUE;
}

/* Add the user to the shadow file. */
static gboolean
lu_shadow_user_add(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	gboolean ret;
	ret = generic_add(module, "shadow", lu_shadow_format_user, ent, error);
	return ret;
}

/* Make last-minute changes before adding the group to the group file. */
static gboolean
lu_files_group_add_prep(struct lu_module *module, struct lu_ent *ent,
		        struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return TRUE;
}

/* Add the group to the group file. */
static gboolean
lu_files_group_add(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	gboolean ret;
	ret = generic_add(module, "group", lu_files_format_group, ent, error);
	return ret;
}

/* Make last-minute changes before adding the shadowed group. */
static gboolean
lu_shadow_group_add_prep(struct lu_module *module, struct lu_ent *ent,
		         struct lu_error **error)
{
	GValue svalue;

	(void)module;
	(void)error;
	/* Make sure the regular password says "shadow!" */
	memset(&svalue, 0, sizeof(svalue));
	g_value_init(&svalue, G_TYPE_STRING);
	g_value_set_string(&svalue, "x");
	lu_ent_clear(ent, LU_GROUPPASSWORD);
	lu_ent_add(ent, LU_GROUPPASSWORD, &svalue);
	g_value_unset(&svalue);

	return TRUE;
}

/* Add a shadowed group. */
static gboolean
lu_shadow_group_add(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	gboolean ret;
	ret = generic_add(module, "gshadow", lu_shadow_format_group, ent, error);
	return ret;
}

/* Modify a particular record in the given file, field by field, using the
 * given format specifiers. */
static gboolean
generic_mod(struct lu_module *module, const char *base_name,
	    const struct format_specifier *formats, size_t format_count,
	    struct lu_ent *ent, struct lu_error **error)
{
	security_context_t prev_context;
	char *filename = NULL, *key = NULL;
	int fd = -1;
	gpointer lock;
	size_t i, j;
	const char *dir = NULL;
	char *p, *q, *new_value;
	GValueArray *names = NULL, *values = NULL;
	GValue *value;
	gboolean ret = FALSE;

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(formats != NULL);
	g_assert(format_count > 0);
	g_assert(ent != NULL);
	g_assert((ent->type == lu_user) || (ent->type == lu_group));

	/* Get the array of names for the entity object. */
	if (ent->type == lu_user) {
		names = lu_ent_get_current(ent, LU_USERNAME);
		if (names == NULL) {
			lu_error_new(error, lu_error_generic,
				     _("entity object has no %s attribute"),
				     LU_USERNAME);
			return FALSE;
		}
	} else if (ent->type == lu_group) {
		names = lu_ent_get_current(ent, LU_GROUPNAME);
		if (names == NULL) {
			lu_error_new(error, lu_error_generic,
				     _("entity object has no %s attribute"),
				     LU_GROUPNAME);
			return FALSE;
		}
	} else
		g_assert_not_reached();

	/* Generate the name of the file to open. */
	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if (!set_default_context(filename, &prev_context, error)) {
		g_free(filename);
		return FALSE;
	}
	/* Create a backup file. */
	if (lu_files_create_backup(filename, error) == FALSE)
		goto err_filename;

	/* Open the file to be modified. */
	fd = open(filename, O_RDWR);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		goto err_filename;
	}

	/* Lock the file. */
	if ((lock = lu_util_lock_obtain(fd, error)) == NULL)
		goto err_fd;

	/* We iterate over all of the fields individually. */
	for (i = 0; i < format_count; i++) {
		gboolean ret2;

		/* Read the values, and format them as a field. */
		values = lu_ent_get(ent, formats[i].attribute);
		new_value = NULL;
		j = 0;
		if (values != NULL) do {
			p = NULL;
			/* Convert a single value to a string. */
			value = g_value_array_get_nth(values, j);
			if (G_VALUE_HOLDS_STRING(value)) {
				p = g_value_dup_string(value);
			} else
			if (G_VALUE_HOLDS_LONG(value)) {
				p = g_strdup_printf("%ld",
						    g_value_get_long(value));
			} else {
				g_assert_not_reached();
			}
			/* Add this new value to the existing string, prepending
			 * a comma if we've already seen any other values. */
			q = g_strconcat(new_value ?: "",
					(j > 0) ? "," : "",
					p,
					NULL);
			if (new_value != NULL) {
				g_free(new_value);
			}
			new_value = q;
			g_free(p);
			j++;
		} while (formats[i].multiple && (j < values->n_values));

		/* Get the current name for this entity. */
		value = g_value_array_get_nth(names, 0);
		/* If the value we're about to write is the default, just use
		 * an empty string. */
		if ((formats[i].suppress_if_def == TRUE) &&
		    (formats[i].def != NULL) &&
		    (strcmp(formats[i].def, new_value) == 0)) {
			ret2 = lu_util_field_write(fd,
						   g_value_get_string(value),
						   formats[i].position,
						   "", error);
		} else {
			/* Otherwise write the new value. */
			ret2 = lu_util_field_write(fd,
						   g_value_get_string(value),
						   formats[i].position,
						   new_value, error);
		}

		g_free(new_value);

		/* If we had a write error, we fail now. */
		if (ret2 == FALSE)
			goto err_lock;

		/* We may have just renamed the account (we're safe assuming
		 * the new name is correct here because if we renamed it, we
		 * changed the name field first), so switch to using the
		 * account's new name. */
		if (ent->type == lu_user) {
			names = lu_ent_get(ent, LU_USERNAME);
			if (names == NULL) {
				lu_error_new(error, lu_error_generic,
					     _("entity object has no %s attribute"),
					     LU_USERNAME);
				goto err_lock;
			}
		} else if (ent->type == lu_group) {
			names = lu_ent_get(ent, LU_GROUPNAME);
			if (names == NULL) {
				lu_error_new(error, lu_error_generic,
					     _("entity object has no %s attribute"),
					     LU_GROUPNAME);
				goto err_lock;
			}
		} else
			g_assert_not_reached();
	}

	ret = TRUE;
	/* Fall through */

 err_lock:
	lu_util_lock_free(lock);
 err_fd:
	close(fd);
 err_filename:
	g_free(filename);
	reset_default_context(prev_context, error);
	return ret;
}

/* Modify an entry in the passwd file. */
static gboolean
lu_files_user_mod(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	gboolean ret;
	ret = generic_mod(module, "passwd", format_passwd,
			  G_N_ELEMENTS(format_passwd), ent, error);
	return ret;
}

/* Modify an entry in the group file. */
static gboolean
lu_files_group_mod(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	gboolean ret;
	ret = generic_mod(module, "group", format_group,
			  G_N_ELEMENTS(format_group), ent, error);
	return ret;
}

/* Modify an entry in the shadow file. */
static gboolean
lu_shadow_user_mod(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	gboolean ret;
	ret = generic_mod(module, "shadow", format_shadow,
			  G_N_ELEMENTS(format_shadow), ent, error);

	return ret;
}

/* Modify an entry in the gshadow file. */
static gboolean
lu_shadow_group_mod(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	gboolean ret;
	ret = generic_mod(module, "gshadow", format_gshadow,
			  G_N_ELEMENTS(format_gshadow), ent, error);
	return ret;
}

/* Delete an entity from the given file. */
static gboolean
generic_del(struct lu_module *module, const char *base_name,
	    struct lu_ent *ent, struct lu_error **error)
{
	security_context_t prev_context;
	GValueArray *name = NULL;
	GValue *value;
	char *contents = NULL, *filename = NULL, *key = NULL;
	char *fragment1 = NULL, *fragment2, *tmp;
	const char *dir;
	struct stat st;
	size_t len;
	int fd = -1;
        gboolean ret = FALSE;
	gboolean found;
	gpointer lock;

	/* Get the entity's current name. */
	if (ent->type == lu_user)
		name = lu_ent_get_current(ent, LU_USERNAME);
	else if (ent->type == lu_group)
		name = lu_ent_get_current(ent, LU_GROUPNAME);
	else
		g_assert_not_reached();
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(ent != NULL);

	/* Generate the name of the file we're going to modify. */
	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if (!set_default_context(filename, &prev_context, error)) {
		g_free(filename);
		return FALSE;
	}
	/* Create a backup of that file. */
	if (lu_files_create_backup(filename, error) == FALSE)
		goto err_filename;

	/* Open the file to be modified. */
	fd = open(filename, O_RDWR);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		goto err_filename;
	}

	/* Lock the file. */
	if ((lock = lu_util_lock_obtain(fd, error)) == NULL)
		goto err_fd;

	/* Determine the file's size. */
	if (fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), filename,
			     strerror(errno));
		goto err_lock;
	}

	/* Allocate space to hold the file and read it all in. */
	contents = g_malloc0(st.st_size + 1);
	if (read(fd, contents, st.st_size) != st.st_size) {
		lu_error_new(error, lu_error_read,
			     _("couldn't read from `%s': %s"), filename,
			     strerror(errno));
		goto err_contents;
	}

	/* Generate string versions of what the beginning of a line might
	 * look like. */
	value = g_value_array_get_nth(name, 0);
	if (G_VALUE_HOLDS_STRING(value))
		fragment1 = g_strdup_printf("%s:", g_value_get_string(value));
	else if (G_VALUE_HOLDS_LONG(value))
		fragment1 = g_strdup_printf("%ld:", g_value_get_long(value));
	else
		g_assert_not_reached();
	fragment2 = g_strdup_printf("\n%s", fragment1);

	/* Remove all occurrences of this entry from the file. */
	len = strlen(fragment1);
	do {
		found = FALSE;
		/* If the data is on the first line of the file, we remove the
		 * first line. */
		if (strncmp(contents, fragment1, len) == 0) {
			char *p = strchr(contents, '\n');
			strcpy(contents, p ? (p + 1) : "");
			found = TRUE;
		} else
		/* If the data occurs elsewhere, cover it up. */
		if ((tmp = strstr(contents, fragment2)) != NULL) {
			char *p = strchr(tmp + 1, '\n');
			strcpy(tmp + 1, p ? (p + 1) : "");
			found = TRUE;
		}
	} while(found);

	g_free(fragment1);
	g_free(fragment2);

	/* If the resulting memory chunk is the same size as the file, then
	 * nothing's changed. */
	len = strlen(contents);
	if ((off_t)len == st.st_size) {
		ret = TRUE;
		goto err_contents;
	}

	/* Otherwise we need to write the new data to the file.  Jump back to
	 * the beginning of the file. */
	if (lseek(fd, 0, SEEK_SET) == -1) {
		lu_error_new(error, lu_error_write,
			     _("couldn't write to `%s': %s"), filename,
			     strerror(errno));
		goto err_contents;
	}

	/* Write the new contents out. */
	if ((size_t)write(fd, contents, len) != len) {
		lu_error_new(error, lu_error_write,
			     _("couldn't write to `%s': %s"), filename,
			     strerror(errno));
		goto err_contents;
	}

	/* Truncate the file to the new (certainly shorter) length. */
	ftruncate(fd, len);
	ret = TRUE;
	/* Fall through */
	
 err_contents:
	g_free(contents);
 err_lock:
	lu_util_lock_free(lock);
 err_fd:
	close(fd);
 err_filename:
	g_free(filename);
	reset_default_context(prev_context, error);
	return ret;
}

/* Remove a user from the passwd file. */
static gboolean
lu_files_user_del(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	gboolean ret;
	ret = generic_del(module, "passwd", ent, error);
	return ret;
}

/* Remove a group from the group file. */
static gboolean
lu_files_group_del(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	gboolean ret;
	ret = generic_del(module, "group", ent, error);
	return ret;
}

/* Remove a user from the shadow file. */
static gboolean
lu_shadow_user_del(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	gboolean ret;
	ret = generic_del(module, "shadow", ent, error);
	return ret;
}

/* Remove a group from the gshadow file. */
static gboolean
lu_shadow_group_del(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	gboolean ret;
	ret = generic_del(module, "gshadow", ent, error);
	return ret;
}

/* Return the "locked" or "unlocked" version of the cryptedPassword string,
 * depending on whether or not lock is true. */
static char *
lock_process(char *cryptedPassword, gboolean lock, struct lu_ent *ent)
{
	char *ret = NULL;
	if (lock) {
		ret = ent->cache->cache(ent->cache, cryptedPassword);
		if (ret[0] != '!') {
			cryptedPassword = g_strconcat("!!", ret, NULL);
			ret = ent->cache->cache(ent->cache, cryptedPassword);
			g_free(cryptedPassword);
		}
	} else {
		ret = ent->cache->cache(ent->cache, cryptedPassword);
		while(ret[0] == '!') {
			ret = ent->cache->cache(ent->cache, ret + 1);
		}
	}
	return ret;
}

/* Lock or unlock an account in the given file, with its encrypted password
 * stored in the given field number. */
static gboolean
generic_lock(struct lu_module *module, const char *base_name, int field,
	     struct lu_ent *ent, gboolean lock_or_not,
	     struct lu_error **error)
{
	security_context_t prev_context;
	GValueArray *name = NULL;
	GValue *val;
	char *filename = NULL, *key = NULL;
	const char *dir;
	char *value, *new_value, *namestring = NULL;
	int fd = -1;
	gpointer lock;
	gboolean ret = FALSE;

	/* Get the name which keys the entries of interest in the file. */
	g_assert((ent->type == lu_user) || (ent->type == lu_group));
	if (ent->type == lu_user)
		name = lu_ent_get_current(ent, LU_USERNAME);
	if (ent->type == lu_group)
		name = lu_ent_get_current(ent, LU_GROUPNAME);
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(ent != NULL);

	/* Generate the name of the file we're going to modify. */
	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if (!set_default_context(filename, &prev_context, error)) {
		g_free(filename);
		return FALSE;
	}
	/* Create a backup of the file. */
	if (lu_files_create_backup(filename, error) == FALSE)
		goto err_filename;

	/* Open the file. */
	fd = open(filename, O_RDWR);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		goto err_filename;
	}

	/* Lock the file. */
	if ((lock = lu_util_lock_obtain(fd, error)) == NULL)
		goto err_fd;

	/* Generate a string representation of the name. */
	val = g_value_array_get_nth(name, 0);
	if (G_VALUE_HOLDS_STRING(val))
		namestring = g_value_dup_string(val);
	else if (G_VALUE_HOLDS_LONG(val))
		namestring = g_strdup_printf("%ld", g_value_get_long(val));
	else
		g_assert_not_reached();

	/* Read the old value from the file. */
	value = lu_util_field_read(fd, namestring, field, error);
	if (value == NULL)
		goto err_namestring;

	/* Check that we actually care about this.  If there's a non-empty,
	 * not locked string in there, but it's too short to be a hash, then
	 * we don't care, so we just nod our heads and smile. */
	if (LU_CRYPT_INVALID(value)) {
		g_free(value);
		ret = TRUE;
		goto err_namestring;
	}

	/* Generate a new value for the file. */
	new_value = lock_process(value, lock_or_not, ent);
	g_free(value);

	/* Make the change. */
	ret = lu_util_field_write(fd, namestring, field, new_value, error);
	/* Fall through */

 err_namestring:
	g_free(namestring);
	lu_util_lock_free(lock);
 err_fd:
	close(fd);
 err_filename:
	g_free(filename);
	reset_default_context(prev_context, error);
	return ret;
}

/* Check if an account [password] is locked. */
static gboolean
generic_is_locked(struct lu_module *module, const char *base_name,
		  int field, struct lu_ent *ent, struct lu_error **error)
{
	GValueArray *name = NULL;
	GValue *val;
	char *filename = NULL, *key = NULL;
	const char *dir, *namestring = NULL;
	char *value;
	int fd = -1;
	gpointer lock;
	gboolean ret = FALSE;

	/* Get the name of this account. */
	g_assert((ent->type == lu_user) || (ent->type == lu_group));
	if (ent->type == lu_user) {
		name = lu_ent_get_current(ent, LU_USERNAME);
	}
	if (ent->type == lu_group) {
		name = lu_ent_get_current(ent, LU_GROUPNAME);
	}
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(ent != NULL);

	/* Construct the name of the file to read. */
	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	/* Open the file. */
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		g_free(filename);
		return FALSE;
	}

	/* Lock the file. */
	if ((lock = lu_util_lock_obtain(fd, error)) == NULL) {
		close(fd);
		g_free(filename);
		return FALSE;
	}

	/* Construct the actual name of the account holder(s). */
	val = g_value_array_get_nth(name, 0);
	if (G_VALUE_HOLDS_STRING(val)) {
		namestring = g_value_dup_string(val);
	} else
	if (G_VALUE_HOLDS_LONG(val)) {
		namestring = g_strdup_printf("%ld", g_value_get_long(val));
	} else {
		g_assert_not_reached();
	}

	/* Read the value. */
	value = lu_util_field_read(fd, namestring, field, error);
	if (value == NULL) {
		lu_util_lock_free(lock);
		close(fd);
		g_free(filename);
		return FALSE;
	}

	/* It all comes down to this. */
	ret = value[0] == '!';
	g_free(value);

	lu_util_lock_free(lock);
	close(fd);
	g_free(filename);
	return ret;
}

/* Lock a user from the passwd file. */
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

/* Lock a group from the group file. */
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

/* Lock a user in the shadow file. */
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

/* Lock a group in the gshadow file. */
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

/* Check if the account is locked. */
static gboolean
lu_files_user_is_locked(struct lu_module *module, struct lu_ent *ent,
		        struct lu_error **error)
{
	gboolean ret;
	ret = generic_is_locked(module, "passwd", 2, ent, error);
	return ret;
}

static gboolean
lu_files_group_is_locked(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	gboolean ret;
	ret = generic_is_locked(module, "group", 2, ent, error);
	return ret;
}

static gboolean
lu_shadow_user_is_locked(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	gboolean ret;
	ret = generic_is_locked(module, "shadow", 2, ent, error);
	return ret;
}

static gboolean
lu_shadow_group_is_locked(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	gboolean ret;
	ret = generic_is_locked(module, "gshadow", 2, ent, error);
	return ret;
}

/* Change a password, in a given file, in a given field, for a given account,
 * to a given value.  Got that? */
static gboolean
generic_setpass(struct lu_module *module, const char *base_name, int field,
		struct lu_ent *ent, const char *password,
		struct lu_error **error)
{
	security_context_t prev_context;
	GValueArray *name = NULL;
	GValue *val;
	char *filename = NULL, *key = NULL, *value, *namestring = NULL;
	const char *dir;
	int fd = -1;
	gpointer lock;
	gboolean ret = FALSE;

	/* Get the name of this account. */
	g_assert((ent->type == lu_user) || (ent->type == lu_group));
	if (ent->type == lu_user)
		name = lu_ent_get_current(ent, LU_USERNAME);
	else if (ent->type == lu_group)
		name = lu_ent_get_current(ent, LU_GROUPNAME);
	g_assert(name != NULL);

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(ent != NULL);

	/* Construct the name of the file to modify. */
	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	if (!set_default_context(filename, &prev_context, error)) {
		g_free(filename);
		return FALSE;
	}

	/* Create a backup of the file. */
	if (lu_files_create_backup(filename, error) == FALSE)
		goto err_filename;

	/* Open the file. */
	fd = open(filename, O_RDWR);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		goto err_filename;
	}

	/* Lock the file. */
	if ((lock = lu_util_lock_obtain(fd, error)) == NULL)
		goto err_fd;

	/* Get the name of the account. */
	val = g_value_array_get_nth(name, 0);
	if (G_VALUE_HOLDS_STRING(val))
		namestring = g_value_dup_string(val);
	else if (G_VALUE_HOLDS_LONG(val))
		namestring = g_strdup_printf("%ld", g_value_get_long(val));
	else
		g_assert_not_reached();

	/* Read the current contents of the field. */
	value = lu_util_field_read(fd, namestring, field, error);
	if (value == NULL)
		goto err_namestring;
	
	/* If we don't really care, nod our heads and smile. */
	if (LU_CRYPT_INVALID(value)) {
		ret = TRUE;
		goto err_value;
	}

	/* The crypt prefix indicates that the password is already hashed.  If
	 * we don't see it, hash the password. */
	if (g_ascii_strncasecmp(password, LU_CRYPTED, strlen(LU_CRYPTED)) == 0) {
		password = password + strlen(LU_CRYPTED);
	} else {
		password = lu_make_crypted(password,
					   lu_common_default_salt_specifier(module));
		if (password == NULL) {
			/* FIXME: STRING_FREEZE */
			lu_error_new(error, lu_error_generic,
				     "error encrypting password");
			goto err_value;
		}
	}

	/* Now write our changes to the file. */
	ret = lu_util_field_write(fd, namestring, field, password, error);
	/* Fall through */

 err_value:
	g_free(value);
 err_namestring:
	g_free(namestring);
	lu_util_lock_free(lock);
 err_fd:
	close(fd);
 err_filename:
	reset_default_context(prev_context, error);
	g_free(filename);
	return ret;
}

/* Set a user's password in the passwd file. */
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

static gboolean
lu_files_user_removepass(struct lu_module *module, struct lu_ent *ent,
		         struct lu_error **error)
{
	gboolean ret;
	ret = generic_setpass(module, "passwd", 2, ent, LU_CRYPTED, error);
	return ret;
}

static gboolean
lu_files_group_removepass(struct lu_module *module, struct lu_ent *ent,
		          struct lu_error **error)
{
	gboolean ret;
	ret = generic_setpass(module, "group", 2, ent, LU_CRYPTED, error);
	return ret;
}

/* Set the shadow last-changed field to today's date. */
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

static gboolean
lu_shadow_user_removepass(struct lu_module *module, struct lu_ent *ent,
		          struct lu_error **error)
{
	gboolean ret;
	ret = generic_setpass(module, "shadow", 2, ent, LU_CRYPTED, error);
	if (ret) {
		set_shadow_last_change(module, ent);
	}
	return ret;
}

static gboolean
lu_shadow_group_removepass(struct lu_module *module, struct lu_ent *ent,
			   struct lu_error **error)
{
	gboolean ret;
	ret = generic_setpass(module, "gshadow", 2, ent, LU_CRYPTED, error);
	if (ret) {
		set_shadow_last_change(module, ent);
	}
	return ret;
}

/* Get a list of all of the entries in a given file which patch a
 * particular pattern. */
static GValueArray *
lu_files_enumerate(struct lu_module *module, const char *base_name,
		   const char *pattern, struct lu_error **error)
{
	int fd;
	gpointer lock;
	GValueArray *ret = NULL;
	GValue value;
	char *buf;
	char *key = NULL, *filename = NULL, *p;
	const char *dir = NULL;
	FILE *fp;

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	pattern = pattern ?: "*";

	/* Generate the name of the file we'll be reading. */
	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	/* Open the file. */
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		g_free(filename);
		return NULL;
	}

	/* Lock the file. */
	if ((lock = lu_util_lock_obtain(fd, error)) == NULL) {
		close(fd);
		g_free(filename);
		return NULL;
	}

	/* Wrap the file for stdio operations. */
	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		lu_util_lock_free(lock);
		close(fd);
		g_free(filename);
		return NULL;
	}

	/* Create a new array to hold values. */
	ret = g_value_array_new(0);
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);
	/* Read each line, */
	while ((buf = line_read(fp)) != NULL) {
		if (strlen(buf) == 1) {
			g_free(buf);
			continue;
		}
		/* require that each non-empty line has meaningful data in it */
		p = strchr(buf, ':');
		if (p != NULL) {
			/* snip off the parts we don't care about, */
			*p = '\0';
			if (fnmatch(pattern, buf, 0) == 0) {
				/* add add it to the list we're returning. */
				g_value_set_string(&value, buf);
				g_value_array_append(ret, &value);
				g_value_reset(&value);
			}
		}
		g_free(buf);
	}

	/* Clean up. */
	g_value_unset(&value);
	lu_util_lock_free(lock);
	fclose(fp);
	g_free(filename);

	return ret;
}

/* Get a list of all users or groups. */
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

/* Get a list of all of the users who are in a given group. */
static GValueArray *
lu_files_users_enumerate_by_group(struct lu_module *module,
				  const char *group, gid_t gid,
				  struct lu_error **error)
{
	int fd;
	gpointer lock;
	GValueArray *ret = NULL;
	GValue value;
	char *buf, grp[CHUNK_SIZE];
	char *key = NULL, *pwdfilename = NULL, *grpfilename = NULL, *p, *q;
	const char *dir = NULL;
	FILE *fp;

	g_assert(module != NULL);
	g_assert(group != NULL);

	/* Generate the names of the two files we'll be looking at. */
	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	pwdfilename = g_strconcat(dir, "/passwd", NULL);
	grpfilename = g_strconcat(dir, "/group", NULL);
	g_free(key);

	/* Open the passwd file. */
	fd = open(pwdfilename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), pwdfilename,
			     strerror(errno));
		g_free(pwdfilename);
		g_free(grpfilename);
		return NULL;
	}

	/* Lock the passwd file. */
	if ((lock = lu_util_lock_obtain(fd, error)) == NULL) {
		close(fd);
		g_free(pwdfilename);
		g_free(grpfilename);
		return NULL;
	}

	/* Wrap the descriptor in a stdio FILE. */
	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), pwdfilename,
			     strerror(errno));
		lu_util_lock_free(lock);
		close(fd);
		g_free(pwdfilename);
		g_free(grpfilename);
		return NULL;
	}

	/* Create an array to store values we're going to return. */
	ret = g_value_array_new(0);
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);
	snprintf(grp, sizeof(grp), "%d", gid);

	/* Iterate over each line. */
	while ((buf = line_read(fp)) != NULL) {
		if (strlen(buf) == 1) {
			g_free(buf);
			continue;
		}
		/* Find the end of the first field. */
		p = strchr(buf, ':');
		q = NULL;
		/* If the field has an end, find the end of the second field. */
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		/* If the second field has an end, find the end of the third. */
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		/* If the third has an end, find the fourth. */
		if (p != NULL) {
			*p = '\0';
			p++;
			q = p;
			p = strchr(p, ':');
		}
		/* If we haven't run out of fields by now, we can match. */
		if (q != NULL) {
			/* Terminate the fourth field. */
			if (p != NULL) {
				*p = '\0';
			}
			/* If it matches the gid, add this user's name to the
			 * list. */
			if (strcmp(q, grp) == 0) {
				g_value_set_string(&value, buf);
				g_value_array_append(ret, &value);
				g_value_reset(&value);
			}
		}
		g_free(buf);
	}
	/* Close the file. */
	g_value_unset(&value);
	lu_util_lock_free(lock);
	fclose(fp);

	/* Open the group file. */
	fd = open(grpfilename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), grpfilename,
			     strerror(errno));
		g_free(pwdfilename);
		g_free(grpfilename);
		g_value_array_free(ret);
		return NULL;
	}

	/* Lock the group file. */
	if ((lock = lu_util_lock_obtain(fd, error)) == NULL) {
		close(fd);
		g_free(pwdfilename);
		g_free(grpfilename);
		g_value_array_free(ret);
		return NULL;
	}

	/* Wrap the group file in an stdio file. */
	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), grpfilename,
			     strerror(errno));
		lu_util_lock_free(lock);
		close(fd);
		g_free(pwdfilename);
		g_free(grpfilename);
		g_value_array_free(ret);
		return NULL;
	}

	/* Iterate over all of these lines as well. */
	while ((buf = line_read(fp)) != NULL) {
		if (strlen(buf) == 1) {
			g_free(buf);
			continue;
		}
		/* Terminate at the end of the first field, and find the end of
		 * the second field. */
		p = strchr(buf, ':');
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		/* If the first field matches, continue. */
		if (strcmp(buf, group) == 0) {
			/* Find the end of the third field. */
			if (p != NULL) {
				*p = '\0';
				p++;
				p = strchr(p, ':');
			}
			/* Find the beginning of the fourth field. */
			if (p != NULL) {
				*p = '\0';
				p++;
				/* Iterate through all of the pieces of
				 * the field. */
				while ((q = strsep(&p, ",\n")) != NULL) {
					/* Add this name. */
					if (strlen(q) > 0) {
						g_value_init(&value,
							     G_TYPE_STRING);
						g_value_set_string(&value, q);
						g_value_array_append(ret,
								     &value);
						g_value_unset(&value);
					}
				}
			}
			g_free(buf);
			break;
		}
		g_free(buf);
	}

	/* Clean up. */
	lu_util_lock_free(lock);
	fclose(fp);

	g_free(pwdfilename);
	g_free(grpfilename);

	return ret;
}

/* Get a list of groups to which the user belongs. */
static GValueArray *
lu_files_groups_enumerate_by_user(struct lu_module *module,
				  const char *user,
				  uid_t uid,
				  struct lu_error **error)
{
	int fd;
	gpointer lock;
	GValueArray *ret = NULL;
	GValue value;
	char *buf;
	char *key = NULL, *pwdfilename = NULL, *grpfilename = NULL, *p, *q;
	const char *dir = NULL;
	FILE *fp;

	(void)uid;
	g_assert(module != NULL);
	g_assert(user != NULL);

	/* Generate the names of files we'll be looking at. */
	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	pwdfilename = g_strconcat(dir, "/passwd", NULL);
	grpfilename = g_strconcat(dir, "/group", NULL);
	g_free(key);

	/* Open the first file. */
	fd = open(pwdfilename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), pwdfilename,
			     strerror(errno));
		g_free(pwdfilename);
		g_free(grpfilename);
		return NULL;
	}

	/* Lock it. */
	if ((lock = lu_util_lock_obtain(fd, error)) == NULL) {
		close(fd);
		g_free(pwdfilename);
		g_free(grpfilename);
		return NULL;
	}

	/* Open it so that we can use stdio. */
	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), pwdfilename,
			     strerror(errno));
		lu_util_lock_free(lock);
		close(fd);
		g_free(pwdfilename);
		g_free(grpfilename);
		return NULL;
	}

	/* Initialize the list of values we'll return. */
	ret = g_value_array_new(0);
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);

	/* Iterate through all of the lines in the file. */
	key = NULL;
	while ((buf = line_read(fp)) != NULL) {
		if (strlen(buf) == 1) {
			g_free(buf);
			continue;
		}
		/* Find the end of the first field. */
		p = strchr(buf, ':');
		/* Find the end of the second field. */
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		/* Find the end of the third field. */
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		/* Find the the fourth field. */
		if (p != NULL) {
			*p = '\0';
			p++;
			q = strchr(p, ':');
			/* If it matches, save the gid. */
			if (strcmp(buf, user) == 0) {
				if (q) {
					*q = '\0';
				}
				key = g_strdup(p);
				g_free(buf);
				break;
			}
		}
		g_free(buf);
	}
	lu_util_lock_free(lock);
	fclose(fp);

	/* Open the groups file. */
	fd = open(grpfilename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), grpfilename,
			     strerror(errno));
		g_free(pwdfilename);
		g_free(grpfilename);
		return NULL;
	}

	/* Lock it. */
	if ((lock = lu_util_lock_obtain(fd, error)) == NULL) {
		close(fd);
		g_free(pwdfilename);
		g_free(grpfilename);
		return NULL;
	}

	/* Open it so that we can use stdio. */
	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), grpfilename,
			     strerror(errno));
		lu_util_lock_free(lock);
		close(fd);
		g_free(pwdfilename);
		g_free(grpfilename);
		return NULL;
	}

	/* Iterate through all of the lines in the file. */
	while ((buf = line_read(fp)) != NULL) {
		if (strlen(buf) == 1) {
			g_free(buf);
			continue;
		}
		/* Find the end of the first field. */
		p = strchr(buf, ':');
		/* Find the end of the second field. */
		if (p != NULL) {
			*p = '\0';
			p++;
			p = strchr(p, ':');
		}
		/* Find the end of the third field. */
		if (p != NULL) {
			*p = '\0';
			p++;
			q = strchr(p, ':');
			if (q && key) {
				/* Terminate the third field. */
				*q = '\0';
				if (strcmp(p, key) == 0) {
					/* Add the name of the group because its
					 * gid is the user's primary. */
					g_value_set_string(&value, buf);
					g_value_array_append(ret, &value);
					g_value_reset(&value);
				}
			}
			p = q;
		}
		/* Find the beginning of the third field. */
		if (p != NULL) {
			p++;
			/* Break out each piece of the fourth field. */
			while ((q = strsep(&p, ",\n")) != NULL) {
				if (strlen(q) > 0) {
					if (strcmp(q, user) == 0) {
						g_value_set_string(&value, buf);
						g_value_array_append(ret,
								     &value);
						g_value_reset(&value);
					}
				}
			}
		}
		g_free(buf);
	}
	g_value_unset(&value);

	lu_util_lock_free(lock);
	fclose(fp);
	g_free(pwdfilename);
	g_free(grpfilename);

	return ret;
}

/* Enumerate all of the accounts listed in the given file, using the
 * given parser to parse matching accounts into an array of entity pointers. */
static GPtrArray *
lu_files_enumerate_full(struct lu_module *module,
			const char *base_name,
			parse_fn parser,
		        const char *pattern,
		        struct lu_error **error)
{
	int fd;
	gpointer lock;
	GPtrArray *ret = NULL;
	char *buf;
	char *key = NULL, *filename = NULL;
	const char *dir = NULL;
	FILE *fp;
	struct lu_ent *ent;

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	pattern = pattern ?: "*";

	/* Generate the name of the file to look at. */
	key = g_strconcat(module->name, "/directory", NULL);
	dir = lu_cfg_read_single(module->lu_context, key, "/etc");
	filename = g_strconcat(dir, "/", base_name, NULL);
	g_free(key);

	/* Open the file. */
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		g_free(filename);
		return NULL;
	}

	/* Lock the file. */
	if ((lock = lu_util_lock_obtain(fd, error)) == NULL) {
		close(fd);
		g_free(filename);
		return NULL;
	}

	/* Wrap the file up in stdio. */
	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		lu_util_lock_free(lock);
		close(fd);
		g_free(filename);
		return NULL;
	}

	/* Allocate an array to hold results. */
	ret = g_ptr_array_new();
	while ((buf = line_read(fp)) != NULL) {
		if (strlen(buf) == 1) {
			g_free(buf);
			continue;
		}
		ent = lu_ent_new();
		/* Snip the line off at the right place. */
		key = strchr(buf, '\n');
		if (key != NULL) {
			*key = '\0';
		}
		if (strchr(buf, ':')) {
			key = g_strndup(buf, strchr(buf, ':') - buf);
		} else {
			key = g_strdup(buf);
		}
		/* If the account name matches the pattern, parse it and add
		 * it to the list. */
		if (fnmatch(pattern, buf, 0) == 0) {
			parser(buf, ent);
			g_ptr_array_add(ret, ent);
		} else {
			lu_ent_free(ent);
		}
		g_free(buf);
		g_free(key);
	}

	lu_util_lock_free(lock);
	fclose(fp);

	return ret;
}

static GPtrArray *
lu_files_users_enumerate_full(struct lu_module *module,
			      const char *user,
			      struct lu_error **error)
{
	return lu_files_enumerate_full(module, "passwd",
				       lu_files_parse_user_entry,
				       user, error);
}

static GPtrArray *
lu_files_groups_enumerate_full(struct lu_module *module,
			       const char *group,
			       struct lu_error **error)
{
	return lu_files_enumerate_full(module, "group",
				       lu_files_parse_group_entry,
				       group, error);
}

static GPtrArray *
lu_files_users_enumerate_by_group_full(struct lu_module *module,
				       const char *user,
				       uid_t uid,
				       struct lu_error **error)
{
	(void)module;
	(void)user;
	(void)uid;
	(void)error;
	/* Implement the placeholder. */
	return NULL;
}

static GPtrArray *
lu_files_groups_enumerate_by_user_full(struct lu_module *module,
				       const char *user,
				       uid_t uid,
				       struct lu_error **error)
{
	(void)module;
	(void)user;
	(void)uid;
	(void)error;
	/* Implement the placeholder. */
	return NULL;
}

static GValueArray *
lu_shadow_users_enumerate(struct lu_module *module,
			  const char *pattern,
			  struct lu_error **error)
{
	(void)module;
	(void)pattern;
	(void)error;
	return NULL;
}

static GValueArray *
lu_shadow_groups_enumerate(struct lu_module *module,
			   const char *pattern,
			   struct lu_error **error)
{
	(void)module;
	(void)pattern;
	(void)error;
	return NULL;
}

static GValueArray *
lu_shadow_users_enumerate_by_group(struct lu_module *module,
				   const char *group,
				   gid_t gid,
				   struct lu_error **error)
{
	(void)module;
	(void)group;
	(void)gid;
	(void)error;
	return NULL;
}

static GValueArray *
lu_shadow_groups_enumerate_by_user(struct lu_module *module,
				   const char *user,
				   uid_t uid,
				   struct lu_error **error)
{
	(void)module;
	(void)user;
	(void)uid;
	(void)error;
	return NULL;
}

static GPtrArray *
lu_shadow_users_enumerate_full(struct lu_module *module,
			       const char *pattern,
			       struct lu_error **error)
{
	return lu_files_enumerate_full(module, "shadow",
				       lu_shadow_parse_user_entry,
				       pattern, error);
}

static GPtrArray *
lu_shadow_groups_enumerate_full(struct lu_module *module,
				const char *pattern,
				struct lu_error **error)
{
	return lu_files_enumerate_full(module, "gshadow",
				       lu_shadow_parse_group_entry,
				       pattern, error);
}

static GPtrArray *
lu_shadow_users_enumerate_by_group_full(struct lu_module *module,
					const char *group,
					gid_t gid,
					struct lu_error **error)
{
	(void)module;
	(void)group;
	(void)gid;
	(void)error;
	/* Implement the placeholder. */
	return NULL;
}

static GPtrArray *
lu_shadow_groups_enumerate_by_user_full(struct lu_module *module,
					const char *user,
					uid_t uid,
					struct lu_error **error)
{
	(void)module;
	(void)user;
	(void)uid;
	(void)error;
	/* Implement the placeholder. */
	return NULL;
}

/* Check if we use/need elevated privileges to manipulate our files. */
static gboolean
lu_files_uses_elevated_privileges(struct lu_module *module)
{
	const char *directory;
	char *path, *key;
	gboolean ret = FALSE;
	/* Get the directory the files are in. */
	key = g_strconcat(module->name, "/directory", NULL);
	directory = lu_cfg_read_single(module->lu_context, key, SYSCONFDIR);
	g_free(key);
	/* If we can't access the passwd file as a normal user, then the
	 * answer is "yes". */
	path = g_strconcat("%s/%s", directory, "/passwd", NULL);
	if (access(path, R_OK | W_OK) != 0) {
		ret = TRUE;
	}
	g_free(path);
	/* If we can't access the group file as a normal user, then the
	 * answer is "yes". */
	path = g_strconcat("%s/%s", directory, "/group", NULL);
	if (access(path, R_OK | W_OK) != 0) {
		ret = TRUE;
	}
	g_free(path);
	return ret;
}

/* Check if we use/need elevated privileges to manipulate our files. */
static gboolean
lu_shadow_uses_elevated_privileges(struct lu_module *module)
{
	const char *directory;
	char *path, *key;
	gboolean ret = FALSE;
	/* Get the directory the files are in. */
	key = g_strconcat(module->name, "/directory", NULL);
	directory = lu_cfg_read_single(module->lu_context, key, SYSCONFDIR);
	g_free(key);
	/* If we can't access the shadow file as a normal user, then the
	 * answer is "yes". */
	path = g_strconcat("%s/%s", directory, "/shadow", NULL);
	if (access(path, R_OK | W_OK) != 0) {
		ret = TRUE;
	}
	g_free(path);
	/* If we can't access the gshadow file as a normal user, then the
	 * answer is "yes". */
	path = g_strconcat("%s/%s", directory, "/gshadow", NULL);
	if (access(path, R_OK | W_OK) != 0) {
		ret = TRUE;
	}
	g_free(path);
	return ret;
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
	ret->uses_elevated_privileges = lu_files_uses_elevated_privileges;

	ret->user_lookup_name = lu_files_user_lookup_name;
	ret->user_lookup_id = lu_files_user_lookup_id;

	ret->user_default = lu_common_user_default;
	ret->user_add_prep = lu_files_user_add_prep;
	ret->user_add = lu_files_user_add;
	ret->user_mod = lu_files_user_mod;
	ret->user_del = lu_files_user_del;
	ret->user_lock = lu_files_user_lock;
	ret->user_unlock = lu_files_user_unlock;
	ret->user_is_locked = lu_files_user_is_locked;
	ret->user_setpass = lu_files_user_setpass;
	ret->user_removepass = lu_files_user_removepass;
	ret->users_enumerate = lu_files_users_enumerate;
	ret->users_enumerate_by_group = lu_files_users_enumerate_by_group;
	ret->users_enumerate_full = lu_files_users_enumerate_full;
	ret->users_enumerate_by_group_full = lu_files_users_enumerate_by_group_full;

	ret->group_lookup_name = lu_files_group_lookup_name;
	ret->group_lookup_id = lu_files_group_lookup_id;

	ret->group_default = lu_common_group_default;
	ret->group_add_prep = lu_files_group_add_prep;
	ret->group_add = lu_files_group_add;
	ret->group_mod = lu_files_group_mod;
	ret->group_del = lu_files_group_del;
	ret->group_lock = lu_files_group_lock;
	ret->group_unlock = lu_files_group_unlock;
	ret->group_is_locked = lu_files_group_is_locked;
	ret->group_setpass = lu_files_group_setpass;
	ret->group_removepass = lu_files_group_removepass;
	ret->groups_enumerate = lu_files_groups_enumerate;
	ret->groups_enumerate_by_user = lu_files_groups_enumerate_by_user;
	ret->groups_enumerate_full = lu_files_groups_enumerate_full;
	ret->groups_enumerate_by_user_full = lu_files_groups_enumerate_by_user_full;

	ret->close = close_module;

	/* Done. */
	return ret;
}

struct lu_module *
libuser_shadow_init(struct lu_context *context,
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
	ret->uses_elevated_privileges = lu_shadow_uses_elevated_privileges;

	ret->user_lookup_name = lu_shadow_user_lookup_name;
	ret->user_lookup_id = lu_shadow_user_lookup_id;

	ret->user_default = lu_common_suser_default;
	ret->user_add_prep = lu_shadow_user_add_prep;
	ret->user_add = lu_shadow_user_add;
	ret->user_mod = lu_shadow_user_mod;
	ret->user_del = lu_shadow_user_del;
	ret->user_lock = lu_shadow_user_lock;
	ret->user_unlock = lu_shadow_user_unlock;
	ret->user_is_locked = lu_shadow_user_is_locked;
	ret->user_setpass = lu_shadow_user_setpass;
	ret->user_removepass = lu_shadow_user_removepass;
	ret->users_enumerate = lu_shadow_users_enumerate;
	ret->users_enumerate_by_group = lu_shadow_users_enumerate_by_group;
	ret->users_enumerate_full = lu_shadow_users_enumerate_full;
	ret->users_enumerate_by_group_full = lu_shadow_users_enumerate_by_group_full;

	ret->group_lookup_name = lu_shadow_group_lookup_name;
	ret->group_lookup_id = lu_shadow_group_lookup_id;

	ret->group_default = lu_common_sgroup_default;
	ret->group_add_prep = lu_shadow_group_add_prep;
	ret->group_add = lu_shadow_group_add;
	ret->group_mod = lu_shadow_group_mod;
	ret->group_del = lu_shadow_group_del;
	ret->group_lock = lu_shadow_group_lock;
	ret->group_unlock = lu_shadow_group_unlock;
	ret->group_is_locked = lu_shadow_group_is_locked;
	ret->group_setpass = lu_shadow_group_setpass;
	ret->group_removepass = lu_shadow_group_removepass;
	ret->groups_enumerate = lu_shadow_groups_enumerate;
	ret->groups_enumerate_by_user = lu_shadow_groups_enumerate_by_user;
	ret->groups_enumerate_full = lu_shadow_groups_enumerate_full;
	ret->groups_enumerate_by_user_full = lu_shadow_groups_enumerate_by_user_full;

	ret->close = close_module;

	/* Done. */
	return ret;
}
