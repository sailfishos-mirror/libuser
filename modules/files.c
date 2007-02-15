/*
 * Copyright (C) 2000-2002, 2004, 2005, 2006 Red Hat, Inc.
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
#include <inttypes.h>
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

enum lock_op { LO_LOCK, LO_UNLOCK, LO_UNLOCK_NONEMPTY };

/* Guides for parsing and formatting entries in the files we're looking at. */
struct format_specifier {
	const char *attribute;
	GType type;		/* G_TYPE_INVALID for "id_t" */
	const char *def;
	gboolean multiple, suppress_if_def, def_if_empty;
};

static const struct format_specifier format_passwd[] = {
	{ LU_USERNAME, G_TYPE_STRING, NULL, FALSE, FALSE, FALSE },
	{
	  LU_USERPASSWORD, G_TYPE_STRING, DEFAULT_PASSWORD, FALSE, FALSE, FALSE
	},
	{ LU_UIDNUMBER, G_TYPE_INVALID, NULL, FALSE, FALSE, FALSE },
	{ LU_GIDNUMBER, G_TYPE_INVALID, NULL, FALSE, FALSE, FALSE },
	{ LU_GECOS, G_TYPE_STRING, NULL, FALSE, FALSE, FALSE },
	{ LU_HOMEDIRECTORY, G_TYPE_STRING, NULL, FALSE, FALSE, FALSE },
	{ LU_LOGINSHELL, G_TYPE_STRING, DEFAULT_SHELL, FALSE, FALSE, TRUE },
};

static const struct format_specifier format_group[] = {
	{ LU_GROUPNAME, G_TYPE_STRING, NULL, FALSE, FALSE, FALSE },
	{
	  LU_GROUPPASSWORD, G_TYPE_STRING, DEFAULT_PASSWORD, FALSE, FALSE,
	  FALSE
	},
	{ LU_GIDNUMBER, G_TYPE_INVALID, NULL, FALSE, FALSE, FALSE },
	{ LU_MEMBERNAME, G_TYPE_STRING, NULL, TRUE, FALSE, FALSE },
};

static const struct format_specifier format_shadow[] = {
	{ LU_SHADOWNAME, G_TYPE_STRING, NULL, FALSE, FALSE, FALSE },
	{
	  LU_SHADOWPASSWORD, G_TYPE_STRING, DEFAULT_PASSWORD, FALSE, FALSE,
	  FALSE
	} ,
	{ LU_SHADOWLASTCHANGE, G_TYPE_LONG, NULL, FALSE, FALSE, FALSE },
	{ LU_SHADOWMIN, G_TYPE_LONG, "0", FALSE, FALSE, TRUE },
	{ LU_SHADOWMAX, G_TYPE_LONG, "99999", FALSE, FALSE, TRUE },
	{ LU_SHADOWWARNING, G_TYPE_LONG, "7", FALSE, FALSE, TRUE },
	{ LU_SHADOWINACTIVE, G_TYPE_LONG, "-1", FALSE, TRUE, TRUE },
	{ LU_SHADOWEXPIRE, G_TYPE_LONG, "-1", FALSE, TRUE, TRUE },
	{ LU_SHADOWFLAG, G_TYPE_LONG, "-1", FALSE, TRUE, TRUE },
};

static const struct format_specifier format_gshadow[] = {
	{ LU_GROUPNAME, G_TYPE_STRING, NULL, FALSE, FALSE, FALSE },
	{
	  LU_SHADOWPASSWORD, G_TYPE_STRING, DEFAULT_PASSWORD, FALSE, FALSE,
	  FALSE
	},
	{ LU_ADMINISTRATORNAME, G_TYPE_STRING, NULL, TRUE, FALSE, FALSE },
	{ LU_MEMBERNAME, G_TYPE_STRING, NULL, TRUE, FALSE, FALSE },
};

static gboolean
set_default_context(const char *filename, security_context_t *prev_context,
		    struct lu_error **error)
{
	(void)filename;
	(void)prev_context;
	(void)error;
#ifdef WITH_SELINUX
	*prev_context = NULL;
	if (is_selinux_enabled() > 0) {
		security_context_t scontext;

		if (getfilecon(filename, &scontext) < 0) {
			lu_error_new(error, lu_error_stat,
				     _("couldn't get security context of "
				       "`%s': %s"), filename, strerror(errno));
			return FALSE;
		}
		if (getfscreatecon(prev_context) < 0) {
			lu_error_new(error, lu_error_stat,
				     _("couldn't set default security "
				       "context: %s"), strerror(errno));
			freecon(scontext);
			return FALSE;
		}
		if (setfscreatecon(scontext) < 0) {
			lu_error_new(error, lu_error_stat,
				     _("couldn't set default security context "
				       "to `%s': %s"), scontext,
				     strerror(errno));
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
	setfscreatecon(prev_context);
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
	gboolean res = FALSE;

	g_assert(filename != NULL);
	g_assert(strlen(filename) > 0);

	/* Open the original file. */
	ifd = open(filename, O_RDONLY);
	if (ifd == -1) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		goto err;
	}

	/* Lock the input file. */
	if ((ilock = lu_util_lock_obtain(ifd, error)) == NULL)
		goto err_ifd;

	/* Read the input file's size. */
	if (fstat(ifd, &ist) == -1) {
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), filename,
			     strerror(errno));
		goto err_ilock;
	}

	/* Generate the backup file's name and open it, creating it if it
	 * doesn't already exist. */
	backupname = g_strconcat(filename, "-", NULL);
	ofd = open(backupname, O_WRONLY | O_CREAT, ist.st_mode);
	if (ofd == -1) {
		lu_error_new(error, lu_error_open,
			     _("error creating `%s': %s"), backupname,
			     strerror(errno));
		goto err_backupname;
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
			goto err_ofd;
		}
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), backupname,
			     strerror(errno));
		goto err_ofd;
	}

	/* Now lock the output file. */
	if ((olock = lu_util_lock_obtain(ofd, error)) == NULL)
		goto err_ofd;

	/* Set the permissions on the new file to match the old one. */
	if (fchown(ofd, ist.st_uid, ist.st_gid) == -1 && errno != EPERM) {
		lu_error_new(error, lu_error_generic,
			     _("Error changing owner of `%s': %s"), backupname,
			     strerror(errno));
		goto err_olock;
	}
	fchmod(ofd, ist.st_mode);

	/* Copy the data, block by block. */
	for (;;) {
		char buf[CHUNK_SIZE];
		ssize_t left;
		char *p;

		left = read(ifd, &buf, sizeof(buf));
		if (left == -1) {
			if (errno == EINTR)
				continue;
			lu_error_new(error, lu_error_read,
				     _("Error reading `%s': %s"), filename,
				     strerror(errno));
			goto err_olock;
		}
		if (left == 0)
			break;
		p = buf;
		while (left > 0) {
			ssize_t out;

			out = write(ofd, p, left);
			if (out == -1) {
				if (errno == EINTR)
					continue;
				lu_error_new(error, lu_error_write,
					     _("Error writing `%s': %s"),
					     backupname, strerror(errno));
				goto err_olock;
			}
			p += out;
			left -= out;
		}
	}

	/* Flush data to disk, and truncate at the current offset.  This is
	 * necessary if the file existed before we opened it. */
	fsync(ofd);
	if (ftruncate(ofd, lseek(ofd, 0, SEEK_CUR)) == -1) {
		lu_error_new(error, lu_error_generic,
			     _("Error writing `%s': %s"), backupname,
			     strerror(errno));
		goto err_olock;
	}

	/* Re-read data about the output file. */
	if (fstat(ofd, &ost) == -1) {
		lu_error_new(error, lu_error_stat,
			     _("couldn't stat `%s': %s"), backupname,
			     strerror(errno));
		goto err_olock;
	}

	/* Complain if the files are somehow not the same. */
	if (ist.st_size != ost.st_size) {
		lu_error_new(error, lu_error_generic,
			     _("backup file size mismatch"));
		goto err_olock;
	}
	res = TRUE;

 err_olock:
	lu_util_lock_free(olock);
 err_ofd:
	close(ofd);
 err_backupname:
	g_free(backupname);
 err_ilock:
	lu_util_lock_free(ilock);
 err_ifd:
	close(ifd);
 err:
	return res;
}

/* Read a line from the file, no matter how long it is, and return it as a
 * newly-allocated string, with the terminator intact. */
static char *
line_read(FILE * fp)
{
	char *p, *buf;
	size_t len, buf_size = CHUNK_SIZE;

	p = buf = g_malloc(buf_size);
	len = 0;
	while (fgets(buf + len, buf_size - len, fp) != NULL) {
		len += strlen(buf + len);
		if (len > 0 && buf[len - 1] == '\n')
			break;

		buf_size += CHUNK_SIZE;
		buf = g_realloc(buf, buf_size);
	}
	if (len == 0) {
		g_free(buf);
		return NULL;
	} else {
		return buf;
	}
}

/* Parse a single field value. */
static gboolean
parse_field(const struct format_specifier *format, GValue *value,
	    const char *string)
{
	switch (format->type) {
	case G_TYPE_STRING:
		g_value_init(value, G_TYPE_STRING);
		g_value_set_string(value, string);
		break;

	case G_TYPE_LONG: {
		long l;
		char *p;

		errno = 0;
		l = strtol(string, &p, 10);
		if (errno != 0 || *p != 0 || p == string) {
			g_warning("invalid number '%s'", string);
			return FALSE;
		}
		g_value_init(value, G_TYPE_LONG);
		g_value_set_long(value, l);
		break;
	}

	case G_TYPE_INVALID: {
		intmax_t imax;
		char *p;

		errno = 0;
		imax = strtoimax(string, &p, 10);
		if (errno != 0 || *p != 0 || p == string
		    || (id_t)imax != imax) {
			g_warning("invalid ID '%s'", string);
			return FALSE;
		}
		lu_value_init_set_id(value, imax);
		break;
	}

	default:
		g_assert_not_reached();
		return FALSE;
	}
	return TRUE;
}

/* Parse a string into an ent structure using the elements in the format
 * specifier array. */
static gboolean
parse_generic(const gchar *line, const struct format_specifier *formats,
	      size_t format_count, struct lu_ent *ent)
{
	size_t i;
	gchar **v = NULL;
	GValue value;

	/* Make sure the line is properly formatted, meaning that it has enough
	   fields in it for us to parse out all the fields we want, allowing
	   for the last one to be empty. */
	v = g_strsplit(line, ":", format_count);
	g_assert(format_count > 0);
	if (g_strv_length(v) < format_count - 1) {
		g_warning("entry is incorrectly formatted");
		return FALSE;
	}

	/* Now parse out the fields. */
	memset(&value, 0, sizeof(value));
	for (i = 0; i < format_count; i++) {
		const gchar *val;

		val = v[i];
		if (val == NULL)
			val = "";
		/* Clear out old values in the destination structure. */
		lu_ent_clear_current(ent, formats[i].attribute);
		if (formats[i].multiple) {
			/* Field contains multiple comma-separated values. */
			gchar **w;
			size_t j;

			/* Split up the field. */
			w = g_strsplit(val, ",", 0);
			/* Clear out old values. */
			for (j = 0; (w != NULL) && (w[j] != NULL); j++) {
				/* Skip over empty strings. */
				if (strlen(w[j]) == 0)
					continue;
				/* Always succeeds assuming
				   formats[i].type == G_TYPE_STRING, which is
				   currently true. */
				parse_field(formats + i, &value, w[j]);
				/* Add it to the current values list. */
				lu_ent_add_current(ent, formats[i].attribute,
						   &value);
				g_value_unset(&value);
			}
			g_strfreev(w);
		} else {
			/* Check if we need to supply the default value. */
			if (formats[i].def_if_empty && formats[i].def != NULL
			    && strlen(val) == 0) {
				gboolean ret;

				/* Make sure we're not doing something
				 * potentially-dangerous here. */
				if (formats[i].type != G_TYPE_STRING)
					g_assert(strlen(formats[i].def) > 0);
				/* Convert the default to the right type. */
				ret = parse_field(formats + i, &value,
						  formats[i].def);
				g_assert (ret != FALSE);
			} else {
				if (parse_field (formats + i, &value, val)
				    == FALSE)
					continue;
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
	ent->type = lu_user;
	lu_ent_clear_all(ent);
	return parse_generic(line, format_passwd, G_N_ELEMENTS(format_passwd),
			     ent);
}

/* Parse an entry from /etc/group into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_files_parse_group_entry(const gchar * line, struct lu_ent *ent)
{
	ent->type = lu_group;
	lu_ent_clear_all(ent);
	return parse_generic(line, format_group, G_N_ELEMENTS(format_group),
			     ent);
}

/* Parse an entry from /etc/shadow into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_shadow_parse_user_entry(const gchar * line, struct lu_ent *ent)
{
	ent->type = lu_user;
	lu_ent_clear_all(ent);
	return parse_generic(line, format_shadow, G_N_ELEMENTS(format_shadow),
			     ent);
}

/* Parse an entry from /etc/shadow into an ent structure, using the attribute
 * names we know. */
static gboolean
lu_shadow_parse_group_entry(const gchar * line, struct lu_ent *ent)
{
	ent->type = lu_group;
	lu_ent_clear_all(ent);
	return parse_generic(line, format_gshadow,
			     G_N_ELEMENTS(format_gshadow), ent);
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
	gboolean ret;
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
	return generic_lookup(module, "passwd", name, 1,
			      lu_files_parse_user_entry, ent, error);
}

/* Look up a user by ID in /etc/passwd. */
static gboolean
lu_files_user_lookup_id(struct lu_module *module,
			uid_t uid,
			struct lu_ent *ent,
			struct lu_error **error)
{
	char *key;
	gboolean ret;

	key = g_strdup_printf("%jd", (intmax_t)uid);
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
	return generic_lookup(module, "shadow", name, 1,
			      lu_shadow_parse_user_entry, ent, error);
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
	char *key;
	gboolean ret;

	/* First look the user up by ID. */
	key = g_strdup_printf("%jd", (intmax_t)uid);
	ret = lu_files_user_lookup_id(module, uid, ent, error);
	if (ret) {
		GValueArray *values;

		/* Now use the user's name to search the shadow file. */
		values = lu_ent_get(ent, LU_USERNAME);
		if (values != NULL) {
			GValue *value;
			char *p;

			value = g_value_array_get_nth(values, 0);
			p = lu_value_strdup(value);
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
	return generic_lookup(module, "group", name, 1,
			      lu_files_parse_group_entry, ent, error);
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

	key = g_strdup_printf("%jd", (intmax_t)gid);
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
	return generic_lookup(module, "gshadow", name, 1,
			      lu_shadow_parse_group_entry, ent, error);
}

/* Look up a group by ID in /etc/gshadow.  This file doesn't contain any
 * GIDs, so we have to use /etc/group to convert the GID to a name first. */
static gboolean
lu_shadow_group_lookup_id(struct lu_module *module, gid_t gid,
			  struct lu_ent *ent, struct lu_error **error)
{
	char *key;
	gboolean ret;

	key = g_strdup_printf("%jd", (intmax_t)gid);
	ret = lu_files_group_lookup_id(module, gid, ent, error);
	if (ret) {
		GValueArray *values;

		values = lu_ent_get(ent, LU_GROUPNAME);
		if (values != NULL) {
			GValue *value;
			char *p;

			value = g_value_array_get_nth(values, 0);
			p = lu_value_strdup(value);
			ret = generic_lookup(module, "gshadow", p, 1,
					     lu_shadow_parse_group_entry,
					     ent, error);
			g_free(p);
		}
	}
	g_free(key);
	return ret;
}

/* Format a single field.
   Return field string for g_free (). */
static char *
format_field(struct lu_ent *ent, const struct format_specifier *format)
{
	GValueArray *values;
	char *ret;

	values = lu_ent_get(ent, format->attribute);
	if (values != NULL) {
		size_t j;

		/* Iterate over all of the data items we can, prepending a
		   comma to all but the first. */
		ret = NULL;
		j = 0;
		do {
			GValue *val;
			char *p, *tmp;

			val = g_value_array_get_nth(values, j);
			p = lu_value_strdup(val);
			/* Add it to the end, prepending a comma if we need to
			   separate it from another value, unless this is the
			   default value for the field and we need to suppress
			   it. */
			if (format->multiple == FALSE
			    && format->suppress_if_def == TRUE
			    && format->def != NULL
			    && strcmp(format->def, p) == 0)
				tmp = g_strdup("");
			else
				tmp = g_strconcat(ret ? ret : "",
						  (j > 0) ? "," : "", p, NULL);
			g_free(p);
			g_free(ret);
			ret = tmp;
			j++;
		} while (format->multiple && j < values->n_values);
	} else {
		/* We have no values, so check for a default value,
		 * unless we're suppressing it. */
		if (format->def != NULL && format->suppress_if_def == FALSE)
			ret = g_strdup(format->def);
		else
			ret = g_strdup("");
	}
	return ret;
}

/* Format a line for the user/group, using the information in ent, using
 * formats to guide the formatting. */
static char *
format_generic(struct lu_ent *ent, const struct format_specifier *formats,
	       size_t format_count)
{
	char *ret = NULL, *tmp;
	size_t i;

	g_return_val_if_fail(ent != NULL, NULL);

	for (i = 0; i < format_count; i++) {
		char *field;

		field = format_field(ent, formats + i);
		tmp = g_strconcat(ret ? ret : "", i > 0 ? ":" : "", field,
				  NULL);
		g_free(field);
		g_free(ret);
		ret = tmp;
	}
	/* Add an end-of-line terminator. */
	tmp = g_strconcat(ret ?: "", "\n", NULL);
	g_free(ret);
	ret = tmp;

	return ret;
}

/* Construct a line for /etc/passwd using data in the lu_ent structure. */
static char *
lu_files_format_user(struct lu_ent *ent)
{
	return format_generic(ent, format_passwd, G_N_ELEMENTS(format_passwd));
}

/* Construct a line for /etc/group using data in the lu_ent structure. */
static char *
lu_files_format_group(struct lu_ent *ent)
{
	return format_generic(ent, format_group, G_N_ELEMENTS(format_group));
}

/* Construct a line for /etc/shadow using data in the lu_ent structure. */
static char *
lu_shadow_format_user(struct lu_ent *ent)
{
	return format_generic(ent, format_shadow, G_N_ELEMENTS(format_shadow));
}

/* Construct a line for /etc/gshadow using data in the lu_ent structure. */
static char *
lu_shadow_format_group(struct lu_ent *ent)
{
	return format_generic(ent, format_gshadow,
			      G_N_ELEMENTS(format_gshadow));
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
	ssize_t r;
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
	line = formatter(ent);
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
		if (write(fd, "\n", 1) != 1) {
			lu_error_new(error, lu_error_write,
				     _("couldn't write to `%s': %s"),
				     filename,
				     strerror(errno));
			goto err_fragment2;
		}
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
		(void)ftruncate(fd, offset);
		goto err_fragment2;
	}
	/* Hey, it succeeded. */
	ret = TRUE;
	/* Fall through */

 err_fragment2:
	g_free(fragment2);
	g_free(fragment1);
	g_free(contents);
	g_free(line);
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
	return generic_add(module, "passwd", lu_files_format_user, ent, error);
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
	return generic_add(module, "shadow", lu_shadow_format_user, ent,
			   error);
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
	return generic_add(module, "group", lu_files_format_group, ent, error);
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
	return generic_add(module, "gshadow", lu_shadow_format_group, ent,
			   error);
}

/* Modify a particular record in the given file, field by field, using the
 * given format specifiers. */
static gboolean
generic_mod(struct lu_module *module, const char *base_name,
	    const struct format_specifier *formats, size_t format_count,
	    struct lu_ent *ent, struct lu_error **error)
{
	security_context_t prev_context;
	char *filename, *key;
	int fd = -1;
	gpointer lock;
	size_t i;
	const char *dir, *name_attribute;
	GValueArray *names;
	gboolean ret = FALSE;

	g_assert(module != NULL);
	g_assert(base_name != NULL);
	g_assert(strlen(base_name) > 0);
	g_assert(formats != NULL);
	g_assert(format_count > 0);
	g_assert(ent != NULL);
	g_assert((ent->type == lu_user) || (ent->type == lu_group));

	/* Get the array of names for the entity object. */
	if (ent->type == lu_user)
		name_attribute = LU_USERNAME;
	else if (ent->type == lu_group)
		name_attribute = LU_GROUPNAME;
	else
		g_assert_not_reached();

	names = lu_ent_get_current(ent, name_attribute);
	if (names == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("entity object has no %s attribute"),
			     name_attribute);
		return FALSE;
	}

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
		GValue *value;
		char *field;
		gboolean ret2;

		field = format_field(ent, formats + i);

		/* Get the current name for this entity. */
		value = g_value_array_get_nth(names, 0);

		/* Write the new value. */
		ret2 = lu_util_field_write(fd, g_value_get_string(value),
					   i + 1, field, error);
		g_free(field);

		/* If we had a write error, we fail now. */
		if (ret2 == FALSE)
			goto err_lock;

		/* We may have just renamed the account (we're safe assuming
		 * the new name is correct here because if we renamed it, we
		 * changed the name field first), so switch to using the
		 * account's new name. */
		names = lu_ent_get(ent, name_attribute);
		if (names == NULL) {
			lu_error_new(error, lu_error_generic,
				     _("entity object has no %s attribute"),
				     name_attribute);
			goto err_lock;
		}
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
	return generic_mod(module, "passwd", format_passwd,
			   G_N_ELEMENTS(format_passwd), ent, error);
}

/* Modify an entry in the group file. */
static gboolean
lu_files_group_mod(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	return generic_mod(module, "group", format_group,
			   G_N_ELEMENTS(format_group), ent, error);
}

/* Modify an entry in the shadow file. */
static gboolean
lu_shadow_user_mod(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	return generic_mod(module, "shadow", format_shadow,
			   G_N_ELEMENTS(format_shadow), ent, error);
}

/* Modify an entry in the gshadow file. */
static gboolean
lu_shadow_group_mod(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	return generic_mod(module, "gshadow", format_gshadow,
			   G_N_ELEMENTS(format_gshadow), ent, error);
}

/* Delete an entity from the given file. */
static gboolean
generic_del(struct lu_module *module, const char *base_name,
	    struct lu_ent *ent, struct lu_error **error)
{
	security_context_t prev_context;
	GValueArray *name = NULL;
	GValue *value;
	char *contents, *filename, *key;
	char *fragment1, *fragment2;
	const char *dir;
	struct stat st;
	size_t len;
	int fd;
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
	contents = g_malloc(st.st_size + 1);
	if (read(fd, contents, st.st_size) != st.st_size) {
		lu_error_new(error, lu_error_read,
			     _("couldn't read from `%s': %s"), filename,
			     strerror(errno));
		goto err_contents;
	}
	contents[st.st_size] = '\0';

	/* Generate string versions of what the beginning of a line might
	 * look like. */
	value = g_value_array_get_nth(name, 0);
	fragment1 = lu_value_strdup(value);
	fragment2 = g_strdup_printf("\n%s:", fragment1);

	/* Remove all occurrences of this entry from the file. */
	len = strlen(fragment1);
	do {
		char *tmp;

		found = FALSE;
		/* If the data is on the first line of the file, we remove the
		 * first line. */
		if (strncmp(contents, fragment1, len) == 0
			&& contents[len] == ':') {
			char *p;

			p = strchr(contents, '\n');
			if (p != NULL)
				memmove(contents, p + 1, strlen(p + 1) + 1);
			else
				strcpy(contents, "");
			found = TRUE;
		} else
		/* If the data occurs elsewhere, cover it up. */
		if ((tmp = strstr(contents, fragment2)) != NULL) {
			char *p;

			p = strchr(tmp + 1, '\n');
			if (p != NULL)
				memmove(tmp + 1, p + 1, strlen (p + 1) + 1);
			else
				strcpy(tmp + 1, "");
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
	if (ftruncate(fd, len) == -1) {
		lu_error_new(error, lu_error_generic,
			     _("couldn't write to `%s': %s"), filename,
			     strerror(errno));
		goto err_contents;
	}
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
	return generic_del(module, "passwd", ent, error);
}

/* Remove a group from the group file. */
static gboolean
lu_files_group_del(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	return generic_del(module, "group", ent, error);
}

/* Remove a user from the shadow file. */
static gboolean
lu_shadow_user_del(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	return generic_del(module, "shadow", ent, error);
}

/* Remove a group from the gshadow file. */
static gboolean
lu_shadow_group_del(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	return generic_del(module, "gshadow", ent, error);
}

/* Return a modified version of the cryptedPassword string, depending on
   op, or NULL on error. */
static char *
lock_process(char *cryptedPassword, enum lock_op op, struct lu_ent *ent,
	     struct lu_error **error)
{
	char *ret = NULL;

	switch (op) {
	case LO_LOCK:
		ret = ent->cache->cache(ent->cache, cryptedPassword);
		if (ret[0] != '!') {
			cryptedPassword = g_strconcat("!!", ret, NULL);
			ret = ent->cache->cache(ent->cache, cryptedPassword);
			g_free(cryptedPassword);
		}
		break;
	case LO_UNLOCK:
		for (ret = cryptedPassword; ret[0] == '!'; ret++)
			;
		ret = ent->cache->cache(ent->cache, ret);
		break;
	case LO_UNLOCK_NONEMPTY:
		for (ret = cryptedPassword; ret[0] == '!'; ret++)
			;
		if (*ret == '\0') {
			lu_error_new(error, lu_error_unlock_empty, NULL);
			return NULL;
		}
		ret = ent->cache->cache(ent->cache, ret);
		break;

	default:
		g_assert_not_reached ();
	}
	return ret;
}

/* Lock or unlock an account in the given file, with its encrypted password
 * stored in the given field number. */
static gboolean
generic_lock(struct lu_module *module, const char *base_name, int field,
	     struct lu_ent *ent, enum lock_op op, struct lu_error **error)
{
	security_context_t prev_context;
	GValueArray *name = NULL;
	GValue *val;
	char *filename, *key;
	const char *dir;
	char *value, *new_value, *namestring;
	int fd;
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
	namestring = lu_value_strdup(val);

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
	new_value = lock_process(value, op, ent, error);
	g_free(value);
	if (new_value == NULL)
		goto err_namestring;

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
	char *filename, *key;
	const char *dir;
	char *value, *namestring;
	int fd;
	gpointer lock;
	gboolean ret;

	/* Get the name of this account. */
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
	namestring = lu_value_strdup(val);

	/* Read the value. */
	value = lu_util_field_read(fd, namestring, field, error);
	g_free (namestring);
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
	return generic_lock(module, "passwd", 2, ent, LO_LOCK, error);
}

static gboolean
lu_files_user_unlock(struct lu_module *module, struct lu_ent *ent,
		     struct lu_error **error)
{
	return generic_lock(module, "passwd", 2, ent, LO_UNLOCK, error);
}

static gboolean
lu_files_user_unlock_nonempty(struct lu_module *module, struct lu_ent *ent,
			      struct lu_error **error)
{
	return generic_lock(module, "passwd", 2, ent, LO_UNLOCK_NONEMPTY,
			    error);
}

/* Lock a group from the group file. */
static gboolean
lu_files_group_lock(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	return generic_lock(module, "group", 2, ent, LO_LOCK, error);
}

static gboolean
lu_files_group_unlock(struct lu_module *module, struct lu_ent *ent,
		      struct lu_error **error)
{
	return generic_lock(module, "group", 2, ent, LO_UNLOCK, error);
}

static gboolean
lu_files_group_unlock_nonempty(struct lu_module *module, struct lu_ent *ent,
			       struct lu_error **error)
{
	return generic_lock(module, "group", 2, ent, LO_UNLOCK_NONEMPTY,
			    error);
}

/* Lock a user in the shadow file. */
static gboolean
lu_shadow_user_lock(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	return generic_lock(module, "shadow", 2, ent, LO_LOCK, error);
}

static gboolean
lu_shadow_user_unlock(struct lu_module *module, struct lu_ent *ent,
		      struct lu_error **error)
{
	return generic_lock(module, "shadow", 2, ent, LO_UNLOCK, error);
}

static gboolean
lu_shadow_user_unlock_nonempty(struct lu_module *module, struct lu_ent *ent,
			       struct lu_error **error)
{
	return generic_lock(module, "shadow", 2, ent, LO_UNLOCK_NONEMPTY,
			    error);
}

/* Lock a group in the gshadow file. */
static gboolean
lu_shadow_group_lock(struct lu_module *module, struct lu_ent *ent,
		     struct lu_error **error)
{
	return generic_lock(module, "gshadow", 2, ent, LO_LOCK, error);
}

static gboolean
lu_shadow_group_unlock(struct lu_module *module, struct lu_ent *ent,
		       struct lu_error **error)
{
	return generic_lock(module, "gshadow", 2, ent, LO_UNLOCK, error);
}

static gboolean
lu_shadow_group_unlock_nonempty(struct lu_module *module, struct lu_ent *ent,
				struct lu_error **error)
{
	return generic_lock(module, "gshadow", 2, ent, LO_UNLOCK_NONEMPTY,
			    error);
}

/* Check if the account is locked. */
static gboolean
lu_files_user_is_locked(struct lu_module *module, struct lu_ent *ent,
		        struct lu_error **error)
{
	return generic_is_locked(module, "passwd", 2, ent, error);
}

static gboolean
lu_files_group_is_locked(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	return generic_is_locked(module, "group", 2, ent, error);
}

static gboolean
lu_shadow_user_is_locked(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	return generic_is_locked(module, "shadow", 2, ent, error);
}

static gboolean
lu_shadow_group_is_locked(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	return generic_is_locked(module, "gshadow", 2, ent, error);
}

/* Change a password, in a given file, in a given field, for a given account,
 * to a given value.  Got that? */
static gboolean
generic_setpass(struct lu_module *module, const char *base_name, int field,
		struct lu_ent *ent, const char *password, gboolean is_shadow,
		struct lu_error **error)
{
	security_context_t prev_context;
	GValueArray *name = NULL;
	GValue *val;
	char *filename, *key, *value, *namestring;
	const char *dir;
	int fd;
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
	namestring = lu_value_strdup(val);

	/* Read the current contents of the field. */
	value = lu_util_field_read(fd, namestring, field, error);
	if (value == NULL)
		goto err_namestring;

	/* If we don't really care, nod our heads and smile.  Still allow
	   "rescuing" accounts with invalid shadow password entries. */
	if (!is_shadow && LU_CRYPT_INVALID(value)) {
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
			lu_error_new(error, lu_error_generic,
				     _("error encrypting password"));
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
	return generic_setpass(module, "passwd", 2, ent, password, FALSE,
			       error);
}

static gboolean
lu_files_group_setpass(struct lu_module *module, struct lu_ent *ent,
		       const char *password, struct lu_error **error)
{
	return generic_setpass(module, "group", 2, ent, password, FALSE,
			       error);
}

static gboolean
lu_files_user_removepass(struct lu_module *module, struct lu_ent *ent,
		         struct lu_error **error)
{
	return generic_setpass(module, "passwd", 2, ent, LU_CRYPTED, FALSE,
			       error);
}

static gboolean
lu_files_group_removepass(struct lu_module *module, struct lu_ent *ent,
		          struct lu_error **error)
{
	return generic_setpass(module, "group", 2, ent, LU_CRYPTED, FALSE,
			       error);
}

static gboolean
lu_shadow_user_setpass(struct lu_module *module, struct lu_ent *ent,
		       const char *password, struct lu_error **error)
{
	gboolean ret;

	ret = generic_setpass(module, "shadow", 2, ent, password, TRUE, error);
	if (ret)
		lu_util_update_shadow_last_change(ent);
	return ret;
}

static gboolean
lu_shadow_group_setpass(struct lu_module *module, struct lu_ent *ent,
			const char *password, struct lu_error **error)
{
	gboolean ret;

	ret = generic_setpass(module, "gshadow", 2, ent, password, TRUE,
			      error);
	if (ret)
		lu_util_update_shadow_last_change(ent);
	return ret;
}

static gboolean
lu_shadow_user_removepass(struct lu_module *module, struct lu_ent *ent,
		          struct lu_error **error)
{
	gboolean ret;

	ret = generic_setpass(module, "shadow", 2, ent, LU_CRYPTED, TRUE,
			      error);
	if (ret)
		lu_util_update_shadow_last_change(ent);
	return ret;
}

static gboolean
lu_shadow_group_removepass(struct lu_module *module, struct lu_ent *ent,
			   struct lu_error **error)
{
	gboolean ret;
	ret = generic_setpass(module, "gshadow", 2, ent, LU_CRYPTED, TRUE,
			      error);
	if (ret)
		lu_util_update_shadow_last_change(ent);
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
	GValueArray *ret;
	GValue value;
	char *buf;
	char *key, *filename;
	const char *dir;
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
		char *p;

		if (strlen(buf) == 1) {
			g_free(buf);
			continue;
		}
		/* require that each non-empty line has meaningful data in it */
		p = strchr(buf, ':');
		if (p != NULL) {
			/* snip off the parts we don't care about, */
			*p = '\0';
			if (buf[0] != '+' && buf[0] != '-' &&
			    fnmatch(pattern, buf, 0) == 0) {
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
	return lu_files_enumerate(module, "passwd", pattern, error);
}

static GValueArray *
lu_files_groups_enumerate(struct lu_module *module, const char *pattern,
			  struct lu_error **error)
{
	return lu_files_enumerate(module, "group", pattern, error);
}

/* Get a list of all of the users who are in a given group. */
static GValueArray *
lu_files_users_enumerate_by_group(struct lu_module *module,
				  const char *group, gid_t gid,
				  struct lu_error **error)
{
	int fd;
	gpointer lock;
	GValueArray *ret;
	GValue value;
	char *buf, grp[CHUNK_SIZE];
	char *key, *pwdfilename, *grpfilename, *p, *q;
	const char *dir;
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
	snprintf(grp, sizeof(grp), "%jd", (intmax_t)gid);

	/* Iterate over each line. */
	while ((buf = line_read(fp)) != NULL) {
		if (strlen(buf) == 1 || buf[0] == '-' || buf[0] == '+') {
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
		if (strlen(buf) == 1 || buf[0] == '+' || buf[0] == '-') {
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
	GValueArray *ret;
	GValue value;
	char *buf;
	char *key, *pwdfilename, *grpfilename, *p, *q;
	const char *dir;
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
		if (strlen(buf) == 1 || buf[0] == '+' || buf[0] == '-') {
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
		if (strlen(buf) == 1 || buf[0] == '+' || buf[0] == '-') {
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
	char *key, *filename;
	const char *dir;
	FILE *fp;

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
		goto err_filename;
	}

	/* Lock the file. */
	if ((lock = lu_util_lock_obtain(fd, error)) == NULL) {
		close(fd);
		goto err_filename;
	}

	/* Wrap the file up in stdio. */
	fp = fdopen(fd, "r");
	if (fp == NULL) {
		lu_error_new(error, lu_error_open,
			     _("couldn't open `%s': %s"), filename,
			     strerror(errno));
		lu_util_lock_free(lock);
		close(fd);
		goto err_filename;
	}

	/* Allocate an array to hold results. */
	ret = g_ptr_array_new();
	while ((buf = line_read(fp)) != NULL) {
		struct lu_ent *ent;

		if (strlen(buf) == 1 || buf[0] == '+' || buf[0] == '-') {
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
		if (fnmatch(pattern, key, 0) == 0 && parser(buf, ent) != FALSE)
			g_ptr_array_add(ret, ent);
		else
			lu_ent_free(ent);
		g_free(buf);
		g_free(key);
	}

	lu_util_lock_free(lock);
	fclose(fp);

 err_filename:
	g_free(filename);
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
	directory = lu_cfg_read_single(module->lu_context, key, "/etc");
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
	directory = lu_cfg_read_single(module->lu_context, key, "/etc");
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
	struct lu_module *ret;

	g_return_val_if_fail(context != NULL, FALSE);

	/* Handle authenticating to the data source. */
	if (geteuid() != 0) {
		const char *val;

		/* Needed for the test suite, handy for debugging. */
		val = lu_cfg_read_single(context, "files/nonroot", NULL);
		if (val == NULL || strcmp (val, "yes") != 0) {
			lu_error_new(error, lu_error_privilege,
				     _("not executing with superuser "
				       "privileges"));
			return NULL;
		}
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
	ret->user_unlock_nonempty = lu_files_user_unlock_nonempty;
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
	ret->group_unlock_nonempty = lu_files_group_unlock_nonempty;
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
	struct lu_module *ret;
	struct stat st;
	char *shadow_file;
	const char *dir;

	g_return_val_if_fail(context != NULL, NULL);

	/* Handle authenticating to the data source. */
	if (geteuid() != 0) {
		const char *val;

		/* Needed for the test suite, handy for debugging. */
		val = lu_cfg_read_single(context, "shadow/nonroot", NULL);
		if (val == NULL || strcmp (val, "yes") != 0) {
			lu_error_new(error, lu_error_privilege,
				     _("not executing with superuser "
				       "privileges"));
			return NULL;
		}
	}

	/* Get the name of the shadow file. */
	dir = lu_cfg_read_single(context, "shadow/directory", "/etc");
	shadow_file = g_strconcat(dir, "/shadow", NULL);

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
	ret->user_unlock_nonempty = lu_shadow_user_unlock_nonempty;
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
	ret->group_unlock_nonempty = lu_shadow_group_unlock_nonempty;
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
