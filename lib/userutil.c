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
#include <crypt.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define LU_DEFAULT_SALT_TYPE "$1$"
#include "../include/libuser/user_private.h"

gint
lu_str_case_equal(gconstpointer v1, gconstpointer v2)
{
	g_return_val_if_fail(v1 != NULL, 0);
	g_return_val_if_fail(v2 != NULL, 0);
	return g_strcasecmp((char*)v1, (char*)v2) == 0;
}

gint
lu_str_equal(gconstpointer v1, gconstpointer v2)
{
	g_return_val_if_fail(v1 != NULL, 0);
	g_return_val_if_fail(v2 != NULL, 0);
	return strcmp((char*)v1, (char*)v2) == 0;
}

gint
lu_strcasecmp(gconstpointer v1, gconstpointer v2)
{
	g_return_val_if_fail(v1 != NULL, 0);
	g_return_val_if_fail(v2 != NULL, 0);
	return g_strcasecmp((char*)v1, (char*)v2);
}

gint
lu_strcmp(gconstpointer v1, gconstpointer v2)
{
	g_return_val_if_fail(v1 != NULL, 0);
	g_return_val_if_fail(v2 != NULL, 0);
	return strcmp((char*)v1, (char*)v2);
}

#define UNACCEPTABLE "!*:$,"
#define ACCEPTABLE "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
		   "abcdefghijklmnopqrstuvwxyz" \
		   "./0123456789"

static gboolean
is_acceptable(const char c)
{
#ifdef VIOLATE_SUSV2
	return (strchr(UNACCEPTABLE, c) == NULL);
#else
	return (strchr(ACCEPTABLE, c) != NULL);
#endif
}

static void
fill_urandom(char *output, size_t length)
{
	int fd;
	size_t got = 0;

	fd = open("/dev/urandom", O_RDONLY);
	g_return_if_fail(fd != -1);

	memset(output, '\0', length);

	while(got < length) {
		read(fd, output + got, 1);
		if(isprint(output[got]) && !isspace(output[got]) && is_acceptable(output[got])) {
			got++;
		}
	}

	close(fd);
}

/**
 * lu_make_crypted:
 * @plain: A password.
 * @previous: An optional salt to use, which also indicates the crypt() variation to be used.
 *
 * Generates a hashed version of @plain by calling the crypt() function, using the hashing method specified in @previous.
 *
 * Returns: a static global string which must not be freed.
 */
const char *
lu_make_crypted(const char *plain, const char *previous)
{
	char salt[2048];
	char *p;
	size_t stlen = 0;

	memset(salt, '\0', sizeof(salt));

	if((previous != NULL) && (previous[0] == '$')) {
		/* If we got a previous salt, and it's got a dollar sign,
		 * figure out the length of the salt type. */
		p = strchr(previous + 1, '$');
		if(p) {
			p++;
			stlen = p - previous;
			if(stlen > 2048) {
				stlen = 2048;
			}
		}
		strncpy(salt, previous, stlen);
	} else if((previous != NULL) && (previous[0] != '$')) {
		/* Otherwise, it's a standard descrypt(). */
		stlen = 0;
	} else if(previous == NULL) {
		/* Fill in the default crypt length. */
		strncpy(salt, LU_DEFAULT_SALT_TYPE, sizeof(salt) - 1);
		stlen = strlen(salt);
	}

	fill_urandom(salt + stlen, sizeof(salt) - stlen - 1);

	return crypt(plain, salt);
}

/**
 * lu_util_lock_obtain:
 * @fd: An open file descriptor.
 *
 * Locks the passed-in descriptor for writing, and returns an opaque lock pointer if the lock succeeds.
 * 
 * Returns: an opaque lock pointer if locking succeeds, NULL on failure.
 */
gpointer
lu_util_lock_obtain(int fd, struct lu_error **error)
{
	struct flock *lck = NULL;
	int i;

	LU_ERROR_CHECK(error);

	g_assert(fd != -1);

	lck = g_malloc0(sizeof(struct flock));
	lck->l_type = F_WRLCK;

	do {
		i = fcntl(fd, F_SETLKW, lck);
	} while((i == -1) && ((errno == EINTR) || (errno == EAGAIN)));

	if(i == -1) {
		g_free(lck);
		lu_error_new(error, lu_error_lock, NULL);
		return NULL;
	}

	return lck;
}

/**
 * lu_util_lock_free:
 * @fd: An open file descriptor.
 * @lock: A lock returned by a previous call to lu_util_lock_obtain().
 *
 * Unlocks a file.
 * 
 * Returns: void
 */
void
lu_util_lock_free(int fd, gpointer lock)
{
	struct flock *lck = (struct flock *) lock;
	g_return_if_fail(fd != -1);
	g_return_if_fail(lock != NULL);
	lck->l_type = F_UNLCK;
	fcntl(fd, F_SETLKW, lck);
	g_free(lck);
}

char *
lu_util_line_get_matchingx(int fd, const char *part, int field,
			   struct lu_error **error)
{
	char *contents;
	char buf[LINE_MAX];
	struct stat st;
	off_t offset;
	char *ret = NULL, *p, *q, *colon;
	int i;

	LU_ERROR_CHECK(error);

	g_assert(fd != -1);
	g_assert(part != NULL);
	g_assert(field > 0);

	offset = lseek(fd, 0, SEEK_CUR);

	if(fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat, NULL);
		return NULL;
	}

	contents = g_malloc0(st.st_size + 1);
	lseek(fd, 0, SEEK_SET);

	if(read(fd, contents, st.st_size) == st.st_size) {
		p = contents;
		do {
			q = strchr(p, '\n');
			if(q != NULL) {
				strncpy(buf, p, MIN(q - p, sizeof(buf) - 1));
				buf[MIN(q - p, sizeof(buf) - 1)] = '\0';
			} else {
				strncpy(buf, p, sizeof(buf) - 1);
				buf[sizeof(buf) - 1] = '\0';
			}

			colon = buf;
			for(i = 1; i < field; i++) {
				if(colon) {
					colon = strchr(colon, ':');
				}
				if(colon) {
					colon++;
				}
			}

			if(colon) {
				if(strncmp(colon, part, strlen(part)) == 0) {
					if((colon[strlen(part)] == ':') || (colon[strlen(part)] == '\n')) {
						ret = g_strdup(buf);
						break;
					}
				}
			}

			p = q ? q + 1 : NULL;
		} while((p != NULL) && (ret == NULL));
	}

	g_free(contents);
	lseek(fd, offset, SEEK_SET);
	return ret;
}

char *
lu_util_line_get_matching1(int fd, const char *part, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_util_line_get_matchingx(fd, part, 1, error);
}

char *
lu_util_line_get_matching3(int fd, const char *part, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_util_line_get_matchingx(fd, part, 3, error);
}

/**
 * lu_strv_len:
 * @v: an array of strings
 *
 * Count the length of an array of strings.
 * 
 * Returns: the number of elements in the array, or 0 if @v is NULL.
 */
guint
lu_strv_len(gchar **v)
{
	int ret = 0;
	while(v && v[ret])
		ret++;
	return ret;
}

/**
 * lu_util_field_read:
 * @fd: Descriptor of open, locked file.
 * @first: Contents of the first field to match the right line with.
 * @field: The number of the field.  Minimum is 1.
 *
 * Read the nth colon-separated field on the line which has first as its first field.
 *
 * Returns: An allocated string which must be freed with g_free().
 */
char *
lu_util_field_read(int fd, const char *first, unsigned int field, struct lu_error **error)
{
	struct stat st;
	unsigned char *buf = NULL;
	char *pattern = NULL;
	char *line = NULL, *start = NULL, *end = NULL;
	char *ret;

	LU_ERROR_CHECK(error);

	g_assert(fd != -1);
	g_assert(first != NULL);
	g_assert(strlen(first) != 0);
	g_assert(field >= 1);

	if(fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat, NULL);
		return NULL;
	}

	if(lseek(fd, 0, SEEK_SET) == -1) {
		lu_error_new(error, lu_error_read, NULL);
		return NULL;
	}

	buf = g_malloc0(st.st_size + 1);
	if(read(fd, buf, st.st_size) != st.st_size) {
		lu_error_new(error, lu_error_read, NULL);
		g_free(buf);
		return NULL;
	}

	pattern = g_strdup_printf("\n%s:", first);
	if(strncmp(buf, pattern + 1, strlen(pattern) - 1) == 0) {
		/* found it on the first line */
		line = buf;
	} else
	if((line = strstr(buf, pattern)) != NULL) {
		/* found it somewhere in the middle */
		line++;
	}

	if(line != NULL) {
		int i = 1;
		char *p;
		start = end = NULL;

		/* find the start of the field */
		if(i == field) {
			start = line;
		} else
		for(p = line;
		    (i < field) && (*p != '\n') && (*p != '\0');
		    p++) {
			if(*p == ':') {
				i++;
			}
			if(i >= field) {
				start = p + 1;
				break;
			}
		}
	}

	/* find the end of the field */
	if(start != NULL) {
		end = start;
		while((*end != '\0') && (*end != '\n') && (*end != ':')) {
			end++;
		}
		g_assert((*end == '\0') || (*end == '\n') || (*end == ':'));
	}

	if((start != NULL) && (end != NULL)) {
		ret = g_strndup(start, end - start);
	} else {
		ret = g_strdup("");
	}

	g_free(pattern);
	g_free(buf);

	return ret;
}

/**
 * lu_util_field_write:
 * @fd: Descriptor of open, locked file.
 * @first: Contents of the first field to match the right line with.
 * @field: The number of the field.  Minimum is 1.
 * @value: The new value for the field.
 *
 * Modify the nth colon-separated field on the line which has first as its first field.
 *
 * Returns: A boolean indicating success or failure.
 */
gboolean
lu_util_field_write(int fd, const char *first, unsigned int field, const char *value, struct lu_error **error)
{
	struct stat st;
	char *buf;
	char *pattern = NULL;
	char *line = NULL, *start = NULL, *end = NULL;
	gboolean ret = FALSE;
	int fi = 1;

	LU_ERROR_CHECK(error);

	g_assert(fd != -1);
	g_assert(field >= 1);

	first = first ?: "";
	value = value ?: "";

	if(fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat, NULL);
		return FALSE;
	}

	if(lseek(fd, 0, SEEK_SET) == -1) {
		lu_error_new(error, lu_error_read, NULL);
		return FALSE;
	}

	buf = g_malloc0(st.st_size + 1 + strlen(value) + field);
	if(read(fd, buf, st.st_size) != st.st_size) {
		lu_error_new(error, lu_error_read, NULL);
		return FALSE;
	}

	pattern = g_strdup_printf("\n%s:", first);
	if(strncmp(buf, pattern + 1, strlen(pattern) - 1) == 0) {
		/* found it on the first line */
		line = buf;
	} else
	if((line = strstr(buf, pattern)) != NULL) {
		/* found it somewhere in the middle */
		line++;
	}

	if(line != NULL) {
		char *p;
		start = end = NULL;

		/* find the start of the field */
		if(fi == field) {
			start = line;
		} else
		for(p = line;
		    (fi < field) && (*p != '\n') && (*p != '\0');
		    p++) {
			if(*p == ':') {
				fi++;
			}
			if(fi >= field) {
				start = p + 1;
				break;
			}
		}
	}

	/* find the end of the field */
	if(start != NULL) {
		end = start;
		while((*end != '\0') && (*end != '\n') && (*end != ':')) {
			end++;
		}
	} else {
		lu_error_new(error, lu_error_search, NULL);
		return FALSE;
	}

	if((start != NULL) && (end != NULL)) {
		/* insert the text here, after moving the data around */
		memmove(start + strlen(value), end, st.st_size - (end - buf) + 1);
		memcpy(start, value, strlen(value));
		ret = TRUE;
	} else {
		if(line) {
			/* fi contains the number of fields, so the difference
			 * between field and fi is the number of colons we need
			 * to add to the end of the line to create the field */
			end = line;
			while((*end != '\0') && (*end != '\n')) {
				end++;
			}
			start = end;
			memmove(start + strlen(value) + (field - fi), end, st.st_size - (end - buf) + 1);
			memset(start, ':', field - fi);
			memcpy(start + (field - fi), value, strlen(value));
			ret = TRUE;
		}
	}

	if(ret == TRUE) {
		size_t len;
		if(lseek(fd, 0, SEEK_SET) == -1) {
			lu_error_new(error, lu_error_write, NULL);
			return FALSE;
		}
		len = strlen(buf);
		if(write(fd, buf, len) == -1) {
			lu_error_new(error, lu_error_write, NULL);
			return FALSE;
		}
		if(ftruncate(fd, len) == -1) {
			lu_error_new(error, lu_error_write, NULL);
			return FALSE;
		}
	} else {
		lu_error_new(error, lu_error_search, NULL);
		return FALSE;
	}

	g_free(pattern);
	g_free(buf);

	return ret;
}
