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
#include "../config.h"
#endif
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <crypt.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define LU_DEFAULT_SALT_TYPE "$1$"
#define LU_DEFAULT_SALT_LEN  8
#define LU_MAX_LOCK_ATTEMPTS 6
#define LU_LOCK_TIMEOUT      2
#include "user_private.h"
#include "internal.h"

struct lu_lock {
	int fd;
	struct flock lock;
};

/* A wrapper for strcasecmp(). */
gint
lu_strcasecmp(gconstpointer v1, gconstpointer v2)
{
	g_return_val_if_fail(v1 != NULL, 0);
	g_return_val_if_fail(v2 != NULL, 0);
	return g_ascii_strcasecmp((char *) v1, (char *) v2);
}

/* A wrapper for strcmp(). */
gint
lu_strcmp(gconstpointer v1, gconstpointer v2)
{
	g_return_val_if_fail(v1 != NULL, 0);
	g_return_val_if_fail(v2 != NULL, 0);
	return strcmp((char *) v1, (char *) v2);
}

/* A list of allowed salt characters, according to SUSv2. */
#define ACCEPTABLE "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
		   "abcdefghijklmnopqrstuvwxyz" \
		   "./0123456789"

static gboolean
is_acceptable(const char c)
{
	if (c == 0) {
		return FALSE;
	}
	return (strchr(ACCEPTABLE, c) != NULL);
}

static gboolean
fill_urandom(char *output, size_t length)
{
	int fd;
	size_t got = 0;

	fd = open("/dev/urandom", O_RDONLY);
	g_return_val_if_fail(fd != -1, FALSE);

	memset(output, '\0', length);

	while (got < length) {
		ssize_t len;

		len = read(fd, output + got, length - got);
		if (len == -1) {
			if (errno == EINTR)
				continue;
			else {
				close(fd);
				return FALSE;
			}
		}
		while (len != 0 && isprint((unsigned char)output[got])
		       && !isspace((unsigned char)output[got])
		       && is_acceptable(output[got])) {
			got++;
			len--;
		}
	}

	close(fd);
	return TRUE;
}

static struct {
	const char *initial;
	size_t salt_length;
	const char *separator;
} salt_type_info[] = {
	{"$1$", 8, "$"},
	{"$2a$", 8, "$"},	/* FIXME: is this 8 or 16? */
	{ "", 2, ""},
};

const char *
lu_make_crypted(const char *plain, const char *previous)
{
	char salt[2048];
	size_t i, len = 0;

	if (previous == NULL) {
		previous = LU_DEFAULT_SALT_TYPE;
	}

	for (i = 0; i < G_N_ELEMENTS(salt_type_info); i++) {
		len = strlen(salt_type_info[i].initial);
		if (strncmp(previous, salt_type_info[i].initial, len) == 0) {
			break;
		}
	}

	g_assert(i < G_N_ELEMENTS(salt_type_info));

	memset(salt, '\0', sizeof(salt));
	strncpy(salt, salt_type_info[i].initial, len);

	g_assert(strlen(salt) +
		 salt_type_info[i].salt_length +
		 strlen(salt_type_info[i].separator) <
		 sizeof(salt));
	if (fill_urandom(salt + len, salt_type_info[i].salt_length) == FALSE)
		return NULL;
	strcat(salt, salt_type_info[i].separator);

	return crypt(plain, salt);
}

gpointer
lu_util_lock_obtain(int fd, struct lu_error ** error)
{
	int i;
	int maxtries = LU_MAX_LOCK_ATTEMPTS;
	int delay = LU_LOCK_TIMEOUT;
	struct lu_lock *ret;

	LU_ERROR_CHECK(error);

	g_assert(fd != -1);
	ret = g_malloc0(sizeof(*ret));

	do {
		ret->fd = fd;
		ret->lock.l_type = F_RDLCK;
		if (write(ret->fd, NULL, 0) == 0) {
			ret->lock.l_type |= F_WRLCK;
		}
		i = fcntl(ret->fd, F_SETLK, &ret->lock);
		if ((i == -1) && ((errno == EINTR) || (errno == EAGAIN))) {
			struct timeval tv;

			if (maxtries-- <= 0) {
				break;
			}
			memset(&tv, 0, sizeof(tv));
			tv.tv_usec = (delay *= 2);
			select(0, NULL, NULL, NULL, &tv);
		}
	} while ((i == -1) && ((errno == EINTR) || (errno == EAGAIN)));

	if (i == -1) {
		lu_error_new(error, lu_error_lock,
			     _("error locking file: %s"), strerror(errno));
		g_free(ret);
		return NULL;
	}

	return ret;
}

void
lu_util_lock_free(gpointer lock)
{
	struct lu_lock *ret;
	int i;
	g_return_if_fail(lock != NULL);
	ret = (struct lu_lock*) lock;
	do {
		ret->lock.l_type = F_UNLCK;
		i = fcntl(ret->fd, F_SETLK, &ret->lock);
	} while ((i == -1) && ((errno == EINTR) || (errno == EAGAIN)));
	g_free(ret);
}

char *
lu_util_line_get_matchingx(int fd, const char *part, int field,
			   struct lu_error **error)
{
	char *contents;
	struct stat st;
	off_t offset;
	char *ret = NULL, *p;
	gboolean mapped = FALSE;

	LU_ERROR_CHECK(error);

	g_assert(fd != -1);
	g_assert(part != NULL);
	g_assert(field > 0);

	offset = lseek(fd, 0, SEEK_CUR);

	if (fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat, NULL);
		return NULL;
	}

	contents = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (contents == MAP_FAILED) {
		contents = g_malloc(st.st_size);
		if (lseek(fd, 0, SEEK_SET) == -1) {
			lu_error_new(error, lu_error_read, NULL);
			g_free(contents);
			return NULL;
		}
		if (read(fd, contents, st.st_size) != st.st_size) {
			lu_error_new(error, lu_error_read, NULL);
			g_free(contents);
			return NULL;
		}
	} else {
		mapped = TRUE;
	}

	p = contents;
	do {
		char *buf, *q, *colon;
		int i;

		q = memchr(p, '\n', st.st_size - (p - contents));

		colon = buf = p;
		for (i = 1; (i < field) && (colon != NULL); i++) {
			if (colon) {
				colon =
				    memchr(colon, ':',
					   st.st_size - (colon -
							 contents));
			}
			if (colon) {
				colon++;
			}
		}

		if (colon) {
			if (strncmp(colon, part, strlen(part)) == 0) {
				if ((colon[strlen(part)] == ':')
				    || (colon[strlen(part)] == '\n')) {
					size_t maxl;
					maxl =
					    st.st_size - (buf - contents);
					if (q) {
						ret =
						    g_strndup(buf,
							      q - buf);
					} else {
						ret = g_strndup(buf, maxl);
					}
					break;
				}
			}
		}

		p = q ? q + 1 : NULL;
	} while ((p != NULL) && (ret == NULL));

	if (mapped) {
		munmap(contents, st.st_size);
	} else {
		g_free(contents);
	}

	lseek(fd, offset, SEEK_SET);
	return ret;
}

char *
lu_util_line_get_matching1(int fd, const char *part,
			   struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_util_line_get_matchingx(fd, part, 1, error);
}

char *
lu_util_line_get_matching3(int fd, const char *part,
			   struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_util_line_get_matchingx(fd, part, 3, error);
}

char *
lu_util_field_read(int fd, const char *first, unsigned int field,
		   struct lu_error **error)
{
	struct stat st;
	char *buf;
	char *pattern;
	char *line, *start = NULL, *end = NULL;
	char *ret;
	size_t len;
	gboolean mapped = FALSE;

	LU_ERROR_CHECK(error);

	g_assert(fd != -1);
	g_assert(first != NULL);
	g_assert(strlen(first) != 0);
	g_assert(field >= 1);

	if (fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat, NULL);
		return NULL;
	}

	buf = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		buf = g_malloc(st.st_size);
		if (lseek(fd, 0, SEEK_SET) == -1) {
			lu_error_new(error, lu_error_read, NULL);
			g_free(buf);
			return NULL;
		}
		if (read(fd, buf, st.st_size) != st.st_size) {
			lu_error_new(error, lu_error_read, NULL);
			g_free(buf);
			return NULL;
		}
	} else {
		mapped = TRUE;
	}

	pattern = g_strdup_printf("%s:", first);
	len = strlen(pattern);
	line = buf;
	if ((st.st_size >= (off_t)len) && (memcmp(buf, pattern, len) == 0)) {
		/* found it on the first line */
	} else
		while ((line =
			memchr(line, '\n',
			       st.st_size - (line - buf))) != NULL) {
			line++;
			if (line < buf + st.st_size - len) {
				if (memcmp(line, pattern, len) == 0) {
					/* found it somewhere in the middle */
					break;
				}
			}
		}

	if (line != NULL) {
		unsigned i = 1;
		char *p;
		start = end = NULL;

		/* find the start of the field */
		if (i == field) {
			start = line;
		} else
			for (p = line;
			     (i < field) && (*p != '\n') && (*p != '\0');
			     p++) {
				if (*p == ':') {
					i++;
				}
				if (i >= field) {
					start = p + 1;
					break;
				}
			}
	}

	/* find the end of the field */
	if (start != NULL) {
		end = start;
		while ((*end != '\0') && (*end != '\n') && (*end != ':')) {
			end++;
		}
		g_assert((*end == '\0') || (*end == '\n')
			 || (*end == ':'));
	}

	if ((start != NULL) && (end != NULL)) {
		ret = g_strndup(start, end - start);
	} else {
		ret = g_strdup("");
	}

	g_free(pattern);
	if (mapped) {
		munmap(buf, st.st_size);
	} else {
		g_free(buf);
	}

	return ret;
}

gboolean
lu_util_field_write(int fd, const char *first, unsigned int field,
		    const char *value, struct lu_error ** error)
{
	struct stat st;
	char *buf;
	char *pattern;
	char *line, *start = NULL, *end = NULL;
	gboolean ret = FALSE;
	unsigned fi = 1;

	LU_ERROR_CHECK(error);

	g_assert(fd != -1);
	g_assert(field >= 1);

	first = first ? : "";
	value = value ? : "";

	if (fstat(fd, &st) == -1) {
		lu_error_new(error, lu_error_stat, NULL);
		return FALSE;
	}

	if (lseek(fd, 0, SEEK_SET) == -1) {
		lu_error_new(error, lu_error_read, NULL);
		return FALSE;
	}

	buf = g_malloc0(st.st_size + 1 + strlen(value) + field);
	if (read(fd, buf, st.st_size) != st.st_size) {
		lu_error_new(error, lu_error_read, NULL);
		return FALSE;
	}

	pattern = g_strdup_printf("\n%s:", first);
	if (strncmp(buf, pattern + 1, strlen(pattern) - 1) == 0) {
		/* found it on the first line */
		line = buf;
	} else if ((line = strstr(buf, pattern)) != NULL) {
		/* found it somewhere in the middle */
		line++;
	}

	if (line != NULL) {
		char *p;
		start = end = NULL;

		/* find the start of the field */
		if (fi == field) {
			start = line;
		} else
			for (p = line;
			     (fi < field) && (*p != '\n') && (*p != '\0');
			     p++) {
				if (*p == ':') {
					fi++;
				}
				if (fi >= field) {
					start = p + 1;
					break;
				}
			}
	}

	/* find the end of the field */
	if (start != NULL) {
		end = start;
		while ((*end != '\0') && (*end != '\n') && (*end != ':')) {
			end++;
		}
	} else {
		lu_error_new(error, lu_error_search, NULL);
		return FALSE;
	}

	if ((start != NULL) && (end != NULL)) {
		/* insert the text here, after moving the data around */
		memmove(start + strlen(value), end,
			st.st_size - (end - buf) + 1);
		memcpy(start, value, strlen(value));
		ret = TRUE;
	} else {
		if (line) {
			/* fi contains the number of fields, so the difference
			 * between field and fi is the number of colons we need
			 * to add to the end of the line to create the field */
			end = line;
			while ((*end != '\0') && (*end != '\n')) {
				end++;
			}
			start = end;
			memmove(start + strlen(value) + (field - fi), end,
				st.st_size - (end - buf) + 1);
			memset(start, ':', field - fi);
			memcpy(start + (field - fi), value, strlen(value));
			ret = TRUE;
		}
	}

	if (ret == TRUE) {
		size_t len;
		if (lseek(fd, 0, SEEK_SET) == -1) {
			lu_error_new(error, lu_error_write, NULL);
			ret = FALSE;
			goto err;
		}
		len = strlen(buf);
		if (write(fd, buf, len) == -1) {
			lu_error_new(error, lu_error_write, NULL);
			ret = FALSE;
			goto err;
		}
		if (ftruncate(fd, len) == -1) {
			lu_error_new(error, lu_error_write, NULL);
			ret = FALSE;
			goto err;
		}
	} else {
		lu_error_new(error, lu_error_search, NULL);
		ret = FALSE;
	}

err:
	g_free(pattern);
	g_free(buf);

	return ret;
}

char *
lu_util_shadow_current_date(struct lu_string_cache *cache)
{
	struct tm gmt;
	time_t now;
	char buf[LINE_MAX];
	GDate *today, *epoch;
	long days;

	time(&now);
	gmt = *(gmtime(&now));

	today =
	    g_date_new_dmy(gmt.tm_mday, gmt.tm_mon + 1,
			   gmt.tm_year + 1900);
	epoch = g_date_new_dmy(1, 1, 1970);
	days = g_date_get_julian(today) - g_date_get_julian(epoch);
	g_date_free(today);
	g_date_free(epoch);

	snprintf(buf, sizeof(buf), "%ld", days);

	return cache->cache(cache, buf);
}
