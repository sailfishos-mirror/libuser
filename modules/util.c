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

#include <libuser/user_private.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "util.h"

gpointer lock_obtain(int fd)
{
	struct flock *lck = NULL;
	int i;

	g_return_val_if_fail(fd != -1, NULL);

	lck = g_malloc0(sizeof(struct flock));
	lck->l_type = F_WRLCK;

	do {
		i = fcntl(fd, F_SETLKW, lck);
	} while((i == -1) && (errno == EINTR));

	return lck;
}

void lock_free(int fd, gpointer lock)
{
	struct flock *lck = (struct flock *) lock;
	g_return_if_fail(fd != -1);
	g_return_if_fail(lock != NULL);
	lck->l_type = F_UNLCK;
	fcntl(fd, F_SETLKW, lck);
	g_free(lck);
}

char *get_matching_line1(int fd, const char *part)
{
	return get_matching_linex(fd, part, 1);
}

char *get_matching_line3(int fd, const char *part)
{
	return get_matching_linex(fd, part, 3);
}

char *get_matching_linex(int fd, const char *part, int field)
{
	char *contents;
	char buf[LINE_MAX];
	struct stat st;
	off_t offset;
	char *ret = NULL, *p, *q, *colon;
	int i;

	g_return_val_if_fail(fd != -1, NULL);
	g_return_val_if_fail(part != NULL, NULL);
	g_return_val_if_fail(field > 0, NULL);

	offset = lseek(fd, 0, SEEK_CUR);

	if(fstat(fd, &st) == -1) {
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
					if((colon[strlen(part)] == ':') ||
					   (colon[strlen(part)] == '\n')) {
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

guint lu_strv_len(gchar **v)
{
	int ret = 0;
	while(v && v[ret])
		ret++;
	return ret;
}
