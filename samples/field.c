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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libuser/user.h>
#include <libuser/user_private.h>

int
main(int argc, char **argv)
{
	int fd;
	gpointer lock;

	if(argc < 4) {
		printf("usage: %s <file> <initial> <field> [value]\n",
		       strchr(argv[0], '/') ?
		       strrchr(argv[0], '/') + 1 :
		       argv[0]);
		exit(1);
	}
	fd = open(argv[1], (argc < 5) ? O_RDONLY : O_RDWR);
	if(fd == -1) {
		fprintf(stderr, "error opening `%s': %s\n", argv[1],
			strerror(errno));
		exit(2);
	}

	lock = lu_util_lock_obtain(fd, NULL);
	if(lock == NULL) {
		fprintf(stderr, "failed to lock `%s': %s\n", argv[1],
			strerror(errno));
		close(fd);
		exit(3);
	}

	if(argc > 4) {
		if(!lu_util_field_write(fd, argv[2], atoi(argv[3]), argv[4], NULL)) {
			fprintf(stderr, "failed to modify `%s': %s\n", argv[1],
				strerror(errno));
		}
	} else {
		char *ret;
		ret = lu_util_field_read(fd, argv[2], atoi(argv[3]), NULL);
		if(ret == NULL) {
			fprintf(stderr, "failed to read `%s': %s\n", argv[1],
				strerror(errno));
		}
		printf("`%s'\n", ret);
		g_free(ret);
	}
	lu_util_lock_free(fd, lock);
	close(fd);
	return 0;
}
