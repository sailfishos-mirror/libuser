/* Copyright (C) 2001 Red Hat, Inc.
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
#include <libintl.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../apps/apputil.h"

int
main(int argc, char **argv)
{
	struct lu_error *error = NULL;
	int add = 0, mod = 0, rem = 0, c = -1;

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	while ((c = getopt(argc, argv, "arm")) != -1) {
		switch (c) {
		case 'a':
			add = 1;
			break;
		case 'r':
			rem = 1;
			break;
		case 'm':
			mod = 1;
		default:
			break;
		}
	}

	if (add
	    && !lu_homedir_populate("/etc/skel", argv[optind], 500, 500,
				    0700, &error)) {
		fprintf(stderr, "populate_homedir(%s) failed: %s\n",
			argv[optind], error->string);
		return 1;
	}
	if (mod
	    && !lu_homedir_move(argv[optind], argv[optind + 1], &error)) {
		fprintf(stderr, "move_homedir(%s, %s) failed: %s\n",
			argv[optind], argv[optind + 1], error->string);
		return 1;
	}
	if (rem && !lu_homedir_remove(argv[optind], &error)) {
		fprintf(stderr, "remove_homedir(%s) failed: %s\n",
			argv[optind], error->string);
		return 1;
	}

	return 0;
}
