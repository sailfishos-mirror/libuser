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
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libuser/quota.h>

static int
do_quota_stuff(const char *ent, const char *special,
	       int is_group, char **args)
{
	int i;
	struct passwd *pwd;
	struct group *grp;
	int32_t inode_soft, inode_hard, inode_grace,
		block_soft, block_hard, block_grace;

	if(is_group) {
		grp = getgrnam(ent);
		if(grp == NULL) {
			fprintf(stderr, "no group named `%s' found\n", ent);
			return 2;
		}
		if(quota_get_group(grp->gr_gid, special,
				   &inode_soft, &inode_hard, &inode_grace,
				   &block_soft, &block_hard, &block_grace)) {
			fprintf(stderr, "error querying group quota for %s: "
				"%s\n", special, strerror(errno));
			return 3;
		}
		if(args[0] && args[1] && args[2] &&
		   args[3] && args[4] && args[5]) {
			inode_soft = atoi(args[0]);
			inode_hard = atoi(args[1]);
			inode_grace = atoi(args[2]);
			block_soft = atoi(args[3]);
			block_hard = atoi(args[4]);
			block_grace = atoi(args[5]);
			i = quota_set_group(grp->gr_gid, special,
					    inode_soft, inode_hard, inode_grace,
					    block_soft, block_hard, block_grace);
			if(i != 0) {
				fprintf(stderr, "error setting group quota for "
					"%s: %s\n", special, strerror(errno));
				return i;
			}
		} else {
			printf("%s:\n"
			       "\tinode (soft, hard, grace) = (%d, %d, %d)\n"
			       "\tblock (soft, hard, grace) = (%d, %d, %d)\n",
			       special, inode_soft, inode_hard, inode_grace,
			       block_soft, block_hard, block_grace);
		}
	} else {
		pwd = getpwnam(ent);
		if(pwd == NULL) {
			fprintf(stderr, "no user named `%s' found\n", ent);
			return 2;
		}
		if(quota_get_user(pwd->pw_uid, special,
				  &inode_soft, &inode_hard, &inode_grace,
				  &block_soft, &block_hard, &block_grace)) {
			fprintf(stderr, "error querying user quota for %s: "
				"%s\n", special, strerror(errno));
			return 3;
		}
		if(args[0] && args[1] && args[2] &&
		   args[3] && args[4] && args[5]) {
			inode_soft = atoi(args[0]);
			inode_hard = atoi(args[1]);
			inode_grace = atoi(args[2]);
			block_soft = atoi(args[3]);
			block_hard = atoi(args[4]);
			block_grace = atoi(args[5]);
			i = quota_set_user(pwd->pw_uid, special,
					   inode_soft, inode_hard, inode_grace,
					   block_soft, block_hard, block_grace);
			if(i != 0) {
				fprintf(stderr, "error setting user quota for "
					"%s: %s\n", special, strerror(errno));
				return i;
			}
		} else {
			printf("%s:\n"
			       "\tinode (soft, hard, grace) = (%d, %d, %d)\n"
			       "\tblock (soft, hard, grace) = (%d, %d, %d)\n",
			       special, inode_soft, inode_hard, inode_grace,
			       block_soft, block_hard, block_grace);
		}
	}
	return 0;
}

int
main(int argc, char **argv)
{
	int is_group = 0;
	int c;
	int ret;
	const char *special, *ent; 
	char **specials;
	if(argc < 2) {
		printf("usage: %s [-g] <user|group> [<special> "
		       "[<inode_soft> <inode_hard> <inode_grace>"
		       " <block_soft> <block_hard> <block_grace>]]\n",
		       strchr(argv[0], '/') ?
		       strrchr(argv[0], '/') + 1 :
		       argv[0]);
		return 1;
	}

	while((c = getopt(argc, argv, "g")) != -1) {
		switch(c) {
			case 'g': is_group = 1;
				  break;
			default:
				  fprintf(stderr, "bad argument\n");
				  return 1;
		}
	}

	ent = argv[optind];
	special = argv[optind + 1];

	if(special != NULL) {
		return do_quota_stuff(ent, special, is_group,
				      &argv[optind + 2]);
	} else {
		int i;
		if(!is_group) {
			specials = quota_get_specials_user();
		} else {
			specials = quota_get_specials_group();
		}
		for(i = 0; specials && specials[i]; i++) {
			ret = do_quota_stuff(ent, specials[i], is_group,
					     &argv[optind + 1]);
			if(ret != 0) {
				break;
			}
		}
		quota_free_specials(specials);
	}

	return ret;
}
