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
#include "../config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/quota.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mntent.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "userquota.h"

#ifdef MIN
#undef MIN
#endif
#define MIN(A,B) (((A)<(B))?(A):(B))

#ifndef MAX_IQ_TIME
#define MAX_IQ_TIME (7 * 24 * 60 * 60)
#endif

#ifndef MAX_DQ_TIME
#define MAX_DQ_TIME (7 * 24 * 60 * 60)
#endif

long quotactl(int cmd, const char* special, qid_t id, caddr_t addr);
_syscall4(long,quotactl,int,cmd,const char*,special,qid_t,id,caddr_t,addr);

static const char *quota_flags[] = { "usrquota", "grpquota", };
static const char *quota_suffixes[] = INITQFNAMES;

static char **
quota_get_specials(const char *flag)
{
	FILE *fp;
	struct mntent *ent;
	int count, i;
	char **ret = NULL;

	count = 0;

	fp = fopen(_PATH_MOUNTED, "r");
	if (fp == NULL) {
		return NULL;
	}

	while ((ent = getmntent(fp)) != NULL) {
		if (hasmntopt(ent, flag) || hasmntopt(ent, "quota")) {
			char **tmp = malloc(sizeof(char *) * (count + 2));
			if (ret != NULL) {
				for (i = 0; i < count + 1; i++) {
					tmp[i] = ret[i];
				}
				free(ret);
			}
			tmp[count] = strdup(ent->mnt_fsname);
			tmp[count + 1] = NULL;
			count++;
			ret = tmp;
		}
	}

	endmntent(fp);

	return ret;
}

char **
quota_get_specials_user()
{
	return quota_get_specials(quota_flags[USRQUOTA]);
}

char **
quota_get_specials_group()
{
	return quota_get_specials(quota_flags[GRPQUOTA]);
}

void
quota_free_specials(char **specials)
{
	int i;
	for (i = 0; (specials != NULL) && (specials[i] != NULL); i++) {
		free(specials[i]);
	}
	if (specials != NULL) {
		free(specials);
	}
}

static int
quota_toggle_ext(struct mntent *ent, const char *option, int command,
		 int flag)
{
	char buf[PATH_MAX];
	struct stat st;
	int ret = 0, fd;

	if (hasmntopt(ent, option) ||
	    ((strcmp(option, "usrquota") == 0)
	     && hasmntopt(ent, "quota"))) {
		snprintf(buf, sizeof(buf), "%s/%s.%s", ent->mnt_dir,
			 QUOTAFILENAME, quota_suffixes[GRPQUOTA]);
		if (stat(buf, &st) == 0) {
			if ((st.st_mode & 0777) != 0600) {
				fd = open(buf, O_RDWR);
				if (fd != -1) {
					struct stat ist;
					if (fstat(fd, &ist) == 0) {
						if ((ist.st_dev ==
						     st.st_dev)
						    && (ist.st_ino ==
							st.st_ino)) {
							fchmod(fd, 0600);
						}
					}
					close(fd);
				}
			}
			ret = quotactl(QCMD(command, GRPQUOTA),
				       ent->mnt_fsname, 0, buf);
			if (ret == -1) {
				if (errno == EBUSY) {
					ret = 0;
				}
			}
			if (ret == -1) {
				return ret;
			}
		}
	}
	return ret;
}

static int
quota_toggle(int command)
{
	int ret = 0;
	struct mntent *ent;
	FILE *fp;

	fp = fopen(_PATH_MOUNTED, "r");
	if (fp == NULL) {
		return -1;
	}

	while ((ent = getmntent(fp)) != NULL) {
		ret = quota_toggle_ext(ent, quota_flags[USRQUOTA],
				       command, USRQUOTA);
		if (ret != 0) {
			break;
		}
		ret = quota_toggle_ext(ent, quota_flags[GRPQUOTA],
				       command, GRPQUOTA);
		if (ret != 0) {
			break;
		}
	}

	endmntent(fp);

	return ret;
}

int
quota_on()
{
	return quota_toggle(Q_QUOTAON);
}

int
quota_off()
{
	return quota_toggle(Q_QUOTAOFF);
}

static int
quota_get(int type, int id, const char *special,
	  int32_t * inode_usage, int32_t * inode_soft,
	  int32_t * inode_hard, int32_t * inode_grace,
	  int32_t * block_usage, int32_t * block_soft,
	  int32_t * block_hard, int32_t * block_grace)
{
	struct mem_dqblk dqblk;
	struct mem_dqinfo dqinfo;
	int ret = 0;

	memset(&dqblk, 0, sizeof(dqblk));
	memset(&dqinfo, 0, sizeof(dqinfo));

	ret =
	    quotactl(QCMD(Q_GETQUOTA, type), special, id,
		     (caddr_t) & dqblk);
	if (ret == 0)
		ret =
		    quotactl(QCMD(Q_GETINFO, type), special, id,
			     (caddr_t) & dqinfo);

	if (ret == 0) {
		if (inode_usage)
			*inode_usage = dqblk.dqb_curinodes;
		if (inode_soft)
			*inode_soft = dqblk.dqb_isoftlimit;
		if (inode_hard)
			*inode_hard = dqblk.dqb_ihardlimit;
		if (inode_grace)
			*inode_grace = dqinfo.dqi_igrace;

		if (block_usage)
			*block_usage =
			    (dqblk.dqb_curspace + QUOTABLOCK_SIZE -
			     1) / QUOTABLOCK_SIZE;
		if (block_soft)
			*block_soft = dqblk.dqb_bsoftlimit;
		if (block_hard)
			*block_hard = dqblk.dqb_bhardlimit;
		if (block_grace)
			*block_grace = dqinfo.dqi_bgrace;
	}
	return ret;
}

static int
quota_set(int type, int id, const char *special,
	  int32_t inode_soft, int32_t inode_hard, int32_t inode_grace,
	  int32_t block_soft, int32_t block_hard, int32_t block_grace)
{
	struct mem_dqblk dqblk;
	struct mem_dqinfo dqinfo;
	int ret = 0;

	memset(&dqblk, 0, sizeof(dqblk));
	memset(&dqinfo, 0, sizeof(dqinfo));

	ret =
	    quotactl(QCMD(Q_GETQUOTA, type), special, id,
		     (caddr_t) & dqblk);
	if (ret == 0)
		ret =
		    quotactl(QCMD(Q_GETINFO, type), special, id,
			     (caddr_t) & dqinfo);

	if (ret == 0) {
		if (inode_soft != -1)
			dqblk.dqb_isoftlimit = inode_soft;
		if (inode_hard != -1)
			dqblk.dqb_ihardlimit = inode_hard;
		if (inode_grace != -1)
			dqinfo.dqi_igrace = MIN(inode_grace, MAX_IQ_TIME);
		if (block_soft != -1)
			dqblk.dqb_bsoftlimit = block_soft;
		if (block_hard != -1)
			dqblk.dqb_bhardlimit = block_hard;
		if (block_grace != -1)
			dqinfo.dqi_bgrace = MIN(block_grace, MAX_IQ_TIME);
	}
	if (ret == 0) {
		ret = quotactl(QCMD(Q_SETQLIM, type), special, id,
			       (caddr_t) & dqblk);
	}
	if (ret == 0) {
		ret = quotactl(QCMD(Q_SETGRACE, type), special, id,
			       (caddr_t) & dqinfo);
	}
	return ret;
}

int
quota_get_user(uid_t uid, const char *special,
	       int32_t * inode_usage, int32_t * inode_soft,
	       int32_t * inode_hard, int32_t * inode_grace,
	       int32_t * block_usage, int32_t * block_soft,
	       int32_t * block_hard, int32_t * block_grace)
{
	return quota_get(USRQUOTA, uid, special,
			 inode_usage, inode_soft, inode_hard, inode_grace,
			 block_usage, block_soft, block_hard, block_grace);
}

int
quota_set_user(uid_t uid, const char *special,
	       int32_t inode_soft, int32_t inode_hard,
	       int32_t inode_grace, int32_t block_soft,
	       int32_t block_hard, int32_t block_grace)
{
	return quota_set(USRQUOTA, uid, special, inode_soft, inode_hard,
			 inode_grace, block_soft, block_hard, block_grace);
}

int
quota_get_group(gid_t gid, const char *special,
		int32_t * inode_usage, int32_t * inode_soft,
		int32_t * inode_hard, int32_t * inode_grace,
		int32_t * block_usage, int32_t * block_soft,
		int32_t * block_hard, int32_t * block_grace)
{
	return quota_get(GRPQUOTA, gid, special,
			 inode_usage, inode_soft, inode_hard, inode_grace,
			 block_usage, block_soft, block_hard, block_grace);
}

int
quota_set_group(gid_t gid, const char *special,
		int32_t inode_soft, int32_t inode_hard,
		int32_t inode_grace, int32_t block_soft,
		int32_t block_hard, int32_t block_grace)
{
	return quota_set(GRPQUOTA, gid, special, inode_soft, inode_hard,
			 inode_grace, block_soft, block_hard, block_grace);
}
