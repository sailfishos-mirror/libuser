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
#include <config.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/quota.h>
#include <limits.h>
#include <mntent.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libuser/quota.h>

static const char *quota_flags[] = {"usrquota", "grpquota",};
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
	if(fp == NULL) {
		return NULL;
	}

	while((ent = getmntent(fp)) != NULL) {
		if(hasmntopt(ent, flag) || hasmntopt(ent, "quota")) {
			char **tmp = malloc(sizeof(char*) * (count + 2));
			if(ret != NULL) {
				for(i = 0; i < count + 1; i++) {
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
	fclose(fp);

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
	for(i = 0; (specials != NULL) && (specials[i] != NULL); i++) {
		free(specials[i]);
	}
	if(specials != NULL) {
		free(specials);
	}
}

static int
quota_toggle(int command)
{
	struct stat st;
	int ret = 0, i, j, k;
	char buf[PATH_MAX];
	char **specials;

	for(i = 0; i < (sizeof(quota_flags) / sizeof(quota_flags[0])); i++) {
		specials = quota_get_specials_user();
		for(j = 0; (specials != NULL) && (specials[j] != NULL); j++) {
			for(k = 0; k < MAXQUOTAS; k++) {
				snprintf(buf, sizeof(buf), "%s/%s.%s",
					 specials[j],
					 QUOTAFILENAME, quota_suffixes[k]);
				if(stat(buf, &st) == 0) {
					ret = quotactl(QCMD(command, k),
						       specials[j], 0, buf);
					if(ret == -1) {
						if(ret == EBUSY) {
							ret = 0;
						}
						break;
					}
					if(ret != 0) {
						break;
					}
				}
			}
			if(ret != 0) {
				break;
			}
		}
		if(specials != NULL) {
			quota_free_specials(specials);
		}
		if(ret != 0) {
			break;
		}
	}
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
quota_get(int type, qid_t id, const char *special,
	  int32_t *inode_soft, int32_t *inode_hard, 
	  int32_t *inode_grace, int32_t *block_soft, 
	  int32_t *block_hard, int32_t *block_grace)
{
	struct mem_dqblk dqblk;
	int ret = 0;

	memset(&dqblk, 0, sizeof(dqblk));
	ret = quotactl(QCMD(Q_GETQUOTA, type), special, id, &dqblk);
	if(ret == 0) {
		*inode_soft = dqblk.dqb_isoftlimit;
		*inode_hard = dqblk.dqb_ihardlimit;
		*inode_grace = dqblk.dqb_itime;
		*block_soft = dqblk.dqb_bsoftlimit;
		*block_hard = dqblk.dqb_bhardlimit;
		*block_grace = dqblk.dqb_btime;
	}
	return ret;
}

static int
quota_set(int type, qid_t id, const char *special,
	  int32_t inode_soft, int32_t inode_hard, int32_t inode_grace,
	  int32_t block_soft, int32_t block_hard, int32_t block_grace)
{
	struct mem_dqblk dqblk;
	int ret = 0;

	memset(&dqblk, 0, sizeof(dqblk));
	ret = quotactl(QCMD(Q_GETQUOTA, type), special, id, &dqblk);
	if(ret == 0) {
		if(inode_soft != -1)
			dqblk.dqb_isoftlimit = inode_soft;
		if(inode_hard != -1)
			dqblk.dqb_ihardlimit = inode_hard;
		if(inode_grace != -1)
			dqblk.dqb_itime = inode_grace;
		if(block_soft != -1)
			dqblk.dqb_bsoftlimit = block_soft;
		if(block_hard != -1)
			dqblk.dqb_bhardlimit = block_hard;
		if(block_grace != -1)
			dqblk.dqb_btime = block_grace;
		ret = quotactl(QCMD(Q_SETQUOTA, type), special, id, &dqblk);
	}
	return ret;
}

int
quota_get_user(uid_t uid, const char *special,
	       int32_t *inode_soft, int32_t *inode_hard, 
	       int32_t *inode_grace, int32_t *block_soft, 
	       int32_t *block_hard, int32_t *block_grace)
{
	return quota_get(USRQUOTA, uid, special, inode_soft, inode_hard,
			 inode_grace, block_soft, block_hard, block_grace);
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
		int32_t *inode_soft, int32_t *inode_hard, 
		int32_t *inode_grace, int32_t *block_soft, 
		int32_t *block_hard, int32_t *block_grace)
{
	return quota_get(GRPQUOTA, gid, special, inode_soft, inode_hard,
			 inode_grace, block_soft, block_hard, block_grace);
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
