#include <sys/types.h>
#include <sys/stat.h>
#include <linux/quota.h>
#include <limits.h>
#include <mntent.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "quota.h"

static const char *quota_suffixes[] = INITQFNAMES;

static char **
quota_get_specials(const char *flag)
{
	FILE *fp;
	struct mntent *ent;
	int count, i;
	char **ret = NULL;

	count = 0;

	fp = fopen("/etc/mtab", "r");
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
	return quota_get_specials("usrquota");
}

char **
quota_get_specials_group()
{
	return quota_get_specials("grpquota");
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
quota_toggle(int flag)
{
	FILE *fp;
	struct mntent *ent;
	struct stat st;
	int ret = 0, i;
	char buf[PATH_MAX];

	fp = fopen(_PATH_MOUNTED, "r");
	while((ent = getmntent(fp)) != NULL) {
		for(i = 0; i < MAXQUOTAS; i++) {
			snprintf(buf, sizeof(buf), "%s/%s.%s",
				 ent->mnt_dir,
				 QUOTAFILENAME, quota_suffixes[i]);
			if(stat(buf, &st) == 0) {
				ret = quotactl(QCMD(flag, i),
					       ent->mnt_fsname, 0, buf);
				if(ret == -1) {
					if(ret == EBUSY) {
						ret = 0;
					}
					break;
				}
			}
		}
		if(ret != 0) {
			break;
		}
	}

	endmntent(fp);
	fclose(fp);

	if(ret != 0) {
		return ret;
	}

	return 0;
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

	memset(&dqblk, 0, sizeof(dqblk));
}

static int
quota_set(int type, qid_t id, const char *special,
	  int32_t inode_soft, int32_t inode_hard, int32_t inode_grace,
	  int32_t block_soft, int32_t block_hard, int32_t block_grace)
{
	return -1;
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
