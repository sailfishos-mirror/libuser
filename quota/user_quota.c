#include <sys/types.h>
#include <linux/quota.h>
#include <limits.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include "quota.h"

static int
quota_toggle(int flag)
{
	FILE *fp;
	struct mntent *ent;
	int ret = 0;
	char buf[PATH_MAX];
	const char *suffixes[] = INITQFNAMES;

	fp = fopen("/etc/mtab", "r");
	while((ent = getmntent(fp)) != NULL) {
		snprintf(buf, sizeof(buf), "%s/%s.%s",
			 ent->mnt_dir, QUOTAFILENAME, suffixes[USRQUOTA]);
		ret = quotactl(QCMD(flag, USRQUOTA),
			       ent->mnt_fsname, 0, buf);
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
