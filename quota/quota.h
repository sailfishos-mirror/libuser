#ifndef libuser_quota_h
#define libuser_quota_h

#include <sys/types.h>

int quota_on(void);
int quota_off(void);

char **quota_get_specials_user(void);
char **quota_get_specials_group(void);
void quota_free_specials(char **specials);

int quota_get_user(uid_t uid, const char *special,
		   int32_t *inode_soft, int32_t *inode_hard, 
		   int32_t *inode_grace, int32_t *block_soft, 
		   int32_t *block_hard, int32_t *block_grace);
int quota_set_user(uid_t uid, const char *special,
		   int32_t inode_soft, int32_t inode_hard, 
		   int32_t inode_grace, int32_t block_soft, 
		   int32_t block_hard, int32_t block_grace);

int quota_get_group(gid_t gid, const char *special,
		    int32_t *inode_soft, int32_t *inode_hard, 
		    int32_t *inode_grace, int32_t *block_soft, 
		    int32_t *block_hard, int32_t *block_grace);
int quota_set_group(gid_t gid, const char *special,
		    int32_t inode_soft, int32_t inode_hard, 
		    int32_t inode_grace, int32_t block_soft, 
		    int32_t block_hard, int32_t block_grace);

#endif
