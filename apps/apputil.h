#ifndef apputil_h
#define apputil_h

#include <sys/types.h>
#include "../include/libuser/user.h"

#define _(String) gettext(String)

gboolean lu_homedir_populate(const char *skel, const char *directory, uid_t owner, gid_t group, mode_t mode,
			     struct lu_error **error);
gboolean lu_homedir_move(const char *oldhome, const char *directory, struct lu_error **error);
gboolean lu_homedir_remove(const char *directory, struct lu_error **error);
void lu_authenticate_unprivileged(struct lu_context *ctx, const char *user, const char *appname);

#endif
