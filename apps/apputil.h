#ifndef apputil_h
#define apputil_h

#include <sys/types.h>

#define _(String) gettext(String)

const char *make_crypted(const char *plain, const char *previous);
gboolean populate_homedir(const char *skel, const char *directory,
			  uid_t owner, gid_t group, mode_t mode);
gboolean move_homedir(const char *oldhome, const char *directory);
gboolean remove_homedir(const char *directory);

#endif
