#ifndef util_h
#define util_h

#include <glib.h>

#define GSHADOW_LIKE_SHADOW_SUITE

gpointer lock_obtain(int fd);
void lock_free(int fd, gpointer lock);
char *get_matching_line1(int fd, const char *firstpart);
char *get_matching_line3(int fd, const char *secondpart);
char *get_matching_linex(int fd, const char *part, int field);
guint lu_strv_len(gchar **v);

#endif
