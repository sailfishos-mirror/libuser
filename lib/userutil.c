#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <libuser/user_private.h>
#include <string.h>

gint
lu_str_case_equal(gconstpointer v1, gconstpointer v2)
{
	g_return_val_if_fail(v1 != NULL, 0);
	g_return_val_if_fail(v2 != NULL, 0);
	return (g_strcasecmp((char*)v1, (char*)v2) == 0);
}

gint
lu_str_equal(gconstpointer v1, gconstpointer v2)
{
	g_return_val_if_fail(v1 != NULL, 0);
	g_return_val_if_fail(v2 != NULL, 0);
	return (strcmp((char*)v1, (char*)v2) == 0);
}
