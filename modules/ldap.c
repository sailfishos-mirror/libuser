#include <libuser/user_private.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ldap.h>
#include "util.h"

static gboolean
lu_ldap_user_lookup_name(struct lu_module *module, gconstpointer name,
			 struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_user_lookup_id(struct lu_module *module, gconstpointer uid,
		       struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_group_lookup_name(struct lu_module *module, gconstpointer name,
			  struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_group_lookup_id(struct lu_module *module, gconstpointer gid,
			struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_user_add(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_user_mod(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_user_del(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_user_lock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_user_unlock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_group_add(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_group_mod(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_group_del(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_group_lock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_group_unlock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_close_module(struct lu_module *module)
{
	g_return_val_if_fail(module != NULL, FALSE);

	module->scache->free(module->scache);
	memset(module, 0, sizeof(struct lu_module));
	g_free(module);

	return TRUE;
}

struct lu_module *
lu_ldap_init(struct lu_context *context)
{
	struct lu_module *ret = NULL;

	g_return_val_if_fail(context != NULL, NULL);

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, "ldap");

	/* Set the method pointers. */
	ret->user_lookup_name = lu_ldap_user_lookup_name;
        ret->user_lookup_id = lu_ldap_user_lookup_id;

	ret->user_add = lu_ldap_user_add;
	ret->user_mod = lu_ldap_user_mod;
	ret->user_del = lu_ldap_user_del;
	ret->user_lock = lu_ldap_user_lock;
	ret->user_unlock = lu_ldap_user_unlock;

        ret->group_lookup_name = lu_ldap_group_lookup_name;
        ret->group_lookup_id = lu_ldap_group_lookup_id;

	ret->group_add = lu_ldap_group_add;
	ret->group_mod = lu_ldap_group_mod;
	ret->group_del = lu_ldap_group_del;
	ret->group_lock = lu_ldap_group_lock;
	ret->group_unlock = lu_ldap_group_unlock;

	ret->close = lu_ldap_close_module;

	/* Done. */
	return ret;
}
