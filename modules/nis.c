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

#include <libuser/user_private.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "util.h"

static gboolean
lu_nis_user_lookup_name(struct lu_module *module, gconstpointer name,
			struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_nis_user_lookup_id(struct lu_module *module, gconstpointer uid,
		      struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_nis_group_lookup_name(struct lu_module *module, gconstpointer name,
			 struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_nis_group_lookup_id(struct lu_module *module, gconstpointer gid,
		       struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_nis_user_add(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_nis_user_mod(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_nis_user_del(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_nis_user_lock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_nis_user_unlock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_nis_group_add(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_nis_group_mod(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_nis_group_del(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_nis_group_lock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_nis_group_unlock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_nis_close_module(struct lu_module *module)
{
	g_return_val_if_fail(module != NULL, FALSE);

	module->scache->free(module->scache);
	memset(module, 0, sizeof(struct lu_module));
	g_free(module);

	return TRUE;
}

struct lu_module *
lu_nis_init(struct lu_context *context)
{
	struct lu_module *ret = NULL;

	g_return_val_if_fail(context != NULL, NULL);

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, "nis");

	/* Set the method pointers. */
	ret->user_lookup_name = lu_nis_user_lookup_name;
        ret->user_lookup_id = lu_nis_user_lookup_id;

	ret->user_add = lu_nis_user_add;
	ret->user_mod = lu_nis_user_mod;
	ret->user_del = lu_nis_user_del;
	ret->user_lock = lu_nis_user_lock;
	ret->user_unlock = lu_nis_user_unlock;

        ret->group_lookup_name = lu_nis_group_lookup_name;
        ret->group_lookup_id = lu_nis_group_lookup_id;

	ret->group_add = lu_nis_group_add;
	ret->group_mod = lu_nis_group_mod;
	ret->group_del = lu_nis_group_del;
	ret->group_lock = lu_nis_group_lock;
	ret->group_unlock = lu_nis_group_unlock;

	ret->close = lu_nis_close_module;

	/* Done. */
	return ret;
}
