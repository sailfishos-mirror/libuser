/*
 * Copyright (C) 2000-2002 Red Hat, Inc.
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
#include "config.h"
#endif
#include <sasl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/user_private.h"

static gboolean
lu_sasldb_uses_elevated_privileges(struct lu_module *module)
{
	/* FIXME: actually check the permissions on the sasldb. */
	return TRUE;
}

static gboolean
lu_sasldb_user_lookup_name(struct lu_module *module, const char *name,
			   struct lu_ent *ent, struct lu_error **error)
{
	int i = SASL_NOUSER;
	const char *err;

#ifdef HAVE_SASL_USER_EXISTS
	i = sasl_user_exists(NULL, NULL, name);
	g_assert((i == SASL_OK) ||
		 (i == SASL_DISABLED) ||
		 (i == SASL_NOUSER) ||
		 (i == SASL_NOMECH));
#else
	i = sasl_checkpass((sasl_conn_t *) module->module_context, name,
			   strlen(name), "", 0, &err);
	g_assert((i == SASL_OK) ||
		 (i == SASL_NOUSER) ||
		 (i == SASL_NOMECH));
#endif

	return (i == SASL_OK) ||
	       (i == SASL_DISABLED) ||
	       (i == SASL_NOMECH);
}

static gboolean
lu_sasldb_user_lookup_id(struct lu_module *module, uid_t uid,
			 struct lu_ent *ent, struct lu_error **error)
{
	return FALSE;
}

static gboolean
lu_sasldb_group_lookup_name(struct lu_module *module, const char *name,
			    struct lu_ent *ent, struct lu_error **error)
{
	return FALSE;
}

static gboolean
lu_sasldb_group_lookup_id(struct lu_module *module, gid_t gid,
			  struct lu_ent *ent, struct lu_error **error)
{
	return FALSE;
}

static gboolean
lu_sasldb_user_munge(struct lu_module *module, struct lu_ent *ent,
		     int flags, const char *password,
		     struct lu_error **error)
{
	int i, ret;
	sasl_conn_t *connection = NULL;
	GValueArray *values = NULL;
	GValue *value;
	char *tmp;
	const char *err = NULL;

	g_assert(module != NULL);
	LU_ERROR_CHECK(error);

	connection = module->module_context;

	values = lu_ent_get(ent, LU_USERNAME);
	for (i = 0; (values != NULL) && (i < values->n_values); i++) {
		value = g_value_array_get_nth(values, i);
		if (G_VALUE_HOLDS_STRING(value)) {
			tmp = g_value_dup_string(value);
		} else
		if (G_VALUE_HOLDS_LONG(value)) {
			tmp = g_strdup_printf("%ld", g_value_get_long(value));
		} else {
			g_assert_not_reached();
		}
		ret = sasl_setpass(connection, tmp, password, 0, flags, &err);
		g_free(tmp);
		g_assert((i == SASL_OK) ||
			 (i == SASL_NOCHANGE) ||
			 (i == SASL_NOMECH) ||
			 (i == SASL_DISABLED) ||
			 (i == SASL_PWLOCK) ||
			 (i == SASL_FAIL) ||
			 (i == SASL_BADPARAM));

		if (i == SASL_OK) {
			return TRUE;
		} else {
			if (password) {
				lu_error_new(error, lu_error_generic,
					     err ?
					     _("Cyrus SASL error creating user: %s: %s")
					     :
					     _("Cyrus SASL error creating user: %s"),
					     sasl_errstring(i, NULL, NULL),
					     err);
			} else {
				lu_error_new(error, lu_error_generic,
					     err ?
					     _("Cyrus SASL error removing user: %s: %s")
					     :
					     _("Cyrus SASL error removing user: %s"),
					     sasl_errstring(i, NULL, NULL),
					     err);
			}
			return FALSE;
		}
	}

	fprintf(stderr, "Error reading user name in %s at %d.\n", __FILE__,
		__LINE__);
	return FALSE;
}

static gboolean
lu_sasldb_user_default(struct lu_module *module,
		       const char *name, gboolean is_system,
		       struct lu_ent *ent,
		       struct lu_error **error)
{
	return !is_system;
}

static gboolean
lu_sasldb_user_add_prep(struct lu_module *module, struct lu_ent *ent,
			struct lu_error **error)
{
	return TRUE;
}

static gboolean
lu_sasldb_user_add(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	if (lu_sasldb_user_munge
	    (module, ent, SASL_SET_CREATE, PACKAGE, error)) {
		/* account created */
		if (lu_sasldb_user_munge(module, ent, SASL_SET_DISABLE,
					 PACKAGE, error) == TRUE) {
			/* account created and locked */
		} else {
			/* account created and couldn't be locked -- delete it */
			lu_sasldb_user_munge(module, ent, 0, NULL, error);
			return FALSE;
		}
	} else {
		/* account not created */
		return FALSE;
	}
	return FALSE;
}

static gboolean
lu_sasldb_user_mod(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	/* Nod our heads and smile. */
	return TRUE;
}

static gboolean
lu_sasldb_user_del(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	/* setting a NULL password removes the user */
	return lu_sasldb_user_munge(module, ent, 0, NULL, error);
}

static gboolean
lu_sasldb_user_lock(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	/* setting the disable flag locks the account, and setting a password unlocks it */
	return lu_sasldb_user_munge(module, ent, SASL_SET_DISABLE, "",
				    error);
}

static gboolean
lu_sasldb_user_unlock(struct lu_module *module, struct lu_ent *ent,
		      struct lu_error **error)
{
	return FALSE;
}

static gboolean
lu_sasldb_user_is_locked(struct lu_module *module, struct lu_ent *ent,
			struct lu_error **error)
{
	int i = SASL_NOUSER;
	GValueArray *values;
	GValue *value;
	char *name = NULL;
	const char *err = NULL;

	values = lu_ent_get(ent, LU_USERNAME);
	value = g_value_array_get_nth(values, 0);
	if (G_VALUE_HOLDS_STRING(value)) {
		name = g_value_dup_string(value);
	} else
	if (G_VALUE_HOLDS_LONG(value)) {
		name = g_strdup_printf("%ld", g_value_get_long(value));
	} else {
		g_assert_not_reached();
	}
#ifdef HAVE_SASL_USER_EXISTS
	i = sasl_user_exists(NULL, NULL, name);
	g_assert((i == SASL_OK) ||
		 (i == SASL_DISABLED) ||
		 (i == SASL_NOUSER) ||
		 (i == SASL_NOMECH));
#else
	i = sasl_checkpass((sasl_conn_t *) module->module_context, name,
			   strlen(name), "", 0, &err);
	g_assert((i == SASL_OK) || (i == SASL_NOUSER)
		 || (i == SASL_NOMECH));
#endif

	g_free(name);

	return (i == SASL_DISABLED);
}

static gboolean
lu_sasldb_user_setpass(struct lu_module *module, struct lu_ent *ent,
		       const char *password, struct lu_error **error)
{
	return lu_sasldb_user_munge(module, ent, 0, password, error);
}

static gboolean
lu_sasldb_group_default(struct lu_module *module,
			const char *name, gboolean is_system,
			struct lu_ent *ent,
			struct lu_error **error)
{
	return FALSE;
}

static gboolean
lu_sasldb_group_add_prep(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	return TRUE;
}

static gboolean
lu_sasldb_group_add(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	return FALSE;
}

static gboolean
lu_sasldb_group_mod(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	return FALSE;
}

static gboolean
lu_sasldb_group_del(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	return FALSE;
}

static gboolean
lu_sasldb_group_lock(struct lu_module *module, struct lu_ent *ent,
		     struct lu_error **error)
{
	return FALSE;
}

static gboolean
lu_sasldb_group_unlock(struct lu_module *module, struct lu_ent *ent,
		       struct lu_error **error)
{
	return FALSE;
}

static gboolean
lu_sasldb_group_is_locked(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	return FALSE;
}

static gboolean
lu_sasldb_group_setpass(struct lu_module *module, struct lu_ent *ent,
			const char *password, struct lu_error **error)
{
	return FALSE;
}

static GValueArray *
lu_sasldb_users_enumerate(struct lu_module *module, const char *pattern,
			  struct lu_error **error)
{
	return NULL;
}

static GPtrArray *
lu_sasldb_users_enumerate_full(struct lu_module *module, const char *pattern,
			       struct lu_error **error)
{
	return NULL;
}

static GValueArray *
lu_sasldb_groups_enumerate(struct lu_module *module, const char *pattern,
			   struct lu_error **error)
{
	return NULL;
}

static GPtrArray *
lu_sasldb_groups_enumerate_full(struct lu_module *module, const char *pattern,
				struct lu_error **error)
{
	return NULL;
}

static GValueArray *
lu_sasldb_users_enumerate_by_group(struct lu_module *module,
				   const char *group,
				   gid_t gid,
				   struct lu_error **error)
{
	return NULL;
}

static GPtrArray *
lu_sasldb_users_enumerate_by_group_full(struct lu_module *module,
					const char *group, gid_t gid,
					struct lu_error **error)
{
	return NULL;
}

static GValueArray *
lu_sasldb_groups_enumerate_by_user(struct lu_module *module,
				   const char *user,
				   uid_t uid,
				   struct lu_error **error)
{
	return NULL;
}

static GPtrArray *
lu_sasldb_groups_enumerate_by_user_full(struct lu_module *module,
					const char *user,
					uid_t uid,
					struct lu_error **error)
{
	return NULL;
}

static gboolean
lu_sasldb_close_module(struct lu_module *module)
{
	sasl_dispose((sasl_conn_t **) & module->module_context);
	sasl_done();
	g_free(module);
	return TRUE;
}

struct lu_module *
libuser_sasldb_init(struct lu_context *context, struct lu_error **error)
{
	struct lu_module *ret = NULL;
	const char *appname = NULL;
	const char *domain = NULL;
	sasl_conn_t *connection;
	struct sasl_callback cb = {
		SASL_CB_LIST_END,
		NULL,
		NULL,
	};
	int i;

	g_assert(context != NULL);
	LU_ERROR_CHECK(error);

	/* Read in configuration variables. */
	appname = lu_cfg_read_single(context, "sasl/appname", "");
	domain = lu_cfg_read_single(context, "sasl/domain", "");

	/* Initialize SASL. */
	i = sasl_server_init(&cb, appname);
	if (i != SASL_OK) {
		lu_error_new(error, lu_error_generic,
			     _("error initializing Cyrus SASL: %s"),
			     sasl_errstring(i, NULL, NULL));
		return NULL;
	}
	i = sasl_server_new(PACKAGE, NULL, domain, &cb,
			    SASL_SEC_NOANONYMOUS, &connection);
	if (i != SASL_OK) {
		lu_error_new(error, lu_error_generic,
			     _("error initializing Cyrus SASL: %s"),
			     sasl_errstring(i, NULL, NULL));
		return NULL;
	}

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, "sasl");
	ret->module_context = connection;

	/* Set the method pointers. */
	ret->uses_elevated_privileges = lu_sasldb_uses_elevated_privileges;

	ret->user_lookup_name = lu_sasldb_user_lookup_name;
	ret->user_lookup_id = lu_sasldb_user_lookup_id;

	ret->user_default = lu_sasldb_user_default;
	ret->user_add_prep = lu_sasldb_user_add_prep;
	ret->user_add = lu_sasldb_user_add;
	ret->user_mod = lu_sasldb_user_mod;
	ret->user_del = lu_sasldb_user_del;
	ret->user_lock = lu_sasldb_user_lock;
	ret->user_unlock = lu_sasldb_user_unlock;
	ret->user_is_locked = lu_sasldb_user_is_locked;
	ret->user_setpass = lu_sasldb_user_setpass;
	ret->users_enumerate = lu_sasldb_users_enumerate;
	ret->users_enumerate_by_group = lu_sasldb_users_enumerate_by_group;
	ret->users_enumerate_full = lu_sasldb_users_enumerate_full;
	ret->users_enumerate_by_group_full = lu_sasldb_users_enumerate_by_group_full;

	ret->group_lookup_name = lu_sasldb_group_lookup_name;
	ret->group_lookup_id = lu_sasldb_group_lookup_id;

	ret->group_default = lu_sasldb_group_default;
	ret->group_add_prep = lu_sasldb_group_add_prep;
	ret->group_add = lu_sasldb_group_add;
	ret->group_mod = lu_sasldb_group_mod;
	ret->group_del = lu_sasldb_group_del;
	ret->group_lock = lu_sasldb_group_lock;
	ret->group_unlock = lu_sasldb_group_unlock;
	ret->group_is_locked = lu_sasldb_group_is_locked;
	ret->group_setpass = lu_sasldb_group_setpass;
	ret->groups_enumerate = lu_sasldb_groups_enumerate;
	ret->groups_enumerate_by_user = lu_sasldb_groups_enumerate_by_user;
	ret->groups_enumerate_full = lu_sasldb_groups_enumerate_full;
	ret->groups_enumerate_by_user_full = lu_sasldb_groups_enumerate_by_user_full;

	ret->close = lu_sasldb_close_module;

	/* Done. */
	return ret;
}
