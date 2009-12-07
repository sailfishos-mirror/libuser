/*
 * Copyright (C) 2000-2002, 2008 Red Hat, Inc.
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

#include <glib.h>
#include <string.h>

#include "user_private.h"

/* An internal attribute used only in lu_common_user_default() and
   lu_common_user_add_check() */
#define LU_INVALID_HOMEDIRECTORY "__pw_dir_invalid!*/\\:"

/* Populate the fields of a user structure with non-name, non-ID data. */
gboolean
lu_common_user_default(struct lu_module *module,
		       const char *name, gboolean is_system,
		       struct lu_ent *ent, struct lu_error **error)
{
	GValue value;

	(void)module;
	(void)is_system;
	(void)error;
	g_return_val_if_fail(name != NULL, FALSE);
	memset(&value, 0, sizeof(value));
	if (lu_ent_get(ent, LU_USERPASSWORD) == NULL) {
		g_value_init(&value, G_TYPE_STRING);
		g_value_set_string(&value, LU_COMMON_DEFAULT_PASSWORD);
		lu_ent_add(ent, LU_USERPASSWORD, &value);
		g_value_unset(&value);
	}
	if (lu_ent_get(ent, LU_SHADOWPASSWORD) == NULL) {
		g_value_init(&value, G_TYPE_STRING);
		g_value_set_string(&value, LU_COMMON_DEFAULT_PASSWORD);
		lu_ent_add(ent, LU_SHADOWPASSWORD, &value);
		g_value_unset(&value);
	}
	if (lu_ent_get(ent, LU_GECOS) == NULL) {
		g_value_init(&value, G_TYPE_STRING);
		g_value_set_string(&value, name);
		lu_ent_add(ent, LU_GECOS, &value);
		g_value_unset(&value);
	}
	if (lu_ent_get(ent, LU_HOMEDIRECTORY) == NULL) {
		if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
			g_value_init(&value, G_TYPE_LONG);
			g_value_set_long(&value, 1);
			lu_ent_add(ent, LU_INVALID_HOMEDIRECTORY, &value);
			g_value_unset(&value);
			/* Don't set the default home directory, so that
			   lu_common_user_add_check() can recognize and
			   explicitly set home directory that ends with "." or
			   "..". */
		} else {
			char *tmp;

			g_value_init(&value, G_TYPE_STRING);
			tmp = g_strdup_printf("/home/%s", name);
			g_value_set_string(&value, tmp);
			g_free(tmp);
			lu_ent_add(ent, LU_HOMEDIRECTORY, &value);
			g_value_unset(&value);
		}
	}
	if (lu_ent_get(ent, LU_LOGINSHELL) == NULL) {
		g_value_init(&value, G_TYPE_STRING);
		g_value_set_string(&value, LU_COMMON_DEFAULT_SHELL);
		lu_ent_add(ent, LU_LOGINSHELL, &value);
		g_value_unset(&value);
	}
	return TRUE;
}

/* If a module calls lu_common_user_default, it must call the following
   function in user_add(). */
gboolean
lu_common_user_add_check(struct lu_module *module, struct lu_ent *ent,
			 struct lu_error **error)
{
	(void)module;
	if (lu_ent_get(ent, LU_INVALID_HOMEDIRECTORY) != NULL) {
		if (lu_ent_get(ent, LU_HOMEDIRECTORY) == NULL) {
			lu_error_new(error, lu_error_name_bad,
				     _("refusing to use dangerous home "
				       "directory by default"));
			return FALSE;
		}
		/* LU_INVALID_HOMEDIRECTORY is purely internal to this file,
		   make sure it won't get saved anywhere. */
		lu_ent_clear(ent, LU_INVALID_HOMEDIRECTORY);
	}
	return TRUE;
}

/* Populate the fields of a group structure with non-name, non-ID data. */
gboolean
lu_common_group_default(struct lu_module *module,
		        const char *name, gboolean is_system,
		        struct lu_ent *ent, struct lu_error **error)
{
	(void)module;
	(void)is_system;
	(void)error;
	g_return_val_if_fail(name != NULL, FALSE);
	if (lu_ent_get(ent, LU_SHADOWPASSWORD) == NULL) {
		GValue value;

		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_STRING);
		g_value_set_string(&value, LU_COMMON_DEFAULT_PASSWORD);
		lu_ent_add(ent, LU_SHADOWPASSWORD, &value);
		g_value_unset(&value);
	}
	return TRUE;
}

/* Populate the fields of a user structure with non-name, non-ID data. */
gboolean
lu_common_suser_default(struct lu_module *module,
		        const char *name, gboolean is_system,
		        struct lu_ent *ent, struct lu_error **error)
{
	GValue value;

	(void)module;
	(void)is_system;
	(void)error;
	g_return_val_if_fail(name != NULL, FALSE);
	memset(&value, 0, sizeof(value));
	if (lu_ent_get(ent, LU_SHADOWPASSWORD) == NULL) {
		g_value_init(&value, G_TYPE_STRING);
		g_value_set_string(&value, LU_COMMON_DEFAULT_PASSWORD);
		lu_ent_add(ent, LU_SHADOWPASSWORD, &value);
		g_value_unset(&value);
	}
	if (lu_ent_get(ent, LU_SHADOWLASTCHANGE) == NULL)
		lu_util_update_shadow_last_change(ent);
	if (lu_ent_get(ent, LU_SHADOWMIN) == NULL) {
		g_value_init(&value, G_TYPE_LONG);
		g_value_set_long(&value, 0);
		lu_ent_add(ent, LU_SHADOWMIN, &value);
		g_value_unset(&value);
	}
	if (lu_ent_get(ent, LU_SHADOWMAX) == NULL) {
		g_value_init(&value, G_TYPE_LONG);
		g_value_set_long(&value, 99999);
		lu_ent_add(ent, LU_SHADOWMAX, &value);
		g_value_unset(&value);
	}
	if (lu_ent_get(ent, LU_SHADOWWARNING) == NULL) {
		g_value_init(&value, G_TYPE_LONG);
		g_value_set_long(&value, 7);
		lu_ent_add(ent, LU_SHADOWWARNING, &value);
		g_value_unset(&value);
	}
	if (lu_ent_get(ent, LU_SHADOWINACTIVE) == NULL) {
		g_value_init(&value, G_TYPE_LONG);
		g_value_set_long(&value, -1);
		lu_ent_add(ent, LU_SHADOWINACTIVE, &value);
		g_value_unset(&value);
	}
	if (lu_ent_get(ent, LU_SHADOWEXPIRE) == NULL) {
		g_value_init(&value, G_TYPE_LONG);
		g_value_set_long(&value, -1);
		lu_ent_add(ent, LU_SHADOWEXPIRE, &value);
		g_value_unset(&value);
	}
	if (lu_ent_get(ent, LU_SHADOWFLAG) == NULL) {
		g_value_init(&value, G_TYPE_LONG);
		g_value_set_long(&value, -1);
		lu_ent_add(ent, LU_SHADOWFLAG, &value);
		g_value_unset(&value);
	}
	return TRUE;
}

gboolean
lu_common_sgroup_default(struct lu_module *module,
		         const char *name, gboolean is_system,
		         struct lu_ent *ent, struct lu_error **error)
{
	g_return_val_if_fail(name != NULL, FALSE);
	return lu_common_group_default(module, name, is_system, ent, error);
}
