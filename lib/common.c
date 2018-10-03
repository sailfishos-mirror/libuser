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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "config.h"
#include <glib.h>
#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "user_private.h"

/* Populate the fields of a user structure with non-name, non-ID data. */
gboolean
lu_common_user_default(struct lu_module *module,
		       const char *name, gboolean is_system,
		       struct lu_ent *ent, struct lu_error **error)
{
	(void)module;
	(void)is_system;
	(void)error;
	g_return_val_if_fail(name != NULL, FALSE);
	if (lu_ent_get(ent, LU_USERPASSWORD) == NULL)
		lu_ent_set_string(ent, LU_USERPASSWORD,
				  LU_COMMON_DEFAULT_PASSWORD);
	if (lu_ent_get(ent, LU_SHADOWPASSWORD) == NULL)
		lu_ent_set_string(ent, LU_SHADOWPASSWORD,
				  LU_COMMON_DEFAULT_PASSWORD);
	if (lu_ent_get(ent, LU_GECOS) == NULL)
		lu_ent_set_string(ent, LU_GECOS, name);
	if (lu_ent_get(ent, LU_HOMEDIRECTORY) == NULL
	    && lu_ent_get(ent, LU_DUBIOUS_HOMEDIRECTORY) == NULL) {
		char *tmp;

		tmp = g_strdup_printf("/home/%s", name);
		if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
			lu_ent_set_string(ent, LU_DUBIOUS_HOMEDIRECTORY, tmp);
		else
			lu_ent_set_string(ent, LU_HOMEDIRECTORY, tmp);
		g_free(tmp);
	}
	if (lu_ent_get(ent, LU_LOGINSHELL) == NULL)
		lu_ent_set_string(ent, LU_LOGINSHELL, LU_COMMON_DEFAULT_SHELL);
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
	if (lu_ent_get(ent, LU_SHADOWPASSWORD) == NULL)
		lu_ent_set_string(ent, LU_SHADOWPASSWORD,
				  LU_COMMON_DEFAULT_PASSWORD);
	return TRUE;
}

/* Populate the fields of a user structure with non-name, non-ID data. */
gboolean
lu_common_suser_default(struct lu_module *module,
		        const char *name, gboolean is_system,
		        struct lu_ent *ent, struct lu_error **error)
{
	(void)module;
	(void)is_system;
	(void)error;
	g_return_val_if_fail(name != NULL, FALSE);
	if (lu_ent_get(ent, LU_SHADOWPASSWORD) == NULL)
		lu_ent_set_string(ent, LU_SHADOWPASSWORD,
				  LU_COMMON_DEFAULT_PASSWORD);
	if (lu_ent_get(ent, LU_SHADOWLASTCHANGE) == NULL)
		lu_util_update_shadow_last_change(ent);
	if (lu_ent_get(ent, LU_SHADOWMIN) == NULL)
		lu_ent_set_long(ent, LU_SHADOWMIN, 0);
	if (lu_ent_get(ent, LU_SHADOWMAX) == NULL)
		lu_ent_set_long(ent, LU_SHADOWMAX, 99999);
	if (lu_ent_get(ent, LU_SHADOWWARNING) == NULL)
		lu_ent_set_long(ent, LU_SHADOWWARNING, 7);
	if (lu_ent_get(ent, LU_SHADOWINACTIVE) == NULL)
		lu_ent_set_long(ent, LU_SHADOWINACTIVE, -1);
	if (lu_ent_get(ent, LU_SHADOWEXPIRE) == NULL)
		lu_ent_set_long(ent, LU_SHADOWEXPIRE, -1);
	if (lu_ent_get(ent, LU_SHADOWFLAG) == NULL)
		lu_ent_set_long(ent, LU_SHADOWFLAG, -1);
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

#ifdef WITH_AUDIT
static int audit_fd = 0;

/* result - 1 is "success" and 0 is "failed" */
void lu_audit_logger(int type, const char *op, const char *name,
                        unsigned int id, unsigned int result)
{
	if (audit_fd == 0) {
		/* First time through */
		audit_fd = audit_open();
		if (audit_fd < 0) {
			/* You get these only when the kernel doesn't have
			 * audit compiled in. */
			if (	   (errno == EINVAL)
				|| (errno == EPROTONOSUPPORT)
				|| (errno == EAFNOSUPPORT))
					return;
			fputs("Cannot open audit interface - aborting.\n", stderr);
			exit(EXIT_FAILURE);
		}
	}
	if (audit_fd < 0)
		return;
	audit_log_acct_message(audit_fd, type, NULL, op, name, id,
		NULL, NULL, NULL, (int) result);
}

/* result - 1 is "success" and 0 is "failed" */
void lu_audit_logger_with_group (int type, const char *op, const char *name,
		unsigned int id, const char *grp, unsigned int result)
{
	int len;
	char enc_group[(LOGIN_NAME_MAX*2)+1], buf[1024];

	if (audit_fd == 0) {
		/* First time through */
		audit_fd = audit_open();
		if (audit_fd < 0) {
			/* You get these only when the kernel doesn't have
			 * audit compiled in. */
			if (	   (errno == EINVAL)
				|| (errno == EPROTONOSUPPORT)
				|| (errno == EAFNOSUPPORT))
					return;
			fputs("Cannot open audit interface - aborting.\n", stderr);
			exit(EXIT_FAILURE);
		}
	}
	if (audit_fd < 0)
		return;
	len = strnlen(grp, sizeof(enc_group)/2);
	if (audit_value_needs_encoding(grp, len)) {
		snprintf(buf, sizeof(buf), "%s grp=%s", op,
			audit_encode_value(enc_group, grp, len));
	} else {
		snprintf(buf, sizeof(buf), "%s grp=\"%s\"", op, grp);
	}
	audit_log_acct_message(audit_fd, type, NULL, buf, name, id,
			NULL, NULL, NULL, (int) result);
}
#endif
