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

#ifndef libuser_h
#define libuser_h

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <glib.h>

#define LU_OBJECTCLASS "objectClass"
#define LU_USERNAME "uid"
#define LU_GROUPNAME "cn"

#define LU_CN "cn"
#define LU_UID "uid"
#define LU_USERPASSWORD "userPassword"
#define LU_UIDNUMBER "uidNumber"
#define LU_GIDNUMBER "gidNumber"
#define LU_GECOS "gecos"
#define LU_HOMEDIRECTORY "homeDirectory"
#define LU_LOGINSHELL "loginShell"

#define LU_GID "gid"
#define LU_MEMBERUID "memberUid"

#define LU_SHADOWLASTCHANGE "shadowLastChange"
#define LU_SHADOWMIN "shadowMin"
#define LU_SHADOWMAX "shadowMax"
#define LU_SHADOWWARNING "shadowWarning"
#define LU_SHADOWINACTIVE "shadowInactive"
#define LU_SHADOWEXPIRE "shadowExpire"
#define LU_SHADOWFLAG "shadowFlag"

#define LU_ADMINISTRATORUID "administratorUid"

struct lu_context;
struct lu_ent;

struct lu_prompt {
	const char *prompt;
	gboolean visible;
	const char *default_value;
	char *value;
	void(*free_value)(char *);
};

typedef gboolean (lu_prompt_fn) (struct lu_context *context,
				 struct lu_prompt *prompts,
				 int count,
				 gpointer callback_data);

gboolean lu_prompt_console(struct lu_context *context,
			   struct lu_prompt *prompts,
			   int count, gpointer callback_data);
gboolean lu_prompt_console_quiet(struct lu_context *context,
				 struct lu_prompt *prompts,
				 int count, gpointer callback_data);

enum lu_type {lu_user, lu_group};

struct lu_context *lu_start(const char *authname, enum lu_type auth_type,
			    const char *info_modules, const char *auth_modules,
			    lu_prompt_fn *prompter, gpointer callback_data);
void lu_set_info_modules(struct lu_context *context, const char *list);
void lu_set_auth_modules(struct lu_context *context, const char *list);
void lu_end(struct lu_context *context);

struct lu_ent *lu_ent_new();
void lu_ent_copy(struct lu_ent *source, struct lu_ent *dest);
void lu_ent_revert(struct lu_ent *ent);
void lu_ent_free(struct lu_ent *ent);

void lu_ent_user_default(struct lu_context *ctx, const char *name,
			 gboolean system, struct lu_ent *ent);
void lu_ent_group_default(struct lu_context *ctx, const char *name,
			  gboolean system, struct lu_ent *ent);
GList *lu_ent_get_attributes(struct lu_ent *ent);
GList *lu_ent_get(struct lu_ent *ent, const char *attribute);
GList *lu_ent_get_original(struct lu_ent *ent, const char *attribute);
gboolean lu_ent_set(struct lu_ent *ent, const char *attr, const char *val);
gboolean lu_ent_set_original(struct lu_ent *ent, const char *attr,
			     const char *val);
gboolean lu_ent_add(struct lu_ent *ent, const char *attr, const char *val);
gboolean lu_ent_add_original(struct lu_ent *ent, const char *attr,
			     const char *val);
gboolean lu_ent_del(struct lu_ent *ent, const char *attr, const char *val);
gboolean lu_ent_clear(struct lu_ent *ent, const char *attr);
gboolean lu_ent_clear_original(struct lu_ent *ent, const char *attr);

gboolean lu_user_lookup_name(struct lu_context *context, const char *name,
			     struct lu_ent *ent);
gboolean lu_group_lookup_name(struct lu_context *context, const char *name,
			      struct lu_ent *ent);
gboolean lu_user_lookup_id(struct lu_context *context, uid_t uid,
			   struct lu_ent *ent);
gboolean lu_group_lookup_id(struct lu_context *context, gid_t gid,
			    struct lu_ent *ent);
gboolean lu_user_add(struct lu_context *context, struct lu_ent *ent);
gboolean lu_group_add(struct lu_context *context, struct lu_ent *ent);
gboolean lu_user_modify(struct lu_context *context, struct lu_ent *ent);
gboolean lu_group_modify(struct lu_context *context, struct lu_ent *ent);
gboolean lu_user_delete(struct lu_context *context, struct lu_ent *ent);
gboolean lu_group_delete(struct lu_context *context, struct lu_ent *ent);
gboolean lu_user_lock(struct lu_context *context, struct lu_ent *ent);
gboolean lu_group_lock(struct lu_context *context, struct lu_ent *ent);
gboolean lu_user_unlock(struct lu_context *context, struct lu_ent *ent);
gboolean lu_group_unlock(struct lu_context *context, struct lu_ent *ent);

/* Read the value of a key in the configuration file.  Multiple values
 * are handled by making them different entries in the GList. */
GList *lu_cfg_read(struct lu_context *context,
		   const char *key, const char *default_value);
const char *lu_cfg_read_single(struct lu_context *context,
			       const char *key, const char *default_value);
/* Read the list of keys in a section of the file. */
GList *lu_cfg_read_keys(struct lu_context *context, const char *parent_key);

#ifdef __cplusplus
};
#endif

#endif
