/*
 * Copyright (C) 2000,2001 Red Hat, Inc.
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

#ifndef libuser_user_h
#define libuser_user_h

#include <sys/types.h>
#include <glib.h>
#include "config.h"
#include "entity.h"
#include "error.h"
#include "prompt.h"

G_BEGIN_DECLS

/* An opaque structure manipulated by the library. */
struct lu_context;

/* An enumeration which decides whether we want to modify information about
 * users or groups.  We don't support both simultaneously.  */
enum lu_entity_type { lu_user, lu_group };

struct lu_context *lu_start(const char *authname,
			    enum lu_entity_type auth_type,
			    const char *modules, const char *create_modules,
			    lu_prompt_fn *prompter,
			    gpointer callback_data,
			    struct lu_error **error);
void lu_end(struct lu_context *context);

void lu_set_prompter(struct lu_context *context,
		     lu_prompt_fn *prompter, gpointer callback_data);
void lu_get_prompter(struct lu_context *context,
		     lu_prompt_fn ** prompter, gpointer *callback_data);

gboolean lu_set_modules(struct lu_context *context,
			const char *list, struct lu_error **error);
const char *lu_get_modules(struct lu_context *context);
gboolean lu_uses_elevated_privileges (struct lu_context *context);

gboolean lu_user_default(struct lu_context *ctx, const char *name,
			 gboolean system, struct lu_ent *ent);
gboolean lu_group_default(struct lu_context *ctx, const char *name,
			  gboolean system, struct lu_ent *ent);

gboolean lu_user_lookup_name(struct lu_context *context,
			     const char *name, struct lu_ent *ent,
			     struct lu_error **error);
gboolean lu_group_lookup_name(struct lu_context *context,
			      const char *name, struct lu_ent *ent,
			      struct lu_error **error);
gboolean lu_user_lookup_id(struct lu_context *context, uid_t uid,
			   struct lu_ent *ent, struct lu_error **error);
gboolean lu_group_lookup_id(struct lu_context *context, gid_t gid,
			    struct lu_ent *ent, struct lu_error **error);
gboolean lu_user_add(struct lu_context *context,
		     struct lu_ent *ent, struct lu_error **error);
gboolean lu_group_add(struct lu_context *context,
		      struct lu_ent *ent, struct lu_error **error);
gboolean lu_user_modify(struct lu_context *context,
			struct lu_ent *ent, struct lu_error **error);
gboolean lu_group_modify(struct lu_context *context,
			 struct lu_ent *ent, struct lu_error **error);
gboolean lu_user_delete(struct lu_context *context,
			struct lu_ent *ent, struct lu_error **error);
gboolean lu_group_delete(struct lu_context *context,
			 struct lu_ent *ent, struct lu_error **error);

gboolean lu_user_lock(struct lu_context *context,
		      struct lu_ent *ent, struct lu_error **error);
gboolean lu_group_lock(struct lu_context *context,
		       struct lu_ent *ent, struct lu_error **error);
gboolean lu_user_unlock(struct lu_context *context,
			struct lu_ent *ent, struct lu_error **error);
gboolean lu_group_unlock(struct lu_context *context,
			 struct lu_ent *ent, struct lu_error **error);

gboolean lu_user_islocked(struct lu_context *context,
			  struct lu_ent *ent, struct lu_error **error);
gboolean lu_group_islocked(struct lu_context *context,
			   struct lu_ent *ent, struct lu_error **error);

gboolean lu_user_setpass(struct lu_context *context,
			 struct lu_ent *ent, const char *newpass,
			 struct lu_error **error);
gboolean lu_group_setpass(struct lu_context *context,
			  struct lu_ent *ent, const char *newpass,
			  struct lu_error **error);

GValueArray *lu_users_enumerate(struct lu_context *context,
				const char *pattern,
				struct lu_error **error);
GValueArray *lu_groups_enumerate(struct lu_context *context,
				 const char *pattern,
				 struct lu_error **error);
GValueArray *lu_users_enumerate_by_group(struct lu_context *context,
					 const char *group,
					 struct lu_error **error);
GValueArray *lu_groups_enumerate_by_user(struct lu_context *context,
					 const char *user,
					 struct lu_error **error);

GPtrArray *lu_users_enumerate_full(struct lu_context *context,
			           const char *pattern,
			           struct lu_error **error);
GPtrArray *lu_groups_enumerate_full(struct lu_context *context,
			            const char *pattern,
			            struct lu_error **error);
GPtrArray *lu_users_enumerate_by_group_full(struct lu_context *context,
					    const char *group,
					    struct lu_error **error);
GPtrArray *lu_groups_enumerate_by_user_full(struct lu_context *context,
					    const char *user,
					    struct lu_error **error);

G_END_DECLS
#endif
