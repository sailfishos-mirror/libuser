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

/*
 * The interfaces defined in this file are in even more flux than the others,
 * because this is where the module interface is defined.  If you include it
 * in your code, bad things can happen.
 */

#ifndef libuser_user_private_h
#define libuser_user_private_h

#include <glib.h>
#include <gmodule.h>
#include "user.h"

#define LU_ENT_MAGIC 0x19d381c2
#define LU_MODULE_VERSION 0x00040000

#include <libintl.h>
#include <locale.h>
#define _(String) gettext(String)

/* A string cache structure.  Useful for side-stepping most issues with
 * whether or not returned strings should be freed. */
typedef struct lu_string_cache {
	GHashTable *table;
	char * (*cache)(struct lu_string_cache *, const char *);
	void (*free)(struct lu_string_cache *);
} lu_string_cache_t;

/** Create a new cache.
  * \param case_sensitive Whether or not case should factor into whether
  * strings in the cache should be considered equal if they differ only
  * in case.  TRUE means that we are case-sensitive when comparing.
  * \returns A new cache object.  Add strings to the cache using the
  * cache() method, and free it by passing its address to its free() method.
  */
struct lu_string_cache *lu_string_cache_new(gboolean case_sensitive);

/* An entity structure. */
struct lu_ent {
	u_int32_t magic;
	enum lu_type type;		/* User or group? */
	struct lu_string_cache *acache;	/* String cache for attribute names. */
	struct lu_string_cache *vcache;	/* String cache for attribute values. */
	GHashTable *original_attributes;/* GLists of the original values
					   associated with attribute names. */
	GHashTable *attributes;		/* GLists of values associated with
					   attribute names. */
	const char *source_info;	/* Name of the info module this user was
					   looked up in. */
	const char *source_auth;	/* Name of the auth module this user was
					   looked up in. */
};

/* What type of function a module serves. */
typedef enum lu_module_type {
	auth = 0xba1f,
	info = 0xdc32,
} lu_module_type_t;

/* A context structure. */
struct lu_context {
	struct lu_string_cache *scache;	/* A string cache. */
	char *auth_name;		/* Suggested client name to use when
					   connecting to servers, for
					   convenience purposes only. */
	enum lu_type auth_type;		/* Whether auth_name is a user or
					   group. */
	void *config;			/* Opaque config structure used by
					   the lu_cfg family of functions. */
	lu_prompt_fn *prompter;		/* Pointer to the prompter function. */
	gpointer prompter_data;		/* Application-specific data to be
					   passed to the prompter function. */
	GList *auth_module_names;	/* A list of loaded auth modules
					   names. */
	GList *info_module_names;	/* A list of loaded information module
					   names. */
	GHashTable *modules;		/* A hash table, keyed by module name,
					   of module structures. */
};

/* A module structure. */
typedef struct lu_module {
	u_int32_t version;		/* Should be LU_MODULE_VERSION. */
	GModule *module_handle;
	struct lu_string_cache *scache;	/* A string cache. */
	const char *name;		/* Name of the module. */
	struct lu_context *lu_context;	/* Context the module was opened in. */
	void *module_context;		/* Module-private data. */

	/* Functions for looking up users and groups by name or ID. */
	gboolean (*user_lookup_name)(struct lu_module *module,
				     gconstpointer name,
				     struct lu_ent *ent,
				     struct lu_error **error);
	gboolean (*group_lookup_name)(struct lu_module *module,
				      gconstpointer name,
				      struct lu_ent *ent,
				      struct lu_error **error);
	gboolean (*user_lookup_id)(struct lu_module *module,
				   gconstpointer uid,
				   struct lu_ent *ent,
				   struct lu_error **error);
	gboolean (*group_lookup_id)(struct lu_module *module,
				    gconstpointer gid,
				    struct lu_ent *ent,
				    struct lu_error **error);

	/* Apply attributes in the ent structure to the user named by
	 * the structure's LU_USERNAME attribute. */
	gboolean (*user_add)(struct lu_module *module, struct lu_ent *ent,
			     struct lu_error **error);
	gboolean (*user_mod)(struct lu_module *module, struct lu_ent *ent,
			     struct lu_error **error);
	gboolean (*user_del)(struct lu_module *module, struct lu_ent *ent,
			     struct lu_error **error);

	/* Lock, unlock, or set the password on the account of the user
	 * named by the structure's LU_USERNAME attribute. */
	gboolean (*user_lock)(struct lu_module *module, struct lu_ent *ent,
			      struct lu_error **error);
	gboolean (*user_unlock)(struct lu_module *module, struct lu_ent *ent,
				struct lu_error **error);
	gboolean (*user_islocked)(struct lu_module *module, struct lu_ent *ent,
				  struct lu_error **error);
	gboolean (*user_setpass)(struct lu_module *module, struct lu_ent *ent,
				 const char *newpass,
				 struct lu_error **error);

	/* Apply attributes in the ent structure to the group named by
	 * the structure's LU_GROUPNAME attribute. */
	gboolean (*group_add)(struct lu_module *module, struct lu_ent *ent,
			      struct lu_error **error);
	gboolean (*group_mod)(struct lu_module *module, struct lu_ent *ent,
			      struct lu_error **error);
	gboolean (*group_del)(struct lu_module *module, struct lu_ent *ent,
			      struct lu_error **error);

	/* Lock, unlock, or set the password on the record for the group
	 * named by the structure's LU_GROUPNAME attribute. */
	gboolean (*group_lock)(struct lu_module *module, struct lu_ent *ent,
			       struct lu_error **error);
	gboolean (*group_unlock)(struct lu_module *module, struct lu_ent *ent,
				 struct lu_error **error);
	gboolean (*group_islocked)(struct lu_module *module, struct lu_ent *ent,
				   struct lu_error **error);
	gboolean (*group_setpass)(struct lu_module *module, struct lu_ent *ent,
				  const char *newpass,
				  struct lu_error **error);

	/* Search for users or groups. */
	GList *(*users_enumerate)(struct lu_module *module,
				  const char *pattern,
				  struct lu_error **error);
	GList *(*groups_enumerate)(struct lu_module *module,
				   const char *pattern,
				   struct lu_error **error);

	/* Clean up any data this module has, and unload it. */
	gboolean (*close)(struct lu_module *module);
} lu_module_t;

/* The type of the initialization function a module exports for the library
 * to use when initializing it.  Should fit "lu_%s_init", where the string
 * is the name of the module being loaded (and this should match the "name"
 * attribute of the module structure. */
typedef struct lu_module * (*lu_module_init_t)(struct lu_context *context,
					       struct lu_error **error);

gboolean lu_cfg_init(struct lu_context *context, struct lu_error **error);
void lu_cfg_done(struct lu_context *context);

void lu_ent_set_source_info(struct lu_ent *ent, const char *source);
void lu_ent_set_source_auth(struct lu_ent *ent, const char *source);

GList *lu_g_list_copy(GList *list);

gint lu_str_equal(gconstpointer v1, gconstpointer v2);
gint lu_str_case_equal(gconstpointer v1, gconstpointer v2);

guint lu_strv_len(gchar **v);

const char *lu_make_crypted(const char *plain, const char *previous);

gpointer lu_util_lock_obtain(int fd, struct lu_error **error);
void lu_util_lock_free(int fd, gpointer lock);

char *lu_util_line_get_matching1(int fd, const char *firstpart,
				 struct lu_error **error);
char *lu_util_line_get_matching3(int fd, const char *thirdpart,
				 struct lu_error **error);
char *lu_util_line_get_matchingx(int fd, const char *part, int field,
				 struct lu_error **error);
char *lu_util_field_read(int fd, const char *first, unsigned int field,
			 struct lu_error **error);
gboolean lu_util_field_write(int fd, const char *first,
	                     unsigned int field, const char *value,
			     struct lu_error **error);

#endif
