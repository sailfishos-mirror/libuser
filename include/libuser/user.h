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

#ifndef libuser_user_h
#define libuser_user_h

#ifdef __cplusplus
extern "C" {
#endif

/** @file user.h */

#include <sys/types.h>
#include <glib.h>
#include "config.h"
#include "entity.h"
#include "error.h"
#include "prompt.h"

/**
 * An lu_context_t holds configuration information for this instance of
 * the library.
 */
typedef struct lu_context lu_context_t;

/**
 * An enumeration which decides whether we want to modify information about
 * users or groups.  We don't yet support both simultaneously.
 */
typedef enum lu_type {lu_user = 0x2345, lu_group = 0x2346} lu_type_t;

/**
 * Initializes the library, loads modules, and authenticates to servers.
 * @param authname The default name to use when authenticating to servers.
 * @param auth_type The type of records we intend to modify -- user or group.
 * @param info_modules An optional comma-separated list of information modules
 * to load.  Information modules are used to modify user information such as
 * Uids, home directories, shells, and so on.
 * @param auth_modules An optional comma-separated list of authentication
 * modules to load.  Auth information is focused on the data used to
 * authenticate a user, to the exclusion of everything else.
 * @param prompter The address of a prompter function.
 * @param callback_data The address of data to be passed to the prompter
 * whenever it is called.
 * @param error An address where a pointer to an error information structure
 * will be stored in case of failure.
 * @return A valid context on successful initialization.
 * @return NULL on failure.
 */
struct lu_context *lu_start(const char *authname, enum lu_type auth_type,
			    const char *info_modules, const char *auth_modules,
			    lu_prompt_fn *prompter, gpointer callback_data,
			    struct lu_error **error);

/**
 * Modifies the list of info modules to be consulted when looking up users
 * and groups, and to be written to when storing information about new users
 * and groups.
 * @param context A library context.
 * @param prompter The address of a suitable prompting function.
 * @return Nothing.
 */
void lu_set_prompter(struct lu_context *context, lu_prompt_fn *prompter,
		     gpointer callback_data);

/**
 * Modifies the list of info modules to be consulted when looking up users
 * and groups, and to be written to when storing information about new users
 * and groups.
 * @param context A library context.
 * @param list A comma-separated list of information modules to use.
 * @return TRUE on success, FALSE on failure.
 */
gboolean lu_set_info_modules(struct lu_context *context, const char *list,
			     struct lu_error **error);
const char *lu_get_info_modules(struct lu_context *context);

/**
 * Modifies the list of auth modules to be consulted when looking up users
 * and groups, and to be written to when storing information about new users
 * and groups.
 * @param context A library context.
 * @param list A comma-separated list of authentication modules to use.
 * @return Nothing.
 */
gboolean lu_set_auth_modules(struct lu_context *context, const char *list,
			     struct lu_error **error);
const char *lu_get_auth_modules(struct lu_context *context);

/**
 * Shuts down the library, releasing memory and closing connections.
 * @param context A library context.
 * @return Nothing.
 */
void lu_end(struct lu_context *context);

/**
 * Fill an entity structure with information suitable for creating an account
 * for name.  If the user is a system account, the initial uid will be chosen
 * from a different range than the one used for non-system accounts.
 * @param ctx A valid library context.
 * @param name The login ID of the new user.
 * @param system A boolean specifying if the account is a system account.
 * @param ent The entity structure to fill the defaults into.
 * @return Nothing.
 */
void lu_user_default(struct lu_context *ctx, const char *name,
		     gboolean system, struct lu_ent *ent);

/**
 * Fill an entity structure with information suitable for creating a group with
 * the given name.
 * @param ctx A valid library context.
 * @param name The name of the new group.
 * @param system A boolean specifying if the group goes with a system account.
 * @param ent The entity structure to fill the defaults into.
 * @return Nothing.
 */
void lu_group_default(struct lu_context *ctx, const char *name,
		      gboolean system, struct lu_ent *ent);

/**
 * Look up a user by name.
 * @param context A valid library context.
 * @param name The name of the user to be searched for.
 * @param ent An entity structure to be populated with the user's data.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_lookup_name(struct lu_context *context, const char *name,
			     struct lu_ent *ent, struct lu_error **error);

/**
 * Look up a group by name.
 * @param context A valid library context.
 * @param name The name of the group to be searched for.
 * @param ent An entity structure to be populated with the group's data.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_lookup_name(struct lu_context *context, const char *name,
			      struct lu_ent *ent, struct lu_error **error);
/**
 * Look up a user by ID.
 * @param context A valid library context.
 * @param gid The user ID for the user to be searched for.
 * @param ent An entity structure to be populated with the user's data.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_lookup_id(struct lu_context *context, uid_t uid,
			   struct lu_ent *ent, struct lu_error **error);
/**
 * Look up a group by ID.
 * @param context A valid library context.
 * @param gid The group ID for the group to be searched for.
 * @param ent An entity structure to be populated with the group's data.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_lookup_id(struct lu_context *context, gid_t gid,
			    struct lu_ent *ent, struct lu_error **error);
/**
 * Add a new user to the system.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the user.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_add(struct lu_context *context, struct lu_ent *ent,
		     struct lu_error **error);

/**
 * Add a new group to the system.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the group.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_add(struct lu_context *context, struct lu_ent *ent,
		      struct lu_error **error);

/**
 * Modify the specified user, so that the stored data matches the structure
 * as closely as possible.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the user.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_modify(struct lu_context *context, struct lu_ent *ent,
		        struct lu_error **error);

/**
 * Modify the specified group, so that the stored data matches the structure
 * as closely as possible.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the group.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_modify(struct lu_context *context, struct lu_ent *ent,
		         struct lu_error **error);

/**
 * Delete the specified user from the system database.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the user to
 * be removed.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_delete(struct lu_context *context, struct lu_ent *ent,
		        struct lu_error **error);

/**
 * Delete the specified group from the system database.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the group to
 * be removed.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_delete(struct lu_context *context, struct lu_ent *ent,
		         struct lu_error **error);

/**
 * Lock the specified user account.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the user whose
 * account should be locked
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_lock(struct lu_context *context, struct lu_ent *ent,
		      struct lu_error **error);

/**
 * Lock the specified group.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the group whose
 * access should be locked
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_lock(struct lu_context *context, struct lu_ent *ent,
		       struct lu_error **error);

/**
 * Unlock the specified user's account.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the user whose
 * account should be unlocked.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_unlock(struct lu_context *context, struct lu_ent *ent,
		        struct lu_error **error);

/**
 * Unlock the specified group.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the group whose
 * access should be unlocked
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_unlock(struct lu_context *context, struct lu_ent *ent,
		         struct lu_error **error);

/**
 * Set the password on the specified user's account.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the user whose
 * password should be changed.
 * @param newpass The new password for the user.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_setpass(struct lu_context *context, struct lu_ent *ent,
			 const char *newpass, struct lu_error **error);

/**
 * Set the password on the specified group's account.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the group whose
 * password should be changed.
 * @param newpass The new password for the group.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_setpass(struct lu_context *context, struct lu_ent *ent,
			  const char *newpass, struct lu_error **error);

/**
 * Get a list of all of the users matching the given patterm from the
 * given module.
 * @param context A valid library context.
 * @param pattern A pattern to match users against.
 * @param module The name of a module to search in.
 * @return If the named monule is not loaded, then an empty list is returned.  
 * If the name is NULL, all loaded modules are queried and the union of their
 * results is returned to the application.
 */
GList *lu_users_enumerate(struct lu_context *context, const char *pattern,
			  const char *module, struct lu_error **error);

/**
 * Get a list of all of the groups matching the given patterm from the
 * given module.
 * @param context A valid library context.
 * @param pattern A pattern to match users against.
 * @param module The name of a module to search in.
 * @return If the named monule is not loaded, then an empty list is returned.  
 * If the name is NULL, all loaded modules are queried and the union of their
 * results is returned to the application.
 */
GList *lu_groups_enumerate(struct lu_context *context, const char *pattern,
			   const char *module, struct lu_error **error);


#ifdef __cplusplus
};
#endif

#endif
