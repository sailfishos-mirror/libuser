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

/** Attributes carried by all entity structures. */
#define LU_OBJECTCLASS "objectClass"	/**< An object class.  Used primarily by the LDAP back-end. */
#define LU_CN "cn"			/**< The name of entity, regardless of whether it is a user or a group. */
#define LU_USERNAME "uid"		/**< The attribute which normally holds the login ID associated with a user account. */
#define LU_GROUPNAME "cn"		/**< The attribute which normally holds
the group name for a group entity. */

/** Attributes carried by user structures. */
#define LU_UID "uid"			/**< The login name of this user. */
#define LU_USERPASSWORD "userPassword"	/**< The user or group's password. */
#define LU_UIDNUMBER "uidNumber"	/**< The UID of this user. */
#define LU_GIDNUMBER "gidNumber"	/**< The primary GID of this user, or the GID of this group. */
#define LU_GECOS "gecos"		/**< Extra information about the user. */
#define LU_HOMEDIRECTORY "homeDirectory"/**< The location of the user's home directory. */
#define LU_LOGINSHELL "loginShell"	/**< The shell which the user uses. */

/** Attributes carried by group structures. */
#define LU_GID "gid"			/**< The name of this group. */
#define LU_MEMBERUID "memberUid"	/**< The name of a member of this group. */
#define LU_ADMINISTRATORUID "administratorUid"	/**< The name of a user who is allowed to administer (add users to and remove users from) this group. */

/** Attributes carried by shadow structures. */
#define LU_SHADOWLASTCHANGE "shadowLastChange"	/**< Date of last password change. */
#define LU_SHADOWMIN "shadowMin"		/**< Minimum number of days which must pass before the user can change her password again. */
#define LU_SHADOWMAX "shadowMax"		/**< Maximum number of days after a password change which are allowed to pass before the user must change her password again. */
#define LU_SHADOWWARNING "shadowWarning"	/**< The number of days before the maximum when the user is given a warning that a password change will soon be needed. */
#define LU_SHADOWINACTIVE "shadowInactive"	/**< The number of days after which the account is considered inactive. */
#define LU_SHADOWEXPIRE "shadowExpire"		/**< The date when the account expires. */
#define LU_SHADOWFLAG "shadowFlag"		/**< Reserved. */

/**
 * An lu_context_t holds configuration information for this instance of
 * the library.
 */
typedef struct lu_context lu_context_t;

/**
 * A user or group structure, conceptualized as a dictionary of lists,
 * keyed by attribute names.
 */
typedef struct lu_ent lu_ent_t;

/**
 * The type of data passed to a prompter function.  The library uses these
 * when it needs to prompt the user for information.
 */
typedef struct lu_prompt {
 	/** The text of a prompt to display. */
	const char *prompt;
 	/** Whether or not the user's response should be echoed to the screen.*/
	gboolean visible;
 	/** A default value, given as a string. */
	const char *default_value;
 	/** The value of the user's response. */
	char *value;
 	/** A function which can free the value. */
	void(*free_value)(char *);
} lu_prompt_t;

/**
 * The type of function which should be passed as a callback function to
 * lu_start().
 */
typedef gboolean (lu_prompt_fn)(struct lu_context *context,
				struct lu_prompt *prompts,
				int count,
				gpointer callback_data);

/**
 * A prompter which prompts for every value, including defaults.
 * @param context A library context.
 * @param prompts An array of lu_prompt_t structures which contain information
 * about what we want to know.
 * @param callback_data Callback data to be passed to the prompting function.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_prompt_console(struct lu_context *context,
			   struct lu_prompt *prompts,
			   int count, gpointer callback_data);

/**
 * A prompter which accepts defaults, and prompts for the rest.
 * @param context A library context.
 * @param prompts An array of lu_prompt_t structures which contain information
 * about what we want to know.
 * @param callback_data Callback data to be passed to the prompting function.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_prompt_console_quiet(struct lu_context *context,
				 struct lu_prompt *prompts,
				 int count, gpointer callback_data);

/**
 * An enumeration which decides whether we want to modify information about
 * users or groups.  We don't yet support both simultaneously.
 */
typedef enum lu_type {lu_user = 0x1234, lu_group = 0x1235} lu_type_t;

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
 * @return A valid context on successful initialization.
 * @return NULL on failure.
 */
struct lu_context *lu_start(const char *authname, enum lu_type auth_type,
			    const char *info_modules, const char *auth_modules,
			    lu_prompt_fn *prompter, gpointer callback_data);

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
 * @return Nothing.
 */
void lu_set_info_modules(struct lu_context *context, const char *list);

/**
 * Modifies the list of auth modules to be consulted when looking up users
 * and groups, and to be written to when storing information about new users
 * and groups.
 * @param context A library context.
 * @param list A comma-separated list of authentication modules to use.
 * @return Nothing.
 */
void lu_set_auth_modules(struct lu_context *context, const char *list);

/**
 * Shuts down the library, releasing memory and closing connections.
 * @param context A library context.
 * @return Nothing.
 */
void lu_end(struct lu_context *context);

/**
 * Creates a new entity structure.  Entity structures are used to hold
 * the attributes of an entry in the data store.
 * @return A valid structure on success.
 * @return NULL on failure.
 */
struct lu_ent *lu_ent_new(void);

/**
 * Copies on entity structure to another.
 * @param source The structure being duplicated.
 * @param dest The structure which will receive the data.
 * @return Nothing.
 */
void lu_ent_copy(struct lu_ent *source, struct lu_ent *dest);

/**
 * Revert any changes which have been made to the structure since it was
 * returned by a lookup request.
 * @param ent The structure which will have its data reverted.
 * @return Nothing.
 */
void lu_ent_revert(struct lu_ent *ent);

/**
 * Free an entity structure.
 * @param ent The structure which is to be freed.
 * @return Nothing.
 */
void lu_ent_free(struct lu_ent *ent);

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
void lu_ent_user_default(struct lu_context *ctx, const char *name,
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
void lu_ent_group_default(struct lu_context *ctx, const char *name,
			  gboolean system, struct lu_ent *ent);

/**
 * Returns a list of strings containing the attributes a particular entry
 * contains.
 * @param ent A valid entity structure.
 * @return A GList* containing names of attributes.
 * @return NULL on failure.
 */
GList *lu_ent_get_attributes(struct lu_ent *ent);

/**
 * Returns a list of strings containing the values for a particular attribute
 * of an entry.
 * @param ent A valid entity structure.
 * @param attribute The name of an attribute.
 * @return A GList* containing strings if the entity contains the specified attribute.
 * @return NULL on failure.
 */
GList *lu_ent_get(struct lu_ent *ent, const char *attribute);

/**
 * Returns a list of strings containing the original values for a particular
 * attribute of an entry.  These are the values which lu_ent_revert() will use.
 * @param ent A valid entity structure.
 * @param attribute The name of an attribute.
 * @return A GList* containing the values this structure originally contained
 * when it was first looked up.
 * @return NULL on failure.
 */
GList *lu_ent_get_original(struct lu_ent *ent, const char *attribute);

/**
 * Set a single value for a named attribute.
 * @param ent A valid entity structure.
 * @param attr The name of an attribute.
 * @param attr The value the attribute should take.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_ent_set(struct lu_ent *ent, const char *attr, const char *val);

/**
 * Set a single value for a named attribute in an entity structure's "original"
 * set of data.
 * @param ent A valid entity structure.
 * @param attr The name of an attribute.
 * @param attr The value the attribute should have.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_ent_set_original(struct lu_ent *ent, const char *attr,
			     const char *val);

/**
 * Add a new element to the list of values for the given attribute in the
 * given entity structure.
 * @param ent A valid entity structure.
 * @param attr The name of an attribute.
 * @param attr The value the attribute should take, in addition to any it
 * already has.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_ent_add(struct lu_ent *ent, const char *attr, const char *val);

/**
 * Add a new element to the list of original values for the given attribute
 * in the given entity structure.
 * @param ent A valid entity structure.
 * @param attr The name of an attribute.
 * @param attr A value the attribute should take, in addition to those it
 * already held when it was looked up.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_ent_add_original(struct lu_ent *ent, const char *attr,
			     const char *val);
/**
 * Remove a value for an attribute from the list of values in the entity
 * structure.
 * @param ent A valid entity structure.
 * @param attr The name of an attribute.
 * @param attr A value for the attribute which should be removed.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_ent_del(struct lu_ent *ent, const char *attr, const char *val);

/**
 * Remove all values for an attribute from the list of values in the entity
 * structure.
 * @param ent A valid entity structure.
 * @param attr The name of an attribute.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_ent_clear(struct lu_ent *ent, const char *attr);

/**
 * Remove all original values for an attribute from the list of values in
 * the entity structure.
 * @param ent A valid entity structure.
 * @param attr The name of an attribute.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_ent_clear_original(struct lu_ent *ent, const char *attr);

/**
 * Look up a user by name.
 * @param context A valid library context.
 * @param name The name of the user to be searched for.
 * @param ent An entity structure to be populated with the user's data.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_lookup_name(struct lu_context *context, const char *name,
			     struct lu_ent *ent);

/**
 * Look up a group by name.
 * @param context A valid library context.
 * @param name The name of the group to be searched for.
 * @param ent An entity structure to be populated with the group's data.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_lookup_name(struct lu_context *context, const char *name,
			      struct lu_ent *ent);
/**
 * Look up a user by ID.
 * @param context A valid library context.
 * @param gid The user ID for the user to be searched for.
 * @param ent An entity structure to be populated with the user's data.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_lookup_id(struct lu_context *context, uid_t uid,
			   struct lu_ent *ent);
/**
 * Look up a group by ID.
 * @param context A valid library context.
 * @param gid The group ID for the group to be searched for.
 * @param ent An entity structure to be populated with the group's data.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_lookup_id(struct lu_context *context, gid_t gid,
			    struct lu_ent *ent);
/**
 * Add a new user to the system.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the user.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_add(struct lu_context *context, struct lu_ent *ent);

/**
 * Add a new group to the system.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the group.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_add(struct lu_context *context, struct lu_ent *ent);

/**
 * Modify the specified user, so that the stored data matches the structure
 * as closely as possible.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the user.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_modify(struct lu_context *context, struct lu_ent *ent);

/**
 * Modify the specified group, so that the stored data matches the structure
 * as closely as possible.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the group.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_modify(struct lu_context *context, struct lu_ent *ent);

/**
 * Delete the specified user from the system database.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the user to
 * be removed.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_delete(struct lu_context *context, struct lu_ent *ent);

/**
 * Delete the specified group from the system database.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the group to
 * be removed.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_delete(struct lu_context *context, struct lu_ent *ent);

/**
 * Lock the specified user account.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the user whose
 * account should be locked
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_lock(struct lu_context *context, struct lu_ent *ent);

/**
 * Lock the specified group.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the group whose
 * access should be locked
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_lock(struct lu_context *context, struct lu_ent *ent);

/**
 * Unlock the specified user's account.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the user whose
 * account should be unlocked.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_user_unlock(struct lu_context *context, struct lu_ent *ent);

/**
 * Unlock the specified group.
 * @param context A valid library context.
 * @param ent An entity structure containing information about the group whose
 * access should be unlocked
 * @return TRUE on success.
 * @return FALSE on failure.
 */
gboolean lu_group_unlock(struct lu_context *context, struct lu_ent *ent);

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
			 const char *newpass);

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
			  const char *newpass);

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
			  const char *module);

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
			   const char *module);


/**
 * Read the value of a potentially multi-valued key in the configuration file.
 * @param context A valid library context.
 * @param key The path to the value in the configuration file.
 * @param default_value The value to return if the key is not found in the file.
 * @return A list of values on success.
 * @return The default value on failure.
 **/
GList *lu_cfg_read(struct lu_context *context,
		   const char *key, const char *default_value);

/**
 * Read the value of a single-valued key in the configuration file.
 * @param context A valid library context.
 * @param key The path to the value in the configuration file.
 * @param default_value The value to return if the key is not found in the file.
 * @return A single value on success.
 * @return The default value on failure.
 */
const char *lu_cfg_read_single(struct lu_context *context,
			       const char *key, const char *default_value);

/**
 * Read the list of keys in a section of the file.
 * @param context A valid library context.
 * @param parent_key A path beneath which keys should be searched for.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
GList *lu_cfg_read_keys(struct lu_context *context, const char *parent_key);

#ifdef __cplusplus
};
#endif

#endif
