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

#ifndef libuser_entity_h
#define libuser_entity_h

/** @file entity.h */

#include <sys/types.h>
#include <glib.h>

/** Attributes carried by all entity structures. */
#define LU_OBJECTCLASS		"objectClass"		/**< An object class.  Used primarily by the LDAP back-end. */
#define LU_CN			"cn"			/**< The name of entity, regardless of whether it is a user or a group. */
#define LU_USERNAME		"uid"			/**< The attribute which normally holds the login ID associated with a user account. */
#define LU_GROUPNAME		"cn"			/**< The attribute which normally holds
the group name for a group entity. */

/** Attributes carried by user structures. */
#define LU_UID			"uid"			/**< The login name of this user. */
#define LU_USERPASSWORD		"userPassword"		/**< The user or group's password. */
#define LU_UIDNUMBER		"uidNumber"		/**< The UID of this user. */
#define LU_GIDNUMBER		"gidNumber"		/**< The primary GID of this user, or the GID of this group. */
#define LU_GECOS		"gecos"			/**< Extra information about the user. */
#define LU_HOMEDIRECTORY	"homeDirectory"		/**< The location of the user's home directory. */
#define LU_LOGINSHELL		"loginShell"		/**< The shell which the user uses. */

/** Attributes carried by group structures. */
#define LU_GID			"gid"			/**< The name of this group. */
#define LU_MEMBERUID		"memberUid"		/**< The name of a member of this group. */
#define LU_ADMINISTRATORUID	"administratorUid"	/**< The name of a user who is allowed to administer (add users to and remove users from) this group. */

/** Attributes carried by shadow structures. */
#define LU_SHADOWLASTCHANGE	"shadowLastChange"	/**< Date of last password change. */
#define LU_SHADOWMIN		"shadowMin"		/**< Minimum number of days which must pass before the user can change her password again. */
#define LU_SHADOWMAX		"shadowMax"		/**< Maximum number of days after a password change which are allowed to pass before the user must change her password again. */
#define LU_SHADOWWARNING	"shadowWarning"		/**< The number of days before the maximum when the user is given a warning that a password change will soon be needed. */
#define LU_SHADOWINACTIVE	"shadowInactive"	/**< The number of days after which the account is considered inactive. */
#define LU_SHADOWEXPIRE		"shadowExpire"		/**< The date when the account expires. */
#define LU_SHADOWFLAG		"shadowFlag"		/**< Reserved. */

/**
 * A user or group structure, conceptualized as a dictionary of lists,
 * keyed by attribute names.
 */
typedef struct lu_ent lu_ent_t;

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
 * when it was first looked up or otherwise initialized.
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
void lu_ent_set(struct lu_ent *ent, const char *attr, const char *val);

/**
 * Set a single value for a named attribute in an entity structure's "original"
 * set of data.
 * @param ent A valid entity structure.
 * @param attr The name of an attribute.
 * @param attr The value the attribute should have.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
void lu_ent_set_original(struct lu_ent *ent, const char *attr, const char *val);

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
void lu_ent_add(struct lu_ent *ent, const char *attr, const char *val);

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
void lu_ent_add_original(struct lu_ent *ent, const char *attr, const char *val);
/**
 * Remove a value for an attribute from the list of values in the entity
 * structure.
 * @param ent A valid entity structure.
 * @param attr The name of an attribute.
 * @param attr A value for the attribute which should be removed.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
void lu_ent_del(struct lu_ent *ent, const char *attr, const char *val);

/**
 * Remove all values for an attribute from the list of values in the entity
 * structure.
 * @param ent A valid entity structure.
 * @param attr The name of an attribute.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
void lu_ent_clear(struct lu_ent *ent, const char *attr);

/**
 * Remove all original values for an attribute from the list of values in
 * the entity structure.
 * @param ent A valid entity structure.
 * @param attr The name of an attribute.
 * @return TRUE on success.
 * @return FALSE on failure.
 */
void lu_ent_clear_original(struct lu_ent *ent, const char *attr);

#endif
