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

/** Additional fields carried by some structures.  If they have them, it's safe to change them. */
#define LU_GIVENNAME		"givenName"
#define LU_SN			"sn"
#define LU_ROOMNUMBER		"roomNumber"
#define LU_TELEPHONENUMBER	"telephoneNumber"
#define LU_HOMEPHONE		"homePhone"

typedef struct lu_ent lu_ent_t;

struct lu_ent *lu_ent_new(void);
void lu_ent_copy(struct lu_ent *source, struct lu_ent *dest);
void lu_ent_revert(struct lu_ent *ent);
void lu_ent_free(struct lu_ent *ent);

GList *lu_ent_get_original(struct lu_ent *ent, const char *attribute);
void lu_ent_set_original(struct lu_ent *ent, const char *attr, const char *val);
void lu_ent_add_original(struct lu_ent *ent, const char *attr, const char *val);
void lu_ent_clear_original(struct lu_ent *ent, const char *attr);

GList *lu_ent_get(struct lu_ent *ent, const char *attribute);
gboolean lu_ent_has(struct lu_ent *ent, const char *attribute);
void lu_ent_set(struct lu_ent *ent, const char *attr, const char *val);
void lu_ent_add(struct lu_ent *ent, const char *attr, const char *val);
void lu_ent_clear(struct lu_ent *ent, const char *attr);
void lu_ent_del(struct lu_ent *ent, const char *attr, const char *val);
GList *lu_ent_get_attributes(struct lu_ent *ent);

#endif
