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

#include <sys/types.h>
#include <stdio.h>
#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

struct lu_ent;

/* Attributes carried by all user structures. */
#define LU_USERNAME		"pw_name"
#define LU_USERPASSWORD		"pw_passwd"
#define LU_UIDNUMBER		"pw_uid"
#define LU_GIDNUMBER		"pw_gid"
#define LU_GECOS		"pw_gecos"
#define LU_HOMEDIRECTORY	"pw_dir"
#define LU_LOGINSHELL		"pw_shell"

/* Attributes carried by group structures. */
#define LU_GROUPNAME		"gr_name"
#define LU_GROUPPASSWORD	"gr_passwd"
/* #define LU_GIDNUMBER		"gr_gid" */
#define LU_MEMBERUID		"gr_mem"
#define LU_ADMINISTRATORUID	"gr_adm"

/* Attributes carried by shadow user structures. */
#define LU_SHADOWNAME		LU_USERNAME
#define LU_SHADOWPASSWORD	"sp_pwdp"
#define LU_SHADOWLASTCHANGE	"sp_lstchg"
#define LU_SHADOWMIN		"sp_min"
#define LU_SHADOWMAX		"sp_max"
#define LU_SHADOWWARNING	"sp_warn"
#define LU_SHADOWINACTIVE	"sp_inact"
#define LU_SHADOWEXPIRE		"sp_expire"
#define LU_SHADOWFLAG		"sp_flag"

/* Additional fields carried by some structures.  If they have them,
 * it's safe to change them. */
#define LU_COMMONNAME		"cn"
#define LU_GIVENNAME		"givenName"
#define LU_SN			"sn"
#define LU_ROOMNUMBER		"roomNumber"
#define LU_TELEPHONENUMBER	"telephoneNumber"
#define LU_HOMEPHONE		"homePhone"
#define LU_EMAIL		"mail"

/* Function to allocate a new entity structure, or destroy one. */
struct lu_ent *lu_ent_new(void);
void lu_ent_free(struct lu_ent *ent);

/* Deep-copy the contents of one entity structure into another. */
void lu_ent_copy(struct lu_ent *source, struct lu_ent *dest);

/* Entity structures have a limited form of version-control, and that gives
 * us the ability to roll back changes. */
void lu_ent_revert(struct lu_ent *ent);

/* This function rolls changes forward. */
void lu_ent_commit(struct lu_ent *ent);

/* These functions are used to set and query "current" data attributes, the
 * values the library itself usually sets. */
GValueArray *lu_ent_get_current(struct lu_ent *ent, const char *attribute);
gboolean lu_ent_has_current(struct lu_ent *ent, const char *attribute);
void lu_ent_set_current(struct lu_ent *ent, const char *attr,
			const GValueArray *values);
void lu_ent_add_current(struct lu_ent *ent, const char *attr,
			const GValue *value);
void lu_ent_clear_current(struct lu_ent *ent, const char *attr);
void lu_ent_clear_all_current(struct lu_ent *ent);
void lu_ent_del_current(struct lu_ent *ent, const char *attr,
			const GValue *value);
GList *lu_ent_get_attributes_current(struct lu_ent *ent);

/* These functions are used to set and query "pending" data attributes, which
 * will take effect when we write this entry back out. */
GValueArray *lu_ent_get(struct lu_ent *ent, const char *attribute);
gboolean lu_ent_has(struct lu_ent *ent, const char *attribute);
void lu_ent_set(struct lu_ent *ent, const char *attr,
		const GValueArray *values);
void lu_ent_add(struct lu_ent *ent, const char *attr,
		const GValue *value);
void lu_ent_clear(struct lu_ent *ent, const char *attr);
void lu_ent_clear_all(struct lu_ent *ent);
void lu_ent_del(struct lu_ent *ent, const char *attr, const GValue *value);
GList *lu_ent_get_attributes(struct lu_ent *ent);

void lu_ent_dump(struct lu_ent *ent, FILE *fp);

G_END_DECLS

#endif
