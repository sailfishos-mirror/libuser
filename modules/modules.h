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

#ifndef modules_h
#define modules_h
#include "../include/libuser/user.h"
struct lu_module *lu_files_init(struct lu_context *context, struct lu_error **error);
struct lu_module *lu_shadow_init(struct lu_context *context, struct lu_error **error);
struct lu_module *lu_krb5_init(struct lu_context *context, struct lu_error **error);
struct lu_module *lu_ldap_init(struct lu_context *context, struct lu_error **error);
struct lu_module *lu_sasldb_init(struct lu_context *context, struct lu_error **error);
#endif
