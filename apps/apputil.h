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

#ident "$Id$"

#ifndef apputil_h
#define apputil_h

#include <sys/types.h>
#include "../include/libuser/user.h"

#define _(String) gettext(String)
#define N_(String) (String)

gboolean lu_homedir_populate(const char *skel, const char *directory,
			     uid_t owner, gid_t group, mode_t mode,
			     struct lu_error **error);
gboolean lu_homedir_move(const char *oldhome, const char *directory,
			 struct lu_error **error);
gboolean lu_homedir_remove(const char *directory, struct lu_error **error);

void lu_authenticate_unprivileged(struct lu_context *ctx,
				  const char *user, const char *appname);

char *lu_strconcat(char *existing, const char *appendee);

void lu_hup_nscd(void);
void lu_signal_nscd(int signal);

gboolean lu_mailspool_create(struct lu_ent *ent);

#endif
