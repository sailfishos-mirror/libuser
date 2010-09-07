/*
 * Copyright (C) 2000-2002 Red Hat, Inc.
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

#ifndef apputil_h
#define apputil_h

#include <sys/types.h>
#include "../lib/user.h"

#ifndef _
#define _(String) gettext(String)
#endif
#ifndef N_
#define N_(String) (String)
#endif

gboolean lu_homedir_populate(struct lu_context *ctx, const char *skel,
			     const char *directory, uid_t owner, gid_t group,
			     mode_t mode, struct lu_error **error)
	G_GNUC_INTERNAL;
gboolean lu_homedir_move(const char *oldhome, const char *directory,
			 struct lu_error **error) G_GNUC_INTERNAL;
gboolean lu_homedir_remove(const char *directory, struct lu_error **error)
	G_GNUC_INTERNAL;

void lu_authenticate_unprivileged(struct lu_context *ctx, const char *user,
				  const char *appname)
	G_GNUC_INTERNAL;

void lu_nscd_flush_cache (const char *table) G_GNUC_INTERNAL;

gboolean lu_mailspool_create_remove(struct lu_context *ctx, struct lu_ent *ent,
				    gboolean action) G_GNUC_INTERNAL;

#endif
