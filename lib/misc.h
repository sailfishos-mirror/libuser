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

#ifndef misc_h
#define misc_h

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <glib.h>
#include "../include/libuser/user_private.h"

void lu_set_prompter(struct lu_context *context, lu_prompt_fn * prompter,
		     gpointer prompter_data);

void lu_get_prompter(struct lu_context *context, lu_prompt_fn **prompter,
		     gpointer *prompter_data);

gboolean lu_set_modules(struct lu_context * context, const char *list,
			struct lu_error ** error);

const char *lu_get_modules(struct lu_context *context);

#endif
