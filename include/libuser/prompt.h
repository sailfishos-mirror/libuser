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

#ifndef libuser_prompt_h
#define libuser_prompt_h

/** @file prompt.h */

#include <sys/types.h>
#include <glib.h>

/**
 * The type of data passed to a prompter function.  The library uses these
 * when it needs to prompt the user for information.
 */
typedef struct lu_prompt {
 	/** An invariant string of the form "module/name", which describes the information being prompted for.  The calling
	 *  application may use this value as an index into a hash table used to cache answers to particular queries. */
	const char *key;
 	/** The text of a prompt to display.  This *may* be translated for the current locale by a module. */
	const char *prompt;
 	/** Whether or not the user's response should be echoed to the screen
	 *  or visible in an entry field.*/
	gboolean visible;
 	/** A default value, given as a string. */
	const char *default_value;
 	/** The user's response. */
	char *value;
 	/** A function which can free the value. */
	void(*free_value)(char *);
} lu_prompt_t;

typedef gboolean (lu_prompt_fn)(struct lu_prompt *prompts,
				int count,
				gpointer callback_data,
				struct lu_error **error);
gboolean lu_prompt_console(struct lu_prompt *prompts,
			   int count, gpointer callback_data,
			   struct lu_error **error);
gboolean lu_prompt_console_quiet(struct lu_prompt *prompts,
				 int count, gpointer callback_data,
				 struct lu_error **error);

#endif
