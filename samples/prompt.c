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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <libuser/user.h>
#include <stdlib.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>

int main(int argc, char **argv)
{
	struct lu_context *lu = NULL;
	struct lu_prompt prompts[] = {
		{"Name", TRUE, g_strdup("anonymous"), NULL, NULL},
		{"Password1", TRUE, g_strdup("anonymous"), NULL, NULL},
		{"Password2", FALSE, g_strdup("anonymous"), NULL, NULL},
	};
	int i;

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	lu = lu_start(NULL, 0, "", "", lu_prompt_console, NULL);
	if(lu == NULL) {
		g_print(gettext("Error initializing lu.\n"));
		return 1;
	}

	if(lu_prompt_console(lu,
			     prompts,
			     sizeof(prompts) / sizeof(prompts[0]),
			     NULL)) {
		g_print(gettext("Prompts succeeded.\n"));
		for(i = 0; i < sizeof(prompts) / sizeof(prompts[0]); i++) {
			if(prompts[i].value) {
				g_print("'%s'\n", prompts[i].value);
				prompts[i].free_value(prompts[i].value);
			} else {
				g_print("(null)\n");
			}
		}
	} else {
		g_print(gettext("Prompts failed.\n"));
	}

#if 0
	lu_end(lu);
#endif

	return 0;
}
