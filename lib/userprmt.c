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
#define _(String) gettext(String)
#include <libintl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include "../include/libuser/user.h"

/** @file userprmt.c */

/**
 * lu_prompt_console:
 * @param prompts An array of structures used to pass prompts and answers into and out of the function.
 * @param count The length of the prompts array.
 * @param calldata Ignored.
 *
 * This function prompts the user for information, including items which have default answers supplied by the caller.
 *
 * @return TRUE on success, or FALSE on error.
 **/
gboolean
lu_prompt_console(struct lu_prompt *prompts, int count, gpointer calldata,
		  struct lu_error **error)
{
	int i;
	char buf[LINE_MAX];
	struct termios otermios, ntermios;

	LU_ERROR_CHECK(error);

	if(count > 0) {
		g_assert(prompts != NULL);
	}

	for(i = 0; i < count; i++) {
		if(prompts[i].prompt) {
			g_print("%s", prompts[i].prompt);
		}
		if(prompts[i].visible && prompts[i].default_value) {
			g_print(" [%s]: ", prompts[i].default_value);
		} else {
			g_print(": ");
		}

		prompts[i].value = NULL;
		prompts[i].free_value = NULL;

		if(prompts[i].visible == FALSE) {
			if(tcgetattr(fileno(stdin), &otermios) == -1) {
				lu_error_new(error, lu_error_terminal, _("error reading terminal attributes"));
				return FALSE;
			}
			ntermios = otermios;
			ntermios.c_lflag &= ~ECHO;
			if(tcsetattr(fileno(stdin), TCSADRAIN, &ntermios) == -1) {
				lu_error_new(error, lu_error_terminal, _("error setting terminal attributes"));
				return FALSE;
			}
		}
		if(fgets(buf, sizeof(buf), stdin) == NULL) {
			lu_error_new(error, lu_error_terminal, _("error reading from terminal"));
			return FALSE;
		}
		if(prompts[i].visible == FALSE) {
			if(tcsetattr(fileno(stdin), TCSADRAIN, &otermios) == -1) {
				lu_error_new(error, lu_error_terminal, _("error setting terminal attributes"));
				return FALSE;
			}
			g_print("\n");
		}

		if(strchr(buf, '\r')) {
			char *p = strchr(buf, '\r');
			*p = '\0';
		}
		if(strchr(buf, '\n')) {
			char *p = strchr(buf, '\n');
			*p = '\0';
		}

		prompts[i].value = (strlen(buf) > 0) ? g_strdup(buf) :
				   (prompts[i].default_value ?
				    g_strdup(prompts[i].default_value) :
				    g_strdup(""));
		prompts[i].free_value = (void*)g_free;
	}
	return TRUE;
}

/**
 * lu_prompt_console_quiet:
 * @param prompts An array of structures used to pass prompts and answers into and out of the function.
 * @param count The length of the prompts array.
 * @param calldata Ignored.
 *
 * This function prompts the user for information.  Items which have default answers supplied by the caller will be returned
 * with their default values set.
 *
 * @return TRUE, or FALSE on error.
 **/
gboolean
lu_prompt_console_quiet(struct lu_prompt *prompts, int count, gpointer calldata, struct lu_error **error)
{
	int i;
	gboolean ret = TRUE;

	LU_ERROR_CHECK(error);

	if(count > 0) {
		g_return_val_if_fail(prompts != NULL, FALSE);
	}

	for(i = 0; (i < count) && ret; i++) {
		if(prompts[i].default_value) {
			prompts[i].value = g_strdup(prompts[i].default_value);
			prompts[i].free_value = (void*)g_free;
		} else {
			ret = ret && lu_prompt_console(&prompts[i], 1, calldata, error);
		}
	}

	return ret;
}
