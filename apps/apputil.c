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
#include "../config.h"
#endif
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <crypt.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <glib.h>
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utime.h>
#include "../include/libuser/user.h"
#include "../include/libuser/error.h"
#include "apputil.h"

gboolean
lu_homedir_populate(const char *skeleton, const char *directory, uid_t owner, gid_t group, mode_t mode, struct lu_error **error)
{
	struct dirent *ent;
	DIR *dir;
	struct stat st;
	char skelpath[PATH_MAX], path[PATH_MAX], buf[PATH_MAX];
	struct utimbuf timebuf;
	int ifd, ofd, i;

	LU_ERROR_CHECK(error);

	dir = opendir(skeleton);
	if(dir == NULL) {
		lu_error_new(error, lu_error_generic, _("Error reading `%s': %s"), skeleton, strerror(errno));
		return FALSE;
	}

	if((mkdir(directory, mode) == -1) && (errno != EEXIST)) {
		lu_error_new(error, lu_error_generic, _("Error creating `%s': %s"), directory, strerror(errno));
		closedir(dir);
		return FALSE;
	}
	chown(directory, owner, group);

	do {
		ent = readdir(dir);
		if(ent != NULL) {
			if(strcmp(ent->d_name, ".") == 0)
				continue;
			if(strcmp(ent->d_name, "..") == 0)
				continue;
			snprintf(skelpath, sizeof(skelpath), "%s/%s", skeleton, ent->d_name);
			snprintf(path, sizeof(path), "%s/%s", directory, ent->d_name);
			if(lstat(skelpath, &st) != -1) {
				timebuf.actime = st.st_atime;
				timebuf.modtime = st.st_mtime;
				if(S_ISDIR(st.st_mode)) {
					if(lu_homedir_populate(skelpath, path, owner, st.st_gid ?: group, st.st_mode, error) == FALSE) {
						closedir(dir);
						return FALSE;
					}
					utime(path, &timebuf);
				}
				if(S_ISLNK(st.st_mode)) {
					memset(buf, '\0', sizeof(buf));
					if(readlink(skelpath, buf, sizeof(buf) - 1) != -1) {
						buf[sizeof(buf) - 1] = '\0';
						symlink(buf, path);
					}
					lchown(path, owner, st.st_gid ?: group);
					utime(path, &timebuf);
				}
				if(S_ISREG(st.st_mode)) {
					ifd = open(skelpath, O_RDONLY);
					if(ifd != -1) {
						ofd = open(path, O_EXCL | O_CREAT | O_WRONLY, st.st_mode);
						if(ofd != -1) {
							do {
								i = read(ifd, &buf, sizeof(buf));
								if(i > 0) {
									write(ofd, buf, i);
								}
							} while(i > 0);
							close(ofd);
						}
						close(ifd);
					}
					chown(path, owner, st.st_gid ?: group);
					utime(path, &timebuf);
				}
			}
		}
	} while(ent != NULL);

	closedir(dir);

	return TRUE;
}

gboolean
lu_homedir_remove(const char *directory, struct lu_error **error)
{
	struct dirent *ent;
	DIR *dir;
	struct stat st;
	char path[PATH_MAX];

	LU_ERROR_CHECK(error);

	dir = opendir(directory);
	if(dir == NULL) {
		lu_error_new(error, lu_error_generic, _("Error removing `%s': %s"), directory, strerror(errno));
		return FALSE;
	}

	do {
		ent = readdir(dir);
		if(ent != NULL) {
			if(strcmp(ent->d_name, ".") == 0)
				continue;
			if(strcmp(ent->d_name, "..") == 0)
				continue;
			snprintf(path, sizeof(path), "%s/%s", directory, ent->d_name);
			if(lstat(path, &st) != -1) {
				if(S_ISDIR(st.st_mode)) {
					if(lu_homedir_remove(path, error) == FALSE) {
						closedir(dir);
						return FALSE;
					}
				} else {
					if(unlink(path) == -1) {
						lu_error_new(error, lu_error_generic, _("Error removing `%s': %s"), path, strerror(errno));
						closedir(dir);
						return FALSE;
					}
				}
			}
		}
	} while(ent != NULL);

	closedir(dir);

	if(rmdir(directory) == -1) {
		lu_error_new(error, lu_error_generic, _("Error removing `%s': %s"), directory, strerror(errno));
		return FALSE;
	}

	return TRUE;
}

gboolean
lu_homedir_move(const char *oldhome, const char *directory, struct lu_error **error)
{
	struct stat st;

	LU_ERROR_CHECK(error);

	if(stat(oldhome, &st) != -1) {
		if(lu_homedir_populate(oldhome, directory, st.st_uid, st.st_gid, st.st_mode, error)) {
			return lu_homedir_remove(oldhome, error);
		}
	}
	return FALSE;
}

struct conv_data {
	lu_prompt_fn *prompt;
	gpointer callback_data;
};

static int
lu_converse(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	struct conv_data *data = appdata_ptr;
	struct lu_prompt prompts[num_msg];
	struct lu_error *error = NULL;
	struct pam_response *responses;
	int i;

	memset(&prompts, 0, sizeof(prompts));

	for(i = 0; i < num_msg; i++) {
		char *pending = NULL;
		switch((*msg)[i].msg_style) {
			case PAM_PROMPT_ECHO_ON:
				if(pending) {
					prompts[i].prompt = g_strconcat(pending, (*msg)[i].msg, NULL);
					g_free(pending);
					pending = NULL;
				} else {
					prompts[i].prompt = g_strdup((*msg)[i].msg);
				}
				prompts[i].visible = TRUE;
				break;
			case PAM_PROMPT_ECHO_OFF:
				if(pending) {
					prompts[i].prompt = g_strconcat(pending, (*msg)[i].msg, NULL);
					g_free(pending);
					pending = NULL;
				} else {
					prompts[i].prompt = g_strdup((*msg)[i].msg);
				}
				prompts[i].visible = FALSE;
				break;
			default:
				if(pending) {
					char *tmp = g_strconcat(pending, (*msg)[i].msg, NULL);
					g_free(pending);
					pending = tmp;
				} else {
					pending = g_strdup((*msg)[i].msg);
				}
		}
		if((prompts[i].prompt != NULL) && (strrchr(prompts[i].prompt, ':'))) {
			char *p = strrchr(prompts[i].prompt, ':');
			*p = '\0';
		}
		if(pending) {
			g_free(pending);
		}
	}

	if(data->prompt(prompts, num_msg, data->callback_data, &error)) {
		responses = malloc(sizeof(struct pam_response) * i);
		if(responses == NULL) {
			return PAM_BUF_ERR;
		}
		memset(responses, 0, sizeof(struct pam_response) * i);
		for(i = 0; i < num_msg; i++) {
			responses[i].resp_retcode = PAM_SUCCESS;
			if(prompts[i].prompt != NULL) {
				g_free((gpointer)prompts[i].prompt);
			}
			if(prompts[i].value != NULL) {
				responses[i].resp = strdup(prompts[i].value);
				prompts[i].free_value(prompts[i].value);
			}
		}
		*resp = responses;
	}

	if(error != NULL) {
		lu_error_free(&error);
	}

	return PAM_CONV_ERR;
}

void
lu_authenticate_unprivileged(struct lu_context *ctx, const char *user, const char *appname)
{
	pam_handle_t *pamh;
	struct pam_conv conv;
	struct conv_data data;
	const char *info, *auth, *net;

	info = lu_get_info_modules(ctx);
	auth = lu_get_auth_modules(ctx);
	net = lu_cfg_read_single(ctx, "defaults/network_modules", NULL);
	if(net) {
		int bypass = 1, i, j;
		char **authlist, **infolist, **netlist;

		authlist = g_strsplit(auth, " ", 0);
		infolist = g_strsplit(info, " ", 0);
		netlist = g_strsplit(net, " ", 0);

		for(i = 0; authlist[i] != NULL; i++) {
			for(j = 0; netlist[j] != NULL; j++) {
				if(strcmp(authlist[i], netlist[j]) == 0) {
					break;
				}
			}
			if(netlist[j] == NULL) {
				bypass = 0;
			}
		}
		for(i = 0; infolist[i] != NULL; i++) {
			for(j = 0; netlist[j] != NULL; j++) {
				if(strcmp(infolist[i], netlist[j]) == 0) {
					break;
				}
			}
			if(netlist[j] == NULL) {
				bypass = 0;
			}
		}

		if(authlist) {
			g_strfreev(authlist);
		}
		if(infolist) {
			g_strfreev(infolist);
		}
		if(netlist) {
			g_strfreev(netlist);
		}

		if(bypass || (geteuid() == 0) || (getuid() == 0)) {
			return;
		}
	}

	lu_get_prompter(ctx, &data.prompt, &data.callback_data);
	if(data.prompt == NULL) {
		fprintf(stderr, _("Internal error.\n"));
		exit(1);
	}

	conv.conv = lu_converse;
	conv.appdata_ptr = &data;

	if(pam_start(appname, user, &conv, &pamh) != PAM_SUCCESS) {
		fprintf(stderr, _("Error initializing PAM.\n"));
		exit(1);
	}

	if(pam_authenticate(pamh, 0) != PAM_SUCCESS) {
		const char *puser = user;
		pam_get_item(pamh, PAM_USER, (const void**) &puser);
		fprintf(stderr, _("Authentication failed for %s.\n"), puser);
		pam_end(pamh, 0);
		exit(1);
	}
}

void
lu_hup_nscd(void)
{
	FILE *fp;
	char buf[LINE_MAX];
	if((fp = fopen("/var/run/nscd.pid", "r")) != NULL) {
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp);
		if(strlen(buf) > 0) {
			pid_t pid = atol(buf);
			if(pid != 0) {
				kill(pid, SIGHUP);
			}
		}
		fclose(fp);
	}
}
