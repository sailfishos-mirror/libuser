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
#include <grp.h>
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utime.h>
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#include <selinux/av_permissions.h>
#include <selinux/flask.h>
#include <selinux/context.h>
#endif
#include "../lib/user.h"
#include "../lib/error.h"
#include "apputil.h"

#ifdef WITH_SELINUX
static int
check_access(const char *chuser, access_vector_t access)
{
	int status;
	security_context_t user_context;

	status = -1;
	if (getprevcon(&user_context) == 0) {
		context_t c;
		const char *user;

		c = context_new(user_context);
		user = context_user_get(c);
		if (strcmp(chuser, user) == 0)
			status = 0;
		else {
			struct av_decision avd;
			int retval;

			retval = security_compute_av(user_context,
						     user_context,
						     SECCLASS_PASSWD,
 						     access, &avd);
			
			if (retval == 0 && (avd.allowed & access) == access)
				status = 0;
		}
		context_free(c);
		freecon(user_context);
	}
	return status;
}

static int
setup_default_context(const char *orig_file)
{
	if (is_selinux_enabled() > 0) {
		security_context_t scontext;
    
		if (getfilecon(orig_file, &scontext) < 0)
			return -1;

		if (setfscreatecon(scontext) < 0) {
			freecon(scontext);
			return -1;
		}
		freecon(scontext);
	}
	return 0;
}
#endif

/* Populate a user's home directory, copying data from a named skeleton
 * directory, setting all ownerships as given, and setting the mode of
 * the top-level directory as given. */
gboolean
lu_homedir_populate(const char *skeleton, const char *directory,
		    uid_t owner, gid_t group, mode_t mode,
		    struct lu_error **error)
{
	struct dirent *ent;
	DIR *dir;
	struct stat st;
	char skelpath[PATH_MAX], path[PATH_MAX], buf[PATH_MAX];
	struct utimbuf timebuf;
	int ifd = -1, ofd = -1, i;
	off_t offset;

	LU_ERROR_CHECK(error);

	dir = opendir(skeleton);
	if (dir == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("Error reading `%s': %s"), skeleton,
			     strerror(errno));
		return FALSE;
	}

	/* Create the top-level directory. */
	if ((mkdir(directory, mode) == -1) && (errno != EEXIST)) {
		lu_error_new(error, lu_error_generic,
			     _("Error creating `%s': %s"), directory,
			     strerror(errno));
		closedir(dir);
		return FALSE;
	}

	/* Set the ownership on the top-level directory. */
	chown(directory, owner, group);

	while ((ent = readdir(dir)) != NULL) {
		/* Iterate through each item in the directory. */
		/* Skip over self and parent hard links. */
		if (strcmp(ent->d_name, ".") == 0) {
			continue;
		}
		if (strcmp(ent->d_name, "..") == 0) {
			continue;
		}

		/* Build the path of the skeleton file or directory and
		 * its corresponding member in the new tree. */
		snprintf(skelpath, sizeof(skelpath), "%s/%s",
			 skeleton, ent->d_name);
		snprintf(path, sizeof(path), "%s/%s", directory,
			 ent->d_name);

		/* What we do next depends on the type of entry we're
		 * looking at. */
		if (lstat(skelpath, &st) != -1) {
			/* We always want to preserve atime/mtime. */
			timebuf.actime = st.st_atime;
			timebuf.modtime = st.st_mtime;

			/* If it's a directory, descend into it. */
			if (S_ISDIR(st.st_mode)) {
				if (!lu_homedir_populate(skelpath,
							 path,
							 owner,
							 st.st_gid ?: group,
							 st.st_mode,
							 error)) {
					/* Aargh!  Fail up. */
					closedir(dir);
					return FALSE;
				}
				/* Set the date on the directory. */
				utime(path, &timebuf);
				continue;
			}

			/* If it's a symlink, duplicate it. */
			if (S_ISLNK(st.st_mode)) {
				ssize_t len;
				
				if ((len = readlink(skelpath, buf,
						    sizeof(buf) - 1)) != -1) {
					buf[len] = '\0';
					symlink(buf, path);
					lchown(path, owner, st.st_gid ?: group);
					utime(path, &timebuf);
				}
				continue;
			}

			/* If it's a regular file, copy it. */
			if (S_ISREG(st.st_mode)) {
				/* Open both the input and output
				 * files.  If we fail to do either,
				 * we have to give up. */
				ifd = open(skelpath, O_RDONLY);
				if (ifd != -1) {
					ofd = open(path,
						   O_EXCL | O_CREAT | O_WRONLY,
						   st.st_mode);
				}
				if ((ifd == -1) || (ofd == -1)) {
					/* Sorry, no can do. */
					close (ifd);
					close (ofd);
					continue;
				}

				/* Now just copy the data. */
				do {
					i = read(ifd, &buf, sizeof(buf));
					if (i > 0) {
						write(ofd, buf, i);
					}
				} while (i > 0);

				/* Close the files. */
				offset = lseek(ofd, 0, SEEK_CUR);
				if (offset != ((off_t) -1)) {
					ftruncate(ofd, offset);
				}
				close (ifd);
				close (ofd);

				/* Set the ownership and timestamp on
				 * the new file. */
				chown(path, owner, st.st_gid ?: group);
				utime(path, &timebuf);
				continue;
			}
			/* Note that we don't copy device specials. */
		}
	}

	closedir(dir);

	return TRUE;
}

/* Recursively remove a user's home (or really, any) directory. */
gboolean
lu_homedir_remove(const char *directory, struct lu_error ** error)
{
	struct dirent *ent;
	DIR *dir;
	struct stat st;
	char path[PATH_MAX];

	LU_ERROR_CHECK(error);

	/* Open the directory.  This catches the case that it's already gone. */
	dir = opendir(directory);
	if (dir == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("Error removing `%s': %s"), directory,
			     strerror(errno));
		return FALSE;
	}

	/* Iterate over all of its contents. */
	while ((ent = readdir(dir)) != NULL) {
		/* Skip over the self and parent hard links. */
		if (strcmp(ent->d_name, ".") == 0) {
			continue;
		}
		if (strcmp(ent->d_name, "..") == 0) {
			continue;
		}

		/* Generate the full path of the next victim. */
		snprintf(path, sizeof(path), "%s/%s", directory, ent->d_name);

		/* What we do next depends on whether or not the next item to
		 * remove is a directory. */
		if (lstat(path, &st) != -1) {
			if (S_ISDIR(st.st_mode)) {
				/* We decend into subdirectories... */
				if (lu_homedir_remove(path, error) == FALSE) {
					closedir(dir);
					return FALSE;
				}
			} else {
				/* ... and unlink everything else. */
				if (unlink(path) == -1) {
					lu_error_new(error,
						     lu_error_generic,
						     _("Error removing "
						     "`%s': %s"),
						     path,
						     strerror
						     (errno));
					closedir(dir);
					return FALSE;
				}
			}
		}
	}

	closedir(dir);

	/* As a final step, remove the directory itself. */
	if (rmdir(directory) == -1) {
		lu_error_new(error, lu_error_generic,
			     _("Error removing `%s': %s"), directory,
			     strerror(errno));
		return FALSE;
	}

	return TRUE;
}

/* Move a directory from one place to another. */
gboolean
lu_homedir_move(const char *oldhome, const char *newhome,
		struct lu_error ** error)
{
	struct stat st;

	LU_ERROR_CHECK(error);

	/* If the directory exists... */
	if (stat(oldhome, &st) != -1) {
		/* ... and we can copy it ... */
		if (lu_homedir_populate(oldhome, newhome,
					st.st_uid, st.st_gid, st.st_mode,
					error)) {
			/* ... remove the old one. */
			return lu_homedir_remove(oldhome, error);
		}
	}

	return FALSE;
}

/* Concatenate a string onto another string on the heap. */
char *
lu_strconcat(char *existing, const char *appendee)
{
	char *tmp;
	if (existing == NULL) {
		existing = g_strdup(appendee);
	} else {
		tmp = g_strconcat(existing, appendee, NULL);
		g_free(existing);
		existing = tmp;
	}
	return existing;
}

#if 0
struct conv_data {
	lu_prompt_fn *prompt;
	gpointer callback_data;
};

/* PAM callback information. */
static int
lu_converse(int num_msg, const struct pam_message **msg,
	    struct pam_response **resp, void *appdata_ptr)
{
	struct conv_data *data = appdata_ptr;
	struct lu_prompt prompts[num_msg];
	struct lu_error *error = NULL;
	struct pam_response *responses;
	char *pending = NULL, *p;
	int i;

	memset(&prompts, 0, sizeof(prompts));

	/* Convert the PAM prompts to our own prompter type. */
	for (i = 0; i < num_msg; i++) {
		switch ((*msg)[i].msg_style) {
			case PAM_PROMPT_ECHO_ON:
				/* Append this text to any pending output text
				 * we already have. */
				prompts[i].prompt = lu_strconcat(pending,
								 (*msg)[i].msg);
				p = strrchr(prompts[i].prompt, ':');
				if (p != NULL) {
					*p = '\0';
				}
				prompts[i].visible = TRUE;
				pending = NULL;
				break;
			case PAM_PROMPT_ECHO_OFF:
				/* Append this text to any pending output text
				 * we already have. */
				prompts[i].prompt = lu_strconcat(pending,
								 (*msg)[i].msg);
				p = strrchr(prompts[i].prompt, ':');
				if (p != NULL) {
					*p = '\0';
				}
				prompts[i].visible = FALSE;
				pending = NULL;
				break;
			default:
				/* Make this pending output text. */
				pending = lu_strconcat(pending, (*msg)[i].msg);
				p = strrchr(pending, ':');
				if (p != NULL) {
					*p = '\0';
				}
				break;
		}
		if (pending != NULL) {
			g_free(pending);
		}
	}

	/* Prompt the user. */
	if (data->prompt(prompts, num_msg, data->callback_data, &error)) {
		/* Allocate room for responses.  This memory will be
		 * freed by the calling application, so use malloc() instead
		 * of g_malloc() and friends. */
		responses = malloc(sizeof(struct pam_response) * i);
		if (responses == NULL) {
			return PAM_BUF_ERR;
		}
		memset(responses, 0, sizeof(struct pam_response) * i);
		/* Transcribe the responses into the PAM structure. */
		for (i = 0; i < num_msg; i++) {
			/* Set the response code and text (if we have text),
			 * and free the prompt text. */
			responses[i].resp_retcode = PAM_SUCCESS;
			if (prompts[i].value != NULL) {
				responses[i].resp = strdup(prompts[i].value);
				prompts[i].free_value(prompts[i].value);
			}
			if (prompts[i].prompt != NULL) {
				g_free((gpointer) prompts[i].prompt);
			}
		}
		/* Set the return pointer. */
		*resp = responses;
	}

	if (error != NULL) {
		lu_error_free(&error);
	}

	return PAM_CONV_ERR;
}
#endif

/* Authenticate the user if the invoking user is not privileged.  If
 * authentication fails, exit immediately. */
void
lu_authenticate_unprivileged(const char *user, const char *appname)
{
	pam_handle_t *pamh;
	struct pam_conv conv;
	const void *puser = user;
	int ret;

#if 0
	struct conv_data data;
	/* Don't bother if none of the modules makes use of elevated
	 * privileges. */
	if (lu_uses_elevated_privileges(ctx) == FALSE) {
		/* Great!  We can drop privileges. */
		if (setegid(getgid()) == -1) {
			fprintf(stderr, _("Failed to drop privileges.\n"));
			exit(1);
		}
		if (seteuid(getuid()) == -1) {
			fprintf(stderr, _("Failed to drop privileges.\n"));
			exit(1);
		}
		return;
	}

	/* Get the address of the glue conversation function. */
	lu_get_prompter(ctx, &data.prompt, &data.callback_data);
	if (data.prompt == NULL) {
		fprintf(stderr, _("Internal error.\n"));
		exit(1);
	}

	conv.conv = lu_converse;
	conv.appdata_ptr = &data;

#endif
	conv.conv = misc_conv;
	conv.appdata_ptr = NULL;

#ifdef WITH_SELINUX
	if (is_selinux_enabled() > 0) {
		if (getuid() == 0 && check_access(user, PASSWD__CHFN) != 0) {
			security_context_t user_context;
			
			if (getprevcon(&user_context) < 0)
				user_context = NULL;
			/* FIXME: "change the finger info?" */
			/* FIXME: STRING_FREEZE */
			fprintf(stderr, "%s is not authorized to change the "
				"finger info of %s\n",
				user_context ? user_context
				: "Unknown user context", user);
			if (user_context != NULL)
				freecon(user_context);
			exit(1);
		}
		/* FIXME: is this right for lpasswd? */
		if (setup_default_context("/etc/passwd") != 0) {
			/* FIXME: STRING_FREEZE */
			fprintf(stderr,
				"Can't set default context for /etc/passwd\n");
			exit(1);
		}
	}
#endif

	/* Start up PAM. */
	if (pam_start(appname, user, &conv, &pamh) != PAM_SUCCESS) {
		fprintf(stderr, _("Error initializing PAM.\n"));
		exit(1);
	}

	/* Use PAM to authenticate the user. */
	ret = pam_authenticate(pamh, 0);
	if (ret != PAM_SUCCESS) {
		pam_get_item(pamh, PAM_USER, &puser);
		fprintf(stderr, _("Authentication failed for %s.\n"),
			(const char *)puser);
		pam_end(pamh, 0);
		exit(1);
	}

	/* Make sure we authenticated the user we wanted to authenticate. */
	ret = pam_get_item(pamh, PAM_USER, &puser);
	if (ret != PAM_SUCCESS) {
		fprintf(stderr, _("Internal PAM error `%s'.\n"),
			pam_strerror(pamh, ret));
		pam_end(pamh, 0);
		exit(1);
	}
	if (strcmp(puser, user) != 0) {
		fprintf(stderr, _("User mismatch.\n"));
		pam_end(pamh, 0);
		exit(1);
	}

	/* Check if the user is allowed to run this program. */
	if (pam_acct_mgmt(pamh, 0) != PAM_SUCCESS) {
		puser = user;
		pam_get_item(pamh, PAM_USER, &puser);
		fprintf(stderr, _("Authentication failed for %s.\n"),
			(const char *)puser);
		pam_end(pamh, 0);
		exit(1);
	}

	/* Clean up -- we're done. */
	pam_end(pamh, 0);
}

/* Send nscd an arbitrary signal. */
void
lu_signal_nscd(int signum)
{
	FILE *fp;
	char buf[LINE_MAX];
	/* If it's running, then its PID is in this file.  Open it. */
	if ((fp = fopen("/var/run/nscd.pid", "r")) != NULL) {
		/* Read the PID. */
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp);
		/* If the PID is sane, send it a signal. */
		if (strlen(buf) > 0) {
			pid_t pid = atol(buf);
			if (pid != 0) {
				kill(pid, signum);
			}
		}
		fclose(fp);
	}
}

/* Send nscd a SIGHUP. */
void
lu_hup_nscd()
{
	lu_signal_nscd(SIGHUP);
}

/* Create a mail spool for the user. */
gboolean
lu_mailspool_create_remove(struct lu_context *ctx, struct lu_ent *ent,
			   gboolean action)
{
	GValueArray *array;
	GValue *value;
	const char *spooldir;
	uid_t uid;
	gid_t gid;
	char *p, *username;
	struct group grp, *err;
	struct lu_ent *groupEnt;
	struct lu_error *error = NULL;
	char buf[LINE_MAX * 4];
	int fd;

	/* Find the GID of the owner of the file. */
	gid = INVALID;
	groupEnt = lu_ent_new();
	if (lu_group_lookup_name(ctx, "mail", groupEnt, &error)) {
		array = lu_ent_get(groupEnt, LU_GIDNUMBER);
		if (array != NULL) {
			value = g_value_array_get_nth(array, 0);
			if (G_VALUE_HOLDS_LONG(value)) {
				gid = g_value_get_long(value);
			} else
			if (G_VALUE_HOLDS_STRING(value)) {
				gid = strtol(g_value_get_string(value), &p, 0);
				if (*p != '\0') {
					gid = INVALID;
				}
			} else {
				g_assert_not_reached();
			}
		}
	}
	lu_ent_free(groupEnt);

	/* Er, okay.  Check with libc. */
	if (gid == INVALID) {
		if ((getgrnam_r("mail", &grp, buf, sizeof(buf), &err) == 0) &&
		    (err == &grp)) {
			gid = grp.gr_gid;
		}
	}

	/* Aiieee.  Use the user's group. */
	if (gid == INVALID) {
		array = lu_ent_get(ent, LU_GIDNUMBER);
		if (array != NULL) {
			value = g_value_array_get_nth(array, 0);
			if (G_VALUE_HOLDS_LONG(value)) {
				gid = g_value_get_long(value);
			} else
			if (G_VALUE_HOLDS_STRING(value)) {
				gid = strtol(g_value_get_string(value), &p, 0);
				if (*p == '\0') {
					gid = INVALID;
				}
			} else {
				g_warning("Unable to determine user's GID.");
				g_assert_not_reached();
			}
		}
	}
	g_return_val_if_fail(gid != INVALID, FALSE);

	/* Now get the user's UID. */
	uid = INVALID;
	array = lu_ent_get(ent, LU_UIDNUMBER);
	if (array != NULL) {
		value = g_value_array_get_nth(array, 0);
		if (G_VALUE_HOLDS_LONG(value)) {
			uid = g_value_get_long(value);
		} else
		if (G_VALUE_HOLDS_STRING(value)) {
			uid = strtol(g_value_get_string(value), &p, 0);
			if (*p != '\0') {
				uid = INVALID;
			}
		} else {
			g_warning("Unable to determine user's UID.");
			g_assert_not_reached();
		}
	}
	g_return_val_if_fail(uid != INVALID, FALSE);

	/* Now get the user's login. */
	username = NULL;
	array = lu_ent_get(ent, LU_USERNAME);
	if (array != NULL) {
		value = g_value_array_get_nth(array, 0);
		if (G_VALUE_HOLDS_LONG(value)) {
			username = g_strdup_printf("%ld",
						   g_value_get_long(value));
		} else
		if (G_VALUE_HOLDS_STRING(value)) {
			username = g_value_dup_string(value);
		} else {
			g_warning("Unable to determine user's name.");
			g_assert_not_reached();
		}
	}
	g_return_val_if_fail(username != NULL, FALSE);

	/* Get the location of the spool directory. */
	spooldir = lu_cfg_read_single(ctx, "defaults/mailspooldir",
				      "/var/mail");

	/* That wasn't that hard.  Now we just need to create the file. */
	p = g_strdup_printf("%s/%s", spooldir, username);
	g_free(username);
	if (action) {
		fd = open(p, O_WRONLY | O_CREAT, 0);
		if (fd != -1) {
			fchown(fd, uid, gid);
			fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
			close(fd);
			g_free(p);
			return TRUE;
		}
	} else {
		if (unlink(p) == 0) {
			g_free(p);
			return TRUE;
		}
		if (errno == ENOENT) {
			g_free(p);
			return TRUE;
		}
	}
	g_free(p);

	return FALSE;
}
