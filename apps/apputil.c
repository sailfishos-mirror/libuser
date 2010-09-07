/*
 * Copyright (C) 2000-2002, 2004, 2005, 2006, 2007 Red Hat, Inc.
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

#include <config.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
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
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utime.h>
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#include <selinux/av_permissions.h>
#include <selinux/flask.h>
#include <selinux/context.h>
#endif
#include "../lib/error.h"
#include "../lib/user.h"
#include "../lib/user_private.h"
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
#endif

/* Copy the "src" directory to "dest", setting all ownerships as given, and
   setting the mode of the top-level directory as given.  The group ID of the
   copied files is preserved if it is nonzero.  If keep_contexts, preserve
   SELinux contexts in files under dest; use matchpathcon otherwise.

   Note that keep_contexts does NOT affect the context of dest; the caller must
   perform an explicit setfscreatecon() before calling lu_homedir_copy() to set
   the context of dest.  The SELinux fscreate context is on return from this
   function is unspecified. */
static gboolean
lu_homedir_copy(const char *src, const char *dest, uid_t owner, gid_t group,
		mode_t mode, gboolean keep_contexts, struct lu_error **error)
{
	struct dirent *ent;
	DIR *dir;
	int ifd, ofd;
	gboolean ret = FALSE;

	LU_ERROR_CHECK(error);

	if (*dest != '/') {
		lu_error_new(error, lu_error_generic,
			     _("Home directory path `%s' is not absolute"),
			     dest);
		goto err;
	}

	dir = opendir(src);
	if (dir == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("Error reading `%s': %s"), src,
			     strerror(errno));
		goto err;
	}

	/* Create the top-level directory. */
	if (mkdir(dest, mode) == -1 && errno != EEXIST) {
		lu_error_new(error, lu_error_generic,
			     _("Error creating `%s': %s"), dest,
			     strerror(errno));
		goto err_dir;
	}

	/* Set the ownership on the top-level directory. */
	if (chown(dest, owner, group) == -1 && errno != EPERM) {
		lu_error_new(error, lu_error_generic,
			     _("Error changing owner of `%s': %s"), dest,
			     strerror(errno));
		goto err_dir;
	}

	while ((ent = readdir(dir)) != NULL) {
		char srcpath[PATH_MAX], path[PATH_MAX], buf[PATH_MAX];
		struct stat st;
		struct utimbuf timebuf;

		/* Iterate through each item in the directory. */
		/* Skip over self and parent hard links. */
		if (strcmp(ent->d_name, ".") == 0) {
			continue;
		}
		if (strcmp(ent->d_name, "..") == 0) {
			continue;
		}

		/* Build the path of the source file or directory and its
		   corresponding member in the new tree. */
		snprintf(srcpath, sizeof(srcpath), "%s/%s", src, ent->d_name);
		snprintf(path, sizeof(path), "%s/%s", dest, ent->d_name);

		/* What we do next depends on the type of entry we're
		 * looking at. */
		if (lstat(srcpath, &st) != 0)
			continue;

		if (keep_contexts != 0) {
			if (!lu_util_fscreate_from_file(srcpath, error))
				goto err_dir;
		} else if (!lu_util_fscreate_for_path(path, st.st_mode & S_IFMT,
						      error))
			goto err_dir;

		/* We always want to preserve atime/mtime. */
		timebuf.actime = st.st_atime;
		timebuf.modtime = st.st_mtime;

		/* If it's a directory, descend into it. */
		if (S_ISDIR(st.st_mode)) {
			if (!lu_homedir_copy(srcpath, path, owner,
					     st.st_gid ?: group, st.st_mode,
					     keep_contexts, error))
				/* Aargh!  Fail up. */
				goto err_dir;
			/* Set the date on the directory. */
			utime(path, &timebuf);
			continue;
		}

		/* If it's a symlink, duplicate it. */
		if (S_ISLNK(st.st_mode)) {
			ssize_t len;

			len = readlink(srcpath, buf, sizeof(buf) - 1);
			if (len == -1) {
				lu_error_new(error, lu_error_generic,
					     _("Error reading `%s': %s"),
					     srcpath, strerror(errno));
				goto err_dir;
			}
			buf[len] = '\0';
			if (symlink(buf, path) == -1) {
				if (errno == EEXIST)
					continue;
				lu_error_new(error, lu_error_generic,
					     _("Error creating `%s': %s"),
					     path, strerror(errno));
				goto err_dir;
			}
			if (lchown(path, owner, st.st_gid ?: group) == -1
			    && errno != EPERM && errno != EOPNOTSUPP) {
				lu_error_new(error, lu_error_generic,
					     _("Error changing owner of `%s': "
					       "%s"), dest, strerror(errno));
				goto err_dir;
			}
			utime(path, &timebuf);
			continue;
		}

		/* If it's a regular file, copy it. */
		if (S_ISREG(st.st_mode)) {
			off_t offset;

			/* Open both the input and output files.  If we fail to
			   do either, we have to give up. */
			ifd = open(srcpath, O_RDONLY);
			if (ifd == -1) {
				lu_error_new(error, lu_error_open,
					     _("Error reading `%s': %s"),
					     srcpath, strerror(errno));
				goto err_dir;
			}
			ofd = open(path, O_EXCL | O_CREAT | O_WRONLY,
				   st.st_mode);
			if (ofd == -1) {
				if (errno == EEXIST) {
					close(ifd);
					continue;
				}
				lu_error_new(error, lu_error_open,
					     _("Error writing `%s': %s"),
					     path, strerror(errno));
				goto err_ifd;
			}

			/* Now just copy the data. */
			for (;;) {
				ssize_t left;
				char *p;

				left = read(ifd, &buf, sizeof(buf));
				if (left == -1) {
					if (errno == EINTR)
						continue;
					lu_error_new(error, lu_error_read,
						     _("Error reading `%s': "
						       "%s"), srcpath,
						     strerror(errno));
					goto err_ofd;
				}
				if (left == 0)
					break;
				p = buf;
				while (left > 0) {
					ssize_t out;

					out = write(ofd, p, left);
					if (out == -1) {
						if (errno == EINTR)
							continue;
						lu_error_new(error,
							     lu_error_write,
							     _("Error writing "
							       "`%s': %s"),
							     path,
							     strerror(errno));
						goto err_ofd;
					}
					p += out;
					left -= out;
				}
			}

			/* Close the files. */
			offset = lseek(ofd, 0, SEEK_CUR);
			if (offset != ((off_t) -1)) {
				if (ftruncate(ofd, offset) == -1) {
					lu_error_new(error, lu_error_generic,
						     _("Error writing `%s': "
						       "%s"), path,
						     strerror(errno));
					goto err_ofd;
				}
			}
			close (ifd);
			close (ofd);

			/* Set the ownership and timestamp on the new file. */
			if (chown(path, owner, st.st_gid ?: group) == -1
			    && errno != EPERM) {
				lu_error_new(error, lu_error_generic,
					     _("Error changing owner of `%s': "
					       "%s"), dest, strerror(errno));
				goto err_dir;
			}
			utime(path, &timebuf);
			continue;
		}
		/* Note that we don't copy device specials. */
	}
	ret = TRUE;
	goto err_dir;

 err_ifd:
	close(ifd);
 err_ofd:
	close(ofd);
 err_dir:
	closedir(dir);
 err:
	return ret;
}

/* Populate a user's home directory, copying data from a named skeleton
   directory (or default if skeleton is NULL), setting all ownerships as
   given, and setting the mode of the top-level directory as given. */
gboolean
lu_homedir_populate(struct lu_context *ctx, const char *skeleton,
		    const char *directory, uid_t owner, gid_t group,
		    mode_t mode, struct lu_error **error)
{
	lu_security_context_t fscreate;
	gboolean ret;

	if (skeleton == NULL)
		skeleton = lu_cfg_read_single(ctx, "defaults/skeleton",
					      "/etc/skel");
	ret = FALSE;
	if (!lu_util_fscreate_save(&fscreate, error))
		goto err;
	if (!lu_util_fscreate_for_path(directory, S_IFDIR, error))
		goto err_fscreate;
	ret = lu_homedir_copy(skeleton, directory, owner, group, mode, 0,
			      error);
err_fscreate:
	lu_util_fscreate_restore(fscreate);
err:
	return ret;
}

/* Recursively remove a user's home (or really, any) directory. */
gboolean
lu_homedir_remove(const char *directory, struct lu_error ** error)
{
	struct dirent *ent;
	DIR *dir;

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
		struct stat st;
		char path[PATH_MAX];

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
	lu_security_context_t fscreate;

	LU_ERROR_CHECK(error);

	/* If the directory exists... */
	if (stat(oldhome, &st) != 0)
		goto err;

	if (!lu_util_fscreate_save(&fscreate, error))
		goto err;
	if (!lu_util_fscreate_from_file(oldhome, error))
		goto err_fscreate;
	/* ... and we can copy it ... */
	if (!lu_homedir_copy(oldhome, newhome, st.st_uid, st.st_gid,
			     st.st_mode, 1, error))
		goto err_fscreate;
	lu_util_fscreate_restore(fscreate);
	/* ... remove the old one. */
	return lu_homedir_remove(oldhome, error);

err_fscreate:
	lu_util_fscreate_restore(fscreate);
err:
	return FALSE;
}

#if 0
/* Concatenate a string onto another string on the heap. */
static char *
lu_strconcat(char *existing, const char *appendee)
{
	if (existing == NULL) {
		existing = g_strdup(appendee);
	} else {
		char *tmp;
		tmp = g_strconcat(existing, appendee, NULL);
		g_free(existing);
		existing = tmp;
	}
	return existing;
}

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
				break;
		}
	}
	g_free(pending); /* Discards trailing PAM_ERROR_MSG or PAM_TEXT_INFO */

	/* Prompt the user. */
	if (data->prompt(prompts, num_msg, data->callback_data, &error)) {
		/* Allocate room for responses.  This memory will be
		 * freed by the calling application, so use malloc() instead
		 * of g_malloc() and friends. */
		responses = calloc(num_msg, sizeof(*responses));
		if (responses == NULL)
			return PAM_BUF_ERR;
		/* Transcribe the responses into the PAM structure. */
		for (i = 0; i < num_msg; i++) {
			/* Set the response code and text (if we have text),
			 * and free the prompt text. */
			responses[i].resp_retcode = PAM_SUCCESS;
			if (prompts[i].value != NULL) {
				responses[i].resp = strdup(prompts[i].value);
				prompts[i].free_value(prompts[i].value);
			}
			g_free((gpointer) prompts[i].prompt);
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
lu_authenticate_unprivileged(struct lu_context *ctx, const char *user,
			     const char *appname)
{
	pam_handle_t *pamh;
	struct pam_conv conv;
	const void *puser;
	int ret;

	/* Don't bother (us and the user) if none of the modules makes use of
	 * elevated privileges and the program is not set*id. */
	if (lu_uses_elevated_privileges(ctx) == FALSE
	    && geteuid() == getuid() && getegid() == getgid())
		return;
#if 0
	struct conv_data data;
	/* Don't bother if none of the modules makes use of elevated
	 * privileges. */
	if (lu_uses_elevated_privileges(ctx) == FALSE) {
		/* Great!  We can drop privileges. */
		if (setegid(getgid()) == -1) {
			fprintf(stderr, _("Failed to drop privileges.\n"));
			goto err;
		}
		if (seteuid(getuid()) == -1) {
			fprintf(stderr, _("Failed to drop privileges.\n"));
			goto err;
		}
		return;
	}

	/* Get the address of the glue conversation function. */
	lu_get_prompter(ctx, &data.prompt, &data.callback_data);
	if (data.prompt == NULL) {
		fprintf(stderr, _("Internal error.\n"));
		goto err;
	}

	conv.conv = lu_converse;
	conv.appdata_ptr = &data;

#endif
	conv.conv = misc_conv;
	conv.appdata_ptr = NULL;

#ifdef WITH_SELINUX
	if (is_selinux_enabled() > 0) {
		/* FIXME: PASSWD_CHSH, PASSWD_PASSWD ? */
		if (getuid() == 0 && check_access(user, PASSWD__CHFN) != 0) {
			security_context_t user_context;

			if (getprevcon(&user_context) < 0)
				user_context = NULL;
			/* FIXME: "change the finger info?" */
			fprintf(stderr,
				_("%s is not authorized to change the finger "
				  "info of %s\n"), user_context ? user_context
				: _("Unknown user context"), user);
			if (user_context != NULL)
				freecon(user_context);
			goto err;
		}
		/* FIXME: is this right for lpasswd? */
		if (!lu_util_fscreate_from_file("/etc/passwd", NULL)) {
			fprintf(stderr,
				_("Can't set default context for "
				  "/etc/passwd\n"));
			goto err;
		}
	}
#endif

	/* Start up PAM. */
	if (pam_start(appname, user, &conv, &pamh) != PAM_SUCCESS) {
		fprintf(stderr, _("Error initializing PAM.\n"));
		goto err;
	}

	/* Use PAM to authenticate the user. */
	ret = pam_authenticate(pamh, 0);
	if (ret != PAM_SUCCESS) {
		if (pam_get_item(pamh, PAM_USER, &puser) != PAM_SUCCESS
		    || puser == NULL)
			puser = user;
		fprintf(stderr, _("Authentication failed for %s.\n"),
			(const char *)puser);
		goto err_pam;
	}

	/* Make sure we authenticated the user we wanted to authenticate. */
	ret = pam_get_item(pamh, PAM_USER, &puser);
	if (ret != PAM_SUCCESS) {
		fprintf(stderr, _("Internal PAM error `%s'.\n"),
			pam_strerror(pamh, ret));
		goto err_pam;
	}
	if (puser == NULL) {
		fprintf(stderr, _("Unknown user authenticated.\n"));
		goto err_pam;
	}
	if (strcmp(puser, user) != 0) {
		fprintf(stderr, _("User mismatch.\n"));
		goto err_pam;
	}

	/* Check if the user is allowed to run this program. */
	ret = pam_acct_mgmt(pamh, 0);
	if (ret != PAM_SUCCESS) {
		if (pam_get_item(pamh, PAM_USER, &puser) != PAM_SUCCESS
		    || puser == NULL)
			puser = user;
		fprintf(stderr, _("Authentication failed for %s.\n"),
			(const char *)puser);
		goto err_pam;
	}

	/* Clean up -- we're done. */
	pam_end(pamh, PAM_SUCCESS);
	return;

err_pam:
	pam_end(pamh, ret);
err:
	exit(1);
}

/* Flush the specified nscd cache */
void
lu_nscd_flush_cache (const char *table)
{
	static char *const envp[] = { NULL };

	posix_spawn_file_actions_t fa;
        char *argv[4];
        pid_t pid;

	if (posix_spawn_file_actions_init(&fa) != 0
	    || posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null",
						O_RDWR, 0) != 0)
                return;

	argv[0] = NSCD;
	argv[1] = "-i";
	argv[2] = (char *)table;
	argv[3] = NULL;
	if (posix_spawn(&pid, argv[0], &fa, NULL, argv, envp) != 0)
		return;
	posix_spawn_file_actions_destroy(&fa);

        /* Wait for the spawned process to exit */
	while (waitpid(pid, NULL, 0) == -1 && errno == EINTR)
		; /* Nothing */
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
	struct lu_ent *groupEnt;
	struct lu_error *error = NULL;

	/* Find the GID of the owner of the file. */
	gid = LU_VALUE_INVALID_ID;
	groupEnt = lu_ent_new();
	if (lu_group_lookup_name(ctx, "mail", groupEnt, &error)) {
		array = lu_ent_get(groupEnt, LU_GIDNUMBER);
		if (array != NULL) {
			value = g_value_array_get_nth(array, 0);
			gid = lu_value_get_id(value);
		}
	}
	if (error != NULL)
		lu_error_free(&error);
	lu_ent_free(groupEnt);

	/* Er, okay.  Check with libc. */
	if (gid == LU_VALUE_INVALID_ID) {
		struct group grp, *err;
		char buf[LINE_MAX * 4];

		if ((getgrnam_r("mail", &grp, buf, sizeof(buf), &err) == 0) &&
		    (err == &grp)) {
			gid = grp.gr_gid;
		}
	}

	/* Aiieee.  Use the user's group. */
	if (gid == LU_VALUE_INVALID_ID) {
		array = lu_ent_get(ent, LU_GIDNUMBER);
		if (array != NULL) {
			value = g_value_array_get_nth(array, 0);
			gid = lu_value_get_id(value);
		}
	}
	g_return_val_if_fail(gid != LU_VALUE_INVALID_ID, FALSE);

	/* Now get the user's UID. */
	uid = LU_VALUE_INVALID_ID;
	array = lu_ent_get(ent, LU_UIDNUMBER);
	if (array != NULL) {
		value = g_value_array_get_nth(array, 0);
		uid = lu_value_get_id(value);
	}
	g_return_val_if_fail(uid != LU_VALUE_INVALID_ID, FALSE);

	/* Now get the user's login. */
	username = NULL;
	array = lu_ent_get(ent, LU_USERNAME);
	if (array != NULL) {
		value = g_value_array_get_nth(array, 0);
		username = lu_value_strdup(value);
	}
	g_return_val_if_fail(username != NULL, FALSE);

	/* Get the location of the spool directory. */
	spooldir = lu_cfg_read_single(ctx, "defaults/mailspooldir",
				      "/var/mail");

	/* That wasn't that hard.  Now we just need to create the file. */
	p = g_strconcat(spooldir, "/", username, (const gchar *)NULL);
	g_free(username);
	if (action) {
		int fd;

		fd = open(p, O_WRONLY | O_CREAT, 0);
		if (fd != -1) {
			gboolean res = TRUE;

			if (fchown(fd, uid, gid) == -1)
				res = FALSE;
			if (fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)
			    == -1)
				res = FALSE;
			close(fd);
			g_free(p);
			return res;
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
