#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <libuser/user.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include "apputil.h"

int
main(int argc, const char **argv)
{
	const char *userPassword = NULL, *cryptedUserPassword = NULL,
		   *uid = NULL, *user = NULL, *gecos = NULL, *oldHomeDirectory,
		   *homeDirectory = NULL, *loginShell = NULL;
	long uidNumber = -2, gidNumber = -2;
	struct lu_context *ctx = NULL;
	struct lu_ent *ent = NULL;
	GList *values;
	int change = FALSE, move_home = FALSE, lock = FALSE, unlock = FALSE;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		{"gecos", 'c', POPT_ARG_STRING, &gecos, 0,
		 "GECOS information", "STRING"},
		{"directory", 'd', POPT_ARG_STRING, &homeDirectory, 0,
		 "home directory", "STRING"},
#ifdef FIXMEFIXMEFIXME
		{"movedirectory", 'm', POPT_ARG_NONE, &move_home, 0,
		 "move home directory contents"},
#endif
		{"shell", 's', POPT_ARG_STRING, &loginShell, 0,
		 "set shell for user", "STRING"},
		{"uid", 'u', POPT_ARG_LONG, &uidNumber, 0,
		 "set UID for user", "NUM"},
		{"gid", 'g', POPT_ARG_LONG, &gidNumber, 0,
		 "set primary GID for user", "NUM"},
		{"login", 'l', POPT_ARG_STRING, &uid, 0,
		 "change login name for user", "STRING"},
		{"plainpassword", 'P', POPT_ARG_STRING, &userPassword, 0,
		 "plaintext password for use with group", "STRING"},
		{"password", 'p', POPT_ARG_STRING, &cryptedUserPassword, 0,
		 "pre-hashed password for use with group", "STRING"},
		{"lock", 'L', POPT_ARG_NONE, &lock, 0, "lock account"},
		{"unlock", 'U', POPT_ARG_NONE, &unlock, 0, "unlock account"},
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0,},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lusermod", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	g_return_val_if_fail(c == -1, 0);
	user = poptGetArg(popt);

	if(user == NULL) {
		fprintf(stderr, _("No user name specified.\n"));
		return 1;
	}

	ctx = lu_start(NULL, 0, NULL, NULL, lu_prompt_console, NULL);
	g_return_val_if_fail(ctx != NULL, 1);

	if(lock && unlock) {
		fprintf(stderr, _("Both -L and -U specified.\n"));
		return 2;
	}

	ent = lu_ent_new();

	if(lu_user_lookup_name(ctx, user, ent) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		return 3;
	}

	change = userPassword || cryptedUserPassword || uid ||
		 gecos || oldHomeDirectory || homeDirectory || loginShell ||
		 (uidNumber != -2) || (gidNumber != -2);

	if(loginShell)
		lu_ent_set(ent, LU_LOGINSHELL, loginShell);
	if(uidNumber != -2) {
		char *tmp = g_strdup_printf("%ld", uidNumber);
		lu_ent_set(ent, LU_UIDNUMBER, tmp);
		g_free(tmp);
	}
	if(gidNumber != -2) {
		char *tmp = g_strdup_printf("%ld", gidNumber);
		lu_ent_set(ent, LU_GIDNUMBER, tmp);
		g_free(tmp);
	}
	if(uid)
		lu_ent_set(ent, LU_USERNAME, uid);
	if(gecos)
		lu_ent_set(ent, LU_GECOS, gecos);
	if(homeDirectory) {
		values = lu_ent_get(ent, LU_HOMEDIRECTORY);
		if(values) {
			oldHomeDirectory = values->data;
		} else {
			fprintf(stderr, _("Error reading old home "
				"directory for %s.\n"), user);
			return 4;
		}
		lu_ent_set(ent, LU_HOMEDIRECTORY, homeDirectory);
	}

	if(userPassword) {
		values = lu_ent_get(ent, LU_USERPASSWORD);
		if(values && values->data) {
			cryptedUserPassword = make_crypted(userPassword,
							   values->data);
		} else {
			cryptedUserPassword = make_crypted(userPassword,
							   DEFAULT_SALT);
		}
	}

	if(cryptedUserPassword) {
		char *tmp = NULL;
		tmp = g_strconcat("{crypt}", cryptedUserPassword, NULL);
		lu_ent_set(ent, LU_USERPASSWORD, tmp);
		g_free(tmp);
	}
	if(userPassword) {
		lu_ent_add(ent, LU_USERPASSWORD, userPassword);
	}

	if(lock) {
		if(lu_user_lock(ctx, ent) == FALSE) {
			fprintf(stderr, _("User %s could not be locked.\n"),
				user);
			return 5;
		}
	}

	if(unlock) {
		if(lu_user_unlock(ctx, ent) == FALSE) {
			fprintf(stderr, _("User %s could not be unlocked.\n"),
				user);
			return 6;
		}
	}

	if(change && (lu_user_modify(ctx, ent) == FALSE)) {
		fprintf(stderr, _("User %s could not be modified.\n"), user);
		return 7;
	}

	if(change && move_home) {
		if(oldHomeDirectory == NULL) {
			fprintf(stderr, _("No old home directory for %s.\n"),
				user);
			return 8;
		}
		if(homeDirectory == NULL) {
			fprintf(stderr, _("No new home directory for %s.\n"),
				user);
			return 9;
		}
		if(move_homedir(oldHomeDirectory, homeDirectory) == FALSE) {
			fprintf(stderr, _("Error moving %s to %s.\n"),
				oldHomeDirectory, homeDirectory);
			return 10;
		}
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
