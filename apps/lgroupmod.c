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
		   *gid = NULL, *addAdmins = NULL, *remAdmins = NULL,
		   *addMembers = NULL, *remMembers = NULL, *group = NULL;
	char **admins = NULL, **members = NULL;
	long gidNumber = -2;
	struct lu_context *ctx = NULL;
	struct lu_ent *ent = NULL;
	int change = FALSE, lock = FALSE, unlock = FALSE;
	GList *values;
	int c;

        poptContext popt;
	struct poptOption options[] = {
		{"gid", 'g', POPT_ARG_LONG, &gidNumber, 0,
		 "gid to change group to", "NUM"},
		{"name", 'n', POPT_ARG_STRING, &gid, 0,
		 "change group to have given name", "NAME"},
		{"plainpassword", 'P', POPT_ARG_STRING, &userPassword, 0,
		 "plaintext password for use with group", "STRING"},
		{"password", 'p', POPT_ARG_STRING, &cryptedUserPassword, 0,
		 "pre-hashed password for use with group", "STRING"},
		{"admin-add", 'A', POPT_ARG_STRING, &addAdmins, 0,
		 "list of administrators to add", "STRING"},
		{"admin-remove", 'a', POPT_ARG_STRING, &remAdmins, 0,
		 "list of administrators to remove", "STRING"},
		{"member-add", 'M', POPT_ARG_STRING, &addMembers, 0,
		 "list of group members to add", "STRING"},
		{"member-remove", 'm', POPT_ARG_STRING, &remMembers, 0,
		 "list of group members to remove", "STRING"},
		{"lock", 'L', POPT_ARG_NONE, &lock, 0, "lock group"},
		{"unlock", 'U', POPT_ARG_NONE, &unlock, 0, "unlock group"},
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("groupmod", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] group"));
        c = poptGetNextOpt(popt);
        g_return_val_if_fail(c == -1, 0);
	group = poptGetArg(popt);

	ctx = lu_start(NULL, 0, NULL, NULL, lu_prompt_console, NULL);
	g_return_val_if_fail(ctx != NULL, 1);

	if(group == NULL) {
		fprintf(stderr, _("No group name specified.\n"));
		return 1;
	}

	if(lock && unlock) {
		fprintf(stderr, _("Both -L and -U specified.\n"));
		return 2;
	}

	ent = lu_ent_new();

	if(lu_group_lookup_name(ctx, group, ent) == FALSE) {
		fprintf(stderr, _("Group %s does not exist.\n"), group);
		return 3;
	}

	change = gid || addAdmins || remAdmins || cryptedUserPassword ||
		 addMembers || remMembers || (gidNumber != -2);

	if(gid)
		lu_ent_set(ent, LU_GROUPNAME, gid);
	if(gidNumber != -2) {
		char *tmp = g_strdup_printf("%ld", gidNumber);
		lu_ent_set(ent, LU_GIDNUMBER, tmp);
		g_free(tmp);
	}

	if(addAdmins) {
		admins = g_strsplit(addAdmins, ",", 0);
		if(admins) {
			for(c = 0; admins && admins[c]; c++) {
				lu_ent_add(ent, LU_ADMINISTRATORUID, admins[c]);
			}
			g_strfreev(admins);
			admins = NULL;
		}
	}
	if(remAdmins) {
		admins = g_strsplit(remAdmins, ",", 0);
		if(admins) {
			for(c = 0; admins && admins[c]; c++) {
				lu_ent_del(ent, LU_ADMINISTRATORUID, admins[c]);
			}
			g_strfreev(admins);
			admins = NULL;
		}
	}

	if(addMembers) {
		members = g_strsplit(addMembers, ",", 0);
		if(members) {
			for(c = 0; members && members[c]; c++) {
				lu_ent_add(ent, LU_MEMBERUID, members[c]);
			}
			g_strfreev(members);
			members = NULL;
		}
	}
	if(remMembers) {
		members = g_strsplit(remMembers, ",", 0);
		if(members) {
			for(c = 0; members && members[c]; c++) {
				lu_ent_del(ent, LU_MEMBERUID, members[c]);
			}
			g_strfreev(members);
			members = NULL;
		}
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

	if(lock) {
		if(lu_group_lock(ctx, ent) == FALSE) {
			fprintf(stderr, _("Group %s could not be locked.\n"),
				group);
			return 4;
		}
	}

	if(unlock) {
		if(lu_group_unlock(ctx, ent) == FALSE) {
			fprintf(stderr, _("Group %s could not be unlocked.\n"),
				group);
			return 5;
		}
	}

	if(change && lu_group_modify(ctx, ent) == FALSE) {
		fprintf(stderr, _("Group %s could not be modified.\n"), group);
		return 6;
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
