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
	struct lu_context *ctx;
	struct lu_ent *ent;
	int remove_home = FALSE;
	const char *user = NULL;
	GList *values;
	int c;

	poptContext popt;
	struct poptOption options[] = {
#ifdef FIXMEFIXMEFIXME
		{"removehome", 'r', POPT_ARG_NONE, NULL, 0,
		 "remove the user's home directory", NULL},
#endif
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0,},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("luserdel", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] user"));
	c = poptGetNextOpt(popt);
	g_return_val_if_fail(c == -1, 0);
	user = poptGetArg(popt);

	ctx = lu_start(NULL, 0, NULL, NULL, lu_prompt_console, NULL);
	g_return_val_if_fail(ctx != NULL, 1);

	if(user == NULL) {
		fprintf(stderr, _("No user name specified.\n"));
		return 1;
	}

	ent = lu_ent_new();

	if(lu_user_lookup_name(ctx, user, ent) == FALSE) {
		fprintf(stderr, _("User %s does not exist.\n"), user);
		return 2;
	}

	if(lu_user_delete(ctx, ent) == FALSE) {
		fprintf(stderr, _("User %s could not be deleted.\n"), user);
		return 3;
	}

#ifdef FIXMEFIXMEFIXME
	if(remove_home) {
		values = lu_ent_get(ent, "homeDirectory");
		if(!(values && values->data)) {
			fprintf(stderr, _("%s did not have a home "
					  "directory.\n"), user);
			return 4;
		} else {
			if(remove_homedir(values->data) == FALSE) {
				fprintf(stderr, _("Error removing %s.\n"),
					(char*)values->data);
				return 5;
			}
		}
	}
#endif

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
