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
	const char *group;
	int c;

	poptContext popt;
	struct poptOption options[] = {
		POPT_AUTOHELP {NULL, '\0', POPT_ARG_NONE, NULL, 0, NULL},
	};

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	popt = poptGetContext("lgroupdel", argc, argv, options, 0);
	poptSetOtherOptionHelp(popt, _("[OPTION...] group"));
	c = poptGetNextOpt(popt);
	g_return_val_if_fail(c == -1, 0);
	group = poptGetArg(popt);

	if(group == NULL) {
		fprintf(stderr, _("No group name specified.\n"));
		return 1;
	}

	ctx = lu_start(NULL, 0, NULL, NULL, lu_prompt_console, NULL);
	g_return_val_if_fail(ctx != NULL, 1);

	ent = lu_ent_new();

	if(lu_group_lookup_name(ctx, group, ent) == FALSE) {
		fprintf(stderr, _("Group %s does not exist.\n"), group);
		return 2;
	}

	if(lu_group_delete(ctx, ent) == FALSE) {
		fprintf(stderr, _("Group %s could not be deleted.\n"), group);
		return 3;
	}

	lu_ent_free(ent);

	lu_end(ctx);

	return 0;
}
