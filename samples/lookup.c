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
	struct lu_context *lu;
	gboolean success = FALSE, group = FALSE, byid = FALSE;
	int c;
	struct lu_ent *ent, *tmp;
	const char *auth_modules = NULL, *info_modules = NULL;
	GList *attributes;

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	while((c = getopt(argc, argv, "a:i:gn")) != -1) {
		switch(c) {
			case 'g': group = TRUE;
				  break;
			case 'n': byid = TRUE;
				  break;
			case 'a': auth_modules = optarg;
				  break;
			case 'i': info_modules = optarg;
				  break;
			default:
				  break;
		}
	}

	lu = lu_start(NULL, 0, auth_modules, info_modules, lu_prompt_console, NULL);

	if(lu == NULL) {
		g_print(gettext("Error initializing lu.\n"));
		return 1;
	}

	c = optind < argc ? atol(argv[optind]) : 0;

	tmp = lu_ent_new();
	if(group) {
		if(byid) {
			g_print(gettext("Searching for group with ID %d.\n"), c);
			success = lu_group_lookup_id(lu, c, tmp);
		} else {
			g_print(gettext("Searching for group named %s.\n"),
				argv[optind]);
			success = lu_group_lookup_name(lu, argv[optind], tmp);
		}
	} else {
		if(byid) {
			g_print(gettext("Searching for user with ID %d.\n"), c);
			success = lu_user_lookup_id(lu, c, tmp);
		} else {
			g_print(gettext("Searching for user named %s.\n"),
				argv[optind]);
			success = lu_user_lookup_name(lu, argv[optind], tmp);
		}
	}

	ent = tmp;
	if(success) {
		GList *a;
		attributes = lu_ent_get_attributes(ent);
		for(a = attributes; a && a->data; a = g_list_next(a)) {
			if(lu_ent_get(ent, (char*) a->data) != NULL) {
				GList *l = NULL;
				for(l = lu_ent_get(ent, (char*) a->data);
				    l;
				    l = g_list_next(l)) {
					g_print(" %s = \"%s\"\n",
						(char*) a->data,
						(char*) l->data);
				}
			}
		}
		g_list_free(attributes);
	} else {
		g_print(gettext("Entry not found.\n"));
	}

	lu_ent_free(ent);

	lu_end(lu);

	return 0;
}
