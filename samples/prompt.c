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
