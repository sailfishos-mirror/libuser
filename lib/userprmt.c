#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <libuser/user_private.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>

gboolean
lu_prompt_console(struct lu_context *context, struct lu_prompt *prompts,
		  int count, gpointer calldata)
{
	int i;
	char buf[LINE_MAX];
	gboolean ret = TRUE;
	struct termios otermios, ntermios;

	g_return_val_if_fail(context != NULL, FALSE);
	if(count > 0) {
		g_return_val_if_fail(prompts != NULL, FALSE);
	}

	for(i = 0; i < count; i++) {
		if(prompts[i].prompt) {
			g_print("%s", prompts[i].prompt);
		}
		if(prompts[i].visible && prompts[i].default_value) {
			g_print(" [");
			g_print("%s", prompts[i].default_value);
			g_print("]: ");
		} else {
			g_print(": ");
		}

		prompts[i].value = NULL;
		prompts[i].free_value = NULL;

		if(prompts[i].visible == FALSE) {
			if(tcgetattr(fileno(stdin), &otermios) == -1) {
				ret = FALSE;
				break;
			}
			ntermios = otermios;
			ntermios.c_lflag &= ~ECHO;
			if(tcsetattr(fileno(stdin), TCSADRAIN, &ntermios) == -1) {
				ret = FALSE;
				break;
			}
		}
		if(fgets(buf, sizeof(buf), stdin) == NULL) {
			ret = FALSE;
			break;
		}
		if(prompts[i].visible == FALSE) {
			if(tcsetattr(fileno(stdin), TCSADRAIN, &otermios) == -1) {
				ret = FALSE;
				break;
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
	return ret;
}
