#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <libuser/user.h>
#include <libuser/user_private.h>
#include <stdlib.h>
#include <libintl.h>
#include <locale.h>

void dump_attribute(gpointer key, gpointer value, gpointer data)
{
	GList *list;
	for(list = (GList*) value; list; list = g_list_next(list))
		g_print(" %s = %s\n", (char*) key, (char*) list->data);
}

int main(int argc, char **argv)
{
	struct lu_context *ctx;
	struct lu_ent *ent, *tmp, *temp;
	GList *ret = NULL;
	int i;
	void *control = NULL;

	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	setlocale(LC_ALL, "");

	control = g_malloc0(65536);

	ctx = lu_start(NULL, 0, NULL, NULL, lu_prompt_console, NULL);

	if(ctx == NULL) {
		g_print(gettext("Error initializing lu.\n"));
		exit(1);
	}

	g_print(gettext("Default user object classes:\n"));
	ret = lu_cfg_read(ctx, "userdefaults/objectclass", "bar");
	for(i = 0; i < g_list_length(ret); i++) {
		g_print(" %s\n", (char*) g_list_nth(ret, i)->data);
	}

	g_print(gettext("Default user attribute names:\n"));
	ret = lu_cfg_read_keys(ctx, "userdefaults");
	for(i = 0; i < g_list_length(ret); i++) {
		g_print(" %s\n", (char*) g_list_nth(ret, i)->data);
	}

	g_print(gettext("Getting default user attributes:\n"));
	ent = lu_ent_new();
	lu_ent_user_default(ctx, "newuser", FALSE, ent);
	g_hash_table_foreach(ent->attributes, dump_attribute, NULL);

	g_print(gettext("Copying user structure:\n"));
	tmp = lu_ent_new();
	lu_ent_copy(ent, tmp);
	temp = lu_ent_new();
	lu_ent_copy(tmp, temp);
	g_hash_table_foreach(temp->attributes, dump_attribute, NULL);

	lu_ent_free(ent);
	lu_ent_free(tmp);
	lu_ent_free(temp);

	lu_end(ctx);

	g_free(control);

	return 0;
}
