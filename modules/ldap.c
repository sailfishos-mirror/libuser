/* Copyright (C) 2000,2001 Red Hat, Inc.
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
#include "config.h"
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <ldap.h>
#include <limits.h>
#include <pwd.h>
#include <sasl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/libuser/user_private.h"

#undef  DEBUG
#define SCHEME "{crypt}"
#define LOCKCHAR '!'
#define LOCKSTRING "!"
#define USERBRANCH "ou=People"
#define GROUPBRANCH "ou=Group"

enum interact_indices {
	LU_LDAP_SERVER,
	LU_LDAP_BASEDN,
	LU_LDAP_BINDDN,
	LU_LDAP_PASSWORD,
	LU_LDAP_USER,
	LU_LDAP_AUTHUSER,
	LU_LDAP_MAX,
};

struct lu_module *
lu_ldap_init(struct lu_context *context, struct lu_error **error);

static char *
lu_ldap_user_attributes[] = {
	LU_OBJECTCLASS,
	LU_USERNAME,
	LU_USERPASSWORD,
	LU_UIDNUMBER,
	LU_GIDNUMBER,
	LU_GECOS,
	LU_HOMEDIRECTORY,
	LU_LOGINSHELL,

	LU_SHADOWLASTCHANGE,
	LU_SHADOWMIN,
	LU_SHADOWMAX,
	LU_SHADOWWARNING,
	LU_SHADOWINACTIVE,
	LU_SHADOWEXPIRE,
	LU_SHADOWFLAG,

	LU_CN,
	LU_GIVENNAME,
	LU_SN,
	LU_ROOMNUMBER,
	LU_TELEPHONENUMBER,
	LU_HOMEPHONE,

	NULL,
};

static char *
lu_ldap_group_attributes[] = {
	LU_OBJECTCLASS,
	LU_GROUPNAME,
	LU_USERPASSWORD,
	LU_GIDNUMBER,
	LU_MEMBERUID,
	LU_ADMINISTRATORUID,

	LU_SHADOWLASTCHANGE,
	LU_SHADOWMIN,
	LU_SHADOWMAX,
	LU_SHADOWWARNING,
	LU_SHADOWINACTIVE,
	LU_SHADOWEXPIRE,
	LU_SHADOWFLAG,

	NULL,
};

struct lu_ldap_context {
	struct lu_context *global_context;
        struct lu_prompt prompts[LU_LDAP_MAX];
	LDAP *ldap;
};

static void
close_server(LDAP *ldap)
{
	ldap_unbind_s(ldap);
}

static char *
getuser()
{
	char buf[LINE_MAX];
	struct passwd pwd, *err;
	int ret;
	getpwuid_r(getuid(), &pwd, buf, sizeof(buf), &err);
	return (err == &pwd) ? strdup(pwd.pw_name) : NULL;
}

static int
interact(LDAP *ld, unsigned flags, void *defs, void *interact_data)
{
	sasl_interact_t *interact;
	struct lu_ldap_context *ctx = (struct lu_ldap_context*) defs;
	int i, retval = LDAP_SUCCESS;

	for(i = 0, retval = LDAP_SUCCESS, interact = interact_data;
	    interact && (interact[i].id != SASL_CB_LIST_END);
	    i++) {
		interact[i].result = NULL;
		interact[i].len = 0;
		switch(interact[i].id) {
			case SASL_CB_USER:
				interact[i].result = ctx->prompts[LU_LDAP_USER].value ?: "";
				interact[i].len = strlen(interact[i].result);
#ifdef DEBUG
				g_print("Sending SASL user `%s'.\n", (char*)interact[i].result);
#endif
				break;
			case SASL_CB_AUTHNAME:
				interact[i].result = ctx->prompts[LU_LDAP_AUTHUSER].value;
				interact[i].len = strlen(interact[i].result);
#ifdef DEBUG
				g_print("Sending SASL auth user `%s'.\n", (char*)interact[i].result);
#endif
				break;
			default:
				retval = LDAP_OTHER;
		}
	}
	return retval;
}

/* Connect to the server. */
static LDAP *
bind_server(struct lu_ldap_context *context, struct lu_error **error)
{
	LDAP *ldap = NULL;
	LDAPControl *server = NULL, *client = NULL;
	int version = LDAP_VERSION3;
	char *generated_binddn = "", *tmp;
	char *user;
	struct lu_string_cache *scache = NULL;

	g_assert(context != NULL);
	LU_ERROR_CHECK(error);

	ldap = ldap_init(context->prompts[LU_LDAP_SERVER].value, LDAP_PORT);
	if(ldap == NULL) {
		lu_error_new(error, lu_error_init, _("error initializing ldap library"));
		return NULL;
	}

	scache = context->global_context->scache;
	user = getuser();
	if(user) {
		char *tmp = scache->cache(scache, user);
		free(user);
		user = tmp;
	}
	tmp = g_strdup_printf("uid=%s,%s,%s", user,
			      lu_cfg_read_single(context->global_context, "ldap/userBranch", USERBRANCH),
			      context->prompts[LU_LDAP_BASEDN].value);
	generated_binddn = scache->cache(scache, tmp);
	g_free(tmp);

	if(ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_OPT_SUCCESS) {
		lu_error_new(error, lu_error_init, _("could not set LDAP protocol to version %d"), version);
		close_server(ldap);
		return NULL;
	}

	if(ldap_start_tls_s(ldap, &server, &client) != LDAP_SUCCESS) {
		lu_error_new(error, lu_error_init, _("could not negotiate TLS with LDAP server"));
		close_server(ldap);
		return NULL;
	}

	if(ldap_sasl_interactive_bind_s(ldap, NULL, NULL, NULL, NULL,
					LDAP_SASL_AUTOMATIC | LDAP_SASL_QUIET,
					interact, context) != LDAP_SUCCESS)
	if(ldap_simple_bind_s(ldap,
			      context->prompts[LU_LDAP_BINDDN].value,
			      context->prompts[LU_LDAP_PASSWORD].value) != LDAP_SUCCESS)
	if(ldap_simple_bind_s(ldap,
			      generated_binddn,
			      context->prompts[LU_LDAP_PASSWORD].value) != LDAP_SUCCESS) {
		lu_error_new(error, lu_error_init, _("could not bind to LDAP server"));
		close_server(ldap);
		return NULL;
	}

	return ldap;
}

/* Generate the distinguished name which corresponds to the lu_ent structure. */
static const char *
lu_ldap_ent_to_dn(struct lu_module *module, struct lu_ent *ent, const char *namingAttr, const char *name,
		  const char *configKey, const char *def)
{
	struct lu_ldap_context *context = module->module_context;
	const char *branch = NULL;
	char *tmp = NULL, *ret = NULL;

	g_assert(module != NULL);
	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);
	g_assert(namingAttr != NULL);
	g_assert(strlen(namingAttr) > 0);
	g_assert(name != NULL);
	g_assert(strlen(name) > 0);
	g_assert(configKey != NULL);
	g_assert(strlen(configKey) > 0);

	tmp = g_strdup_printf("ldap/%s", configKey);
	branch = lu_cfg_read_single(module->lu_context, tmp, def);
	g_free(tmp);

	if(branch) {
		tmp = g_strdup_printf("%s=%s,%s,%s", namingAttr, name, branch, context->prompts[LU_LDAP_BASEDN].value);
		ret = module->scache->cache(module->scache, tmp);
		g_free(tmp);
	}

	return ret;
}

/* Generate the distinguished name which corresponds to the lu_ent structure. */
static const char *
lu_ldap_base(struct lu_module *module, const char *configKey, const char *def)
{
	struct lu_ldap_context *context = module->module_context;
	const char *branch = NULL;
	char *tmp = NULL, *ret = NULL;

	g_assert(module != NULL);
	g_assert(configKey != NULL);
	g_assert(strlen(configKey) > 0);

	tmp = g_strdup_printf("ldap/%s", configKey);
	branch = lu_cfg_read_single(module->lu_context, tmp, def);
	g_free(tmp);

	if(branch) {
		tmp = g_strdup_printf("%s,%s", branch, context->prompts[LU_LDAP_BASEDN].value);
	} else {
		tmp = g_strdup(context->prompts[LU_LDAP_BASEDN].value);
	}

	ret = module->scache->cache(module->scache, tmp);

	g_free(tmp);

	return ret;
}

/* This is the lookup workhorse. */
static gboolean
lu_ldap_lookup(struct lu_module *module, const char *namingAttr, const char *name, struct lu_ent *ent,
	       const char *configKey, const char *def, const char *filter, char **attributes, struct lu_error **error)
{
	LDAPMessage *messages = NULL, *entry = NULL;
	const char *attr;
	char *filt = NULL, **values = NULL;
	const char *dn = NULL;
	const char *base = NULL;
	int i, j;
	gboolean ret = FALSE;
	struct lu_ldap_context *ctx;

	g_assert(module != NULL);
	g_assert(namingAttr != NULL);
	g_assert(strlen(namingAttr) > 0);
	g_assert(name != NULL);
	g_assert(strlen(name) > 0);
	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);
	g_assert(configKey != NULL);
	g_assert(strlen(configKey) > 0);
	g_assert(attributes != NULL);
	g_assert(attributes[0] != NULL);
	LU_ERROR_CHECK(error);

	ctx = module->module_context;

	dn = lu_ldap_ent_to_dn(module, ent, namingAttr, name, configKey, def);
	if(dn == NULL) {
		lu_error_new(error, lu_error_generic, _("error mapping name to LDAP distinguished name"));
		return FALSE;
	}
	base = lu_ldap_base(module, configKey, def);
	if(base == NULL) {
		lu_error_new(error, lu_error_generic, _("error mapping name to LDAP base distinguished name"));
		return FALSE;
	}

	if(filter && (strlen(filter) > 0)) {
		filt = g_strdup_printf("(&%s(%s=%s))", filter, namingAttr, name);
	} else {
		filt = g_strdup_printf("(%s=%s)", namingAttr, name);
	}

#ifdef DEBUG
	g_print("Looking up `%s' with filter `%s'.\n", dn, filt);
#endif

	if(ldap_search_s(ctx->ldap, dn, LDAP_SCOPE_BASE, filt, attributes, FALSE, &messages) == LDAP_SUCCESS) {
		entry = ldap_first_entry(ctx->ldap, messages);
	}
	if(entry == NULL) {
#ifdef DEBUG
		g_print("Looking under `%s' with filter `%s'.\n", base, filt);
#endif
		if(ldap_search_s(ctx->ldap, base, LDAP_SCOPE_SUBTREE, filt, attributes, FALSE, &messages) == LDAP_SUCCESS) {
			entry = ldap_first_entry(ctx->ldap, messages);
		}
	}
	if(entry != NULL) {
		for(i = 0; attributes[i]; i++) {
			attr = attributes[i];
			values = ldap_get_values(ctx->ldap, entry, attr);
			if(values) {
				lu_ent_clear_original(ent, attr);
				for(j = 0; values[j]; j++) {
#ifdef DEBUG
					g_print("Got `%s' = `%s'.\n", attr, values[j]);
#endif
					lu_ent_add_original(ent, attr, values[j]);
				}
			}
		}
		ret = TRUE;
	} else {
#ifdef DEBUG
		g_print("No such entry found in directory.\n");
#endif
		lu_error_new(error, lu_error_generic, _("error searching LDAP directory"));
		ret = FALSE;
	}

	return ret;
}

static gboolean
lu_ldap_user_lookup_name(struct lu_module *module, gconstpointer name, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_lookup(module, LU_USERNAME, name, ent, "userBranch", USERBRANCH, "(objectclass=posixAccount)",
			      lu_ldap_user_attributes, error);
}

static gboolean
lu_ldap_user_lookup_id(struct lu_module *module, gconstpointer uid, struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = FALSE;
	gchar *uid_string = NULL;

	LU_ERROR_CHECK(error);
	uid_string = g_strdup_printf("%d", GPOINTER_TO_INT(uid));
	ret = lu_ldap_lookup(module, LU_UIDNUMBER, uid_string, ent, "userBranch", USERBRANCH, "(objectclass=posixAccount)",
			     lu_ldap_user_attributes, error);
	g_free(uid_string);

	return ret;
}

static gboolean
lu_ldap_group_lookup_name(struct lu_module *module, gconstpointer name, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_lookup(module, LU_GROUPNAME, name, ent, "groupBranch", GROUPBRANCH, "(objectclass=posixGroup)",
			      lu_ldap_group_attributes, error);
}

static gboolean
lu_ldap_group_lookup_id(struct lu_module *module, gconstpointer gid, struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = FALSE;
	gchar *gid_string = NULL;

	LU_ERROR_CHECK(error);
	gid_string = g_strdup_printf("%d", GPOINTER_TO_INT(gid));
	ret = lu_ldap_lookup(module, LU_GIDNUMBER, gid_string, ent, "groupBranch", GROUPBRANCH, "(objectclass=posixGroup)",
			     lu_ldap_group_attributes, error);
	g_free(gid_string);

	return ret;
}

static gboolean
lists_equal(GList *a, GList *b)
{
	GList *i;
	if(g_list_length(a) != g_list_length(b))
		return FALSE;
	for(i = a; i != NULL; i = g_list_next(i)) {
		if(g_list_index(b, i->data) < 0)
			return FALSE;
	}
	for(i = b; i != NULL; i = g_list_next(i)) {
		if(g_list_index(a, i->data) < 0)
			return FALSE;
	}
	return TRUE;
}

static LDAPMod **
get_ent_mods(struct lu_ent *ent)
{
	LDAPMod **mods = NULL;
	GList *attrs = NULL, *values = NULL;
	int i, j, k, l;

	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);

	attrs = lu_ent_get_attributes(ent);
	if(attrs) {
		mods = g_malloc0(sizeof(LDAPMod*) * (g_list_length(attrs) + 1));
		for(i = j = 0; g_list_nth(attrs, i); i++) {
			GList *original, *current;
			current = lu_ent_get(ent, g_list_nth(attrs, i)->data);
			original = lu_ent_get_original(ent, g_list_nth(attrs, i)->data);
			if(lists_equal(current, original)) {
#ifdef DEBUG
				g_print("`%s' attribute unchanged\n", g_list_nth(attrs, i)->data);
#endif
				continue;
			}
			mods[j] = g_malloc0(sizeof(LDAPMod));
			mods[j]->mod_op = LDAP_MOD_REPLACE;
			mods[j]->mod_type = g_list_nth(attrs, i)->data;

			values = lu_ent_get(ent, mods[j]->mod_type);
			if(values == NULL) {
				continue;
			}
			mods[j]->mod_values = g_malloc0((g_list_length(values) + 1) * sizeof(char*));
			for(k = l = 0; g_list_nth(values, k); k++) {
				gboolean add;

				if(g_strcasecmp(mods[j]->mod_type, LU_USERPASSWORD) == 0) {
					add = FALSE;
					if(strncmp(g_list_nth(values, k)->data, SCHEME, strlen(SCHEME)) == 0) {
						add = TRUE;
					}
				} else {
					add = TRUE;
				}
				if(add) {
#ifdef DEBUG
				g_message("%s attribute will be changed to %s\n",
					  (char*)g_list_nth(attrs, i)->data,
					  (char*)g_list_nth(values, k)->data);
#endif
					mods[j]->mod_values[l++] = g_list_nth(values, k)->data;
				}
			}
			j++;
		}
	}
	return mods;
}

static void
free_ent_mods(LDAPMod **mods)
{
	int i;
	g_assert(mods != NULL);
	for(i = 0; mods && mods[i]; i++) {
		if(mods[i]->mod_values) {
			g_free(mods[i]->mod_values);
		}
		g_free(mods[i]);
	}
	g_free(mods);
}

static void
dump_mods(LDAPMod **mods)
{
	int i, j;
	g_assert(mods != NULL);
	for(i = 0; mods[i]; i++) {
		g_print("%s (%d)\n", mods[i]->mod_type, mods[i]->mod_op);
		if(mods[i]->mod_values) {
			for(j = 0; mods[i]->mod_values[j]; j++) {
				g_print(" = `%s'\n",  mods[i]->mod_values[j]);
			}
		}
	}
}

static gboolean
lu_ldap_set(struct lu_module *module, enum lu_type type, struct lu_ent *ent,
	    const char *configKey, const char *def, char **attributes, struct lu_error **error)
{
	LDAPMod **mods = NULL;
	LDAPControl *server = NULL, *client = NULL;
	GList *name = NULL, *old_name = NULL;
	char *tmp;
	const char *dn = NULL, *namingAttr = NULL;
	int err;
	gboolean ret = FALSE;
	struct lu_ldap_context *ctx;

	g_assert(module != NULL);
	g_assert((type == lu_user) || (type == lu_group));
	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);
	g_assert(configKey != NULL);
	g_assert(strlen(configKey) > 0);
	g_assert(attributes != NULL);
	LU_ERROR_CHECK(error);

	ctx = module->module_context;

	if(type == lu_user) {
		namingAttr = LU_USERNAME;
	} else {
		namingAttr = LU_GROUPNAME;
	}

	name = lu_ent_get(ent, namingAttr);
	if(name == NULL) {
		lu_error_new(error, lu_error_generic, _("user object had no %s attribute"), namingAttr);
		return FALSE;
	}

	old_name = lu_ent_get_original(ent, namingAttr);
	if(old_name == NULL) {
		lu_error_new(error, lu_error_generic, _("user object was created with no `%s'"), namingAttr);
		return FALSE;
	}

	dn = lu_ldap_ent_to_dn(module, ent, namingAttr, name->data, configKey, def);
	if(dn == NULL) {
		lu_error_new(error, lu_error_generic, _("error mapping name to LDAP distinguished name"));
		return FALSE;
	}

	mods = get_ent_mods(ent);
	if(mods == NULL) {
		lu_error_new(error, lu_error_generic, _("could not convert internal data to LDAPMods"));
		return FALSE;
	}

#ifdef DEBUG
	dump_mods(mods);
	g_message("Modifying `%s'.\n", dn);
#endif

	err = ldap_modify_ext_s(ctx->ldap, dn, mods, &server, &client);
	if(err == LDAP_SUCCESS) {
		ret = TRUE;
	} else {
		lu_error_new(error, lu_error_write, _("error modifying LDAP directory entry: %s"), ldap_err2string(err));
		free_ent_mods(mods);
		return FALSE;
	}

	if(name && name->data && old_name && old_name->data) {
		if(strcmp((char*)name->data, ((char*)old_name->data)) != 0) {
			ret = FALSE;
			tmp = g_strdup_printf("%s=%s", namingAttr, (char*)name->data);
			err = ldap_rename_s(ctx->ldap, dn, tmp, NULL, TRUE, &server, &client);
			if(err == LDAP_SUCCESS) {
				ret = TRUE;
			} else {
				lu_error_new(error, lu_error_write, _("error renaming LDAP directory entry: %s\n"),
					     ldap_err2string(err));
				free_ent_mods(mods);
				return FALSE;
			}
		}
	}

	free_ent_mods(mods);

	return ret;
}

static gboolean
lu_ldap_del(struct lu_module *module, enum lu_type type, struct lu_ent *ent,
	    const char *configKey, const char *def, struct lu_error **error)
{
	LDAPControl *server = NULL, *client = NULL;
	GList *name = NULL;
	const char *dn = NULL, *namingAttr = NULL;
	int err;
	gboolean ret = FALSE;
	struct lu_ldap_context *ctx;

	g_assert(module != NULL);
	g_assert((type == lu_user) || (type == lu_group));
	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);
	g_assert(configKey != NULL);
	g_assert(strlen(configKey) > 0);
	LU_ERROR_CHECK(error);

	ctx = module->module_context;

	if(type == lu_user) {
		namingAttr = LU_USERNAME;
	} else {
		namingAttr = LU_GROUPNAME;
	}

	name = lu_ent_get(ent, namingAttr);
	if(name == NULL) {
		lu_error_new(error, lu_error_generic, _("object had no %s attribute"), namingAttr);
		return FALSE;
	}

	dn = lu_ldap_ent_to_dn(module, ent, namingAttr, name->data, configKey, def);
	if(dn == NULL) {
		lu_error_new(error, lu_error_generic, _("error mapping name to LDAP distinguished name"));
		return FALSE;
	}

#ifdef DEBUG
	g_message("Removing `%s'.\n", dn);
#endif
	err = ldap_delete_ext_s(ctx->ldap, dn, &server, &client);
	if(err == LDAP_SUCCESS) {
		ret = TRUE;
	} else {
		lu_error_new(error, lu_error_write, _("error removing LDAP directory entry: %s.\n"), ldap_err2string(err));
		return FALSE;
	}

	return ret;
}

static gboolean
lu_ldap_user_add(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_set(module, lu_user, ent, "userBranch", USERBRANCH, lu_ldap_user_attributes, error);
}

static gboolean
lu_ldap_user_mod(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_set(module, lu_user, ent, "userBranch", USERBRANCH, lu_ldap_user_attributes, error);
}

static gboolean
lu_ldap_user_del(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_del(module, lu_user, ent, "userBranch", USERBRANCH, error);
}

static gboolean
lu_ldap_handle_lock(struct lu_module *module, struct lu_ent *ent, const char *namingAttr, gboolean sense,
		    const char *configKey, const char *def, struct lu_error **error)
{
	const char *dn;
	char *val;
	gboolean ret = FALSE;
	GList *name, *password;
	struct lu_ldap_context *ctx = module->module_context;

	g_assert(module != NULL);
	g_assert(ent != NULL);
	g_assert(namingAttr != NULL);
	g_assert(strlen(namingAttr) > 0);
	LU_ERROR_CHECK(error);

	name = lu_ent_get(ent, namingAttr);
	if(name == NULL) {
		lu_error_new(error, lu_error_generic, _("object has no %s attribute"), namingAttr);
		return FALSE;
	}

	dn = lu_ldap_ent_to_dn(module, ent, namingAttr, name->data, configKey, def);
	if(dn == NULL) {
		lu_error_new(error, lu_error_generic, _("error mapping name to LDAP distinguished name"));
		return FALSE;
	}

	password = lu_ent_get(ent, LU_USERPASSWORD);
	if(password == NULL) {
		lu_error_new(error, lu_error_generic, _("object has no %s attribute"), LU_USERPASSWORD);
		return FALSE;
	}

	val = password->data ?: "";
	if(strncmp(val, SCHEME, strlen(SCHEME)) == 0) {
		LDAPMod mod, **mods;
		LDAPControl *server = NULL, *client = NULL;
		char *values[] = {NULL, NULL};
		int err;

		val += 7;
		val = sense ?
			((val[0] != LOCKCHAR) ?
			 g_strconcat(LOCKSTRING, val, NULL) :
			 g_strdup(val)):
			((val[0] == LOCKCHAR) ?
			 g_strdup(val + 1) :
			 g_strdup(val));
		mod.mod_op = LDAP_MOD_REPLACE;
		mod.mod_type = LU_USERPASSWORD;
		values[0] = val;
		values[1] = NULL;
		mod.mod_values = values;

		mods = g_malloc0(sizeof(LDAPMod*) * 2);
		mods[0] = &mod;
		mods[1] = NULL;
	
		err = ldap_modify_ext_s(ctx->ldap, dn, mods, &server, &client);
		if(err == LDAP_SUCCESS) {
			ret = TRUE;
		} else {
			lu_error_new(error, lu_error_write, _("error modifying LDAP directory entry: %s"), ldap_err2string(err));
			g_free(mods);
			g_free(val);
			return FALSE;
		}

		g_free(mods);
		g_free(val);
	}

	return ret;
}

static gboolean
lu_ldap_user_lock(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_handle_lock(module, ent, LU_USERNAME, TRUE, "userBranch", USERBRANCH, error);
}

static gboolean
lu_ldap_user_unlock(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_handle_lock(module, ent, LU_USERNAME, FALSE, "userBranch", USERBRANCH, error);
}

static gboolean
lu_ldap_islocked(struct lu_module *module, enum lu_type type, struct lu_ent *ent, const char *namingAttr, const char *configKey,
		 const char *def, struct lu_error **error)
{
	const char *dn;
	GList *name;
	struct lu_ldap_context *ctx = module->module_context;
	char *attributes[] = {LU_USERPASSWORD, NULL};
	char **values = NULL;
	LDAPMessage *entry = NULL, *messages = NULL;
	int i;
	gboolean locked = FALSE;

	name = lu_ent_get(ent, namingAttr);
	if(name == NULL) {
		lu_error_new(error, lu_error_generic, _("object has no %s attribute"), namingAttr);
		return FALSE;
	}

	dn = lu_ldap_ent_to_dn(module, ent, namingAttr, name->data, configKey, def);
	if(dn == NULL) {
		lu_error_new(error, lu_error_generic, _("error mapping name to LDAP distinguished name"));
		return FALSE;
	}

#ifdef DEBUG
	g_print("Looking up `%s'.\n", dn);
#endif

	if(ldap_search_s(ctx->ldap, dn, LDAP_SCOPE_BASE, "(objectclass=posixAccount)", attributes, FALSE, &messages) == LDAP_SUCCESS) {
		entry = ldap_first_entry(ctx->ldap, messages);
	}
	if(entry == NULL) {
		lu_error_new(error, lu_error_generic, _("no such object in LDAP directory"));
		return FALSE;
	}

	values = ldap_get_values(ctx->ldap, entry, LU_USERPASSWORD);
	if(values) {
		for(i = 0; values[i]; i++) {
#ifdef DEBUG
			g_print("Got `%s' = `%s'.\n", LU_USERPASSWORD, values[i]);
#endif
			if(strncmp(values[i], SCHEME, strlen(SCHEME)) == 0) {
				locked = (values[i][strlen(SCHEME)] == LOCKCHAR);
					 
				break;
			}
		}
		if(values[i] == NULL) {
			lu_error_new(error, lu_error_generic, _("no `%s' attribute using `%s' scheme found"), LU_USERPASSWORD, SCHEME);
			return FALSE;
		}
	} else {
#ifdef DEBUG
		g_print("No `%s' attribute found for entry.", LU_USERPASSWORD);
#endif
		lu_error_new(error, lu_error_generic, _("no `%s' attribute found"), LU_USERPASSWORD);
		return FALSE;
	}

	return locked;
}

static gboolean
lu_ldap_user_islocked(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_islocked(module, lu_user, ent, LU_USERNAME, "userBranch", USERBRANCH, error);
}

static gboolean
lu_ldap_setpass(struct lu_module *module, const char *namingAttr, struct lu_ent *ent, const char *configKey, const char *def,
		const char *password, struct lu_error **error)
{
	const char *dn;
	GList *name;
	struct lu_ldap_context *ctx = module->module_context;
	char *attributes[] = {LU_USERPASSWORD, NULL};
	char **values, *addvalues[] = {NULL, NULL}, *rmvalues[] = {NULL, NULL};
	char *tmp = NULL;
	const char *crypted = NULL, *previous = NULL;
	int i;
	LDAPMessage *entry = NULL, *messages = NULL;
	LDAPMod addmod, rmmod;
	LDAPMod *mods[] = {&addmod, &rmmod, NULL};
	LDAPControl *server = NULL, *client = NULL;
	char filter[LINE_MAX];

	g_print("Setting password to `%s'.\n", password);
	name = lu_ent_get(ent, namingAttr);
	if(name == NULL) {
		lu_error_new(error, lu_error_generic, _("object has no %s attribute"), namingAttr);
		return FALSE;
	}

	dn = lu_ldap_ent_to_dn(module, ent, namingAttr, name->data, configKey, def);
	if(dn == NULL) {
		lu_error_new(error, lu_error_generic, _("error mapping name to LDAP distinguished name"));
		return FALSE;
	}

#ifdef DEBUG
	g_print("Setting password for `%s'.\n", dn);
#endif

	snprintf(filter, sizeof(filter), "(%s=%s)", namingAttr, (char*)name->data);
	if((i = ldap_search_s(ctx->ldap, dn, LDAP_SCOPE_BASE, filter, attributes, FALSE, &messages)) == LDAP_SUCCESS) {
		entry = ldap_first_entry(ctx->ldap, messages);
		if(entry != NULL) {
			values = ldap_get_values(ctx->ldap, entry, LU_USERPASSWORD);
			if(values) {
				for(i = 0; values[i] != NULL; i++) {
#ifdef DEBUG
					g_print("Got `%s' = `%s'.\n", LU_USERPASSWORD, values[i]);
#endif
					if(strncmp(values[i], SCHEME, strlen(SCHEME)) == 0) {
#ifdef DEBUG
						g_print("Previous entry was `%s'.\n", values[i]);
#endif
						previous = values[i];
						break;
					}
				}
			}
		}
	} else {
#ifdef DEBUG
		g_print("Error searching LDAP directory for `%s': %s.\n", dn, ldap_err2string(i));
#endif
	}

	if(strncmp(password, SCHEME, strlen(SCHEME)) == 0) {
		crypted = password;
	} else {
		crypted = lu_make_crypted(password, previous ? (previous + strlen(SCHEME)) : "$1$");
		tmp = g_strconcat(SCHEME, crypted, NULL);
		addvalues[0] = module->scache->cache(module->scache, tmp);
		g_free(tmp);
		if(previous) {
			rmvalues[0] = (char*)previous;
		}
	}

	addmod.mod_op = LDAP_MOD_ADD;
	addmod.mod_type = LU_USERPASSWORD;
	addmod.mod_values = addvalues;

	rmmod.mod_op = LDAP_MOD_DELETE;
	rmmod.mod_type = LU_USERPASSWORD;
	rmmod.mod_values = rmvalues;

	if((i = ldap_modify_ext_s(ctx->ldap, dn, mods, &server, &client)) != LDAP_SUCCESS) {
		lu_error_new(error, lu_error_generic, _("error setting password in LDAP directory for %s: %s"), dn, ldap_err2string(i));
		return FALSE;
	}

	return TRUE;
}

static gboolean
lu_ldap_user_setpass(struct lu_module *module, struct lu_ent *ent, const char *password, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_setpass(module, LU_USERNAME, ent, "userBranch", USERBRANCH, password, error);
}

static gboolean
lu_ldap_group_add(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_set(module, lu_group, ent, "groupBranch", GROUPBRANCH, lu_ldap_group_attributes, error);
}

static gboolean
lu_ldap_group_mod(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_set(module, lu_group, ent, "groupBranch", GROUPBRANCH, lu_ldap_group_attributes, error);
}

static gboolean
lu_ldap_group_del(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_del(module, lu_group, ent, "groupBranch", GROUPBRANCH, error);
}

static gboolean
lu_ldap_group_lock(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_handle_lock(module, ent, LU_GROUPNAME, TRUE, "groupBranch", GROUPBRANCH, error);
}

static gboolean
lu_ldap_group_unlock(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_handle_lock(module, ent, LU_GROUPNAME, FALSE, "groupBranch", GROUPBRANCH, error);
}

static gboolean
lu_ldap_group_islocked(struct lu_module *module, struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_islocked(module, lu_group, ent, LU_GROUPNAME, "groupBranch", GROUPBRANCH, error);
}

static gboolean
lu_ldap_group_setpass(struct lu_module *module, struct lu_ent *ent, const char *password, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_setpass(module, LU_GROUPNAME, ent, "groupBranch", GROUPBRANCH, password, error);
}

static GList *
lu_ldap_enumerate(struct lu_module *module,
		  const char *searchAttr, const char *pattern,
		  const char *returnAttr,
	          const char *configKey, const char *def,
		  struct lu_error **error)
{
	LDAPMessage *messages = NULL, *entry = NULL;
	char **values = NULL;
	char *base = NULL, *filt = NULL;
	const char *branch;
	int j;
	GList *ret = NULL;
	struct lu_ldap_context *ctx;
	char *attributes[] = {(char*)returnAttr, NULL};
	char *tmp;

	g_assert(module != NULL);
	g_assert(searchAttr != NULL);
	g_assert(strlen(searchAttr) > 0);
	g_assert(returnAttr != NULL);
	g_assert(strlen(returnAttr) > 0);
	g_assert(configKey != NULL);
	g_assert(strlen(configKey) > 0);
	g_assert(attributes != NULL);
	g_assert(attributes[0] != NULL);
	LU_ERROR_CHECK(error);

	ctx = module->module_context;

	tmp = g_strdup_printf("ldap/%s", configKey);
	branch = lu_cfg_read_single(module->lu_context, tmp, def);
	g_free(tmp);

	base = g_strdup_printf("%s,%s", branch,
			       ctx->prompts[LU_LDAP_BASEDN].value &&
			       strlen(ctx->prompts[LU_LDAP_BASEDN].value) ?
			       ctx->prompts[LU_LDAP_BASEDN].value : "*");
	filt = g_strdup_printf("(%s=%s)", searchAttr, pattern);

#ifdef DEBUG
	g_print("Looking under `%s' with filter `%s'.\n", base, filt);
#endif

	if(ldap_search_s(ctx->ldap, base, LDAP_SCOPE_SUBTREE, filt, attributes, FALSE, &messages) == LDAP_SUCCESS) {
		entry = ldap_first_entry(ctx->ldap, messages);
		if(entry != NULL) {
			while(entry != NULL) {
				values = ldap_get_values(ctx->ldap, entry, returnAttr);
				if(values) {
					for(j = 0; values[j]; j++) {
#ifdef DEBUG
						g_print("Got `%s' = `%s'.\n", returnAttr, values[j]);
#endif
						ret = g_list_append(ret, module->scache->cache(module->scache, values[j]));
					}
				}
				entry = ldap_next_entry(ctx->ldap, entry);
			}
		} else {
#ifdef DEBUG
			g_print("No such entry found in LDAP, continuing.\n");
#endif
		}
	}

	g_free(base);
	g_free(filt);

	return ret;
}

static GList *
lu_ldap_users_enumerate(struct lu_module *module, const char *pattern, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_enumerate(module, LU_USERNAME, pattern, LU_USERNAME, "userBranch", USERBRANCH, error);
}

static GList *
lu_ldap_groups_enumerate(struct lu_module *module, const char *pattern, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_enumerate(module, LU_GROUPNAME, pattern, LU_GROUPNAME, "groupBranch", GROUPBRANCH, error);
}

static GList *
lu_ldap_users_enumerate_by_group(struct lu_module *module, const char *group, gid_t gid, struct lu_error **error)
{
	GList *primaries = NULL, *secondaries = NULL, *ret = NULL, *i = NULL;
	char grp[LINE_MAX];

	LU_ERROR_CHECK(error);
	snprintf(grp, sizeof(grp), "%d", gid);

	primaries = lu_ldap_enumerate(module, LU_GIDNUMBER, grp, LU_USERNAME, "userBranch", USERBRANCH, error);
	if((error == NULL) || (*error == NULL)) {
		secondaries = lu_ldap_enumerate(module, LU_GROUPNAME, group, LU_MEMBERUID, "groupBranch", GROUPBRANCH, error);
	}

	for(i = primaries; i != NULL; i = g_list_next(i)) {
		ret = g_list_append(ret, i->data);
	}
	for(i = secondaries; i != NULL; i = g_list_next(i)) {
		ret = g_list_append(ret, i->data);
	}

	if(primaries != NULL) {
		g_list_free(primaries);
	}
	if(secondaries != NULL) {
		g_list_free(secondaries);
	}

#ifdef DEBUG
	for(i = ret; i != NULL; i = g_list_next(i)) {
		g_print("`%s' contains `%s'\n", group, (char*)i->data);
	}
#endif
	return ret;
}

static GList *
lu_ldap_groups_enumerate_by_user(struct lu_module *module, const char *user, struct lu_error **error)
{
	GList *primaries = NULL, *secondaries = NULL, *ret = NULL, *i = NULL, *tmp = NULL;
	struct lu_ent *ent = NULL;

	LU_ERROR_CHECK(error);

	primaries = lu_ldap_enumerate(module, LU_USERNAME, user, LU_GIDNUMBER, "userBranch", USERBRANCH, error);
	if((error == NULL) || (*error == NULL)) {
		secondaries = lu_ldap_enumerate(module, LU_MEMBERUID, user, LU_GROUPNAME, "groupBranch", GROUPBRANCH, error);
	}

	for(i = primaries; i != NULL; i = g_list_next(i)) {
		ent = lu_ent_new();
		if(lu_group_lookup_id(module->lu_context, atol((char*)i->data), ent, error)) {
			tmp = lu_ent_get(ent, LU_GROUPNAME);
			if(tmp && tmp->data) {
				ret = g_list_append(ret, module->scache->cache(module->scache, (char*)tmp->data));
			}
		}
		lu_ent_free(ent);
	}

	for(i = secondaries; i != NULL; i = g_list_next(i)) {
		ret = g_list_append(ret, module->scache->cache(module->scache, i->data));
	}

	if(primaries != NULL) {
		g_list_free(primaries);
	}
	if(secondaries != NULL) {
		g_list_free(secondaries);
	}

#ifdef DEBUG
	for(i = ret; i != NULL; i = g_list_next(i)) {
		g_print("`%s' is in `%s'\n", user, (char*)i->data);
	}
#endif

	return ret;
}

static gboolean
lu_ldap_close_module(struct lu_module *module)
{
	struct lu_ldap_context *ctx;

	g_assert(module != NULL);

	ctx = module->module_context;
	ldap_unbind_s(ctx->ldap);

	module->scache->free(module->scache);
	memset(module, 0, sizeof(struct lu_module));
	g_free(module);

	return TRUE;
}

struct lu_module *
lu_ldap_init(struct lu_context *context, struct lu_error **error)
{
	struct lu_module *ret = NULL;
	struct lu_ldap_context *ctx = NULL;
	char *user;
	LDAP *ldap = NULL;

	g_assert(context != NULL);
	g_assert(context->prompter != NULL);
	LU_ERROR_CHECK(error);

	ctx = g_malloc0(sizeof(struct lu_ldap_context));

	ctx->global_context = context;

	ctx->prompts[LU_LDAP_SERVER].key = "ldap/server";
	ctx->prompts[LU_LDAP_SERVER].prompt = _("LDAP Server Name");
	ctx->prompts[LU_LDAP_SERVER].default_value = lu_cfg_read_single(context, "ldap/server", "ldap");
	ctx->prompts[LU_LDAP_SERVER].visible = TRUE;

	ctx->prompts[LU_LDAP_BASEDN].key = "ldap/basedn";
	ctx->prompts[LU_LDAP_BASEDN].prompt = _("LDAP Base DN");
	ctx->prompts[LU_LDAP_BASEDN].default_value = lu_cfg_read_single(context, "ldap/basedn", "dc=example,dc=com");
	ctx->prompts[LU_LDAP_BASEDN].visible = TRUE;

	ctx->prompts[LU_LDAP_BINDDN].key = "ldap/binddn";
	ctx->prompts[LU_LDAP_BINDDN].prompt = _("LDAP Bind DN");
	ctx->prompts[LU_LDAP_BINDDN].visible = TRUE;
	ctx->prompts[LU_LDAP_BINDDN].default_value = lu_cfg_read_single(context, "ldap/binddn", "cn=manager,dc=example,dc=com");

	ctx->prompts[LU_LDAP_PASSWORD].key = "ldap/password";
	ctx->prompts[LU_LDAP_PASSWORD].prompt = _("LDAP Bind Password");
	ctx->prompts[LU_LDAP_PASSWORD].visible = FALSE;

	user = getuser();

	ctx->prompts[LU_LDAP_USER].key = "ldap/user";
	ctx->prompts[LU_LDAP_USER].prompt = _("LDAP SASL User");
	ctx->prompts[LU_LDAP_USER].visible = TRUE;
	ctx->prompts[LU_LDAP_USER].default_value = lu_cfg_read_single(context, "ldap/user", user);

	ctx->prompts[LU_LDAP_AUTHUSER].key = "ldap/authuser";
	ctx->prompts[LU_LDAP_AUTHUSER].prompt = _("LDAP SASL Authorization User");
	ctx->prompts[LU_LDAP_AUTHUSER].visible = TRUE;
	ctx->prompts[LU_LDAP_AUTHUSER].default_value = lu_cfg_read_single(context, "ldap/authuser", user);

	if(user) {
		free(user);
		user = NULL;
	}

	if(context->prompter(ctx->prompts, sizeof(ctx->prompts) / sizeof(ctx->prompts[0]), context->prompter_data, error) == FALSE) {
		g_free(ctx);
		return NULL;
	}

	ldap = bind_server(ctx, error);
	if(ldap == NULL) {
		g_free(ctx);
		return FALSE;
	}
	ctx->ldap = ldap;

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->module_context = ctx;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, "ldap");

	/* Set the method pointers. */
	ret->user_lookup_name = lu_ldap_user_lookup_name;
        ret->user_lookup_id = lu_ldap_user_lookup_id;

	ret->user_add = lu_ldap_user_add;
	ret->user_mod = lu_ldap_user_mod;
	ret->user_del = lu_ldap_user_del;
	ret->user_lock = lu_ldap_user_lock;
	ret->user_unlock = lu_ldap_user_unlock;
	ret->user_islocked = lu_ldap_user_islocked;
	ret->user_setpass = lu_ldap_user_setpass;
	ret->users_enumerate = lu_ldap_users_enumerate;
	ret->users_enumerate_by_group = lu_ldap_users_enumerate_by_group;

        ret->group_lookup_name = lu_ldap_group_lookup_name;
        ret->group_lookup_id = lu_ldap_group_lookup_id;

	ret->group_add = lu_ldap_group_add;
	ret->group_mod = lu_ldap_group_mod;
	ret->group_del = lu_ldap_group_del;
	ret->group_lock = lu_ldap_group_lock;
	ret->group_unlock = lu_ldap_group_unlock;
	ret->group_islocked = lu_ldap_group_islocked;
	ret->group_setpass = lu_ldap_group_setpass;
	ret->groups_enumerate = lu_ldap_groups_enumerate;
	ret->groups_enumerate_by_user = lu_ldap_groups_enumerate_by_user;

	ret->close = lu_ldap_close_module;

	/* Done. */
	return ret;
}
