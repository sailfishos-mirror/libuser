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

#include <libuser/user_private.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <ldap.h>
#include <sasl.h>

#define LU_LDAP_SERVER		0
#define LU_LDAP_BASEDN		1
#define LU_LDAP_BINDDN		2
#define LU_LDAP_USER		3
#define LU_LDAP_AUTHUSER	4
#define LU_LDAP_PASSWORD	5

struct lu_module *
lu_ldap_init(struct lu_context *context);

static const char *
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

	NULL,
};

static const char *
lu_ldap_group_attributes[] = {
	LU_OBJECTCLASS,
	LU_GROUPNAME
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
        struct lu_prompt prompts[6];
	LDAP *ldap;
};

static void
close_server(LDAP *ldap)
{
	ldap_unbind_s(ldap);
}

static const char *
getuser()
{
	struct passwd *pwd = NULL;
	pwd = getpwuid(getuid());
	return pwd ? pwd->pw_name : NULL;
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
				interact[i].result =
					ctx->prompts[LU_LDAP_USER].value;
				interact[i].len = strlen(interact[i].result);
#ifdef DEBUG
				g_print("Sending SASL user '%s'.\n",
					interact[i].result);
#endif
				break;
			case SASL_CB_AUTHNAME:
				interact[i].result =
					ctx->prompts[LU_LDAP_AUTHUSER].value;
				interact[i].len = strlen(interact[i].result);
#ifdef DEBUG
				g_print("Sending SASL auth user '%s'.\n",
					interact[i].result);
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
bind_server(struct lu_ldap_context *context)
{
	LDAP *ldap = NULL;
	LDAPControl *server = NULL, *client = NULL;
	int version = LDAP_VERSION3;
	char *generated_binddn = "", *tmp;
	struct lu_string_cache *scache = NULL;

	g_return_val_if_fail(context != NULL, NULL);

	ldap = ldap_init(context->prompts[LU_LDAP_SERVER].value, LDAP_PORT);
	if(ldap) {
		scache = context->global_context->scache;
		tmp = g_strdup_printf("uid=%s,%s,%s", getuser(),
				      lu_cfg_read_single(context->global_context,
							 "ldap/userBranch",
							 "ou=People"),
				      context->prompts[LU_LDAP_BASEDN].value);
		generated_binddn = scache->cache(scache, tmp);
		g_free(tmp);
		if(ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION,
				   &version) != LDAP_OPT_SUCCESS) {
			g_warning(_("Could not force protocol version 3 with "
				    "LDAP server %s.\n"),
				  context->prompts[LU_LDAP_SERVER].value);
			close_server(ldap);
			return NULL;
		}
		if(ldap_start_tls_s(ldap, &server, &client) != LDAP_SUCCESS) {
			g_warning(_("Could not negotiate TLS with "
				    "LDAP server %s.\n"),
				  context->prompts[LU_LDAP_SERVER].value);
			close_server(ldap);
			return NULL;
		}
		if(ldap_sasl_interactive_bind_s(ldap, NULL, NULL, NULL, NULL,
						LDAP_SASL_AUTOMATIC | LDAP_SASL_QUIET,
						interact, context)
			!= LDAP_SUCCESS)
		if(ldap_simple_bind_s(ldap,
				      context->prompts[LU_LDAP_BINDDN].value,
				      context->prompts[LU_LDAP_PASSWORD].value)
			!= LDAP_SUCCESS)
		if(ldap_simple_bind_s(ldap,
				      generated_binddn,
				      context->prompts[LU_LDAP_PASSWORD].value)
			!= LDAP_SUCCESS) {
			g_warning(_("Could not perform simple bind to "
				    "LDAP server %s.\n"),
				  context->prompts[LU_LDAP_SERVER].value);
			close_server(ldap);
			return NULL;
		}
	}

	return ldap;
}

/* Generate the distinguished name which corresponds to the lu_ent structure. */
static const char *
lu_ldap_ent_to_dn(struct lu_module *module, struct lu_ent *ent,
		  const char *namingAttr, const char *name,
		  const char *configKey, const char *def)
{
	struct lu_ldap_context *context = module->module_context;
	const char *branch = NULL;
	char *tmp = NULL, *ret = NULL;

	g_return_val_if_fail(module != NULL, NULL);
	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);
	g_return_val_if_fail(namingAttr != NULL, NULL);
	g_return_val_if_fail(strlen(namingAttr) > 0, NULL);
	g_return_val_if_fail(name != NULL, NULL);
	g_return_val_if_fail(strlen(name) > 0, NULL);
	g_return_val_if_fail(configKey != NULL, NULL);
	g_return_val_if_fail(strlen(configKey) > 0, NULL);

	tmp = g_strdup_printf("ldap/%s", configKey);
	branch = lu_cfg_read_single(module->lu_context, tmp, def);
	g_free(tmp);

	if(branch) {
		tmp = g_strdup_printf("%s=%s,%s,%s",
				      namingAttr, name, branch,
				      context->prompts[LU_LDAP_BASEDN].value);
		ret = module->scache->cache(module->scache, tmp);
		g_free(tmp);
	}

	return ret;
}

/* This is the lookup workhorse. */
static gboolean
lu_ldap_lookup(struct lu_module *module, const char *namingAttr,
	       const char *name, struct lu_ent *ent,
	       const char *configKey, const char *def,
	       const char *filter, const char **attributes)
{
	LDAPMessage *messages = NULL, *entry = NULL;
	const char *attr;
	char *filt = NULL, **values = NULL;
	const char *dn = NULL;
	int i, j;
	gboolean ret = FALSE;
	struct lu_ldap_context *ctx;

	g_return_val_if_fail(module != NULL, FALSE);
	g_return_val_if_fail(namingAttr != NULL, FALSE);
	g_return_val_if_fail(strlen(namingAttr) > 0, FALSE);
	g_return_val_if_fail(name != NULL, FALSE);
	g_return_val_if_fail(strlen(name) > 0, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	g_return_val_if_fail(configKey != NULL, FALSE);
	g_return_val_if_fail(strlen(configKey) > 0, FALSE);
	g_return_val_if_fail(attributes != NULL, FALSE);
	g_return_val_if_fail(attributes[0] != NULL, FALSE);

	ctx = module->module_context;

	dn = lu_ldap_ent_to_dn(module, ent, namingAttr, name, configKey, def);
	if(dn == NULL) {
		g_warning(_("Could not determine expected DN.\n"));
		return FALSE;
	}

	if(filter && (strlen(filter) > 0)) {
		filt = g_strdup_printf("(&%s(%s=%s))", filter,
				       namingAttr, name);
	} else {
		filt = g_strdup_printf("(%s=%s)", namingAttr, name);
	}

#ifdef DEBUG
	g_print("Looking up '%s' with filter '%s'.\n", dn, filt);
#endif

	if(ldap_search_s(ctx->ldap, dn, LDAP_SCOPE_BASE, filt, attributes,
			 FALSE, &messages) == LDAP_SUCCESS) {
		entry = ldap_first_entry(ctx->ldap, messages);
		if(entry != NULL) {
			for(i = 0; attributes[i]; i++) {
				attr = attributes[i];
				values = ldap_get_values(ctx->ldap, entry,
							 attr);
				if(values) {
					lu_ent_clear_original(ent, attr);
					for(j = 0; values[j]; j++) {
#ifdef DEBUG
						g_print("Got '%s' = '%s'.\n",
							attr, values[j]);
#endif
						lu_ent_add_original(ent, attr,
								    values[j]);
					}
				}
			}
			ret = TRUE;
		} else {
#ifdef DEBUG
			g_print("No entry found in LDAP.\n");
#endif
			ret = FALSE;
		}
	}

	return ret;
}

static gboolean
lu_ldap_user_lookup_name(struct lu_module *module, gconstpointer name,
			 struct lu_ent *ent)
{
	return lu_ldap_lookup(module, LU_USERNAME, name, ent,
			      "userBranch", "ou=People",
			      "(objectclass=posixAccount)",
			      lu_ldap_user_attributes);
}

static gboolean
lu_ldap_user_lookup_id(struct lu_module *module, gconstpointer uid,
		       struct lu_ent *ent)
{
	gboolean ret = FALSE;
	gchar *uid_string = NULL;

	uid_string = g_strdup_printf("%d", GPOINTER_TO_INT(uid));
	ret = lu_ldap_lookup(module, LU_UIDNUMBER, uid_string, ent,
			     "userBranch", "ou=People",
			     "(objectclass=posixAccount)",
			     lu_ldap_user_attributes);
	g_free(uid_string);

	return ret;
}

static gboolean
lu_ldap_group_lookup_name(struct lu_module *module, gconstpointer name,
			  struct lu_ent *ent)
{
	return lu_ldap_lookup(module, LU_GROUPNAME, name, ent,
			      "groupBranch", "ou=Group",
			      "(objectclass=posixGroup)",
			      lu_ldap_group_attributes);
}

static gboolean
lu_ldap_group_lookup_id(struct lu_module *module, gconstpointer gid,
			struct lu_ent *ent)
{
	gboolean ret = FALSE;
	gchar *gid_string = NULL;

	gid_string = g_strdup_printf("%d", GPOINTER_TO_INT(gid));
	ret = lu_ldap_lookup(module, LU_GIDNUMBER, gid_string, ent,
			     "groupBranch", "ou=Group",
			     "(objectclass=posixGroup)",
			     lu_ldap_group_attributes);
	g_free(gid_string);

	return ret;
}

static LDAPMod **
get_ent_mods(struct lu_ent *ent)
{
	LDAPMod **mods = NULL;
	GList *attrs = NULL, *values = NULL;
	int i, j, k;

	g_return_val_if_fail(ent != NULL, NULL);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, NULL);

	attrs = lu_ent_get_attributes(ent);
	if(attrs) {
		mods = g_malloc0(sizeof(LDAPMod*) * (g_list_length(attrs) + 1));
		for(i = 0; g_list_nth(attrs, i); i++) {
			mods[i] = g_malloc0(sizeof(LDAPMod));
			mods[i]->mod_op = LDAP_MOD_REPLACE;
			mods[i]->mod_type = g_list_nth(attrs, i)->data;

			values = lu_ent_get(ent, mods[i]->mod_type);
			if(values == NULL) {
				continue;
			}
			mods[i]->mod_values =
				g_malloc0((g_list_length(values) + 1) *
					  sizeof(char*));
			for(j = k = 0; g_list_nth(values, j); j++) {
				gboolean add = FALSE;

				if(g_strcasecmp(mods[i]->mod_type,
						LU_USERPASSWORD) == 0) {
					if(strncmp(g_list_nth(values, j)->data,
						   "{crypt}", 7) == 0) {
						add = TRUE;
					}
				}

				if(g_strcasecmp(mods[i]->mod_type,
						LU_USERPASSWORD) != 0) {
					add = TRUE;
				}

				if(add) {
					mods[i]->mod_values[k++] =
						g_list_nth(values, j)->data;
				}
			}
		}
	}
	return mods;
}

static void
free_ent_mods(LDAPMod **mods)
{
	int i;
	g_return_if_fail(mods != NULL);
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
	g_return_if_fail(mods != NULL);
	for(i = 0; mods[i]; i++) {
		g_print("%s (%d)\n", mods[i]->mod_type, mods[i]->mod_op);
		if(mods[i]->mod_values) {
			for(j = 0; mods[i]->mod_values[j]; j++) {
				g_print("= '%s'\n",  mods[i]->mod_values[j]);
			}
		}
	}
}

static gboolean
lu_ldap_set(struct lu_module *module, enum lu_type type, struct lu_ent *ent,
	    const char *configKey, const char *def, const char **attributes)
{
	LDAPMod **mods = NULL;
	LDAPControl *server = NULL, *client = NULL;
	GList *name = NULL, *old_name = NULL;
	char *tmp;
	const char *dn = NULL, *namingAttr = NULL;
	int err;
	gboolean ret = FALSE;
	struct lu_ldap_context *ctx;

	g_return_val_if_fail(module != NULL, FALSE);
	g_return_val_if_fail((type == lu_user) || (type == lu_group), FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	g_return_val_if_fail(configKey != NULL, FALSE);
	g_return_val_if_fail(strlen(configKey) > 0, FALSE);
	g_return_val_if_fail(attributes != NULL, FALSE);

	ctx = module->module_context;

	if(type == lu_user) {
		namingAttr = LU_USERNAME;
	} else {
		namingAttr = LU_GROUPNAME;
	}

	name = lu_ent_get(ent, namingAttr);
	if(name == NULL) {
		g_warning(_("User object had no '%s'.\n"), namingAttr);
		return FALSE;
	}

	old_name = lu_ent_get_original(ent, namingAttr);
	if(old_name == NULL) {
		g_warning(_("User object was created with no '%s'.\n"),
			  namingAttr);
		return FALSE;
	}

	dn = lu_ldap_ent_to_dn(module, ent, namingAttr, name->data,
			       configKey, def);
	if(dn == NULL) {
		g_warning(_("Could not determine expected DN.\n"));
		return FALSE;
	}

	mods = get_ent_mods(ent);
	if(mods == NULL) {
		g_warning(_("Could not convert internals to LDAPMod data.\n"));
		return FALSE;
	}

#ifdef DEBUG
	dump_mods(mods);
#endif

	err = ldap_modify_ext_s(ctx->ldap, dn, mods, &server, &client);
	if(err == LDAP_SUCCESS) {
		ret = TRUE;
	} else {
		g_warning(_("Error modifying directory entry: %s.\n"),
			  ldap_err2string(err));
	}

	if(name && name->data && old_name && old_name->data) {
		if(strcmp((char*)name->data, ((char*)old_name->data)) != 0) {
			ret = FALSE;
			tmp = g_strdup_printf("%s=%s", namingAttr, (char*)name->data);
			err = ldap_rename_s(ctx->ldap, dn, tmp, NULL, TRUE,
					    &server, &client);
			if(err == LDAP_SUCCESS) {
				ret = TRUE;
			} else {
				g_warning(_("Error renaming directory entry: "
					  "%s.\n"), ldap_err2string(err));
			}
		}
	}

	free_ent_mods(mods);

	return ret;
}

static gboolean
lu_ldap_del(struct lu_module *module, enum lu_type type, struct lu_ent *ent,
	    const char *configKey, const char *def)
{
	LDAPControl *server = NULL, *client = NULL;
	GList *name = NULL;
	const char *dn = NULL, *namingAttr = NULL;
	int err;
	gboolean ret = FALSE;
	struct lu_ldap_context *ctx;

	g_return_val_if_fail(module != NULL, FALSE);
	g_return_val_if_fail((type == lu_user) || (type == lu_group), FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic == LU_ENT_MAGIC, FALSE);
	g_return_val_if_fail(configKey != NULL, FALSE);
	g_return_val_if_fail(strlen(configKey) > 0, FALSE);

	ctx = module->module_context;

	if(type == lu_user) {
		namingAttr = LU_USERNAME;
	} else {
		namingAttr = LU_GROUPNAME;
	}

	name = lu_ent_get(ent, namingAttr);
	if(name == NULL) {
		g_warning(_("Account object had no '%s'.\n"), namingAttr);
		return FALSE;
	}

	dn = lu_ldap_ent_to_dn(module, ent, namingAttr, name->data,
			       configKey, def);
	if(dn == NULL) {
		g_warning(_("Could not determine expected DN.\n"));
		return FALSE;
	}

	err = ldap_delete_ext_s(ctx->ldap, dn, &server, &client);
	if(err == LDAP_SUCCESS) {
		ret = TRUE;
	} else {
		g_warning(_("Error removing directory entry: %s.\n"),
			  ldap_err2string(err));
	}

	return ret;
}

static gboolean
lu_ldap_user_add(struct lu_module *module, struct lu_ent *ent)
{
	return lu_ldap_set(module, lu_user, ent, "userBranch", "ou=People",
			   lu_ldap_user_attributes);
}

static gboolean
lu_ldap_user_mod(struct lu_module *module, struct lu_ent *ent)
{
	return lu_ldap_set(module, lu_user, ent, "userBranch", "ou=People",
			   lu_ldap_user_attributes);
}

static gboolean
lu_ldap_user_del(struct lu_module *module, struct lu_ent *ent)
{
	return lu_ldap_del(module, lu_user, ent, "userBranch", "ou=People");
}

static gboolean
lu_ldap_user_lock(struct lu_module *module, struct lu_ent *ent)
{
	/* FIXME */
	return FALSE;
}

static gboolean
lu_ldap_user_unlock(struct lu_module *module, struct lu_ent *ent)
{
	/* FIXME */
	return FALSE;
}

static gboolean
lu_ldap_user_setpass(struct lu_module *module, struct lu_ent *ent,
		     const char *password)
{
	/* FIXME */
	return FALSE;
}

static gboolean
lu_ldap_group_add(struct lu_module *module, struct lu_ent *ent)
{
	return lu_ldap_set(module, lu_group, ent, "groupBranch", "ou=Group",
			   lu_ldap_group_attributes);
}

static gboolean
lu_ldap_group_mod(struct lu_module *module, struct lu_ent *ent)
{
	return lu_ldap_set(module, lu_group, ent, "groupBranch", "ou=Group",
			   lu_ldap_group_attributes);
}

static gboolean
lu_ldap_group_del(struct lu_module *module, struct lu_ent *ent)
{
	return lu_ldap_del(module, lu_group, ent, "groupBranch", "ou=Group");
}

static gboolean
lu_ldap_group_lock(struct lu_module *module, struct lu_ent *ent)
{
	/* FIXME */
	return FALSE;
}

static gboolean
lu_ldap_group_unlock(struct lu_module *module, struct lu_ent *ent)
{
	/* FIXME */
	return FALSE;
}

static gboolean
lu_ldap_group_setpass(struct lu_module *module, struct lu_ent *ent,
		      const char *password)
{
	/* FIXME */
	return FALSE;
}

static GList *
lu_ldap_users_enumerate(struct lu_module *module, const char *pattern)
{
	/* FIXME */
	return NULL;
}

static GList *
lu_ldap_groups_enumerate(struct lu_module *module, const char *pattern)
{
	/* FIXME */
	return NULL;
}

static gboolean
lu_ldap_close_module(struct lu_module *module)
{
	struct lu_ldap_context *ctx;

	g_return_val_if_fail(module != NULL, FALSE);

	ctx = module->module_context;
	ldap_unbind_s(ctx->ldap);

	module->scache->free(module->scache);
	memset(module, 0, sizeof(struct lu_module));
	g_free(module);

	return TRUE;
}

struct lu_module *
lu_ldap_init(struct lu_context *context)
{
	struct lu_module *ret = NULL;
	struct lu_ldap_context *ctx = NULL;
	LDAP *ldap = NULL;

	g_return_val_if_fail(context != NULL, NULL);

	ctx = g_malloc0(sizeof(struct lu_ldap_context));

	ctx->global_context = context;

	ctx->prompts[LU_LDAP_SERVER].prompt = _("LDAP Server Name");
	ctx->prompts[LU_LDAP_SERVER].default_value =
					lu_cfg_read_single(context,
							   "ldap/server",
							   "ldap");
	ctx->prompts[LU_LDAP_SERVER].visible = TRUE;

	ctx->prompts[LU_LDAP_BASEDN].prompt = _("LDAP Base DN");
	ctx->prompts[LU_LDAP_BASEDN].default_value =
					lu_cfg_read_single(context,
							   "ldap/basedn",
							   "dc=example,dc=com");
	ctx->prompts[LU_LDAP_BASEDN].visible = TRUE;

	ctx->prompts[LU_LDAP_BINDDN].prompt = _("LDAP DN");
	ctx->prompts[LU_LDAP_BINDDN].visible = TRUE;
	ctx->prompts[LU_LDAP_BINDDN].default_value =
					lu_cfg_read_single(context,
							   "ldap/binddn",
							   "cn=manager,"
							   "dc=example,dc=com");

	ctx->prompts[LU_LDAP_USER].prompt = _("LDAP User");
	ctx->prompts[LU_LDAP_USER].visible = TRUE;
	ctx->prompts[LU_LDAP_USER].default_value =
					lu_cfg_read_single(context,
							   "ldap/user",
							   getuser());

	ctx->prompts[LU_LDAP_AUTHUSER].prompt = _("LDAP Authorization User");
	ctx->prompts[LU_LDAP_AUTHUSER].visible = TRUE;
	ctx->prompts[LU_LDAP_AUTHUSER].default_value =
					lu_cfg_read_single(context,
							   "ldap/authuser",
							   getuser());

	ctx->prompts[LU_LDAP_PASSWORD].prompt = _("LDAP Password");
	ctx->prompts[LU_LDAP_PASSWORD].visible = FALSE;

	if((context->prompter == NULL) ||
           (context->prompter(context,
			      ctx->prompts,
			      sizeof(ctx->prompts) / sizeof(ctx->prompts[0]),
			      context->prompter_data) == FALSE)) {
		g_free(ctx);
		return NULL;
	}

	ldap = bind_server(ctx);
	if(ldap == NULL) {
		g_warning(_("Could not bind to LDAP server.\n"));
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
	ret->user_setpass = lu_ldap_user_setpass;
	ret->users_enumerate = lu_ldap_users_enumerate;

        ret->group_lookup_name = lu_ldap_group_lookup_name;
        ret->group_lookup_id = lu_ldap_group_lookup_id;

	ret->group_add = lu_ldap_group_add;
	ret->group_mod = lu_ldap_group_mod;
	ret->group_del = lu_ldap_group_del;
	ret->group_lock = lu_ldap_group_lock;
	ret->group_unlock = lu_ldap_group_unlock;
	ret->group_setpass = lu_ldap_group_setpass;
	ret->groups_enumerate = lu_ldap_groups_enumerate;

	ret->close = lu_ldap_close_module;

	/* Done. */
	return ret;
}
