#include <libuser/user_private.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ldap.h>
#include "util.h"

#define DEBUG

#define LU_LDAP_SERVER		0
#define LU_LDAP_BASEDN		1
#define LU_LDAP_BINDDN		2
#define LU_LDAP_PASSWORD	3

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
        struct lu_prompt prompts[4];
};

static void
close_server(LDAP *ldap)
{
	ldap_unbind_s(ldap);
}

static LDAP *
bind_server(struct lu_ldap_context *context)
{
	LDAP *ldap = NULL;
	LDAPControl *server = NULL, *client = NULL;
	int version = LDAP_VERSION3;

	ldap = ldap_init(context->prompts[LU_LDAP_SERVER].value, LDAP_PORT);
	if(ldap) {
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
		if(ldap_simple_bind_s(ldap,
				      context->prompts[LU_LDAP_BINDDN].value,
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

static const char *
lu_ldap_ent_to_dn(struct lu_module *module, struct lu_ent *ent,
		  const char *namingAttr, const char *name,
		  const char *configKey, const char *def)
{
	struct lu_ldap_context *context = module->module_context;
	GList *branch = NULL;
	char *tmp = NULL, *ret = NULL;

	tmp = g_strdup_printf("ldap/%s", configKey);
	branch = lu_cfg_read(module->lu_context, tmp, def);
	g_free(tmp);

	if(branch && branch->data) {
		tmp = g_strdup_printf("%s=%s,%s,%s",
				      namingAttr, name, branch->data,
				      context->prompts[LU_LDAP_BASEDN].value);
		ret = module->scache->cache(module->scache, tmp);
		g_free(tmp);
	}

	return ret;
}

static gboolean
lu_ldap_lookup(struct lu_module *module, const char *namingAttr,
	       const char *name, struct lu_ent *ent,
	       const char *configKey, const char *def,
	       const char *filter, const char **attributes)
{
	struct lu_ldap_context *context = module->module_context;
	LDAP *ldap = NULL;
	LDAPMessage *messages = NULL, *entry = NULL;
	const char *attr;
	char *tmp = NULL, *filt = NULL, **values = NULL;
	const char *dn = NULL;
	int i, j;
	gboolean ret = FALSE;

	ldap = bind_server(module->module_context);
	if(ldap == NULL) {
		g_warning(_("Could not bind to LDAP server.\n"));
		return FALSE;
	}

	dn = lu_ldap_ent_to_dn(module, ent, namingAttr, name, configKey, def);
	if(dn == NULL) {
		g_warning(_("Could not determine expected DN.\n"));
		close_server(ldap);
		return FALSE;
	}

	filt = g_strdup_printf("(&%s(%s=%s))", filter, namingAttr, name);

#ifdef DEBUG
	g_print("Looking up '%s' with filter '%s'.\n", dn, filt);
#endif

	if(ldap_search_s(ldap, dn, LDAP_SCOPE_BASE, filt, attributes,
			 FALSE, &messages) == LDAP_SUCCESS) {
		entry = ldap_first_entry(ldap, messages);
		if(entry != NULL) {
			for(i = 0; attributes[i]; i++) {
				attr = attributes[i];
				values = ldap_get_values(ldap, entry, attr);
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
		}
	}

	close_server(ldap);

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

	uid_string = g_strdup_printf("%ld", GPOINTER_TO_INT(uid));
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
			      "groupBranch", "ou=Groups",
			      "(objectclass=posixGroup)",
			      lu_ldap_group_attributes);
}

static gboolean
lu_ldap_group_lookup_id(struct lu_module *module, gconstpointer gid,
			struct lu_ent *ent)
{
	gboolean ret = FALSE;
	gchar *gid_string = NULL;

	gid_string = g_strdup_printf("%ld", GPOINTER_TO_INT(gid));
	ret = lu_ldap_lookup(module, LU_GIDNUMBER, gid_string, ent,
			     "groupBranch", "ou=Groups",
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
	int i, j;

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
			for(j = 0; g_list_nth(values, j); j++) {
				mods[i]->mod_values[j] =
					g_list_nth(values, j)->data;
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
	LDAP *ldap = NULL;
	LDAPMod **mods = NULL;
	LDAPControl *server = NULL, *client = NULL;
	GList *name = NULL;
	const char *dn = NULL, *namingAttr = NULL;
	int err;
	gboolean ret = FALSE;

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

	ldap = bind_server(module->module_context);
	if(ldap == NULL) {
		g_warning(_("Could not bind to LDAP server.\n"));
		return FALSE;
	}

	dn = lu_ldap_ent_to_dn(module, ent, namingAttr, name->data,
			       configKey, def);
	if(dn == NULL) {
		g_warning(_("Could not determine expected DN.\n"));
		close_server(ldap);
		return FALSE;
	}

	mods = get_ent_mods(ent);
	if(mods == NULL) {
		g_warning(_("Could not convert internals to LDAPMod data.\n"));
		close_server(ldap);
		return FALSE;
	}

#ifdef DEBUG
	dump_mods(mods);
#endif

	err = ldap_modify_ext_s(ldap, dn, mods, &server, &client);
	if(err == LDAP_SUCCESS) {
		ret = TRUE;
	} else {
		g_warning(_("Error modifying directory entry: %s.\n"),
			  ldap_err2string(err));
	}

	free_ent_mods(mods);

	close_server(ldap);

	return ret;
}

static gboolean
lu_ldap_del(struct lu_module *module, enum lu_type type, struct lu_ent *ent,
	    const char *configKey, const char *def, const char **attributes)
{
	LDAP *ldap = NULL;
	LDAPControl *server = NULL, *client = NULL;
	GList *name = NULL;
	const char *dn = NULL, *namingAttr = NULL;
	int err;
	gboolean ret = FALSE;

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

	ldap = bind_server(module->module_context);
	if(ldap == NULL) {
		g_warning(_("Could not bind to LDAP server.\n"));
		return FALSE;
	}

	dn = lu_ldap_ent_to_dn(module, ent, namingAttr, name->data,
			       configKey, def);
	if(dn == NULL) {
		g_warning(_("Could not determine expected DN.\n"));
		close_server(ldap);
		return FALSE;
	}

	err = ldap_delete_ext_s(ldap, dn, &server, &client);
	if(err == LDAP_SUCCESS) {
		ret = TRUE;
	} else {
		g_warning(_("Error removing directory entry: %s.\n"),
			  ldap_err2string(err));
	}

	close_server(ldap);

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
	return FALSE;
}

static gboolean
lu_ldap_user_lock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_user_unlock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_group_add(struct lu_module *module, struct lu_ent *ent)
{
	return lu_ldap_set(module, lu_group, ent, "groupBranch", "ou=Groups",
			   lu_ldap_group_attributes);
}

static gboolean
lu_ldap_group_mod(struct lu_module *module, struct lu_ent *ent)
{
	return lu_ldap_set(module, lu_group, ent, "groupBranch", "ou=Groups",
			   lu_ldap_group_attributes);
}

static gboolean
lu_ldap_group_del(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_group_lock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_group_unlock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_close_module(struct lu_module *module)
{
	g_return_val_if_fail(module != NULL, FALSE);

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

	ctx->prompts[LU_LDAP_SERVER].prompt = _("LDAP Server Name");
	ctx->prompts[LU_LDAP_SERVER].default_value = "ldap.example.com";
	ctx->prompts[LU_LDAP_SERVER].visible = TRUE;
#ifdef DEBUG
	ctx->prompts[LU_LDAP_SERVER].default_value = "devserv.devel.redhat.com";
#endif

	ctx->prompts[LU_LDAP_BASEDN].prompt = _("LDAP Base DN");
	ctx->prompts[LU_LDAP_BASEDN].default_value = "dc=example,dc=com";
	ctx->prompts[LU_LDAP_BASEDN].visible = TRUE;
#ifdef DEBUG
	ctx->prompts[LU_LDAP_BASEDN].default_value = "dc=devel,dc=redhat,dc=com";
#endif

	ctx->prompts[LU_LDAP_BINDDN].prompt = _("LDAP Bind DN");
	ctx->prompts[LU_LDAP_BINDDN].visible = TRUE;

	ctx->prompts[LU_LDAP_PASSWORD].prompt = _("LDAP Bind Password");
	ctx->prompts[LU_LDAP_PASSWORD].visible = FALSE;

        if(context->prompter(context, ctx->prompts, 4,
			     context->prompter_data) == FALSE) {
		g_free(ctx);
		return NULL;
	}

	ldap = bind_server(ctx);
	if(ldap == NULL) {
		g_warning(_("Could not bind to LDAP server.\n"));
		return FALSE;
	}

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

        ret->group_lookup_name = lu_ldap_group_lookup_name;
        ret->group_lookup_id = lu_ldap_group_lookup_id;

	ret->group_add = lu_ldap_group_add;
	ret->group_mod = lu_ldap_group_mod;
	ret->group_del = lu_ldap_group_del;
	ret->group_lock = lu_ldap_group_lock;
	ret->group_unlock = lu_ldap_group_unlock;

	ret->close = lu_ldap_close_module;

	/* Done. */
	return ret;
}
