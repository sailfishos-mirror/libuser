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

static gboolean
lu_ldap_lookup(struct lu_module *module, const char *namingAttr,
	       const char *name, struct lu_ent *ent,
	       const char *configKey, const char *def,
	       const char *filter, const char **attributes)
{
	return FALSE;
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
	ret = lu_ldap_lookup(module, LU_USERNAME, uid_string, ent,
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
	ret = lu_ldap_lookup(module, LU_GID, gid_string, ent,
			     "groupBranch", "ou=Groups",
			     "(objectclass=posixGroup)",
			     lu_ldap_group_attributes);
	g_free(gid_string);

	return ret;
}

static gboolean
lu_ldap_user_add(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_ldap_user_mod(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
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
	return FALSE;
}

static gboolean
lu_ldap_group_mod(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
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
	ctx->prompts[LU_LDAP_SERVER].default_value = "devserv.devel.redhat.com";
	ctx->prompts[LU_LDAP_SERVER].visible = TRUE;

	ctx->prompts[LU_LDAP_BASEDN].prompt = _("LDAP Base DN");
	ctx->prompts[LU_LDAP_BASEDN].default_value = "dc=example,dc=com";
	ctx->prompts[LU_LDAP_BASEDN].default_value = "dc=devel,dc=redhat,dc=com";
	ctx->prompts[LU_LDAP_BASEDN].visible = TRUE;

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

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
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
