#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <krb5.h>
#include <kadm5/admin.h>
#include <libuser/user_private.h>
#include "util.h"

#define LU_KRB5_REALM 0
#define LU_KRB5_PRINC 1
#define LU_KRB5_PASSWORD 2
#define LU_KRBNAME "krbName"

struct lu_krb5_context {
	struct lu_prompt prompts[3];
};

static const char *
get_default_realm(struct lu_context *context)
{
	krb5_context kcontext;
	const char *ret = "";
	char *realm;

	if(krb5_init_context(&kcontext) == 0) {
		if(krb5_get_default_realm(kcontext, &realm) == 0) {
			ret = context->scache->cache(context->scache, realm);
			krb5_free_default_realm(kcontext, realm);
		}
		krb5_free_context(kcontext);
	}

	return ret;
}

static void *
get_server_handle(struct lu_krb5_context *context)
{
	kadm5_config_params params;
	void *handle = NULL;
	int ret;

	memset(&params, 0, sizeof(params));
	params.mask = KADM5_CONFIG_REALM;
	params.realm = context->prompts[LU_KRB5_REALM].value;
	ret = kadm5_init_with_password(context->prompts[LU_KRB5_PRINC].value,
				       context->prompts[LU_KRB5_PASSWORD].value,
				       KADM5_ADMIN_SERVICE,
				       &params,
				       KADM5_STRUCT_VERSION,
				       KADM5_API_VERSION_2,
				       &handle);
	if(ret == KADM5_OK) {
		return handle;
	} else {
		return NULL;
	}
}

static void
free_server_handle(void *handle)
{
	if(handle != NULL) {
		kadm5_destroy(handle);
	}
}

static gboolean
lu_krb5_user_lookup_name(struct lu_module *module, gconstpointer name,
			 struct lu_ent *ent)
{
	krb5_context context = NULL;
	krb5_principal principal = NULL;
	kadm5_principal_ent_rec principal_rec;
	gboolean ret = FALSE;
	void *handle = NULL;

	if(krb5_init_context(&context) != 0) {
		g_warning(_("Error initializing Kerberos."));
		return FALSE;
	}

	if(krb5_parse_name(context, name, &principal) != 0) {
		g_warning(_("Error parsing user name '%s' for Kerberos."),
			  name);
		krb5_free_context(context);
		return FALSE;
	}

	handle = get_server_handle(module->module_context);
	if(handle) {
		if(kadm5_get_principal(handle, principal,
				       &principal_rec, 0) == 0) {
			lu_ent_set_original(ent, LU_USERPASSWORD, "{crypt}*K*");
			ret = TRUE;
		}
	}

	free_server_handle(handle);
	krb5_free_principal(context, principal);
	krb5_free_context(context);
	
	return ret;
}

static gboolean
lu_krb5_user_lookup_id(struct lu_module *module, gconstpointer uid,
		       struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_krb5_group_lookup_name(struct lu_module *module, gconstpointer name,
			  struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_krb5_group_lookup_id(struct lu_module *module, gconstpointer gid,
			struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_krb5_user_add(struct lu_module *module, struct lu_ent *ent)
{
	krb5_context context = NULL;
	kadm5_principal_ent_rec principal;
	GList *name, *pass, *i;
	char *password;
	void *handle;
	int err;
	gboolean ret = FALSE;

	if(krb5_init_context(&context) != 0) {
		g_warning(_("Error initializing Kerberos."));
		return FALSE;
	}

	name = lu_ent_get(ent, LU_KRBNAME);
	if(name == NULL) {
		name = lu_ent_get(ent, LU_USERNAME);
	}
	if(name == NULL) {
		g_warning(_("Entity structure has no %s or %s attributes."),
			  LU_KRBNAME, LU_USERNAME);
		krb5_free_context(context);
		return FALSE;
	}

	if(krb5_parse_name(context, name->data, &principal.principal) != 0) {
		g_warning(_("Error parsing user name '%s' for Kerberos."),
			  name);
		krb5_free_context(context);
		return FALSE;
	}

	pass = lu_ent_get(ent, LU_USERPASSWORD);
	for(i = pass; i; i = g_list_next(i)) {
		password = i->data;
		if(password && strncmp(password, "{crypt}", 7)) {
			handle = get_server_handle(module->module_context);
			if(handle) {
				err = kadm5_create_principal(handle,
							     &principal,
							     KADM5_PRINCIPAL,
							     password);
				free_server_handle(handle);
				if(err == KADM5_OK) {
					ret = TRUE;
					break;
				}
			}
		}
	}

	return ret;
}

static gboolean
lu_krb5_user_mod(struct lu_module *module, struct lu_ent *ent)
{
	krb5_context context = NULL;
	krb5_principal principal = NULL, old_principal = NULL;
	GList *name, *old_name, *pass, *i;
	void *handle;
	char *password;
	gboolean ret = TRUE;

	if(krb5_init_context(&context) != 0) {
		g_warning(_("Error initializing Kerberos."));
		return FALSE;
	}

	name = lu_ent_get(ent, LU_KRBNAME);
	if(name == NULL) {
		name = lu_ent_get(ent, LU_USERNAME);
	}
	if(name == NULL) {
		g_warning(_("Entity has no %s or %s attributes."),
			  LU_KRBNAME, LU_USERNAME);
		krb5_free_context(context);
		return FALSE;
	}

	old_name = lu_ent_get_original(ent, LU_KRBNAME);
	if(old_name == NULL) {
		old_name = lu_ent_get(ent, LU_USERNAME);
	}
	if(old_name == NULL) {
		g_warning(_("Entity was created with no %s or %s attributes."),
			  LU_KRBNAME, LU_USERNAME);
		krb5_free_context(context);
		return FALSE;
	}

	if(krb5_parse_name(context, name->data, &principal) != 0) {
		g_warning(_("Error parsing user name '%s' for Kerberos."),
			  name);
		krb5_free_context(context);
		return FALSE;
	}
	if(krb5_parse_name(context, old_name->data, &old_principal) != 0) {
		g_warning(_("Error parsing user name '%s' for Kerberos."),
			  old_name);
		krb5_free_principal(context, principal);
		krb5_free_context(context);
		return FALSE;
	}


	/* All we know how to change is the LU_USERPASSWORD. */
	pass = lu_ent_get(ent, LU_USERPASSWORD);

	handle = get_server_handle(module->module_context);

	if(handle) {
		if(krb5_principal_compare(context, principal,
					  old_principal) == FALSE) {
			ret = FALSE;
			if(kadm5_rename_principal(handle,
						  old_principal,
						  principal) == KADM5_OK) {
				ret = TRUE;
			}
		}
		for(i = pass; i; i = g_list_next(i)) {
			password = i->data;
			if(password != NULL) {
				if(strncmp(password, "{crypt}", 7)) {
					/* A change was requested. */
					ret = FALSE;
					if(kadm5_chpass_principal(handle,
						  	principal,
						  	password) == KADM5_OK) {
						/* That change succeeded. */
						ret = TRUE;
					}
				}
			}
		}
		free_server_handle(handle);
	}

	krb5_free_principal(context, principal);
	krb5_free_principal(context, old_principal);
	krb5_free_context(context);

	return ret;
}

static gboolean
lu_krb5_user_del(struct lu_module *module, struct lu_ent *ent)
{
	krb5_context context = NULL;
	krb5_principal principal;
	GList *name;
	void *handle;
	gboolean ret = FALSE;

	if(krb5_init_context(&context) != 0) {
		g_warning(_("Error initializing Kerberos."));
		return FALSE;
	}

	name = lu_ent_get(ent, LU_KRBNAME);
	if(name == NULL) {
		name = lu_ent_get(ent, LU_USERNAME);
	}
	if(name == NULL) {
		g_warning(_("Entity structure has no %s or %s attributes."),
			  LU_KRBNAME, LU_USERNAME);
		krb5_free_context(context);
		return FALSE;
	}

	if(krb5_parse_name(context, name->data, &principal) != 0) {
		g_warning(_("Error parsing user name '%s' for Kerberos."),
			  name);
		krb5_free_context(context);
		return FALSE;
	}

	handle = get_server_handle(module->module_context);
	if(handle) {
		ret = (kadm5_delete_principal(handle, principal) == KADM5_OK);
		free_server_handle(handle);
	}

	krb5_free_principal(context, principal);
	krb5_free_context(context);

	return ret;
}

static gboolean
lu_krb5_user_lock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_krb5_user_unlock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_krb5_group_add(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_krb5_group_mod(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_krb5_group_del(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_krb5_group_lock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_krb5_group_unlock(struct lu_module *module, struct lu_ent *ent)
{
	return FALSE;
}

static gboolean
lu_krb5_close_module(struct lu_module *module)
{
	g_return_val_if_fail(module != NULL, FALSE);

	module->scache->free(module->scache);
	memset(module, 0, sizeof(struct lu_module));
	g_free(module);

	return TRUE;
}

struct lu_module *
lu_krb5_init(struct lu_context *context)
{
	struct lu_module *ret = NULL;
	struct lu_krb5_context *ctx = NULL;
	void *handle = NULL;

	g_return_val_if_fail(context != NULL, NULL);

	/* Verify that we can connect to the kadmind server. */
	if(context->prompter == NULL) {
		return NULL;
	}

	ctx = g_malloc0(sizeof(struct lu_krb5_context));

	ctx->prompts[0].prompt = _("Kerberos Realm");
	ctx->prompts[0].visible = TRUE;
	ctx->prompts[0].default_value = get_default_realm(context);

	ctx->prompts[1].prompt = _("Kerberos Admin Principal");
	ctx->prompts[1].visible = TRUE;
	if(context->auth_name) {
		ctx->prompts[1].default_value = context->auth_name;
	} else {
		char *tmp = g_strconcat(getlogin(), "/admin", NULL);
		ctx->prompts[1].default_value =
			context->scache->cache(context->scache, tmp);
		g_free(tmp);
	}

	ctx->prompts[2].prompt = _("Password");
	ctx->prompts[2].visible = FALSE;

	if((context->prompter == NULL) ||
	   (context->prompter(context, ctx->prompts, 3,
			      context->prompter_data) == FALSE)) {
		g_free(ctx);
		return NULL;
	}

	handle = get_server_handle(ctx);
	if(handle == NULL) {
		return NULL;
	}
	free_server_handle(handle);

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, "krb5");
	ret->module_context = ctx;

	/* Set the method pointers. */
	ret->user_lookup_name = lu_krb5_user_lookup_name;
        ret->user_lookup_id = lu_krb5_user_lookup_id;

	ret->user_add = lu_krb5_user_add;
	ret->user_mod = lu_krb5_user_mod;
	ret->user_del = lu_krb5_user_del;
	ret->user_lock = lu_krb5_user_lock;
	ret->user_unlock = lu_krb5_user_unlock;

        ret->group_lookup_name = lu_krb5_group_lookup_name;
        ret->group_lookup_id = lu_krb5_group_lookup_id;

	ret->group_add = lu_krb5_group_add;
	ret->group_mod = lu_krb5_group_mod;
	ret->group_del = lu_krb5_group_del;
	ret->group_lock = lu_krb5_group_lock;
	ret->group_unlock = lu_krb5_group_unlock;

	ret->close = lu_krb5_close_module;

	/* Done. */
	return ret;
}
