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

#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <krb5.h>
#include <krb5/kdb.h>
#include <kadm5/admin.h>
#include <libuser/user_private.h>

#define LU_KRB5_REALM 0
#define LU_KRB5_PRINC 1
#define LU_KRB5_PASSWORD 2
#define LU_KRBNAME "krbName"

struct lu_module *
lu_krb5_init(struct lu_context *context);

struct lu_krb5_context {
	struct lu_prompt prompts[3];
	void *handle;
};

static const char *
get_default_realm(struct lu_context *context)
{
	krb5_context kcontext;
	const char *ret = "";
	char *realm;

	g_return_val_if_fail(context != NULL, NULL);

	if(krb5_init_context(&kcontext) == 0) {
		if(krb5_get_default_realm(kcontext, &realm) == 0) {
			ret = context->scache->cache(context->scache, realm);
			krb5_free_default_realm(kcontext, realm);
		}
		krb5_free_context(kcontext);
	}

	ret = lu_cfg_read_single(context, "krb5/realm", ret);

	return ret;
}

static void *
get_server_handle(struct lu_krb5_context *context)
{
	kadm5_config_params params;
	void *handle = NULL;
	int ret;
	char *service = NULL;

	g_return_val_if_fail(context != NULL, NULL);

	memset(&params, 0, sizeof(params));
	params.mask = KADM5_CONFIG_REALM;
	params.realm = context->prompts[LU_KRB5_REALM].value;
	if(strstr(context->prompts[LU_KRB5_PRINC].value, "/")) {
		service = KADM5_ADMIN_SERVICE;
	} else {
		service = KADM5_CHANGEPW_SERVICE;
	}
	ret = kadm5_init(context->prompts[LU_KRB5_PRINC].value,
			 context->prompts[LU_KRB5_PASSWORD].value,
			 service,
			 &params,
			 KADM5_STRUCT_VERSION,
			 KADM5_API_VERSION_2,
			 &handle);
	if(ret == KADM5_OK) {
		return handle;
	} else {
		g_warning(_("Error connecting to the kadm5 server for service "
			    "%s in realm %s: %s."), service, params.realm,
			  error_message(ret));
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
	struct lu_krb5_context *ctx = NULL;
	gboolean ret = FALSE;

	g_return_val_if_fail(module != NULL, FALSE);
	g_return_val_if_fail(name != NULL, FALSE);
	g_return_val_if_fail(strlen((char*)name) > 0, FALSE);

	ctx = (struct lu_krb5_context*) module->module_context;

	if(krb5_init_context(&context) != 0) {
		g_warning(_("Error initializing Kerberos."));
		return FALSE;
	}

	if(krb5_parse_name(context, (const char*)name, &principal) != 0) {
		g_warning(_("Error parsing user name '%s' for Kerberos."),
			  (const char*)name);
		krb5_free_context(context);
		return FALSE;
	}

	if(kadm5_get_principal(ctx->handle, principal,
			       &principal_rec, 0) == KADM5_OK) {
		lu_ent_set_original(ent, LU_USERPASSWORD, "{crypt}*K*");
		ret = TRUE;
	}

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
	int err;
	gboolean ret = FALSE;
	struct lu_krb5_context *ctx;

	g_return_val_if_fail(module != NULL, FALSE);
	g_return_val_if_fail(name != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic = LU_ENT_MAGIC, FALSE);

	ctx = (struct lu_krb5_context *) module->module_context;

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
			  (const char*) name->data);
		krb5_free_context(context);
		return FALSE;
	}

	pass = lu_ent_get(ent, LU_USERPASSWORD);
	for(i = pass; i; i = g_list_next(i)) {
		password = i->data;
		if(password && (strncmp(password, "{crypt}", 7) != 0)) {
			/* Note that we tried to create the account. */
			ret = FALSE;
			err = kadm5_create_principal(ctx->handle, &principal,
						     KADM5_PRINCIPAL, password);
			if(err == KADM5_OK) {
				/* Change the password field so that a
				 * subsequent information add will note that
				 * the user is Kerberized. */
				lu_ent_set(ent, LU_USERPASSWORD,
					   "{crypt}*K*");
				/* Hey, it worked! */
				ret = TRUE;
				break;
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
	char *password;
	gboolean ret = TRUE;
	struct lu_krb5_context *ctx;

	g_return_val_if_fail(module != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic = LU_ENT_MAGIC, FALSE);

	ctx = (struct lu_krb5_context *) module->module_context;

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
			  (const char*) name->data);
		krb5_free_context(context);
		return FALSE;
	}
	if(krb5_parse_name(context, old_name->data, &old_principal) != 0) {
		g_warning(_("Error parsing user name '%s' for Kerberos."),
			  (const char*) old_name->data);
		krb5_free_principal(context, principal);
		krb5_free_context(context);
		return FALSE;
	}

	/* If we need to rename the principal, do it first. */
	if(krb5_principal_compare(context, principal,
				  old_principal) == FALSE) {
		ret = FALSE;
		if(kadm5_rename_principal(ctx->handle, old_principal,
					  principal) == KADM5_OK) {
			ret = TRUE;
		}
	}

	/* Now try to change the password. */
	pass = lu_ent_get(ent, LU_USERPASSWORD);
	for(i = pass; i; i = g_list_next(i)) {
		password = i->data;
		if(password != NULL) {
#ifdef DEBUG
			g_print("Working password for %s is '%s'.\n",
				name->data, password);
#endif
			if(strncmp(password, "{crypt}", 7) != 0) {
				/* A change was requested. */
				ret = FALSE;
#ifdef DEBUG
				g_print("Changing password for %s.\n",
					name->data);
#endif
				if(kadm5_chpass_principal(ctx->handle,
					  	principal,
					  	password) == KADM5_OK) {
#ifdef DEBUG
					g_print("...succeeded.\n");
#endif
					/* Change the password field so
					 * that a subsequent information
					 * modify will note that the
					 * user is Kerberized. */
					lu_ent_set(ent, LU_USERPASSWORD,
						   "{crypt}*K*");
					ret = TRUE;
#ifdef DEBUG
				} else {
					g_print("...failed.\n");
#endif
				}
			}
		}
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
	gboolean ret = FALSE;
	struct lu_krb5_context *ctx;

	g_return_val_if_fail(module != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic = LU_ENT_MAGIC, FALSE);

	ctx = (struct lu_krb5_context*) module->module_context;

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
			  (const char*) name->data);
		krb5_free_context(context);
		return FALSE;
	}

	ret = (kadm5_delete_principal(ctx->handle, principal) == KADM5_OK);

	krb5_free_principal(context, principal);
	krb5_free_context(context);

	return ret;
}

static gboolean
lu_krb5_user_do_lock(struct lu_module *module, struct lu_ent *ent, gboolean lck)
{
	krb5_context context = NULL;
	kadm5_principal_ent_rec principal;
	GList *name;
	gboolean ret = FALSE;
	struct lu_krb5_context *ctx;

	g_return_val_if_fail(module != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic = LU_ENT_MAGIC, FALSE);

	ctx = (struct lu_krb5_context*) module->module_context;

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
			  (const char*) name->data);
		krb5_free_context(context);
		return FALSE;
	}

	ret = (kadm5_get_principal(ctx->handle, principal.principal, &principal,
			KADM5_PRINCIPAL | KADM5_ATTRIBUTES) == KADM5_OK);
	if(ret == FALSE) {
		g_warning(_("Error reading information for '%s' from "
			    "Kerberos."), (const char *) name->data);
	} else {
		if(lck) {
			principal.attributes |=
				KRB5_KDB_DISALLOW_ALL_TIX;
		} else {
			principal.attributes &=
				~KRB5_KDB_DISALLOW_ALL_TIX;
		}
		ret = (kadm5_modify_principal(ctx->handle, &principal,
					      KADM5_PRINCIPAL|KADM5_ATTRIBUTES)
					      == KADM5_OK);
	}

	krb5_free_principal(context, principal.principal);

	return ret;
}

static gboolean
lu_krb5_user_lock(struct lu_module *module, struct lu_ent *ent)
{
	return lu_krb5_user_do_lock(module, ent, TRUE);
}

static gboolean
lu_krb5_user_unlock(struct lu_module *module, struct lu_ent *ent)
{
	return lu_krb5_user_do_lock(module, ent, FALSE);
}

static gboolean
lu_krb5_user_setpass(struct lu_module *module, struct lu_ent *ent,
		     const char *password)
{
	krb5_context context = NULL;
	krb5_principal principal = NULL;
	GList *name;
	gboolean ret = TRUE;
	struct lu_krb5_context *ctx;

	g_return_val_if_fail(module != NULL, FALSE);
	g_return_val_if_fail(ent != NULL, FALSE);
	g_return_val_if_fail(ent->magic = LU_ENT_MAGIC, FALSE);

	ctx = (struct lu_krb5_context *) module->module_context;

	if(krb5_init_context(&context) != 0) {
		g_warning(_("Error initializing Kerberos."));
		return FALSE;
	}

	if(name == NULL) {
		name = lu_ent_get(ent, LU_USERNAME);
	}
	if(name == NULL) {
		g_warning(_("Entity has no %s attribute."),
			  LU_USERNAME);
		krb5_free_context(context);
		return FALSE;
	}

	if(krb5_parse_name(context, name->data, &principal) != 0) {
		g_warning(_("Error parsing user name '%s' for Kerberos."),
			  (const char*) name->data);
		krb5_free_context(context);
		return FALSE;
	}

	/* Now try to change the password. */
	if(password != NULL) {
#ifdef DEBUG
		g_print("Working password for %s is '%s'.\n",
			name->data, password);
		g_print("Changing password for %s.\n",
			name->data);
#endif
		if(kadm5_chpass_principal(ctx->handle, principal,
					  password) == KADM5_OK) {
#ifdef DEBUG
			g_print("...succeeded.\n");
#endif
			/* Change the password field so
			 * that a subsequent information
			 * modify will note that the
			 * user is Kerberized. */
			lu_ent_set(ent, LU_USERPASSWORD, "*K*");
			ret = TRUE;
#ifdef DEBUG
		} else {
			g_print("...failed.\n");
#endif
		}
	}

	krb5_free_principal(context, principal);
	krb5_free_context(context);

	return ret;
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
lu_krb5_group_setpass(struct lu_module *module, struct lu_ent *ent,
		      const char* password)
{
	return FALSE;
}

static GList *
lu_krb5_users_enumerate(struct lu_module *module, const char *pattern)
{
	return NULL;
}

static GList *
lu_krb5_groups_enumerate(struct lu_module *module, const char *pattern)
{
	return NULL;
}

static gboolean
lu_krb5_close_module(struct lu_module *module)
{
	struct lu_krb5_context *ctx = NULL;

	g_return_val_if_fail(module != NULL, FALSE);

	ctx = (struct lu_krb5_context*) module->module_context;
	free_server_handle(ctx->handle);
	memset(ctx, 0, sizeof(*ctx));
	g_free(ctx);

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
	char *tmp;

	g_return_val_if_fail(context != NULL, NULL);
	initialize_krb5_error_table();
	initialize_kadm_error_table();

	/* Verify that we can connect to the kadmind server. */
	if(context->prompter == NULL) {
		return NULL;
	}

	ctx = g_malloc0(sizeof(struct lu_krb5_context));

	ctx->prompts[LU_KRB5_REALM].prompt = _("Kerberos Realm");
	ctx->prompts[LU_KRB5_REALM].visible = TRUE;
	ctx->prompts[LU_KRB5_REALM].default_value = get_default_realm(context);

	ctx->prompts[LU_KRB5_PRINC].prompt = _("Kerberos Admin Principal");
	ctx->prompts[LU_KRB5_PRINC].visible = TRUE;
	if(context->auth_name) {
		tmp = g_strconcat(context->auth_name, "/admin", NULL);
		ctx->prompts[LU_KRB5_PRINC].default_value =
			context->scache->cache(context->scache, tmp);
		g_free(tmp);
	} else {
		tmp = g_strconcat(getlogin(), "/admin", NULL);
		ctx->prompts[LU_KRB5_PRINC].default_value =
			context->scache->cache(context->scache, tmp);
		g_free(tmp);
	}

	if((context->prompter == NULL) ||
	   (context->prompter(context, ctx->prompts, 2,
			      context->prompter_data) == FALSE)) {
		g_free(ctx);
		return NULL;
	}

	tmp = g_strdup_printf(_("Kerberos password for %s"),
			      ctx->prompts[LU_KRB5_PRINC].value);
	ctx->prompts[LU_KRB5_PASSWORD].prompt =
		context->scache->cache(context->scache, tmp);
	ctx->prompts[LU_KRB5_PASSWORD].visible = FALSE;
	g_free(tmp);

	if(context->prompter(context, ctx->prompts + 2, 1,
			     context->prompter_data) == FALSE) {
		g_free(ctx);
		return NULL;
	}

	handle = get_server_handle(ctx);
	if(handle == NULL) {
		return NULL;
	}
	ctx->handle = handle;

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
	ret->user_setpass = lu_krb5_user_setpass;
	ret->users_enumerate = lu_krb5_users_enumerate;

        ret->group_lookup_name = lu_krb5_group_lookup_name;
        ret->group_lookup_id = lu_krb5_group_lookup_id;

	ret->group_add = lu_krb5_group_add;
	ret->group_mod = lu_krb5_group_mod;
	ret->group_del = lu_krb5_group_del;
	ret->group_lock = lu_krb5_group_lock;
	ret->group_unlock = lu_krb5_group_unlock;
	ret->group_setpass = lu_krb5_group_setpass;
	ret->groups_enumerate = lu_krb5_groups_enumerate;

	ret->close = lu_krb5_close_module;

	/* Done. */
	return ret;
}
