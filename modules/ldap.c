/*
 * Copyright (C) 2000-2002, 2004 Red Hat, Inc.
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
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <ldap.h>
#include <sasl.h>
#include "../lib/user_private.h"

#include "default.-c"

#undef  DEBUG
#define LOCKCHAR '!'
#define LOCKSTRING "!"
#define USERBRANCH "ou=People"
#define GROUPBRANCH "ou=Group"
#define OBJECTCLASS "objectClass"
#define ACCOUNT       "account"
#define POSIXACCOUNT  "posixAccount"
#define POSIXGROUP    "posixGroup"
#define SHADOWACCOUNT "shadowAccount"
#define INETORGPERSON "inetOrgPerson"
#define DISTINGUISHED_NAME "dn"

LU_MODULE_INIT(libuser_ldap_init)
#define LU_LDAP_USER	(1 << 0)
#define LU_LDAP_GROUP	(1 << 1)
#define LU_LDAP_SHADOW	(1 << 2)

enum interact_indices {
	LU_LDAP_SERVER,
	LU_LDAP_BASEDN,
	LU_LDAP_BINDDN,
	LU_LDAP_PASSWORD,
	LU_LDAP_AUTHUSER,
	LU_LDAP_AUTHZUSER,
	LU_LDAP_MAX,
};

static const struct {
	const char *lu_attribute;
	const char *ldap_attribute;
	const char *objectclass;
	int applicability;
} ldap_attribute_map[] = {
	{LU_USERNAME, "uid", POSIXACCOUNT, LU_LDAP_USER},
	{LU_USERPASSWORD, "userPassword", POSIXACCOUNT, LU_LDAP_USER},
	{LU_UIDNUMBER, "uidNumber", POSIXACCOUNT, LU_LDAP_USER},
	{LU_GIDNUMBER, "gidNumber", POSIXACCOUNT, LU_LDAP_USER},
	{LU_GECOS, "gecos", POSIXACCOUNT, LU_LDAP_USER},
	{LU_HOMEDIRECTORY, "homeDirectory", POSIXACCOUNT, LU_LDAP_USER},
	{LU_LOGINSHELL, "loginShell", POSIXACCOUNT, LU_LDAP_USER},

	{LU_GROUPNAME, "cn", POSIXGROUP, LU_LDAP_GROUP},
	{LU_GROUPPASSWORD, "userPassword", POSIXGROUP, LU_LDAP_GROUP},
	{LU_GIDNUMBER, "gidNumber", POSIXGROUP, LU_LDAP_GROUP},
	{LU_MEMBERNAME, "memberUid", POSIXGROUP, LU_LDAP_GROUP},

	{LU_SHADOWLASTCHANGE, "shadowLastChange", SHADOWACCOUNT,
	 LU_LDAP_SHADOW},
	{LU_SHADOWMIN, "shadowMin", SHADOWACCOUNT, LU_LDAP_SHADOW},
	{LU_SHADOWMAX, "shadowMax", SHADOWACCOUNT, LU_LDAP_SHADOW},
	{LU_SHADOWWARNING, "shadowWarning", SHADOWACCOUNT, LU_LDAP_SHADOW},
	{LU_SHADOWINACTIVE, "shadowInactive", SHADOWACCOUNT, LU_LDAP_SHADOW},
	{LU_SHADOWEXPIRE, "shadowExpire", SHADOWACCOUNT, LU_LDAP_SHADOW},
	{LU_SHADOWFLAG, "shadowFlag", SHADOWACCOUNT, LU_LDAP_SHADOW},

	{LU_COMMONNAME, "cn", INETORGPERSON, LU_LDAP_USER},
	{LU_GIVENNAME, "givenName", INETORGPERSON, LU_LDAP_USER},
	{LU_SN, "sn", INETORGPERSON, LU_LDAP_USER},
	{LU_ROOMNUMBER, "roomNumber", INETORGPERSON, LU_LDAP_USER},
	{LU_TELEPHONENUMBER, "telephoneNumber", INETORGPERSON, LU_LDAP_USER},
	{LU_HOMEPHONE, "homePhone", INETORGPERSON, LU_LDAP_USER},
};

static const char *const lu_ldap_user_attributes[] = {
	LU_USERNAME,
	LU_USERPASSWORD,
	LU_UIDNUMBER,
	LU_GIDNUMBER,
	LU_GECOS,
	LU_HOMEDIRECTORY,
	LU_LOGINSHELL,

	/* Not LU_SHADOWPASSWORD: We can't allow modification of
	 * LU_USERPASSWORD and LU_SHADOWPASSWORD at the same time; LDAP simply
	 * doesn't implement LU_SHADOWPASSWORD. */
	LU_SHADOWLASTCHANGE,
	LU_SHADOWMIN,
	LU_SHADOWMAX,
	LU_SHADOWWARNING,
	LU_SHADOWINACTIVE,
	LU_SHADOWEXPIRE,
	LU_SHADOWFLAG,

	LU_COMMONNAME,
	LU_GIVENNAME,
	LU_SN,
	LU_ROOMNUMBER,
	LU_TELEPHONENUMBER,
	LU_HOMEPHONE,

	NULL
};

static const char *const lu_ldap_group_attributes[] = {
	LU_GROUPNAME,
	LU_GROUPPASSWORD,
	LU_GIDNUMBER,
	LU_MEMBERNAME,
	LU_ADMINISTRATORNAME,

	NULL
};

struct lu_ldap_context {
	struct lu_context *global_context;	/* The library context. */
	struct lu_module *module;		/* The module's structure. */
	struct lu_prompt prompts[LU_LDAP_MAX];	/* Questions and answers. */
	gboolean bind_simple, bind_sasl;	/* What kind of bind to use. */
	char **mapped_user_attributes, **mapped_group_attributes;
	LDAP *ldap;				/* The connection. */
};

static void
close_server(LDAP *ldap)
{
	ldap_unbind_s(ldap);
}

/* Get the name of the user running the calling application. */
static char *
getuser(void)
{
	char buf[LINE_MAX * 4];
	struct passwd pwd, *err;
	int i;
	i = getpwuid_r(getuid(), &pwd, buf, sizeof(buf), &err);
	return ((i == 0) && (err == &pwd)) ? g_strdup(pwd.pw_name) : NULL;
}

static gboolean
nonempty(const char *string)
{
	return (string != NULL) && (strlen(string) > 0);
}

/* Connect to the server. */
static LDAP *
connect_server(struct lu_ldap_context *context, struct lu_error **error)
{
	LDAP *ldap = NULL;
	LDAPControl *server = NULL, *client = NULL;
	int version, ret;

	g_assert(context != NULL);
	LU_ERROR_CHECK(error);

	/* Create the LDAP context. */
	ldap = ldap_open(context->prompts[LU_LDAP_SERVER].value, LDAP_PORT);
	if (ldap == NULL) {
		lu_error_new(error, lu_error_init,
			     _("error initializing ldap library"));
		return NULL;
	}

	/* Switch to LDAPv3, which gives us some more features we need. */
	version = LDAP_VERSION3;
	ret = ldap_set_option(ldap,
			      LDAP_OPT_PROTOCOL_VERSION,
			      &version);
	if (ret != LDAP_OPT_SUCCESS) {
		lu_error_new(error, lu_error_init,
			     _("could not set LDAP protocol to version %d"),
			     version);
		close_server(ldap);
		return NULL;
	}

	/* Try to start TLS. */
	ret = ldap_start_tls_s(ldap, &server, &client);
	if (ret != LDAP_SUCCESS) {
		lu_error_new(error, lu_error_init,
			     _("could not negotiate TLS with LDAP server"));
		close_server(ldap);
		return NULL;
	}

	/* If we need to, try the LDAPS route. */
	if (ldap == NULL) { /* FIXME: dead code */
		/* Create the LDAP context. */
		ldap = ldap_open(context->prompts[LU_LDAP_SERVER].value,
				 LDAPS_PORT);
		if (ldap == NULL) {
			lu_error_new(error, lu_error_init,
				     _("error initializing ldap library"));
			return NULL;
		}

		/* Switch to LDAPv3, which we probably(?) need. */
		version = LDAP_VERSION3;
		ret = ldap_set_option(ldap,
				      LDAP_OPT_PROTOCOL_VERSION,
				      &version);
		if (ret != LDAP_OPT_SUCCESS) {
			lu_error_new(error, lu_error_init,
				     _("could not set LDAP protocol to version %d"),
				     version);
			close_server(ldap);
			return NULL;
		}
	}

	return ldap;
}

/* Authentication callback. */
static int
interact(LDAP *ld, unsigned flags, void *defs, void *xinteract_data)
{
	sasl_interact_t *interact_data;
	struct lu_ldap_context *ctx = (struct lu_ldap_context*) defs;
	int i, retval = LDAP_SUCCESS;

	(void)ld;
	(void)flags;
	for(i = 0, retval = LDAP_SUCCESS, interact_data = xinteract_data;
	    interact_data && (interact_data[i].id != SASL_CB_LIST_END);
	    i++) {
		interact_data[i].result = NULL;
		interact_data[i].len = 0;
		switch(interact_data[i].id) {
			case SASL_CB_USER:
				interact_data[i].result = ctx->prompts[LU_LDAP_AUTHUSER].value ?: "";
				interact_data[i].len = strlen(interact_data[i].result);
#ifdef DEBUG
				g_print("Sending SASL user `%s'.\n", (char*)interact_data[i].result);
#endif
				break;
			case SASL_CB_AUTHNAME:
				interact_data[i].result = ctx->prompts[LU_LDAP_AUTHZUSER].value;
				interact_data[i].len = strlen(interact_data[i].result);
#ifdef DEBUG
				g_print("Sending SASL auth user `%s'.\n", (char*)interact_data[i].result);
#endif
				break;
			default:
				retval = LDAP_OTHER;
		}
	}
	return retval;
}

/* Authenticate to the server. */
static LDAP *
bind_server(struct lu_ldap_context *context, struct lu_error **error)
{
	LDAP *ldap = NULL;
	LDAPControl *server = NULL, *client = NULL;
	int ret;
	const char *generated_binddn = "";
	char *binddn, *tmp, *key;
	char *user;
	char *password;
	struct lu_string_cache *scache = NULL;

	g_assert(context != NULL);
	LU_ERROR_CHECK(error);

	/* Create the connection. */
	ldap = connect_server(context, error);
	if (ldap == NULL) {
		return NULL;
	}

	/* Generate the DN we might want to bind to. */
	scache = context->global_context->scache;
	user = getuser();
	if (user) {
		tmp = scache->cache(scache, user);
		free(user);
		user = tmp;
	}
	if (nonempty(context->prompts[LU_LDAP_AUTHUSER].value)) {
		user = context->prompts[LU_LDAP_AUTHUSER].value;
	}
	key = g_strdup_printf("%s/%s", context->module->name, "userBranch");
	tmp = g_strdup_printf("uid=%s,%s,%s", user,
			      lu_cfg_read_single(context->global_context,
						 key,
						 USERBRANCH),
			      context->prompts[LU_LDAP_BASEDN].value);
	generated_binddn = scache->cache(scache, tmp);
	g_free(key);
	g_free(tmp);

	/* Try to bind to the server using SASL. */
	binddn = context->prompts[LU_LDAP_BINDDN].value;
	if (nonempty(context->prompts[LU_LDAP_AUTHUSER].value)) {
		ldap_set_option(ldap, LDAP_OPT_X_SASL_AUTHCID,
				context->prompts[LU_LDAP_AUTHUSER].value);
	}
	if (nonempty(context->prompts[LU_LDAP_AUTHZUSER].value)) {
		ldap_set_option(ldap, LDAP_OPT_X_SASL_AUTHZID,
				context->prompts[LU_LDAP_AUTHZUSER].value);
	}
	if (context->prompts[LU_LDAP_PASSWORD].value != NULL) {
		password = context->prompts[LU_LDAP_PASSWORD].value;
	} else {
		password = NULL;
	}

	ret = LDAP_SUCCESS + 1; /* Not LDAP_SUCCESS */

	if ((binddn != NULL) && (strlen(binddn) == 0)) {
		binddn = NULL;
	}
	if (context->bind_sasl) {
		/* Try to bind using SASL, and if that fails... */
#ifdef DEBUG
		g_print("Attempting SASL bind to `%s'.\n", binddn);
#endif
		ret = ldap_sasl_interactive_bind_s(ldap, binddn, NULL,
						   &server, &client,
						   LDAP_SASL_INTERACTIVE |
						   LDAP_SASL_QUIET,
						   interact,
						   context);
		if (ret != LDAP_SUCCESS) {
#ifdef DEBUG
			g_print("Attempting SASL bind to `%s'.\n",
				generated_binddn);
#endif
			ret = ldap_sasl_interactive_bind_s(ldap,
							   generated_binddn,
							   NULL, &server,
							   &client,
							   LDAP_SASL_INTERACTIVE |
							   LDAP_SASL_QUIET,
							   interact, context);
		}
	}
	if (ret != LDAP_SUCCESS && context->bind_simple) {
		/* try to bind using a password, and if that fails... */
		if ((password != NULL) && (strlen(password) > 0)) {
			if (nonempty(context->prompts[LU_LDAP_BINDDN].value)) {
#ifdef DEBUG
				g_print("Attempting simple bind to `%s'.\n",
					binddn);
#endif
				ret = ldap_simple_bind_s(ldap, binddn,
							 password);
			}
			if (ret != LDAP_SUCCESS) {
#ifdef DEBUG
				g_print("Attempting simple bind to `%s'.\n",
					generated_binddn);
#endif
				ret = ldap_simple_bind_s(ldap, generated_binddn,
							 password);
			}
		}
	}
	if (ret != LDAP_SUCCESS) {
		/* give up. */
		lu_error_new(error, lu_error_init,
			     _("could not bind to LDAP server"));
		close_server(ldap);
		return NULL;
	}
	return ldap;
#if 0
	/* Check if there are any supported SASL mechanisms. */
	if (ldap_search_ext_s(ldap, LDAP_ROOT_DSE, LDAP_SCOPE_BASE,
			      NULL, saslmechs, FALSE,
			      &server, &client,
			      NULL, 0, &results) != LDAP_SUCCESS) {
		lu_error_new(error, lu_error_init,
			     _("could not search LDAP server"));
		close_server(ldap);
		return NULL;
	}

	/* Get the DSE entry. */
	entry = ldap_first_entry(ldap, results);
	if (entry == NULL) {
		lu_error_new(error, lu_error_init,
			     _("LDAP server appears to have no root DSE"));
		close_server(ldap);
		return NULL;
	}

	/* Get the list of supported mechanisms. */
	values = ldap_get_values(ldap, entry, saslmechs[0]);
	if ((values != NULL) && (strlen(values[0]) > 0)) {
		sasl = TRUE;
	}

	if (ldap_sasl_interactive_bind_s(ldap, NULL, NULL, NULL, NULL,
					 LDAP_SASL_AUTOMATIC |
					 LDAP_SASL_QUIET, interact,
					 context) != LDAP_SUCCESS)
		if (ldap_simple_bind_s
		    (ldap, context->prompts[LU_LDAP_BINDDN].value,
		     context->prompts[LU_LDAP_PASSWORD].value) !=
		    LDAP_SUCCESS)
			if (ldap_simple_bind_s
			    (ldap, generated_binddn,
			     context->prompts[LU_LDAP_PASSWORD].value) !=
			    LDAP_SUCCESS) {
			}

	return ldap;
#endif
}

/* Create a string representation of the given value, which must be freed. */
char *
value_as_string(GValue *value)
{
	if (G_VALUE_HOLDS_STRING(value)) {
		return g_value_dup_string(value);
	} else
	if (G_VALUE_HOLDS_LONG(value)) {
		return  g_strdup_printf("%ld", g_value_get_long(value));
	} else {
		g_assert_not_reached();
	}
	return NULL;
}

/* Compare two values, which had better be of the same type. */
int
value_compare(GValue *aval, GValue *bval)
{
	if (G_VALUE_HOLDS_LONG(aval) && G_VALUE_HOLDS_LONG(bval)) {
		return g_value_get_long(aval) - g_value_get_long(bval);
	} else if (G_VALUE_HOLDS_STRING(aval) && G_VALUE_HOLDS_STRING(bval)) {
		return strcmp(g_value_get_string(aval),
			      g_value_get_string(bval));
	} else {
		return -1;
	}
	return 0;
}

/* Map an attribute name from an internal name to an LDAP atribute name. */
static const char *
map_to_ldap(struct lu_string_cache *cache, const char *libuser_attribute)
{
	size_t i;

	/* Luckily the only duplicate is LU_GIDNUMBER, which maps to the
	   same value in both cases. */
	for (i = 0; i < G_N_ELEMENTS(ldap_attribute_map); i++) {
		if (g_ascii_strcasecmp(ldap_attribute_map[i].lu_attribute,
				       libuser_attribute) == 0) {
			return ldap_attribute_map[i].ldap_attribute;
		}
	}
	return cache->cache(cache, libuser_attribute);
}

/* Generate the distinguished name which corresponds to the container where
 * the lu_ent structure's entry would be found. */
static const char *
lu_ldap_base(struct lu_module *module, const char *configKey,
	     const char *def)
{
	struct lu_ldap_context *context = module->module_context;
	const char *branch = NULL;
	char *tmp = NULL, *ret = NULL;

	g_assert(module != NULL);
	g_assert(configKey != NULL);
	g_assert(strlen(configKey) > 0);

	/* Read the branch of the tree we want to look in. */
	tmp = g_strdup_printf("%s/%s", module->name, configKey);
	branch = lu_cfg_read_single(module->lu_context, tmp, def);
	g_free(tmp);

	/* Generate the branch DN. */
	if (branch) {
		tmp = g_strdup_printf("%s,%s", branch,
				      context->prompts[LU_LDAP_BASEDN].
				      value);
	} else {
		tmp = g_strdup(context->prompts[LU_LDAP_BASEDN].value);
	}

	ret = module->scache->cache(module->scache, tmp);

	g_free(tmp);

	return ret;
}

/* Discover the distinguished name which corresponds to an account. */
static const char *
lu_ldap_ent_to_dn(struct lu_module *module, const char *namingAttr,
		  const char *name, const char *configKey, const char *def)
{
	const char *branch = NULL;
	char *tmp = NULL, *ret = NULL, *filter;
	char *noattrs[] = {NULL};
	const char *base = NULL;
	struct lu_ldap_context *ctx = NULL;
	LDAPMessage *messages = NULL, *entry = NULL;

	g_assert(module != NULL);
	g_assert(namingAttr != NULL);
	g_assert(strlen(namingAttr) > 0);
	g_assert(name != NULL);
	g_assert(strlen(name) > 0);
	g_assert(configKey != NULL);
	g_assert(strlen(configKey) > 0);

	/* Search for the right object using the entity's current name. */
	branch = lu_ldap_base(module, configKey, def);
	ctx = module->module_context;
	base = ctx->prompts[LU_LDAP_BASEDN].value;

	filter = g_strdup_printf("(%s=%s)",
				 map_to_ldap(module->scache, namingAttr),
				 name);
	if (ldap_search_s(ctx->ldap, branch, LDAP_SCOPE_SUBTREE, filter,
			  noattrs, FALSE, &messages) == LDAP_SUCCESS) {
		entry = ldap_first_entry(ctx->ldap, messages);
		if (entry != NULL) {
			tmp = ldap_get_dn(ctx->ldap, entry);
			ret = module->scache->cache(module->scache, tmp);
			if (tmp)
			  ldap_memfree(tmp);
		}
		ldap_msgfree(messages);
	}
	g_free(filter);

	if (ret == NULL) {
		/* Guess at the DN using the branch and the base. */
		if (branch) {
			tmp = g_strdup_printf("%s=%s,%s",
					      map_to_ldap(module->scache,
						          namingAttr),
					      name, branch);
			ret = module->scache->cache(module->scache, tmp);
			g_free(tmp);
		}
	}

	return ret;
}

/* This is the lookup workhorse. */
static gboolean
lu_ldap_lookup(struct lu_module *module,
	       const char *namingAttr, const char *name,
	       struct lu_ent *ent, GPtrArray *ent_array,
	       const char *configKey, const char *def,
	       const char *filter, const char *const *attributes,
	       int applicability, struct lu_error **error)
{
	LDAPMessage *messages = NULL, *entry = NULL;
	GValueArray *array;
	GValue value, *val;
	const char *attr;
	char *filt = NULL, **values = NULL, *p, **mapped_attributes;
	const char *dn = NULL;
	const char *base = NULL;
	size_t i, j;
	gboolean ret = FALSE;
	struct lu_ldap_context *ctx;

	g_assert(module != NULL);
	g_assert(namingAttr != NULL);
	g_assert(strlen(namingAttr) > 0);
	name = name ?: "*";
	g_assert((ent != NULL) || (ent_array != NULL));
	if (ent != NULL) {
		g_assert(ent->magic == LU_ENT_MAGIC);
	}
	g_assert(configKey != NULL);
	g_assert(strlen(configKey) > 0);
	g_assert(attributes != NULL);
	g_assert(attributes[0] != NULL);
	LU_ERROR_CHECK(error);

	ctx = module->module_context;

	if (ent != NULL) {
		/* Try to use the dn the object already knows about. */
		dn = NULL;

		if (dn == NULL) {
			array = lu_ent_get(ent, DISTINGUISHED_NAME);
			if ((array != NULL) && (array->n_values > 0)) {
				val = g_value_array_get_nth(array, 0);
				if (G_VALUE_HOLDS_STRING(val)) {
					dn = g_value_get_string(val);
				}
			}
		}

		if (dn == NULL)
			/* Map the user or group name to an LDAP object name. */
			dn = lu_ldap_ent_to_dn(module, namingAttr, name,
					       configKey, def);

		if (dn == NULL) {
			lu_error_new(error, lu_error_generic,
				     _("error mapping name to LDAP distinguished name"));
			return FALSE;
		}
	}

	/* Get the entry in the directory under which we'll search for this
	 * entity. */
	base = lu_ldap_base(module, configKey, def);
	if (base == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("error mapping name to LDAP base distinguished name"));
		return FALSE;
	}

	/* Generate an LDAP filter, optionally including a filter supplied
	 * by the caller. */
	if (filter && (strlen(filter) > 0)) {
		filt = g_strdup_printf("(&%s(%s=%s))", filter,
				       namingAttr, name);
	} else {
		filt = g_strdup_printf("(%s=%s)", namingAttr, name);
	}

#ifdef DEBUG
	g_print("Looking up `%s' with filter `%s'.\n", dn, filt);
#endif

	if (attributes == lu_ldap_user_attributes)
		mapped_attributes = ctx->mapped_user_attributes;
	else if (attributes == lu_ldap_group_attributes)
		mapped_attributes = ctx->mapped_group_attributes;
	else {
		g_assert_not_reached();
		mapped_attributes = NULL;
	}

	if (ent != NULL) {
		/* Perform the search and read the first (hopefully only)
		 * entry. */
		if (ldap_search_s(ctx->ldap, dn, LDAP_SCOPE_BASE, filt,
				  mapped_attributes, FALSE,
				  &messages) == LDAP_SUCCESS) {
			entry = ldap_first_entry(ctx->ldap, messages);
		}
	}

	/* If there isn't an entry with this exact name, search for something
	 * which matches. */
	if (entry == NULL) {
#ifdef DEBUG
		g_print("Looking under `%s' with filter `%s'.\n", base,
			filt);
#endif
		if (messages != NULL) {
			ldap_msgfree(messages);
			messages = NULL;
		}
		if (ldap_search_s(ctx->ldap, base, LDAP_SCOPE_SUBTREE, filt,
				  mapped_attributes, FALSE, &messages) == LDAP_SUCCESS) {
			entry = ldap_first_entry(ctx->ldap, messages);
		}
	}

	/* We don't need the generated filter any more, so free it. */
	g_free(filt);

	/* If we got an entry, read its contents into an entity structure. */
	while (entry != NULL) {
		/* Mark that the search succeeded. */
		ret = TRUE;
		/* If we need to add the data to the array, then create a new
		 * data item to hold the data. */
		if (ent_array != NULL) {
			if (applicability & LU_LDAP_USER) {
				ent = lu_ent_new_typed(lu_user);
			} else
			if (applicability & LU_LDAP_GROUP) {
				ent = lu_ent_new_typed(lu_group);
			} else {
				g_assert_not_reached();
			}
		}
		/* Set the distinguished name. */
		memset(&value, 0, sizeof(value));
		g_value_init(&value, G_TYPE_STRING);
		p = ldap_get_dn(ctx->ldap, entry);
		g_value_set_string(&value, p);
		ldap_memfree(p);
		lu_ent_clear_current(ent, DISTINGUISHED_NAME);
		lu_ent_add_current(ent, DISTINGUISHED_NAME, &value);
		g_value_unset(&value);

		/* Read each of the attributes we asked for. */
		for (i = 0; attributes[i]; i++) {
			/* Get the values which correspond to this attribute. */
			attr = attributes[i];
			values = ldap_get_values(ctx->ldap, entry,
						 mapped_attributes[i]);
			/* If we got answers, add them. */
			if (values) {
				lu_ent_clear_current(ent, attr);
				for (j = 0; values[j]; j++) {
#ifdef DEBUG
					g_print("Got `%s' = `%s'.\n",
						attr, values[j]);
#endif
					/* Check if the value is numeric. */
					strtol(values[j], &p, 0);
					if (*p == '\0') {
						/* If it's a number, use a
						 * long. */
						g_value_init(&value, G_TYPE_LONG);
						g_value_set_long(&value, atol(values[j]));
					} else {
						/* Otherwise it's a string. */
						g_value_init(&value, G_TYPE_STRING);
						g_value_set_string(&value, values[j]);
					}
					/* Add this value, and then clear the
					 * value structure. */
					lu_ent_add_current(ent, attr, &value);
					g_value_unset(&value);
				}
				ldap_value_free(values);
			}
		}
		/* Stash the data in the array if we need to. */
		if (ent_array != NULL) {
			g_ptr_array_add(ent_array, ent);
			ent = NULL;
			/* Go to the next entry. */
			entry = ldap_next_entry(ctx->ldap, entry);
		} else {
			/* Stop here. */
			entry = NULL;
		}
	}
	/* Free all of the responses. */
	if (messages) {
		ldap_msgfree(messages);
	}

	return ret;
}

/* Look up a user by name. */
static gboolean
lu_ldap_user_lookup_name(struct lu_module *module, const char *name,
			 struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_lookup(module, map_to_ldap(ent->cache, LU_USERNAME),
			      name, ent, NULL, "userBranch", USERBRANCH,
			      "("OBJECTCLASS"="POSIXACCOUNT")",
			      lu_ldap_user_attributes,
			      LU_LDAP_USER | LU_LDAP_SHADOW, error);
}

/* Look up a user by ID. */
static gboolean
lu_ldap_user_lookup_id(struct lu_module *module, uid_t uid,
		       struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = FALSE;

	gchar *uid_string = NULL;

	LU_ERROR_CHECK(error);
	uid_string = g_strdup_printf("%ld", (long)uid);
	ret = lu_ldap_lookup(module, map_to_ldap(ent->cache, LU_UIDNUMBER),
			     uid_string, ent, NULL, "userBranch", USERBRANCH,
			     "("OBJECTCLASS"="POSIXACCOUNT")",
			     lu_ldap_user_attributes,
			     LU_LDAP_USER | LU_LDAP_SHADOW, error);
	g_free(uid_string);

	return ret;
}

/* Look up a group by name. */
static gboolean
lu_ldap_group_lookup_name(struct lu_module *module, const char *name,
			  struct lu_ent *ent, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_lookup(module, map_to_ldap(ent->cache, LU_GROUPNAME),
			      name, ent, NULL,
			      "groupBranch", GROUPBRANCH,
			      "("OBJECTCLASS"="POSIXGROUP")",
			      lu_ldap_group_attributes, LU_LDAP_GROUP, error);
}

/* Look up a group by ID. */
static gboolean
lu_ldap_group_lookup_id(struct lu_module *module, gid_t gid,
			struct lu_ent *ent, struct lu_error **error)
{
	gboolean ret = FALSE;
	gchar *gid_string = NULL;

	LU_ERROR_CHECK(error);
	gid_string = g_strdup_printf("%ld", (long)gid);
	ret = lu_ldap_lookup(module, map_to_ldap(ent->cache, LU_GIDNUMBER),
			     gid_string, ent, NULL,
			     "groupBranch", GROUPBRANCH,
			     "("OBJECTCLASS"="POSIXGROUP")",
			     lu_ldap_group_attributes, LU_LDAP_GROUP, error);
	g_free(gid_string);

	return ret;
}

/* Compare the contents of two GValueArrays, and return TRUE if they contain
 * the same set of values, though not necessarily in the same order. */
static gboolean
arrays_equal(GValueArray *a, GValueArray *b)
{
	GValue *aval, *bval;
	size_t i, j;
	if ((a != NULL) && (b == NULL)) {
		return FALSE;
	}
	if ((a == NULL) && (b != NULL)) {
		return FALSE;
	}
	/* FIXME: Can be done in O(N log N) */
	for (i = 0; i < a->n_values; i++) {
		aval = g_value_array_get_nth(a, i);
		for (j = 0; j < b->n_values; j++) {
			bval = g_value_array_get_nth(b, j);
			if (value_compare(aval, bval) == 0) {
				break;
			}
		}
		if (j >= b->n_values) {
			return FALSE;
		}
	}
	for (j = 0; j < b->n_values; j++) {
		bval = g_value_array_get_nth(b, j);
		for (i = 0; i < a->n_values; i++) {
			aval = g_value_array_get_nth(a, i);
			if (value_compare(aval, bval) == 0) {
				break;
			}
		}
		if (i >= a->n_values) {
			return FALSE;
		}
	}
	return TRUE;
}

/* Check whether class is among old_values or new_values */
static int
objectclass_present(const char *dn, const char *class, char *const *old_values,
		    size_t old_count, char *const *new_values,
		    size_t new_count)
{
	size_t i;
	
	for (i = 0; i < old_count; i++) {
		if (strcmp(class, old_values[i]) == 0) {
#ifdef DEBUG
			g_print("Entity `%s' is already a `%s'.\n", dn,
				old_values[i]);
#endif
			return 1;
		}
	}
	for (i = 0; i < new_count; i++) {
		if (strcmp(class, new_values[i]) == 0) {
#ifdef DEBUG
			g_print("Entity `%s' was already determined to be a "
				"`%s'.\n", dn, new_values[i]);
#endif
			return 1;
		}
	}
	return 0;
}

/* Create a list of new object classes needed for representing all attributes,
 * assuming old_values (may be NULL).
 *
 * Returns NULL if no new object classes are needed. */
static char **
lu_ldap_needed_objectclasses(const char *dn, struct lu_ent *ent,
			     char **old_values)
{
	char **new_values;
	size_t old_count, new_count;
	GList *attributes, *a;
	int applicability;

	if (old_values)
		old_count = ldap_count_values(old_values);
	else
		old_count = 0;
	
	if (ent->type == lu_user)
		applicability = LU_LDAP_USER | LU_LDAP_SHADOW;
	else
		applicability = LU_LDAP_GROUP;

	new_values = g_malloc(sizeof(*new_values) *
			      (G_N_ELEMENTS(ldap_attribute_map) + 1 + 1));
	new_count = 0;
	
	/* Iterate over all of the attributes the object possesses. */
	attributes = lu_ent_get_attributes(ent);
	for (a = attributes; a != NULL; a = a->next) {
		size_t i;
		const char *attr;

		attr = a->data;
#ifdef DEBUG
		g_print("Entity `%s' has attribute `%s'.\n", dn, attr);
#endif
		/* Get the name of the next object class the object needs
		 * to be a member of. */
		for (i = 0; i < G_N_ELEMENTS(ldap_attribute_map); i++) {
			if ((ldap_attribute_map[i].applicability
			     & applicability) != 0
			    && strcasecmp(ldap_attribute_map[i].lu_attribute,
					  attr) == 0) {
#ifdef DEBUG
				g_print("Entity `%s' needs to be a `%s'.\n",
					dn, ldap_attribute_map[i].objectclass);
#endif
				break;
			}
		}
		/* If the attribute doesn't map to a class, skip it. */
		if (i >= G_N_ELEMENTS(ldap_attribute_map))
			continue;
		/* Check if the object class the object needs to be in is
		 * already one of which it is a part or is already being
		 * added. */
		if (objectclass_present(dn, ldap_attribute_map[i].objectclass,
					old_values, old_count, new_values,
					new_count))
			continue;

		/* Add it to the class. */
		new_values[new_count]
			= (char *)ldap_attribute_map[i].objectclass;
#ifdef DEBUG
		g_print("Adding entity `%s' to class `%s'.\n", dn,
			new_values[new_count]);
#endif
		new_count++;
	}
	g_list_free(attributes);
	/* Ugly, but implied by the fact that the basic account schemas are not
	 * structural.  We can't use INETORGPERSON unless LU_SN is present,
	 * which would already force usage of INETORGPERSON; so if
	 * INETORGPERSON is not used, we add ACCOUNT. */
	if (ent->type == lu_user
	    && !objectclass_present(dn, INETORGPERSON, old_values, old_count,
				    new_values, new_count))
		new_values[new_count++] = ACCOUNT;
	if (new_count != 0)
		new_values[new_count] = NULL;
	else {
		g_free(new_values);
		new_values = NULL;
	}
	return new_values;
}

/* Build a list of LDAPMod structures for adding the entity object. */
static LDAPMod **
get_ent_adds(const char *dn, struct lu_ent *ent)
{
	LDAPMod **mods;
	GList *attrs;

	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);

	mods = NULL;
	/* If there are no attributes, then this is EASY. */
	attrs = lu_ent_get_attributes(ent);
	if (attrs) {
		char **classes;
		size_t mod_count, i;
		LDAPMod *mod;
		GValueArray *vals;
		GValue *value;
		const GList *a;

		mods = g_malloc0(sizeof(*mods)
				 * (g_list_length(attrs) + 2 + 1));
		mod_count = 0;
		for (a = attrs; a != NULL; a = a->next) {
			const char *attribute;

			attribute = a->data;
			if (strcasecmp(attribute, DISTINGUISHED_NAME) == 0)
				continue;
			/* We don't have shadow passwords.  Period. */
			if (strcasecmp(attribute, LU_SHADOWPASSWORD) == 0)
				continue;
			vals = lu_ent_get(ent, attribute);
			if (vals == NULL || vals->n_values == 0)
				continue;
			attribute = map_to_ldap(ent->cache, attribute);

			mod = g_malloc0(sizeof(*mod));
			mod->mod_op = LDAP_MOD_ADD;
			mod->mod_type = (char *)attribute;
			mod->mod_values
				= g_malloc0((vals->n_values + 1)
					    * sizeof(*mod->mod_values));
			for (i = 0; i < vals->n_values; i++) {
				value = g_value_array_get_nth(vals, i);
				mod->mod_values[i] = value_as_string(value);
			}
			mods[mod_count++] = mod;
		}
		/* We don't need the list of attributes any more. */
		g_list_free(attrs);
		classes = lu_ldap_needed_objectclasses(dn, ent, NULL);
		if (classes != NULL) {
			mod = g_malloc0(sizeof(*mod));
			mod->mod_op = LDAP_MOD_ADD;
			mod->mod_type = OBJECTCLASS;
			mod->mod_values
				= g_malloc0((ldap_count_values(classes) + 1)
					    * sizeof(*mod->mod_values));
			for (i = 0; classes[i] != NULL; i++)
				mod->mod_values[i] = g_strdup(classes[i]);
			g_free(classes);
			mods[mod_count++] = mod;
		}
		/* Ugly hack:
		 *
		 * Make sure there is 'cn', posixAccount requires it. */
		if (ent->type == lu_user
		    && lu_ent_get(ent, LU_COMMONNAME) == NULL) {
			char *cn;
			
			vals = lu_ent_get(ent, LU_GECOS);
			if (vals != NULL) {
				char *p;

				value = g_value_array_get_nth(vals, 0);
				cn = value_as_string(value);
				p = strchr(cn, ',');
				if (p != NULL)
					*p = 0;
			} else {
				vals = lu_ent_get(ent, LU_USERNAME);
				/* Guaranteed by lu_ldap_set() */
				g_assert (vals != NULL);
				value = g_value_array_get_nth(vals, 0);
				cn = value_as_string(value);
			}
			mod = g_malloc0(sizeof(*mod));
			mod->mod_op = LDAP_MOD_ADD;
			mod->mod_type = (char *)map_to_ldap(ent->cache,
							    LU_COMMONNAME);
			mod->mod_values
				= g_malloc0(2 * sizeof (*mod->mod_values));
			mod->mod_values[0] = cn;
			mods[mod_count++] = mod;
		}
	}
	return mods;
}

/* Build a list of LDAPMod structures based on the differences between the
 * pending and current values in the entity object. */
static LDAPMod **
get_ent_mods(struct lu_module *module, struct lu_ent *ent,
	     const char *namingAttr)
{
	LDAPMod **mods = NULL;
	GList *attrs = NULL;

	g_assert(ent != NULL);
	g_assert(ent->magic == LU_ENT_MAGIC);
	g_assert(namingAttr != NULL);
	g_assert(namingAttr[0] != 0);

	/* If there are no attributes, then this is EASY. */
	attrs = lu_ent_get_attributes(ent);
	if (attrs) {
		GValueArray *empty;
		size_t mod_count;
		LDAPMod *mod;
		const GList *a;

		empty = g_value_array_new(0);
		/* Allocate an array big enough to hold two LDAPMod structures
		 * for each attribute, in case all of them need changing. */
		mods = g_malloc0(sizeof(*mods) *
				 ((2 * g_list_length(attrs)) + 1));
		mod_count = 0;
		for (a = attrs; a != NULL; a = a->next) {
			GValueArray *current, *pending, *additions, *deletions;
			GValue *value, *pvalue, *cvalue;
			char *attribute;
			size_t j, k;

			/* Get the name of the attribute, and its current and
			 * pending values. */
			attribute = a->data;
			if (strcasecmp(attribute, DISTINGUISHED_NAME) == 0
			    || strcasecmp(attribute, namingAttr) == 0)
				continue;
			current = lu_ent_get_current(ent, attribute) ?: empty;
			pending = lu_ent_get(ent, attribute) ?: empty;
			additions = g_value_array_new(0);
			deletions = g_value_array_new(0);
			attribute = (char *)map_to_ldap(ent->cache, attribute);

			/* Create a pair of modification request structures,
			 * using the LDAP name for the attribute, using
			 * elements from the first array which aren't in the
			 * second for the remove list, and elements which are
			 * in the second but not the first for the add list. */
			for (j = 0; j < current->n_values; j++) {
				cvalue = g_value_array_get_nth(current, j);
				/* Search for this value in the other array. */
				for (k = 0; k < pending->n_values; k++) {
					pvalue = g_value_array_get_nth(pending,
								       k);
					if (value_compare(cvalue, pvalue) == 0){
						break;
					}
				}
				/* If not found, it's a mod. */
				if (k >= pending->n_values)
					/* Delete this value. */
					g_value_array_append(deletions, cvalue);
			}
			/* If we have deletions, create an LDAPMod structure
			 * containing them. */
			if (deletions->n_values != 0) {
				mod = g_malloc0(sizeof(*mod));
				mod->mod_op = LDAP_MOD_DELETE;
				mod->mod_type = attribute;
				mod->mod_values
					= g_malloc0((deletions->n_values + 1)
						    * sizeof(*mod->mod_values));
				for (j = 0; j < deletions->n_values; j++) {
					value = g_value_array_get_nth(deletions, j);
					mod->mod_values[j]
						= value_as_string(value);
				}
				mods[mod_count++] = mod;
			}

			/* Now extract additions. */
			for (j = 0; j < pending->n_values; j++) {
				pvalue = g_value_array_get_nth(pending, j);
				/* Search for this value in the other array. */
				for (k = 0; k < current->n_values; k++) {
					cvalue = g_value_array_get_nth(current,
								       k);
					if (value_compare(cvalue, pvalue) == 0){
						break;
					}
				}
				/* If not found, it's a mod. */
				if (k >= current->n_values)
					/* Add this value. */
					g_value_array_append(additions, pvalue);
			}
			/* If we have additions, create an LDAPMod structure
			 * containing them. */
			if (additions->n_values != 0) {
				mod = g_malloc0(sizeof(*mod));
				mod->mod_op = LDAP_MOD_ADD;
				mod->mod_type = attribute;
				mod->mod_values
					= g_malloc0((additions->n_values + 1)
						    * sizeof(*mod->mod_values));
				for (j = 0; j < additions->n_values; j++) {
					value = g_value_array_get_nth(additions, j);
					mod->mod_values[j]
						= value_as_string(value);
				}
				mods[mod_count++] = mod;
			}

			g_value_array_free(additions);
			g_value_array_free(deletions);
		}
		g_value_array_free(empty);
		/* We don't need the list of attributes any more. */
		g_list_free(attrs);
	}
	return mods;
}

/* Free a set of modification structures generated by get_ent_mods(). */
static void
free_ent_mods(LDAPMod ** mods)
{
	int i, j;
	g_assert(mods != NULL);
	for (i = 0; mods && mods[i]; i++) {
		if (mods[i]->mod_values) {
			for (j = 0; mods[i]->mod_values[j] != NULL; j++) {
				g_free(mods[i]->mod_values[j]);
			}
			g_free(mods[i]->mod_values);
		}
		g_free(mods[i]);
	}
	g_free(mods);
}

#ifdef DEBUG
/* Dump out the modifications structure.  For debugging only. */
static void
dump_mods(LDAPMod ** mods)
{
	int i, j;
	g_assert(mods != NULL);
	for (i = 0; mods[i]; i++) {
		g_print("%s (%d)\n", mods[i]->mod_type, mods[i]->mod_op);
		if (mods[i]->mod_values) {
			for (j = 0; mods[i]->mod_values[j]; j++) {
				g_print(" = `%s'\n",
					mods[i]->mod_values[j]);
			}
		}
	}
}
#endif /* DEBUG */

/* Add an entity's LDAP object to the proper object classes to allow the
 * user to possess the attributes she needs to. */
static void
lu_ldap_fudge_objectclasses(struct lu_ldap_context *ctx,
			    const char *dn,
			    struct lu_ent *ent)
{
	char *attrs[] = {
		OBJECTCLASS,
		NULL,
	};
	char **old_values, **new_values;
	LDAPMessage *res = NULL;
	LDAPMessage *entry;

	/* Pull up this object's entry. */
	if (ldap_search_s(ctx->ldap, dn, LDAP_SCOPE_BASE, NULL,
			  attrs, FALSE, &res) != LDAP_SUCCESS) {
		return;
	}

	entry = ldap_first_entry(ctx->ldap, res);
	if (entry == NULL) {
		ldap_msgfree(res);
		return;
	}

	/* Get the list of object classes the object is in now. */
	old_values = ldap_get_values(ctx->ldap, entry, OBJECTCLASS);

	new_values = lu_ldap_needed_objectclasses(dn, ent, old_values);
	if (new_values != NULL) {
		LDAPMod mod;
		LDAPMod *mods[] = { &mod, NULL };
#ifdef DEBUG
		g_print("Adding user `%s' to new classes.\n", dn);
#endif
		/* Set up the modify request. */
		memset(&mod, 0, sizeof(mod));
		mod.mod_op = LDAP_MOD_ADD;
		mod.mod_type = OBJECTCLASS;
		mod.mod_values = new_values;

		/* Give it the old try. */
		ldap_modify_s(ctx->ldap, dn, mods);
		g_free (new_values);
	}
	ldap_value_free(old_values);

	ldap_msgfree(res);
}

/* Apply the changes to a given entity structure, or add a new entitty. */
static gboolean
lu_ldap_set(struct lu_module *module, enum lu_entity_type type, int add,
	    struct lu_ent *ent, const char *configKey, const char *def,
	    struct lu_error **error)
{
	LDAPMod **mods = NULL;
	LDAPControl *server = NULL, *client = NULL;
	GValueArray *name = NULL, *old_name = NULL;
	GValue *value;
	char *name_string;
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

	/* Get the user/group's pending name, which may be different from the
	 * current name.  If so, we want to change it seperately, because it
	 * requires a renaming of the object in the directory. */
	if (type == lu_user)
		namingAttr = LU_USERNAME;
	else
		namingAttr = LU_GROUPNAME;
	name = lu_ent_get(ent, namingAttr);
	if (name == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("user object had no %s attribute"),
			     namingAttr);
		return FALSE;
	}

	/* Get the object's old (current) name. */
	old_name = lu_ent_get_current(ent, namingAttr);
	if (old_name == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("user object was created with no `%s'"),
			     namingAttr);
		return FALSE;
	}

	/* Get the object's current object name. */
	value = g_value_array_get_nth(add ? name : old_name, 0);
	name_string = value_as_string(value);
	dn = lu_ldap_ent_to_dn(module, namingAttr, name_string, configKey,
			       def);
	g_free(name_string);
	if (dn == NULL) {
		lu_error_new(error, lu_error_generic,
			     _
			     ("error mapping name to LDAP distinguished name"));
		return FALSE;
	}

	/* Get the list of changes needed. */
	if (add)
		mods = get_ent_adds(dn, ent);
	else
		mods = get_ent_mods(module, ent, namingAttr);
	if (mods == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("could not convert internal data to LDAPMods"));
		return FALSE;
	}
#ifdef DEBUG
	dump_mods(mods);
	g_message("Modifying `%s'.\n", dn);
#endif

	if (add) {
		err = ldap_add_ext_s(ctx->ldap, dn, mods, &server, &client);
		if (err == LDAP_SUCCESS)
			ret = TRUE;
		else {
			/* FIXME: STRING_FREEZE */
			lu_error_new(error, lu_error_write, "error creating "
				     "a LDAP directory entry: %s",
				     ldap_err2string(err));
			goto err_mods;
		}
	} else {
		/* Attempt the modify operation. */
		err = ldap_modify_ext_s(ctx->ldap, dn, mods, &server, &client);
		if (err == LDAP_SUCCESS)
			ret = TRUE;
		else {
			if (err == LDAP_OBJECT_CLASS_VIOLATION) {
				/* AAAARGH!  The application decided it wanted
				 * to add some new attributes!  Damage
				 * control.... */
				lu_ldap_fudge_objectclasses(ctx, dn, ent);
				err = ldap_modify_ext_s(ctx->ldap, dn, mods,
							&server, &client);
			}
			if (err == LDAP_SUCCESS)
				ret = TRUE;
			else {
				lu_error_new(error, lu_error_write,
					     _("error modifying LDAP "
					       "directory entry: %s"),
					     ldap_err2string(err));
				goto err_mods;
			}
		}

		/* If the name has changed, process a rename (modrdn). */
		if (arrays_equal(name, old_name) == FALSE) {
			char *tmp1, *tmp2;

			ret = FALSE;
			/* Format the name to rename it to. */
			value = g_value_array_get_nth(name, 0);
			tmp1 = value_as_string(value);
			tmp2 = g_strconcat(map_to_ldap(module->scache,
						       namingAttr), "=",
					   tmp1, NULL);
			g_free (tmp1);
			/* Attempt the rename. */
			err = ldap_rename_s(ctx->ldap, dn, tmp2, NULL, TRUE,
					    &server, &client);
			g_free(tmp2);
			if (err == LDAP_SUCCESS)
				ret = TRUE;
			else {
				lu_error_new(error, lu_error_write,
					     _("error renaming LDAP directory "
					       "entry: %s\n"),
					     ldap_err2string(err));
				goto err_mods;
			}
		}
	}
	
 err_mods:
	free_ent_mods(mods);

	return ret;
}

/* Remove an entry from the directory. */
static gboolean
lu_ldap_del(struct lu_module *module, enum lu_entity_type type,
	    struct lu_ent *ent, const char *configKey, const char *def,
	    struct lu_error **error)
{
	LDAPControl *server = NULL, *client = NULL;
	GValueArray *name = NULL;
	GValue *value;
	char *name_string;
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

	/* Get the user or group's name. */
	if (type == lu_user) {
		namingAttr = LU_USERNAME;
	} else {
		namingAttr = LU_GROUPNAME;
	}

	name = lu_ent_get(ent, namingAttr);
	if (name == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("object had no %s attribute"), namingAttr);
		return FALSE;
	}

	/* Convert the name to a distinguished name. */
	value = g_value_array_get_nth(name, 0);
	name_string = value_as_string(value);
	dn = lu_ldap_ent_to_dn(module, namingAttr, name_string, configKey,
			       def);
	g_free(name_string);
	if (dn == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("error mapping name to LDAP distinguished name"));
		return FALSE;
	}
	/* Process the removal. */
#ifdef DEBUG
	g_message("Removing `%s'.\n", dn);
#endif
	err = ldap_delete_ext_s(ctx->ldap, dn, &server, &client);
	if (err == LDAP_SUCCESS) {
		ret = TRUE;
	} else {
		lu_error_new(error, lu_error_write,
			     _("error removing LDAP directory entry: %s.\n"),
			     ldap_err2string(err));
		return FALSE;
	}

	return ret;
}

/* Lock an account of some kind. */
static gboolean
lu_ldap_handle_lock(struct lu_module *module, struct lu_ent *ent,
		    const char *namingAttr, gboolean sense,
		    const char *configKey, const char *def,
		    struct lu_error **error)
{
	const char *dn;
	gboolean ret = FALSE;
	LDAPMod mod[2], *mods[3];
	LDAPControl *server = NULL, *client = NULL;
	GValueArray *name, *password;
	GValue *value;
	char *result, *name_string, *oldpassword, *values[2][2];
	const char *tmp, *attribute;
	struct lu_ldap_context *ctx = module->module_context;
	size_t scheme_len = strlen(LU_CRYPTED);
	int err;

	g_assert(module != NULL);
	g_assert(ent != NULL);
	g_assert(namingAttr != NULL);
	g_assert(strlen(namingAttr) > 0);
	LU_ERROR_CHECK(error);

	/* Get the entry's name. */
	name = lu_ent_get(ent, namingAttr);
	if (name == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("object has no %s attribute"), namingAttr);
		return FALSE;
	}

	/* Convert the name to a distinguished name. */
	value = g_value_array_get_nth(name, 0);
	name_string = value_as_string(value);
	dn = lu_ldap_ent_to_dn(module, namingAttr, name_string, configKey,
			       def);
	g_free(name_string);
	if (dn == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("error mapping name to LDAP distinguished name"));
		return FALSE;
	}

	attribute = ent->type == lu_user ? LU_USERPASSWORD : LU_GROUPPASSWORD;

	/* Get the values for the entry's password. */
	password = lu_ent_get_current(ent, attribute);
	if (password == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("object has no %s attribute"),
			     LU_USERPASSWORD);
		return FALSE;
	}
	value = g_value_array_get_nth(password, 0);
	oldpassword = value_as_string(value);

	/* We only know how to lock crypted passwords, so crypt it if it
	 * isn't already. */
	if (strncmp(oldpassword, LU_CRYPTED, scheme_len) != 0) {
		tmp = lu_make_crypted(oldpassword,
				      lu_common_default_salt_specifier(module));
		if (tmp == NULL) {
			/* FIXME: STRING_FREEZE */
			lu_error_new(error, lu_error_generic,
				     "error encrypting password");
			g_free(oldpassword);
			return FALSE;
		}
	} else {
		tmp = ent->cache->cache(ent->cache, oldpassword + scheme_len);
	}
	result = ent->cache->cache(ent->cache, tmp);

	/* Generate a new string with the modification applied. */
	if (sense) {
		if (result[0] != LOCKCHAR)
			result = g_strdup_printf("%s%c%s", LU_CRYPTED,
						 LOCKCHAR, result);
		else
			result = g_strdup_printf("%s%s", LU_CRYPTED, result);
	} else {
		if (result[0] == LOCKCHAR)
			result = g_strdup_printf("%s%s", LU_CRYPTED,
						 result + 1);
		else
			result = g_strdup_printf("%s%s", LU_CRYPTED, result);
	}
	/* Set up the LDAP modify operation. */
	mod[0].mod_op = LDAP_MOD_DELETE;
	mod[0].mod_type = (char *)map_to_ldap(ent->cache, attribute);
	values[0][0] = ent->cache->cache(ent->cache, oldpassword);
	values[0][1] = NULL;
	mod[0].mod_values = values[0];

	mod[1].mod_op = LDAP_MOD_ADD;
	mod[1].mod_type = mod[0].mod_type;
	values[1][0] = ent->cache->cache(ent->cache, result);
	values[1][1] = NULL;
	mod[1].mod_values = values[1];
	g_free(result);

	/* Set up the array to pass to the modification routines. */
	mods[0] = &mod[0];
	mods[1] = &mod[1];
	mods[2] = NULL;

	err = ldap_modify_ext_s(ctx->ldap, dn, mods, &server, &client);
	if (err == LDAP_SUCCESS) {
		ret = TRUE;
	} else {
		lu_error_new(error, lu_error_write,
			     _("error modifying LDAP directory entry: %s"),
			     ldap_err2string(err));
		ret = FALSE;
	}

	g_free(oldpassword);

	return ret;
}

/* Check if an account is locked. */
static gboolean
lu_ldap_is_locked(struct lu_module *module, struct lu_ent *ent,
		  const char *namingAttr, const char *configKey,
		  const char *def, struct lu_error **error)
{
	const char *dn, *mapped_password;
	GValueArray *name;
	GValue *value;
	char *name_string;
	struct lu_ldap_context *ctx = module->module_context;
	char *attributes[] = { NULL, NULL };
	char **values = NULL;
	LDAPMessage *entry = NULL, *messages = NULL;
	int i;
	gboolean locked = FALSE;

	/* Get the name of the user or group. */
	name = lu_ent_get(ent, namingAttr);
	if (name == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("object has no %s attribute"), namingAttr);
		return FALSE;
	}

	/* Convert the name to a distinguished name. */
	value = g_value_array_get_nth(name, 0);
	name_string = value_as_string(value);
	dn = lu_ldap_ent_to_dn(module, namingAttr, name_string, configKey,
			       def);
	g_free(name_string);
	if (dn == NULL) {
		lu_error_new(error, lu_error_generic,
			     _
			     ("error mapping name to LDAP distinguished name"));
		return FALSE;
	}
#ifdef DEBUG
	g_print("Looking up `%s'.\n", dn);
#endif

	mapped_password = map_to_ldap(module->scache, ent->type == lu_user
				      ? LU_USERPASSWORD : LU_GROUPPASSWORD);

	/* Read the entry data. */
	attributes[0] = (char *)mapped_password;
	if (ldap_search_s(ctx->ldap, dn, LDAP_SCOPE_BASE, ent->type == lu_user
			  ? "("OBJECTCLASS"="POSIXACCOUNT")"
			  : "("OBJECTCLASS"="POSIXGROUP")", attributes,
			  FALSE, &messages) == LDAP_SUCCESS) {
		entry = ldap_first_entry(ctx->ldap, messages);
	}
	if (entry == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("no such object in LDAP directory"));
		return FALSE;
	}

	/* Read the values for the attribute we want to change. */
	values = ldap_get_values(ctx->ldap, entry, mapped_password);
	if (values == NULL) {
		ldap_msgfree(messages);
#ifdef DEBUG
		g_print("No `%s' attribute found for entry.", mapped_password);
#endif
		lu_error_new(error, lu_error_generic,
			     _("no `%s' attribute found"), mapped_password);
		return FALSE;
	}
	/* Check any of the possibly-multiple passwords. */
	locked = FALSE;
	for (i = 0; values[i] != NULL; i++) {
#ifdef DEBUG
		g_print("Got `%s' = `%s'.\n", mapped_password, values[i]);
#endif
		if (strncmp(values[i], LU_CRYPTED, strlen(LU_CRYPTED)) == 0) {
			locked = (values[i][strlen(LU_CRYPTED)] == LOCKCHAR);
			break;
		}
	}
	/* Clean up and return. */
	ldap_value_free(values);
	if (messages != NULL) {
		ldap_msgfree(messages);
	}

	return locked;
}

/* Set the password for an account. */
static gboolean
lu_ldap_setpass(struct lu_module *module, const char *namingAttr,
		struct lu_ent *ent, const char *configKey, const char *def,
		const char *password, struct lu_error **error)
{
	const char *dn, *mapped_password;
	GValueArray *name;
	GValue *value;
	char *name_string;
	struct lu_ldap_context *ctx = module->module_context;
	char *attributes[] = { NULL, NULL };
	char **values, *addvalues[] = { NULL, NULL }, *rmvalues[] = {
	NULL, NULL};
	char *tmp = NULL, *previous;
	int i;
	size_t j;
	LDAPMessage *entry = NULL, *messages = NULL;
	LDAPMod addmod, rmmod;
	LDAPMod *mods[3];
	LDAPControl *server = NULL, *client = NULL;
	char filter[LINE_MAX];

	/* Get the user or group's name. */
#ifdef DEBUG
	g_print("Setting password to `%s'.\n", password);
#endif
	name = lu_ent_get(ent, namingAttr);
	if (name == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("object has no %s attribute"), namingAttr);
		return FALSE;
	}

	/* Convert the name to a distinguished name. */
	value = g_value_array_get_nth(name, 0);
	name_string = value_as_string(value);
	dn = lu_ldap_ent_to_dn(module, namingAttr, name_string, configKey,
			       def);
	if (dn == NULL) {
		lu_error_new(error, lu_error_generic,
			     _("error mapping name to LDAP distinguished "
			       "name"));
		g_free(name_string);
		return FALSE;
	}
#ifdef DEBUG
	g_print("Setting password for `%s'.\n", dn);
#endif

	snprintf(filter, sizeof(filter), "(%s=%s)",
		 map_to_ldap(module->scache, namingAttr), name_string);
	g_free(name_string);
	mapped_password = map_to_ldap(module->scache, ent->type == lu_user
				      ? LU_USERPASSWORD : LU_GROUPPASSWORD);
	
	previous = NULL;
	values = NULL;
	attributes[0] = (char *)mapped_password;
	if ((i = ldap_search_s(ctx->ldap, dn, LDAP_SCOPE_BASE, filter,
			       attributes, FALSE,
			       &messages)) == LDAP_SUCCESS) {
		entry = ldap_first_entry(ctx->ldap, messages);
		if (entry != NULL) {
			values = ldap_get_values(ctx->ldap, entry,
						 mapped_password);
			if (values) {
				for (j = 0; values[j] != NULL; j++) {
#ifdef DEBUG
					g_print("Got `%s' = `%s'.\n",
						mapped_password, values[j]);
#endif
					if (strncmp
					    (values[j], LU_CRYPTED,
					     strlen(LU_CRYPTED)) == 0) {
#ifdef DEBUG
						g_print
						    ("Previous entry was `%s'.\n",
						     values[j]);
#endif
						previous = g_strdup(values[j]);
						break;
					}
				}
				ldap_value_free(values);
			}
		}
	} else {
#ifdef DEBUG
		g_print("Error searching LDAP directory for `%s': %s.\n",
			dn, ldap_err2string(i));
#endif
	}
	if (messages != NULL) {
		ldap_msgfree(messages);
	}

	if (strncmp(password, LU_CRYPTED, strlen(LU_CRYPTED)) == 0) {
		addvalues[0] = (char *)password;
	} else {
		const char *crypted;

		crypted =
		    lu_make_crypted(password, previous
				    ? (previous + strlen(LU_CRYPTED)) :
				    lu_common_default_salt_specifier(module));
		if (crypted == NULL) {
			/* FIXME: STRING_FREEZE */
			lu_error_new(error, lu_error_generic,
				     "error encrypting password");
			g_free(previous);
			return FALSE;
		}
		tmp = g_strconcat(LU_CRYPTED, crypted, NULL);
		addvalues[0] = module->scache->cache(module->scache, tmp);
		g_free(tmp);
	}

	j = 0;
	if (values != NULL) {
		if (previous)
			rmvalues[0] = previous;
		/* else deletes all values */
		
		rmmod.mod_op = LDAP_MOD_DELETE;
		rmmod.mod_type = (char *)mapped_password;
		rmmod.mod_values = rmvalues;
		mods[j++] = &rmmod;
	}
	addmod.mod_op = LDAP_MOD_ADD;
	addmod.mod_type = (char *)mapped_password;
	addmod.mod_values = addvalues;
	mods[j++] = &addmod;
	mods[j] = NULL;

	i = ldap_modify_ext_s(ctx->ldap, dn, mods, &server, &client);
	g_free(previous);
	if (i != LDAP_SUCCESS) {
		lu_error_new(error, lu_error_generic,
			     _
			     ("error setting password in LDAP directory for %s: %s"),
			     dn, ldap_err2string(i));
		return FALSE;
	}

	return TRUE;
}

static gboolean
lu_ldap_user_removepass(struct lu_module *module, struct lu_ent *ent,
		        struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_setpass(module, LU_USERNAME, ent, "userBranch",
			       USERBRANCH, LU_CRYPTED, error);
}

static gboolean
lu_ldap_group_removepass(struct lu_module *module, struct lu_ent *ent,
		         struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_setpass(module, LU_GROUPNAME, ent, "groupBranch",
			       GROUPBRANCH, LU_CRYPTED, error);
}

static GValueArray *
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
	int i;
	GValue value;
	GValueArray *ret = NULL;
	struct lu_ldap_context *ctx;
	char *attributes[] = { (char *) returnAttr, NULL };
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

	/* Get the name of the key which tells us where to search. */
	tmp = g_strdup_printf("%s/%s", module->name, configKey);
	branch = lu_cfg_read_single(module->lu_context, tmp, def);
	g_free(tmp);

	/* Generate the base DN to search under. */
	base = g_strdup_printf("%s,%s", branch,
			       ctx->prompts[LU_LDAP_BASEDN].value &&
			       strlen(ctx->prompts[LU_LDAP_BASEDN].value) ?
			       ctx->prompts[LU_LDAP_BASEDN].value : "*");
	/* Generate the filter to search with. */
	filt = g_strdup_printf("(%s=%s)", searchAttr, pattern ?: "*");

#ifdef DEBUG
	g_print("Looking under `%s' with filter `%s'.\n", base, filt);
#endif

	/* Perform the search. */
	ret = g_value_array_new(0);
	memset(&value, 0, sizeof(value));
	g_value_init(&value, G_TYPE_STRING);
	if (ldap_search_s(ctx->ldap, base, LDAP_SCOPE_SUBTREE, filt, attributes,
			  FALSE, &messages) == LDAP_SUCCESS) {
		entry = ldap_first_entry(ctx->ldap, messages);
		if (entry != NULL) {
			while (entry != NULL) {
				values = ldap_get_values(ctx->ldap, entry,
							 returnAttr);
				for (i = 0;
				     (values != NULL) && (values[i] != NULL);
				     i++) {
#ifdef DEBUG
					g_print("Got `%s' = `%s'.\n",
						returnAttr, values[i]);
#endif
					g_value_set_string(&value, values[i]);
					g_value_array_append(ret, &value);
				}
				if (values != NULL) {
					ldap_value_free(values);
				}
				entry = ldap_next_entry(ctx->ldap, entry);
			}
#ifdef DEBUG
		} else {
			g_print("No such entry found in LDAP, continuing.\n");
#endif
		}
	}
	if (messages != NULL) {
		ldap_msgfree(messages);
	}

	g_value_unset(&value);
	g_free(base);
	g_free(filt);

	return ret;
}

/* Add a user to the directory. */
static gboolean
lu_ldap_user_add_prep(struct lu_module *module, struct lu_ent *ent,
		      struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return TRUE;
}

static gboolean
lu_ldap_user_add(struct lu_module *module, struct lu_ent *ent,
		 struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_set(module, lu_user, 1, ent, "userBranch", USERBRANCH,
			   error);
}

/* Modify a user record in the directory. */
static gboolean
lu_ldap_user_mod(struct lu_module *module, struct lu_ent *ent,
		 struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_set(module, lu_user, 0, ent, "userBranch", USERBRANCH,
			   error);
}

/* Remove a user from the directory. */
static gboolean
lu_ldap_user_del(struct lu_module *module, struct lu_ent *ent,
		 struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_del(module, lu_user, ent, "userBranch", USERBRANCH,
			   error);
}

/* Lock a user account in the directory. */
static gboolean
lu_ldap_user_lock(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_handle_lock(module, ent, LU_USERNAME, TRUE,
				   "userBranch", USERBRANCH, error);
}

/* Unlock a user account in the directory. */
static gboolean
lu_ldap_user_unlock(struct lu_module *module, struct lu_ent *ent,
		    struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_handle_lock(module, ent, LU_USERNAME, FALSE,
				   "userBranch", USERBRANCH, error);
}

/* Check if a user account in the directory is locked. */
static gboolean
lu_ldap_user_is_locked(struct lu_module *module, struct lu_ent *ent,
		       struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_is_locked(module, ent, LU_USERNAME, "userBranch",
				 USERBRANCH, error);
}

/* Set a user's password in the directory. */
static gboolean
lu_ldap_user_setpass(struct lu_module *module, struct lu_ent *ent,
		     const char *password, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_setpass(module, LU_USERNAME, ent, "userBranch",
			       USERBRANCH, password, error);
}

/* Add a group entry to the directory. */
static gboolean
lu_ldap_group_add_prep(struct lu_module *module, struct lu_ent *ent,
		       struct lu_error **error)
{
	(void)module;
	(void)ent;
	(void)error;
	return TRUE;
}

static gboolean
lu_ldap_group_add(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_set(module, lu_group, 1, ent, "groupBranch",
			   GROUPBRANCH, error);
}

/* Modify a group entry in the directory. */
static gboolean
lu_ldap_group_mod(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_set(module, lu_group, 0, ent, "groupBranch",
			   GROUPBRANCH, error);
}

/* Remove a group entry from the directory. */
static gboolean
lu_ldap_group_del(struct lu_module *module, struct lu_ent *ent,
		  struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_del(module, lu_group, ent, "groupBranch",
			   GROUPBRANCH, error);
}

/* Lock a group account in the directory. */
static gboolean
lu_ldap_group_lock(struct lu_module *module, struct lu_ent *ent,
		   struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_handle_lock(module, ent, LU_GROUPNAME, TRUE,
				   "groupBranch", GROUPBRANCH, error);
}

/* Unlock a group account in the directory. */
static gboolean
lu_ldap_group_unlock(struct lu_module *module, struct lu_ent *ent,
		     struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_handle_lock(module, ent, LU_GROUPNAME, FALSE,
				   "groupBranch", GROUPBRANCH, error);
}

/* Check if a group account in the directory is locked. */
static gboolean
lu_ldap_group_is_locked(struct lu_module *module, struct lu_ent *ent,
		        struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_is_locked(module, ent, LU_GROUPNAME, "groupBranch",
				 GROUPBRANCH, error);
}

/* Set a group's password in the directory. */
static gboolean
lu_ldap_group_setpass(struct lu_module *module, struct lu_ent *ent,
		      const char *password, struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_setpass(module, LU_GROUPNAME, ent, "groupBranch",
			       GROUPBRANCH, password, error);
}

/* Populate user or group structures with the proper defaults. */
static gboolean
lu_ldap_user_default(struct lu_module *module,
		     const char *user, gboolean is_system,
		     struct lu_ent *ent, struct lu_error **error)
{
	return lu_common_user_default(module, user, is_system, ent, error) &&
	       lu_common_suser_default(module, user, is_system, ent, error);
}

static gboolean
lu_ldap_group_default(struct lu_module *module,
		      const char *group, gboolean is_system,
		      struct lu_ent *ent, struct lu_error **error)
{
	return lu_common_group_default(module, group, is_system, ent, error) &&
	       lu_common_sgroup_default(module, group, is_system, ent, error);
}

/* Get a listing of all user names. */
static GValueArray *
lu_ldap_users_enumerate(struct lu_module *module, const char *pattern,
			struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_enumerate(module,
				 map_to_ldap(module->scache, LU_USERNAME),
				 pattern,
				 map_to_ldap(module->scache, LU_USERNAME),
				 "userBranch", USERBRANCH, error);
}

static GPtrArray *
lu_ldap_users_enumerate_full(struct lu_module *module, const char *pattern,
			     struct lu_error **error)
{
	GPtrArray *array = g_ptr_array_new();
	LU_ERROR_CHECK(error);
	lu_ldap_lookup(module,
		       map_to_ldap(module->scache, LU_USERNAME), pattern,
		       NULL, array,
		       "userBranch", USERBRANCH,
		       "("OBJECTCLASS"="POSIXACCOUNT")",
		       lu_ldap_user_attributes, LU_LDAP_USER | LU_LDAP_SHADOW,
		       error);
	return array;
}

/* Get a listing of all group names. */
static GValueArray *
lu_ldap_groups_enumerate(struct lu_module *module, const char *pattern,
			 struct lu_error **error)
{
	LU_ERROR_CHECK(error);
	return lu_ldap_enumerate(module,
				 map_to_ldap(module->scache, LU_GROUPNAME),
				 pattern,
				 map_to_ldap(module->scache, LU_GROUPNAME),
				 "groupBranch", GROUPBRANCH, error);
}

static GPtrArray *
lu_ldap_groups_enumerate_full(struct lu_module *module, const char *pattern,
			      struct lu_error **error)
{
	GPtrArray *array = g_ptr_array_new();
	LU_ERROR_CHECK(error);
	lu_ldap_lookup(module,
		       map_to_ldap(module->scache, LU_GROUPNAME), pattern,
		       NULL, array,
		       "groupBranch", GROUPBRANCH,
		       "("OBJECTCLASS"="POSIXGROUP")",
		       lu_ldap_group_attributes, LU_LDAP_GROUP | LU_LDAP_SHADOW,
		       error);
	return array;
}

/* Get a list of all users in a group, either via their primary or supplemental
 * group memberships. */
static GValueArray *
lu_ldap_users_enumerate_by_group(struct lu_module *module,
				 const char *group, gid_t gid,
				 struct lu_error **error)
{
	GValueArray *primaries = NULL, *secondaries = NULL;
	GValue *value;
	char *grp;
	size_t i;

	LU_ERROR_CHECK(error);
	grp = g_strdup_printf("%ld", (long)gid);

	primaries = lu_ldap_enumerate(module,
				      map_to_ldap(module->scache, LU_GIDNUMBER),
				      grp,
				      map_to_ldap(module->scache, LU_USERNAME),
				      "userBranch", USERBRANCH,
				      error);
	if ((error == NULL) || (*error == NULL)) {
		secondaries = lu_ldap_enumerate(module,
						map_to_ldap(module->scache, LU_GROUPNAME),
						group,
						map_to_ldap(module->scache, LU_MEMBERNAME),
						"groupBranch", GROUPBRANCH,
						error);
		for (i = 0; i < secondaries->n_values; i++) {
			value = g_value_array_get_nth(secondaries, i);
			g_value_array_append(primaries, value);
		}
		g_value_array_free(secondaries);
	}

#ifdef DEBUG
	for (i = 0; i < primaries->n_values; i++) {
		value = g_value_array_get_nth(primaries, i);
		g_print("`%s' contains `%s'\n", group,
			g_value_get_string(value));
	}
#endif
	g_free(grp);
	return primaries;
}

static GPtrArray *
lu_ldap_users_enumerate_by_group_full(struct lu_module *module,
				      const char *group, gid_t gid,
				      struct lu_error **error)
{
	(void)module;
	(void)group;
	(void)gid;
	(void)error;
	return NULL;
}

/* Get a list of all groups to which the user belongs, via either primary or
 * supplemental group memberships. */
static GValueArray *
lu_ldap_groups_enumerate_by_user(struct lu_module *module,
				 const char *user,
				 uid_t uid,
				 struct lu_error **error)
{
	GValueArray *primaries = NULL, *secondaries = NULL, *values, *gids;
	GValue *value;
	size_t i, j;
	long gid;
	char *p;
	struct lu_ent *ent = NULL;

	(void)uid;
	LU_ERROR_CHECK(error);

	/* Create an array to hold the values returned. */
	primaries = g_value_array_new(0);

	/* Get the user's primary GID(s). */
	gids = lu_ldap_enumerate(module,
				 map_to_ldap(module->scache, LU_USERNAME),
				 user,
				 map_to_ldap(module->scache, LU_GIDNUMBER),
				 "userBranch", USERBRANCH, error);
	/* For each GID, look up the group.  Which has this GID. */
	for (i = 0; (gids != NULL) && (i < gids->n_values); i++) {
		value = g_value_array_get_nth(gids, i);
		gid = -1;
		if (G_VALUE_HOLDS_STRING(value)) {
			gid = strtol(g_value_get_string(value), &p, 0);
			if (*p != 0)
				continue;
		} else if (G_VALUE_HOLDS_LONG(value))
			gid = g_value_get_long(value);
		else
			g_assert_not_reached();
		ent = lu_ent_new();
		if (lu_group_lookup_id(module->lu_context, gid,
				       ent, error)) {
			/* Get the group's names and add them to the list
			 * of values to return. */
			values = lu_ent_get(ent, LU_GROUPNAME);
			for (j = 0; j < values->n_values; j++) {
				value = g_value_array_get_nth(values, j);
				g_value_array_append(primaries, value);
			}
		}
		lu_ent_free(ent);
	}
	g_value_array_free(gids);
	/* Search for the supplemental groups which list this user as
	 * a member. */
	if ((error == NULL) || (*error == NULL)) {
		secondaries = lu_ldap_enumerate(module,
						map_to_ldap(module->scache, LU_MEMBERNAME),
						user,
						map_to_ldap(module->scache, LU_GROUPNAME),
						"groupBranch", GROUPBRANCH,
						error);
		for (i = 0; i < secondaries->n_values; i++) {
			value = g_value_array_get_nth(secondaries, i);
			g_value_array_append(primaries, value);
		}
		g_value_array_free(secondaries);
	}

#ifdef DEBUG
	for (i = 0; i < primaries->n_values; i++) {
		value = g_value_array_get_nth(primaries, i);
		g_print("`%s' is in `%s'\n", user,
			g_value_get_string(value));
	}
#endif

	return primaries;
}

static GPtrArray *
lu_ldap_groups_enumerate_by_user_full(struct lu_module *module,
				      const char *user, uid_t uid,
				      struct lu_error **error)
{
	(void)module;
	(void)user;
	(void)uid;
	(void)error;
	return NULL;
}

static gboolean
lu_ldap_close_module(struct lu_module *module)
{
	struct lu_ldap_context *ctx;
	size_t i;

	g_assert(module != NULL);

	ctx = module->module_context;
	ldap_unbind_s(ctx->ldap);

	module->scache->free(module->scache);
	for (i = 0; i < sizeof(ctx->prompts) / sizeof(ctx->prompts[0]);
	     i++) {
		if (ctx->prompts[i].value && ctx->prompts[i].free_value) {
			ctx->prompts[i].free_value(ctx->prompts[i].value);
		}
	}
	g_free(ctx->mapped_user_attributes);
	g_free(ctx->mapped_group_attributes);
	g_free(ctx);
	memset(module, 0, sizeof(struct lu_module));
	g_free(module);

	return TRUE;
}

static gboolean
lu_ldap_uses_elevated_privileges(struct lu_module *module)
{
	(void)module;
	/* FIXME: do some checking, don't know what we need, though */
	return FALSE;
}

struct lu_module *
libuser_ldap_init(struct lu_context *context, struct lu_error **error)
{
	struct lu_module *ret = NULL;
	struct lu_ldap_context *ctx = NULL;
	struct lu_prompt prompts[G_N_ELEMENTS(ctx->prompts)];
	char *user;
	const char *bind_type;
	char **bind_types;
	size_t i;
	LDAP *ldap = NULL;

	g_assert(context != NULL);
	g_assert(context->prompter != NULL);
	LU_ERROR_CHECK(error);

	ctx = g_malloc0(sizeof(struct lu_ldap_context));
	ctx->global_context = context;

	/* Initialize the prompts structure. */
	ctx->prompts[LU_LDAP_SERVER].key = "ldap/server";
	ctx->prompts[LU_LDAP_SERVER].prompt = N_("LDAP Server Name");
	ctx->prompts[LU_LDAP_SERVER].default_value =
		lu_cfg_read_single(context, "ldap/server", "ldap");
	ctx->prompts[LU_LDAP_SERVER].visible = TRUE;

	ctx->prompts[LU_LDAP_BASEDN].key = "ldap/basedn";
	ctx->prompts[LU_LDAP_BASEDN].prompt = N_("LDAP Search Base DN");
	ctx->prompts[LU_LDAP_BASEDN].default_value =
		lu_cfg_read_single(context, "ldap/basedn", "dc=example,dc=com");
	ctx->prompts[LU_LDAP_BASEDN].visible = TRUE;

	ctx->prompts[LU_LDAP_BINDDN].key = "ldap/binddn";
	ctx->prompts[LU_LDAP_BINDDN].prompt = N_("LDAP Bind DN");
	ctx->prompts[LU_LDAP_BINDDN].visible = TRUE;
	ctx->prompts[LU_LDAP_BINDDN].default_value =
		lu_cfg_read_single(context, "ldap/binddn",
				   "cn=manager,dc=example,dc=com");

	ctx->prompts[LU_LDAP_PASSWORD].key = "ldap/password";
	ctx->prompts[LU_LDAP_PASSWORD].prompt = N_("LDAP Bind Password");
	ctx->prompts[LU_LDAP_PASSWORD].visible = FALSE;

	user = getuser();

	ctx->prompts[LU_LDAP_AUTHUSER].key = "ldap/user";
	ctx->prompts[LU_LDAP_AUTHUSER].prompt = N_("LDAP SASL User");
	ctx->prompts[LU_LDAP_AUTHUSER].visible = TRUE;
	ctx->prompts[LU_LDAP_AUTHUSER].default_value =
		lu_cfg_read_single(context, "ldap/user", user);

	ctx->prompts[LU_LDAP_AUTHZUSER].key = "ldap/authuser";
	ctx->prompts[LU_LDAP_AUTHZUSER].prompt =
		N_("LDAP SASL Authorization User");
	ctx->prompts[LU_LDAP_AUTHZUSER].visible = TRUE;
	ctx->prompts[LU_LDAP_AUTHZUSER].default_value =
		lu_cfg_read_single(context, "ldap/authuser", "");

	if (user) {
		free(user);
		user = NULL;
	}

	/* Try to be somewhat smart and allow the user to specify which bind
	 * type to use, which should prevent us from asking for information
	 * we can be certain we don't have a use for. */
	bind_type = lu_cfg_read_single(context, "ldap/bindtype", "simple,sasl");
	bind_types = g_strsplit(bind_type, ",", 0);
	for (i = 0; (bind_types != NULL) && (bind_types[i] != NULL); i++) {
		if (g_ascii_strcasecmp(bind_types[i], "simple") == 0) {
			ctx->bind_simple = TRUE;
		} else
		if (g_ascii_strcasecmp(bind_types[i], "sasl") == 0) {
			ctx->bind_sasl = TRUE;
		}
	}
	g_strfreev(bind_types);

	/* Get the information we're sure we'll need. */
	i = 0;
	prompts[i++] = ctx->prompts[LU_LDAP_SERVER];
	prompts[i++] = ctx->prompts[LU_LDAP_BASEDN];
	if (ctx->bind_simple) {
		prompts[i++] = ctx->prompts[LU_LDAP_BINDDN];
		prompts[i++] = ctx->prompts[LU_LDAP_PASSWORD];
	}
	if (ctx->bind_sasl) {
		prompts[i++] = ctx->prompts[LU_LDAP_AUTHUSER];
		prompts[i++] = ctx->prompts[LU_LDAP_AUTHZUSER];
	}
	if (context->prompter(prompts, i,
			      context->prompter_data, error) == FALSE) {
		g_free(ctx);
		return NULL;
	}
	i = 0;
	ctx->prompts[LU_LDAP_SERVER] = prompts[i++];
	ctx->prompts[LU_LDAP_BASEDN] = prompts[i++];
	if (ctx->bind_simple) {
		ctx->prompts[LU_LDAP_BINDDN] = prompts[i++];
		ctx->prompts[LU_LDAP_PASSWORD] = prompts[i++];
	}
	if (ctx->bind_sasl) {
		ctx->prompts[LU_LDAP_AUTHUSER] = prompts[i++];
		ctx->prompts[LU_LDAP_AUTHZUSER] = prompts[i++];
	}

	/* Allocate the method structure. */
	ret = g_malloc0(sizeof(struct lu_module));
	ret->version = LU_MODULE_VERSION;
	ret->module_context = ctx;
	ret->scache = lu_string_cache_new(TRUE);
	ret->name = ret->scache->cache(ret->scache, "ldap");
	ctx->module = ret;

	/* Try to bind to the server to verify that we can. */
	ldap = bind_server(ctx, error);
	if (ldap == NULL) {
		g_free(ret);
		g_free(ctx);
		return NULL;
	}
	ctx->ldap = ldap;

	ctx->mapped_user_attributes
		= g_malloc0(sizeof(*ctx->mapped_user_attributes)
			    * G_N_ELEMENTS(lu_ldap_user_attributes));
	for (i = 0; i < G_N_ELEMENTS(lu_ldap_user_attributes); i++) {
		if (lu_ldap_user_attributes[i] != NULL)
			ctx->mapped_user_attributes[i] = (char *)
				map_to_ldap(ret->scache,
					    lu_ldap_user_attributes[i]);
		else
			ctx->mapped_user_attributes[i] = NULL;
	}
			
	ctx->mapped_group_attributes
		= g_malloc0(sizeof(*ctx->mapped_group_attributes)
			    * G_N_ELEMENTS(lu_ldap_group_attributes));
	for (i = 0; i < G_N_ELEMENTS(lu_ldap_group_attributes); i++) {
		if (lu_ldap_group_attributes[i] != NULL)
			ctx->mapped_group_attributes[i] = (char *)
				map_to_ldap(ret->scache,
					    lu_ldap_group_attributes[i]);
		else
			ctx->mapped_group_attributes[i] = NULL;
	}

	/* Set the method pointers. */
	ret->uses_elevated_privileges = lu_ldap_uses_elevated_privileges;

	ret->user_lookup_name = lu_ldap_user_lookup_name;
	ret->user_lookup_id = lu_ldap_user_lookup_id;
	ret->user_default = lu_ldap_user_default;
	ret->user_add_prep = lu_ldap_user_add_prep;
	ret->user_add = lu_ldap_user_add;
	ret->user_mod = lu_ldap_user_mod;
	ret->user_del = lu_ldap_user_del;
	ret->user_lock = lu_ldap_user_lock;
	ret->user_unlock = lu_ldap_user_unlock;
	ret->user_is_locked = lu_ldap_user_is_locked;
	ret->user_setpass = lu_ldap_user_setpass;
	ret->user_removepass = lu_ldap_user_removepass;
	ret->users_enumerate = lu_ldap_users_enumerate;
	ret->users_enumerate_by_group = lu_ldap_users_enumerate_by_group;
	ret->users_enumerate_full = lu_ldap_users_enumerate_full;
	ret->users_enumerate_by_group_full = lu_ldap_users_enumerate_by_group_full;

	ret->group_lookup_name = lu_ldap_group_lookup_name;
	ret->group_lookup_id = lu_ldap_group_lookup_id;
	ret->group_default = lu_ldap_group_default;
	ret->group_add_prep = lu_ldap_group_add_prep;
	ret->group_add = lu_ldap_group_add;
	ret->group_mod = lu_ldap_group_mod;
	ret->group_del = lu_ldap_group_del;
	ret->group_lock = lu_ldap_group_lock;
	ret->group_unlock = lu_ldap_group_unlock;
	ret->group_is_locked = lu_ldap_group_is_locked;
	ret->group_setpass = lu_ldap_group_setpass;
	ret->group_removepass = lu_ldap_group_removepass;
	ret->groups_enumerate = lu_ldap_groups_enumerate;
	ret->groups_enumerate_by_user = lu_ldap_groups_enumerate_by_user;
	ret->groups_enumerate_full = lu_ldap_groups_enumerate_full;
	ret->groups_enumerate_by_user_full = lu_ldap_groups_enumerate_by_user_full;

	ret->close = lu_ldap_close_module;

	/* Done. */
	return ret;
}
