#ifndef libuser_private_h
#define libuser_private_h

#include <glib.h>
#include <gmodule.h>
#include <libuser/user.h>

#define LU_ENT_MAGIC 0x19d238c2
#define LU_MODULE_VERSION 0x00010000

#include <libintl.h>
#include <locale.h>
#define _(String) gettext(String)

struct lu_string_cache {
	GHashTable *table;
	char * (*cache)(struct lu_string_cache *, const char *);
	void (*free)(struct lu_string_cache *);
};
struct lu_string_cache *lu_string_cache_new(gboolean case_sensitive);

struct lu_ent {
	u_int32_t magic;
	enum lu_type type;
	struct lu_string_cache *acache;
	struct lu_string_cache *vcache;
	GHashTable *original_attributes;
	GHashTable *attributes;
	const char *source_info;
	const char *source_auth;
};

enum lu_dispatch_id {
	user_lookup_name,
	group_lookup_name,
	user_lookup_id,
	group_lookup_id,
	user_add,
	user_mod,
	user_del,
	user_lock,
	user_unlock,
	group_add,
	group_mod,
	group_del,
	group_lock,
	group_unlock,
};

enum lu_module_type {
	auth,
	info,
};

struct lu_context {
	struct lu_string_cache *scache;
	char *auth_name;
	enum lu_type auth_type;
	void *config;
	lu_prompt_fn *prompter;
	gpointer prompter_data;
	GList *auth_module_names;
	GList *info_module_names;
	GHashTable *modules;
};

struct lu_module {
	u_int32_t version;
	GModule *module_handle;
	struct lu_string_cache *scache;
	const char *name;
	struct lu_context *lu_context;
	void *module_context;
	gboolean (*user_lookup_name)(struct lu_module *module,
				     gconstpointer name,
				     struct lu_ent *ent);
	gboolean (*group_lookup_name)(struct lu_module *module,
				      gconstpointer name,
				      struct lu_ent *ent);
	gboolean (*user_lookup_id)(struct lu_module *module,
				   gconstpointer uid,
				   struct lu_ent *ent);
	gboolean (*group_lookup_id)(struct lu_module *module,
				    gconstpointer gid,
				    struct lu_ent *ent);

	gboolean (*user_add)(struct lu_module *module, struct lu_ent *ent);
	gboolean (*user_mod)(struct lu_module *module, struct lu_ent *ent);
	gboolean (*user_del)(struct lu_module *module, struct lu_ent *ent);
	gboolean (*user_lock)(struct lu_module *module, struct lu_ent *ent);
	gboolean (*user_unlock)(struct lu_module *module, struct lu_ent *ent);

	gboolean (*group_add)(struct lu_module *module, struct lu_ent *ent);
	gboolean (*group_mod)(struct lu_module *module, struct lu_ent *ent);
	gboolean (*group_del)(struct lu_module *module, struct lu_ent *ent);
	gboolean (*group_lock)(struct lu_module *module, struct lu_ent *ent);
	gboolean (*group_unlock)(struct lu_module *module, struct lu_ent *ent);

	gboolean (*close)(struct lu_module *module);
};

typedef struct lu_module * (*lu_module_init_t)(struct lu_context *context);
gboolean lu_cfg_init(struct lu_context *context);
gboolean lu_cfg_done(struct lu_context *context);

void lu_ent_set_source_info(struct lu_ent *ent, const char *source);
void lu_ent_set_source_auth(struct lu_ent *ent, const char *source);

void lu_g_list_free(GList *list);
GList *lu_g_list_copy(GList *list);
gint lu_str_equal(gconstpointer v1, gconstpointer v2);
gint lu_str_case_equal(gconstpointer v1, gconstpointer v2);

#endif
