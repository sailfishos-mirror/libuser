#ifndef common_h
#define common_h

#include <Python.h>
#include <libuser/user.h>
#include "debug.h"

struct libuser_admin {
	PyObject_HEAD
	lu_context_t *ctx;
	struct libuser_admin_domain *user, *group;
	PyObject *prompter;
};

struct libuser_entity {
	PyObject_HEAD
	lu_ent_t *ent;
};

struct libuser_prompt {
	PyObject_HEAD
	lu_prompt_t prompt;
};
				
static PyTypeObject EntityType;
static PyTypeObject AdminType;
static PyTypeObject PromptType;

static struct libuser_admin *libuser_admin_new(PyObject *self, PyObject *args, PyObject *kwargs);

static gboolean libuser_admin_python_prompter(struct lu_prompt *prompts, int count,
		                              gpointer callback_data, struct lu_error **error);
static PyObject *libuser_admin_prompt_console(struct libuser_admin *self, PyObject *args);
static PyObject *libuser_admin_prompt_console_quiet(struct libuser_admin *self, PyObject *args);

static PyObject *convert_glist_pystringlist(GList *list);
static struct libuser_prompt *libuser_prompt_new(void);

static PyObject *libuser_get_user_shells(PyObject *ignored, PyObject *args);
static PyObject *libuser_wrap_ent(struct lu_ent *ent);

void initlibuser(void);

#endif
