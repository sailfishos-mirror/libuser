#ifndef common_h
#define common_h

#include <Python.h>
#include "../lib/user.h"
#include "debug.h"

/* FIXME: remove this when dropping Python < 2.5 compatibility */
#if PY_VERSION_HEX < 0x02050000 && !defined(PY_SSIZE_T_MIN)
typedef int Py_ssize_t;
typedef inquiry lenfunc;
#endif

struct libuser_admin {
	PyObject_HEAD
	PyObject *prompt_data[2];
	struct lu_context *ctx;
};

struct libuser_entity {
	PyObject_HEAD
	struct lu_ent *ent;
};

struct libuser_prompt {
	PyObject_HEAD
	struct lu_prompt prompt;
};

static PyTypeObject EntityType;
static PyTypeObject AdminType;
static PyTypeObject PromptType;

static struct libuser_admin *libuser_admin_new(PyObject *self,
					       PyObject *args,
					       PyObject *kwargs);

static gboolean libuser_admin_python_prompter(struct lu_prompt *prompts,
					      int count,
		                              gpointer callback_data,
					      struct lu_error **error);
static PyObject *libuser_admin_prompt_console(PyObject *self,
					      PyObject *args,
					      PyObject *kwargs);
static PyObject *libuser_admin_prompt_console_quiet(PyObject *self,
						    PyObject *args,
						    PyObject *kwargs);

static PyObject *convert_value_array_pylist(GValueArray *array);
static struct libuser_prompt *libuser_prompt_new(void);

static PyObject *libuser_get_user_shells(PyObject *ignored);
static PyObject *libuser_wrap_ent(struct lu_ent *ent);

void initlibuser(void);

#endif
