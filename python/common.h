#ifndef common_h
#define common_h

#include <Python.h>
#include "../lib/user.h"
#include "debug.h"

/* FIXME: remove this when dropping Python < 2.5 compatibility */
#if PY_VERSION_HEX < 0x02050000 && !defined(PY_SSIZE_T_MIN)
typedef int Py_ssize_t;
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

extern PyTypeObject EntityType G_GNUC_INTERNAL;

PyObject *libuser_admin_new(PyObject *self, PyObject *args, PyObject *kwargs)
	G_GNUC_INTERNAL;

gboolean libuser_admin_python_prompter(struct lu_prompt *prompts, int count,
				       gpointer callback_data,
				       struct lu_error **error) G_GNUC_INTERNAL;
PyObject *libuser_admin_prompt_console(PyObject *self, PyObject *args,
				       PyObject *kwargs) G_GNUC_INTERNAL;
PyObject *libuser_admin_prompt_console_quiet(PyObject *self, PyObject *args,
					     PyObject *kwargs) G_GNUC_INTERNAL;

PyObject *convert_value_array_pylist(GValueArray *array) G_GNUC_INTERNAL;
PyObject *convert_ent_array_pylist(GPtrArray *array) G_GNUC_INTERNAL;
PyObject *libuser_prompt_new(PyObject *ignored_self, PyObject *ignore)
	G_GNUC_INTERNAL;

PyObject *libuser_get_user_shells(PyObject *self, PyObject *ignored)
	G_GNUC_INTERNAL;
PyObject *libuser_wrap_ent(struct lu_ent *ent) G_GNUC_INTERNAL;

void initlibuser(void);

#endif
