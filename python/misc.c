/* Copyright (C) 2001,2002 Red Hat, Inc.
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
#include "../config.h"
#endif
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
#include "../lib/user.h"
#include "../lib/user_private.h"
#include <Python.h>
#include "common.h"

static PyTypeObject PromptType;
#define Prompt_Check(__x) ((__x)->ob_type == &PromptType)

static struct libuser_prompt *libuser_prompt_new(void);

static gboolean
libuser_admin_python_prompter(struct lu_prompt *prompts, int count,
			      gpointer callback_data,
			      struct lu_error **error)
{
	PyObject *list = NULL, *tuple = NULL, *ret;
	PyObject **prompt_data = (PyObject **) callback_data;
	int i;

	DEBUG_ENTRY;
	if (count > 0) {
		if (!PyCallable_Check(prompt_data[0])) {
			lu_error_new(error, lu_error_generic, NULL);
			PyErr_SetString(PyExc_RuntimeError,
					"prompter is not callable");
			DEBUG_EXIT;
			return FALSE;
		}
		list = PyList_New(0);
		for (i = 0; i < count; i++) {
			struct libuser_prompt *prompt;
			prompt = libuser_prompt_new();
			prompt->prompt = prompts[i];
			PyList_Append(list, (PyObject *) prompt);
		}
		tuple = PyTuple_New(PyTuple_Check(prompt_data[1]) ?
			            PyTuple_Size(prompt_data[1]) + 1 : 1);
		PyTuple_SetItem(tuple, 0, list);
		if (PyTuple_Check(prompt_data[1])) {
			for (i = 0; i < PyTuple_Size(prompt_data[1]); i++) {
				PyTuple_SetItem(tuple, i + 1,
						PyTuple_GetItem(prompt_data[1],
								i));
			}
		}
		ret = PyObject_CallObject(prompt_data[0], tuple);
		if (PyErr_Occurred()) {
			PyErr_Print();
			Py_DECREF(list);
			DEBUG_EXIT;
			lu_error_new(error, lu_error_generic,
				     _
				     ("error while prompting for necessary information"));
			return FALSE;
		}
		for (i = 0; i < count; i++) {
			struct libuser_prompt *prompt;
			prompt =
			    (struct libuser_prompt *) PyList_GetItem(list,
								     i);
			prompts[i] = prompt->prompt;
		}
		Py_DECREF(ret);
	}

	DEBUG_EXIT;
	return TRUE;
}

static PyObject *
libuser_admin_prompt(struct libuser_admin *self, PyObject * args,
		     PyObject * kwargs, lu_prompt_fn * prompter)
{
	int count, i;
	PyObject *list = NULL, *item = NULL, *moreargs = NULL;
	struct lu_prompt *prompts = NULL;
	struct lu_error *error = NULL;
	gboolean success = FALSE;
	char *keywords[] = { "prompt_list", "more_args", NULL };

	g_return_val_if_fail(self != NULL, NULL);

	DEBUG_ENTRY;
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|O", keywords,
					 &PyList_Type, &list,
	     &moreargs)) {
		DEBUG_EXIT;
		return NULL;
	}
	DEBUG_CALL;
	count = PyList_Size(list);
	DEBUG_CALL;
	for (i = 0; i < count; i++) {
		item = PyList_GetItem(list, i);
		DEBUG_CALL;
		if (!Prompt_Check(item)) {
			PyErr_SetString(PyExc_TypeError,
					"expected list of Prompt objects");
			DEBUG_EXIT;
			return NULL;
		}
		DEBUG_CALL;
	}
	DEBUG_CALL;
	count = PyList_Size(list);
	DEBUG_CALL;
	prompts = g_malloc0(count * sizeof(struct lu_prompt));
	DEBUG_CALL;

	for (i = 0; i < count; i++) {
		struct libuser_prompt *obj;
		obj = (struct libuser_prompt *) PyList_GetItem(list, i);
		Py_INCREF(obj);
		prompts[i].key = g_strdup(obj->prompt.key ? : "");
		prompts[i].domain = g_strdup(obj->prompt.domain ? : "");
		prompts[i].prompt = g_strdup(obj->prompt.prompt ? : "");
		prompts[i].default_value =
		    obj->prompt.default_value ? g_strdup(obj->prompt.default_value) :
		    NULL;
		prompts[i].visible = obj->prompt.visible;
	}
#ifdef DEBUG_BINDING
	fprintf(stderr, "Prompter function promptConsole is at <%p>.\n",
		lu_prompt_console);
	fprintf(stderr,
		"Prompter function promptConsoleQuiet is at <%p>.\n",
		lu_prompt_console_quiet);
	fprintf(stderr, "Calling prompter function at <%p>.\n", prompter);
#endif
	success = prompter(prompts, count, self->prompt_data, &error);
	if (success) {
		for (i = 0; i < count; i++) {
			struct libuser_prompt *obj;
			obj = (struct libuser_prompt *) PyList_GetItem(list, i);
			obj->prompt.value = g_strdup(prompts[i].value ? : "");
			obj->prompt.free_value = (typeof(obj->prompt.free_value)) g_free;
			if (prompts[i].value && prompts[i].free_value) {
				prompts[i].free_value(prompts[i].value);
				prompts[i].value = NULL;
				prompts[i].free_value = NULL;
			}
			Py_DECREF(obj);
		}
		DEBUG_EXIT;
		return Py_BuildValue("");
	} else {
		PyErr_SetString(PyExc_RuntimeError,
				"error prompting the user for information");
		DEBUG_EXIT;
		return NULL;
	}
}

static PyObject *
libuser_admin_prompt_console(PyObject * self, PyObject * args,
			     PyObject * kwargs)
{
	DEBUG_CALL;
	return libuser_admin_prompt((struct libuser_admin *) self, args,
				    kwargs, lu_prompt_console);
}

static PyObject *
libuser_admin_prompt_console_quiet(PyObject * self, PyObject * args,
				   PyObject * kwargs)
{
	DEBUG_CALL;
	return libuser_admin_prompt((struct libuser_admin *) self, args,
				    kwargs, lu_prompt_console_quiet);
}

static void
libuser_prompt_destroy(struct libuser_prompt *self)
{
	DEBUG_ENTRY;
	if (self->prompt.value && self->prompt.free_value)
		self->prompt.free_value(self->prompt.value);
	if (self->prompt.key)
		g_free((char *) self->prompt.key);
	if (self->prompt.prompt)
		g_free((char *) self->prompt.prompt);
	if (self->prompt.default_value)
		g_free((char *) self->prompt.default_value);
	memset(&self->prompt, 0, sizeof(self->prompt));
	PyMem_DEL(self);
	DEBUG_EXIT;
}

static PyObject *
libuser_prompt_getattr(struct libuser_prompt *self, char *attr)
{
	DEBUG_ENTRY;
	if (strcmp(attr, "key") == 0) {
		DEBUG_EXIT;
		return PyString_FromString(self->prompt.key);
	}
	if (strcmp(attr, "prompt") == 0) {
		DEBUG_EXIT;
		return PyString_FromString(self->prompt.prompt);
	}
	if (strcmp(attr, "domain") == 0) {
		DEBUG_EXIT;
		return PyString_FromString(self->prompt.domain ?: "");
	}
	if (strcmp(attr, "visible") == 0) {
		DEBUG_EXIT;
		return PyInt_FromLong(self->prompt.visible);
	}
	if ((strcmp(attr, "default_value") == 0) ||
	    (strcmp(attr, "defaultValue") == 0)) {
		DEBUG_EXIT;
		return self->prompt.
		    default_value ? PyString_FromString(self->prompt.
							default_value) :
		    Py_BuildValue("");
	}
	if (strcmp(attr, "value") == 0) {
		DEBUG_EXIT;
		return self->prompt.value ? PyString_FromString(self->
								prompt.
								value) :
		    Py_BuildValue("");
	}
	DEBUG_EXIT;
	return Py_FindMethod(NULL, (PyObject *) self, attr);
}

static int
libuser_prompt_setattr(struct libuser_prompt *self, const char *attr,
		       PyObject * args)
{
	DEBUG_ENTRY;
	if (strcmp(attr, "prompt") == 0) {
		if (!PyString_Check(args)) {
			PyErr_SetString(PyExc_TypeError,
					"prompt must be a string");
			DEBUG_EXIT;
			return -1;
		}
		if (self->prompt.prompt)
			g_free((char *) self->prompt.prompt);
		self->prompt.prompt = g_strdup(PyString_AsString(args));
		DEBUG_EXIT;
		return 0;
	}
	if (strcmp(attr, "domain") == 0) {
		if (!PyString_Check(args)) {
			PyErr_SetString(PyExc_TypeError,
					"domain must be a string");
			DEBUG_EXIT;
			return -1;
		}
		if (self->prompt.domain)
			g_free((char *) self->prompt.domain);
		self->prompt.domain = g_strdup(PyString_AsString(args));
		DEBUG_EXIT;
		return 0;
	}
	if (strcmp(attr, "key") == 0) {
		if (!PyString_Check(args)) {
			PyErr_SetString(PyExc_TypeError,
					"key must be a string");
			DEBUG_EXIT;
			return -1;
		}
		if (self->prompt.key)
			g_free((char *) self->prompt.key);
		self->prompt.key = g_strdup(PyString_AsString(args));
		DEBUG_EXIT;
		return 0;
	}
	if (strcmp(attr, "visible") == 0) {
		self->prompt.visible = PyObject_IsTrue(args);
		DEBUG_EXIT;
		return 0;
	}
	if ((strcmp(attr, "default_value") == 0) ||
	    (strcmp(attr, "defaultValue") == 0)) {
		if (!PyString_Check(args)) {
			PyErr_SetString(PyExc_TypeError,
					"default value must be a string");
			DEBUG_EXIT;
			return -1;
		}
		if (self->prompt.default_value)
			g_free((char *) self->prompt.default_value);
		self->prompt.default_value =
		    (args == Py_None) ?
		    NULL :
		    g_strdup(PyString_AsString(args));
		DEBUG_EXIT;
		return 0;
	}
	if (strcmp(attr, "value") == 0) {
		if (!PyString_Check(args)) {
			PyErr_SetString(PyExc_TypeError,
					"value must be a string");
			DEBUG_EXIT;
			return -1;
		}
		if (self->prompt.value && self->prompt.free_value)
			self->prompt.free_value(self->prompt.value);
		self->prompt.value = g_strdup(PyString_AsString(args));
		self->prompt.free_value =
		    (typeof(self->prompt.free_value)) g_free;
		DEBUG_EXIT;
		return 0;
	}
	DEBUG_EXIT;
	PyErr_SetString(PyExc_AttributeError, "invalid attribute");
	return -1;
}

static int
libuser_prompt_print(struct libuser_prompt *self, FILE * fp, int flags)
{
	(void)flags;
	fprintf(fp,
		"(key = \"%s\", prompt = \"%s\", domain = \"%s\", visible = %s, default_value = \"%s\", value = \"%s\")",
		self->prompt.key ? : "",
		self->prompt.prompt ? : "",
		self->prompt.domain ? : "",
		self->prompt.visible ? "true" : "false",
		self->prompt.default_value ? : "",
		self->prompt.value ? : "");
	return 0;
}

static struct libuser_prompt *
libuser_prompt_new(void)
{
	struct libuser_prompt *ret = NULL;
	DEBUG_ENTRY;
	ret = PyObject_NEW(struct libuser_prompt, &PromptType);
	if (ret != NULL) {
		memset(&ret->prompt, 0, sizeof(ret->prompt));
	}
	DEBUG_EXIT;
	return ret;
}

static PyTypeObject PromptType = {
	PyObject_HEAD_INIT(&PyType_Type)
	    0,
	"Prompt",
	sizeof(struct libuser_prompt),
	0,

	(destructor) libuser_prompt_destroy,
	(printfunc) libuser_prompt_print,
	(getattrfunc) libuser_prompt_getattr,
	(setattrfunc) libuser_prompt_setattr,
	(cmpfunc) NULL,
	(reprfunc) NULL,

	(PyNumberMethods *) NULL,
	(PySequenceMethods *) NULL,
	(PyMappingMethods *) NULL,
	(hashfunc) NULL,
	(ternaryfunc) NULL,
	(reprfunc) NULL,
};
