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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
#include <libuser/user.h>
#include <libuser/user_private.h>
#include <Python.h>
#include "common.h"

static PyMappingMethods libuser_entity_mapping_methods;
static PyMethodDef libuser_entity_methods[];
static PyMethodDef libuser_methods[];
static PyTypeObject EntityType;
#define Entity_Check(__x) ((__x)->ob_type == &EntityType)

static PyObject *
convert_glist_pystringlist(GList *strings)
{
	GList *i = NULL;
	PyObject *ret = NULL;;

	DEBUG_ENTRY;

	ret = PyList_New(0);
	for(i = strings; i != NULL; i = g_list_next(i)) {
		if(ret == NULL) {
			ret = PyList_New(0);
		}
		PyList_Append(ret, PyString_FromString((char*)i->data));
#ifdef DEBUG_BINDING
		fprintf(stderr, "adding `%s' to string list\n", (char*)i->data);
#endif
	}

	DEBUG_EXIT;
	return ret ?: Py_BuildValue("");
}

static PyObject *
libuser_wrap_ent(struct lu_ent *ent)
{
	struct libuser_entity *ret = NULL;

	DEBUG_ENTRY;

	if(ent == NULL) {
		DEBUG_EXIT;
		g_return_val_if_fail(ent != NULL, NULL);
	}

	ret = PyObject_NEW(struct libuser_entity, &EntityType);
	if(ret == NULL) {
		lu_ent_free(ent);
		DEBUG_EXIT;
		return NULL;
	}

	ret->ent = ent;

	DEBUG_EXIT;
	return (PyObject*) ret;
}

static void
libuser_entity_destroy(struct libuser_entity *self)
{
	DEBUG_ENTRY;
	lu_ent_free(self->ent);
	self->ent = NULL;
	PyMem_DEL(self);
	DEBUG_EXIT;
}

static PyObject *
libuser_entity_getattr(struct libuser_entity *self, char *name)
{
	DEBUG_CALL;
#ifdef DEBUG_BINDING
	fprintf(stderr, "Searching for attribute `%s'\n", name);
#endif
	return Py_FindMethod(libuser_entity_methods, (PyObject*)self, name);
}

static int
libuser_entity_setattr(struct libuser_entity *self, char *name, PyObject *args)
{
	PyObject *list;
	int size, i;

	DEBUG_ENTRY;

	if(PyArg_ParseTuple(args, "O", &list)) {
		lu_ent_clear(self->ent, name);

		if(PyList_Check(list)) {
			size = PyList_Size(list);
			#ifdef DEBUG_BINDING
			fprintf(stderr, "%sList has %d items.\n", getindent(), size);
			#endif

			for(i = 0; i < size; i++) {
				#ifdef DEBUG_BINDING
				fprintf(stderr, "%sAdding (`%s') to `%s'.\n", getindent(),
					PyString_AsString(PyList_GetItem(list, i)),
					name);
				#endif
				lu_ent_add(self->ent, name, PyString_AsString(PyList_GetItem(list, i)));
			}
			DEBUG_EXIT;
			return 0;
		} else
		if(PyString_Check(list)) {
			lu_ent_set(self->ent, name, PyString_AsString(list));
			DEBUG_EXIT;
			return 0;
		}
	}

	PyErr_SetString(PyExc_SystemError,
			"expected string or list of strings");
	DEBUG_EXIT;
	return -1;
}

static PyObject *
libuser_entity_getattrlist(struct libuser_entity *self, PyObject *args)
{
	DEBUG_CALL;
	return convert_glist_pystringlist(lu_ent_get_attributes(self->ent));
}

static PyObject *
libuser_entity_get(struct libuser_entity *self, PyObject *args)
{
	char *arg;
	PyObject *default_value = NULL;

	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "s|O", &arg, &default_value)) {
		DEBUG_EXIT;
		return NULL;
	}
	if(lu_ent_has(self->ent, arg)) {
		DEBUG_EXIT;
		return convert_glist_pystringlist(lu_ent_get(self->ent, arg));
	} else {
		if(default_value != NULL) {
			Py_INCREF(default_value);
			DEBUG_EXIT;
			return default_value;
		} else {
			DEBUG_EXIT;
			return Py_BuildValue("");
		}
	}
}

static PyObject *
libuser_entity_add(struct libuser_entity *self, PyObject *args)
{
	char *attr = NULL, *val = NULL;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "ss", &attr, &val)) {
		DEBUG_EXIT;
		return NULL;
	}
	lu_ent_add(self->ent, attr, val);
	DEBUG_EXIT;
	return Py_BuildValue("");
}

static PyObject *
libuser_entity_set(struct libuser_entity *self, PyObject *args)
{
	char *attr = NULL, *val = NULL;
	PyObject *list = NULL;
	int i, size;

	DEBUG_ENTRY;

	if(PyArg_ParseTuple(args, "sO!", &attr, &PyList_Type, &list)) {
		lu_ent_clear(self->ent, attr);

		size = PyList_Size(list);
		#ifdef DEBUG_BINDING
		fprintf(stderr, "%sList has %d items.\n", getindent(), size);
		#endif

		for(i = 0; i < size; i++) {
			#ifdef DEBUG_BINDING
			fprintf(stderr, "%sAdding (`%s') to `%s'.\n", getindent(),
				PyString_AsString(PyList_GetItem(list, i)), attr);
			#endif
			lu_ent_add(self->ent, attr, PyString_AsString(PyList_GetItem(list, i)));
		}
		DEBUG_EXIT;
		return Py_BuildValue("");
	}

	if(PyArg_ParseTuple(args, "ss", &attr, &val)) {
		lu_ent_set(self->ent, attr, val);
		DEBUG_EXIT;
		return Py_BuildValue("");
	}

	PyErr_SetString(PyExc_SystemError, "expected string or list of strings");
	DEBUG_EXIT;
	return NULL;
}

static PyObject *
libuser_entity_clear(struct libuser_entity *self, PyObject *args)
{
	char *arg;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "s", &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	lu_ent_clear(self->ent, arg);
	return Py_BuildValue("");
}

static PyObject *
libuser_entity_revert(struct libuser_entity *self, PyObject *args)
{
	DEBUG_ENTRY;
	lu_ent_revert(self->ent);
	DEBUG_EXIT;
	return Py_BuildValue("");
}

static int
libuser_entity_length(struct libuser_entity *self)
{
	DEBUG_CALL;
	return g_list_length(lu_ent_get_attributes(self->ent));
}

static PyObject*
libuser_entity_get_item(struct libuser_entity *self, PyObject *item)
{
	char *attr;

	DEBUG_ENTRY;

	if(!PyString_Check(item)) {
		PyErr_SetString(PyExc_TypeError, "expected a string");
		DEBUG_EXIT;
		return NULL;
	}
	attr = PyString_AsString(item);

	if(!lu_ent_has(self->ent, attr)) {
		PyErr_SetString(PyExc_KeyError, "no such attribute defined for this entity");
		DEBUG_EXIT;
		return NULL;
	}

	DEBUG_EXIT;
	return convert_glist_pystringlist(lu_ent_get(self->ent, attr));
}

static PyObject*
libuser_entity_has_key(struct libuser_entity *self, PyObject *item)
{
	char *attr;

	DEBUG_ENTRY;

	if(!PyArg_ParseTuple(item, "s", &attr)) {
		PyErr_SetString(PyExc_TypeError, "expected a tuple or string");
		DEBUG_EXIT;
		return NULL;
	}
	return Py_BuildValue("i", lu_ent_has(self->ent, attr) ? 1 : 0);
}

static int
libuser_entity_set_item(struct libuser_entity *self, PyObject *item,
	       		PyObject *args)
{
	char *attr = NULL;
	int i, size;

	DEBUG_ENTRY;

	if(!PyString_Check(item)) {
		PyErr_SetString(PyExc_TypeError, "expected a string");
		DEBUG_EXIT;
		return -1;
	}
	attr = PyString_AsString(item);
	#ifdef DEBUG_BINDING
	fprintf(stderr, "%sSetting item (`%s')...\n", getindent(), attr);
	#endif

	if(PyString_Check(args)) {
		#ifdef DEBUG_BINDING
		fprintf(stderr, "%sSetting (`%s') to `%s'.\n", getindent(), attr, PyString_AsString(args));
		#endif
		lu_ent_set(self->ent, attr, PyString_AsString(args));
		DEBUG_EXIT;
		return 0;
	}

	if(PyList_Check(args)) {
		size = PyList_Size(args);
		#ifdef DEBUG_BINDING
		fprintf(stderr, "%sList has %d items.\n", getindent(), size);
		#endif
		lu_ent_clear(self->ent, attr);
		for(i = 0; i < size; i++) {
			if(!PyString_Check(PyList_GetItem(args, i))) {
				PyErr_SetString(PyExc_TypeError, "expected strings in list");
				continue;
			}
			#ifdef DEBUG_BINDING
			fprintf(stderr, "%sAdding (`%s') to `%s'.\n", getindent(),
				PyString_AsString(PyList_GetItem(args, i)), attr);
			#endif
			lu_ent_add(self->ent, attr, PyString_AsString(PyList_GetItem(args, i)));
		}
		DEBUG_EXIT;
		return 0;
	}

	PyErr_SetString(PyExc_TypeError, "expected string or list of strings");
	DEBUG_EXIT;
	return -1;
}

static PyMappingMethods
libuser_entity_mapping_methods = {
	(inquiry) libuser_entity_length,
	(binaryfunc) libuser_entity_get_item,
	(objobjargproc) libuser_entity_set_item,
};

static PyMethodDef
libuser_entity_methods[] = {
	{"getattrlist", (PyCFunction)libuser_entity_getattrlist, METH_VARARGS,
	 "get a list of the attributes this entity has"},
	{"has_key", (PyCFunction)libuser_entity_has_key, METH_VARARGS,
	 "check if the entity has a given attribute"},
	{"get", (PyCFunction)libuser_entity_get, METH_VARARGS,
	 "get a list of the values for a given attribute"},
	{"set", (PyCFunction)libuser_entity_set, METH_VARARGS,
	 "set the list of values for a given attribute"},
	{"add", (PyCFunction)libuser_entity_add, METH_VARARGS,
	 "add a value to the current list of values for a given attribute"},
	{"clear", (PyCFunction)libuser_entity_clear, METH_VARARGS,
	 "clear the list of values for a given attribute"},
	{"revert", (PyCFunction)libuser_entity_revert, METH_VARARGS,
	 "revert the list of values for a given attribute to the values which "
	 "were set when the entity was looked up"},
	{"keys", (PyCFunction)libuser_entity_getattrlist, METH_VARARGS},
	{NULL, NULL, 0},
};

static PyTypeObject EntityType = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,
	"Entity",
	sizeof(struct libuser_entity),
	0,

	(destructor) libuser_entity_destroy,
	(printfunc) NULL,
	(getattrfunc) libuser_entity_getattr,
	(setattrfunc) libuser_entity_setattr,
	(cmpfunc) NULL,
	(reprfunc) NULL,

	(PyNumberMethods*) NULL,
	(PySequenceMethods*) NULL,
	(PyMappingMethods*) &libuser_entity_mapping_methods,
	(hashfunc) NULL,
	(ternaryfunc) NULL,
	(reprfunc) NULL,
};
