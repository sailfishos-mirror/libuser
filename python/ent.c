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
#include "../config.h"
#endif
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
#include "../include/libuser/user.h"
#include "../include/libuser/user_private.h"
#include <Python.h>
#include "common.h"

static PyMappingMethods libuser_entity_mapping_methods;
static PyMethodDef libuser_entity_methods[];
static PyMethodDef libuser_methods[];
static PyTypeObject EntityType;
#define Entity_Check(__x) ((__x)->ob_type == &EntityType)

/* Convert a g_value_array into a Python list of values. */
static PyObject *
convert_value_array_pylist(GValueArray *array)
{
	PyObject *ret = NULL;;
	GValue *value;
	int i;
	long l;
	const char *s;

	DEBUG_ENTRY;

	/* Create a new list. */
	ret = PyList_New(0);
	/* Iterate over the array. */
	for (i = 0; (array != NULL) && (i < array->n_values); i++) {
		value = g_value_array_get_nth(array, i);
		/* If the item is a G_TYPE_LONG, add it as a PyLong. */
		if (G_VALUE_HOLDS_LONG(value)) {
			l = g_value_get_long(value);
			PyList_Append(ret, PyLong_FromLong(l));
#ifdef DEBUG_BINDING
			fprintf(stderr, "adding %d to list\n", l);
#endif
		}
		/* If the item is a G_TYPE_STRING, add it as a PyString. */
		if (G_VALUE_HOLDS_STRING(value)) {
			s = g_value_get_string(value);
			PyList_Append(ret, PyString_FromString(s));
#ifdef DEBUG_BINDING
			fprintf(stderr, "adding `%s' to list\n", s);
#endif
		}
	}

	DEBUG_EXIT;
	return ret;
}

/* Wrap up an entity object in a pretty Python wrapper. */
static PyObject *
libuser_wrap_ent(struct lu_ent *ent)
{
	struct libuser_entity *ret = NULL;

	DEBUG_ENTRY;

	/* No fair messing with me. */
	if (ent == NULL) {
		DEBUG_EXIT;
		g_return_val_if_fail(ent != NULL, NULL);
	}

	/* Create a new Python object suitable for holding a struct lu_ent. */
	ret = PyObject_NEW(struct libuser_entity, &EntityType);
	if (ret == NULL) {
		lu_ent_free(ent);
		DEBUG_EXIT;
		return NULL;
	}

	/* Keep track of the entity. */
	ret->ent = ent;

	DEBUG_EXIT;
	return (PyObject *) ret;
}

/* Destroy an entity Python object. */
static void
libuser_entity_destroy(struct libuser_entity *self)
{
	DEBUG_ENTRY;
	lu_ent_free(self->ent);
	self->ent = NULL;
	PyMem_DEL(self);
	DEBUG_EXIT;
}

/* The getattr function.  Returns the right method given its name. */
static PyObject *
libuser_entity_getattr(struct libuser_entity *self, char *name)
{
	DEBUG_CALL;
#ifdef DEBUG_BINDING
	fprintf(stderr, "Searching for attribute `%s'\n", name);
#endif
	return Py_FindMethod(libuser_entity_methods, (PyObject *) self,
			     name);
}

/* A helper function to convert a PyObject to a GValue. */
static void
libuser_convert_to_value(PyObject *item, GValue *value)
{
	/* Reset the value. */
	if (G_VALUE_TYPE(value) != 0) {
		g_value_unset(value);
		memset(value, 0, sizeof(*value));
	}
	/* If it's a PyLong, convert it. */
	if (PyLong_Check(item)) {
		g_value_init(value, G_TYPE_LONG);
		g_value_set_long(value, PyLong_AsLong(item));
#ifdef DEBUG_BINDING
		fprintf(stderr, "%sAdding (%d) to list.\n",
			getindent(), PyLong_AsLong(item));
#endif
	} else
	/* If it's a PyNumber, convert it. */
	if (PyNumber_Check(item)) {
		g_value_init(value, G_TYPE_LONG);
		g_value_set_long(value, PyNumber_AsLong(item));
#ifdef DEBUG_BINDING
		fprintf(stderr, "%sAdding (%d) to list.\n",
			getindent(), PyNumber_AsLong(item));
#endif
	} else
	/* If it's a PyString, convert it. */
	if (PyString_Check(item)) {
		g_value_init(value, G_TYPE_STRING);
		g_value_set_string(value, PyString_AsString(item));
#ifdef DEBUG_BINDING
		fprintf(stderr, "%sAdding (`%s') to list.\n",
			getindent(), PyString_AsString(item));
#endif
	}
}

/* The setattr function.  Sets an attribute to have the value of the given
 * Python object. */
static int
libuser_entity_setattr(struct libuser_entity *self, char *name, PyObject *args)
{
	PyObject *list, *item;
	GValue value;
	int size, i;

	DEBUG_ENTRY;

	/* Parse out the arguments.  We expect a single object. */
	if (PyArg_ParseTuple(args, "O", &list)) {
		lu_ent_clear(self->ent, name);

		/* If the object is a list, add it as a set of values. */
		if (PyList_Check(list)) {
			/* We need the length of the list. */
			size = PyList_Size(list);
#ifdef DEBUG_BINDING
			fprintf(stderr, "%sList has %d items.\n",
				getindent(), size);
#endif

			/* Add each item in turn. */
			for (i = 0; i < size; i++) {
				item = PyList_GetItem(list, i);
				libuser_convert_to_value(item, &value);
				lu_ent_add(self->ent, name, &value);
				g_value_unset(&value);
			}
			DEBUG_EXIT;
			return 0;
		} else if (PyString_Check(list) ||
			   PyLong_Check(list) ||
			   PyNumber_Check(list)) {
			/* It's a single item, so just add it. */
			libuser_convert_to_value(list, &value);
			lu_ent_add(self->ent, name, &value);
			DEBUG_EXIT;
			return 0;
		}
	}

	PyErr_SetString(PyExc_SystemError,
			"expected Number, Long, String, or list");

	DEBUG_EXIT;
	return -1;
}

/* Get the list of attributes, returning them as a PyList of PyStrings. */
static PyObject *
libuser_entity_getattrlist(struct libuser_entity *self, PyObject * args)
{
	GList *i;
	PyObject *ret;
	DEBUG_ENTRY;
	ret = PyList_New(0);
	for (i = lu_ent_get_attributes(self->ent);
	     i != NULL;
	     i = g_list_next(i)) {
		PyList_Append(ret, PyString_FromString((char*)i->data));
	}
	DEBUG_EXIT;
	return ret;
}

/* Get the values for a particular attribute, or somesuch. */
static PyObject *
libuser_entity_get(struct libuser_entity *self, PyObject * args)
{
	char *arg;
	PyObject *default_value = NULL;

	DEBUG_ENTRY;
	/* The first argument should be the name of the attribute, and the
	 * optional argument is the default value. */
	if (!PyArg_ParseTuple(args, "s|O", &arg, &default_value)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* If we have this attribute, convert it to a list and hand it back. */
	if (lu_ent_has(self->ent, arg)) {
		DEBUG_EXIT;
		return convert_value_array_pylist(lu_ent_get(self->ent, arg));
	} else {
		/* If not, return a new reference for the default. */
		if (default_value != NULL) {
			Py_INCREF(default_value);
			DEBUG_EXIT;
			return default_value;
		} else {
			/* If we have no default, return an empty list. */
			DEBUG_EXIT;
			return PyList_New(0);
		}
	}
}

/* Add a value to the entity. */
static PyObject *
libuser_entity_add(struct libuser_entity *self, PyObject *args)
{
	char *attr = NULL;
	PyObject *val;
	GValue value;
	DEBUG_ENTRY;
	/* We expect a string and some kind of object. */
	if (!PyArg_ParseTuple(args, "sO", &attr, &val)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Convert the item to a value. */
	libuser_convert_to_value(val, &value);
	lu_ent_add(self->ent, attr, &value);
	DEBUG_EXIT;
	return Py_BuildValue("");
}

/* Set the attribute to a given list of arguments. */
static PyObject *
libuser_entity_set(struct libuser_entity *self, PyObject *args)
{
	char *attr = NULL;
	PyObject *list = NULL, *item = NULL, *val = NULL;
	GValue value;
	int i, size;

	DEBUG_ENTRY;

	/* Remove all current values. */
	lu_ent_clear(self->ent, attr);

	/* We expect a string and some kind of object. */
	if (PyArg_ParseTuple(args, "sO!", &attr, &PyList_Type, &list)) {
		/* It's a list. */
		size = PyList_Size(list);
#ifdef DEBUG_BINDING
		fprintf(stderr, "%sList has %d items.\n", getindent(),
			size);
#endif

		/* Add each of the list items in turn. */
		for (i = 0; i < size; i++) {
			item = PyList_GetItem(list, i);
			libuser_convert_to_value(item, &value);
			lu_ent_add(self->ent, attr, &value);
		}
		DEBUG_EXIT;
		return Py_BuildValue("");
	}

	/* It's an object of some kind. */
	if (PyArg_ParseTuple(args, "sO", &attr, &val)) {
		libuser_convert_to_value(val, &value);
		lu_ent_add(self->ent, attr, &value);
		g_value_unset(&value);
		DEBUG_EXIT;
		return Py_BuildValue("");
	}

	PyErr_SetString(PyExc_SystemError,
			"expected value or list of values");
	DEBUG_EXIT;
	return NULL;
}

/* Clear out all values for an attribute. */
static PyObject *
libuser_entity_clear(struct libuser_entity *self, PyObject * args)
{
	char *arg;
	DEBUG_ENTRY;
	if (!PyArg_ParseTuple(args, "s", &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	lu_ent_clear(self->ent, arg);
	return Py_BuildValue("");
}

/* Clear out all values for all attributes. */
static PyObject *
libuser_entity_clear_all(struct libuser_entity *self, PyObject * args)
{
	DEBUG_ENTRY;
	if (!PyArg_ParseTuple(args, "")) {
		DEBUG_EXIT;
		return NULL;
	}
	lu_ent_clear_all(self->ent);
	return Py_BuildValue("");
}

/* Roll-back any changes we've made to the object since it was last read from or
 * saved to the information store. */
static PyObject *
libuser_entity_revert(struct libuser_entity *self, PyObject * args)
{
	DEBUG_ENTRY;
	lu_ent_revert(self->ent);
	DEBUG_EXIT;
	return Py_BuildValue("");
}

/* Get the length of the list of attributes. */
static int
libuser_entity_length(struct libuser_entity *self)
{
	DEBUG_CALL;
	return g_list_length(lu_ent_get_attributes(self->ent));
}

/* Get the value for a particular item, dictionary style. */
static PyObject *
libuser_entity_get_item(struct libuser_entity *self, PyObject *item)
{
	char *attr;

	DEBUG_ENTRY;

	/* Our lone argument should be a string. */
	if (!PyString_Check(item)) {
		PyErr_SetString(PyExc_TypeError, "expected a string");
		DEBUG_EXIT;
		return NULL;
	}
	attr = PyString_AsString(item);

	if (!lu_ent_has(self->ent, attr)) {
		PyErr_SetString(PyExc_KeyError,
				"no such attribute defined for this entity");
		DEBUG_EXIT;
		return NULL;
	}

	DEBUG_EXIT;
	return convert_value_array_pylist(lu_ent_get(self->ent, attr));
}

/* Check if an object has values for the given attribute. */
static PyObject *
libuser_entity_has_key(struct libuser_entity *self, PyObject *item)
{
	char *attr;

	DEBUG_ENTRY;

	if (!PyArg_ParseTuple(item, "s", &attr)) {
		PyErr_SetString(PyExc_TypeError,
				"expected a tuple or string");
		DEBUG_EXIT;
		return NULL;
	}
	return Py_BuildValue("i", lu_ent_has(self->ent, attr) ? 1 : 0);
}

/* Set a value, dictionary style. */
static int
libuser_entity_set_item(struct libuser_entity *self, PyObject *item,
			PyObject *args)
{
	char *attr = NULL;
	int i, size;
	GValue value;

	DEBUG_ENTRY;

	/* The item should be a string. */
	if (!PyString_Check(item)) {
		PyErr_SetString(PyExc_TypeError, "expected a string");
		DEBUG_EXIT;
		return -1;
	}
	attr = PyString_AsString(item);
#ifdef DEBUG_BINDING
	fprintf(stderr, "%sSetting item (`%s')...\n", getindent(), attr);
#endif

	/* Remove any existing values. */
	lu_ent_clear(self->ent, attr);

	/* If the new value is a list, convert each and add in turn. */
	if (PyList_Check(args)) {
		size = PyList_Size(args);
#ifdef DEBUG_BINDING
		fprintf(stderr, "%sList has %d items.\n", getindent(), size);
#endif
		lu_ent_clear(self->ent, attr);
		for (i = 0; i < size; i++) {
			item = PyList_GetItem(args, i);
			libuser_convert_to_value(item, &value);
#ifdef DEBUG_BINDING
			fprintf(stderr, "%sAdding (`%s') to `%s'.\n",
				getindent(),
				g_value_get_string(&value));
#endif
			lu_ent_add(self->ent, attr, &value);
			g_value_unset(&value);
		}
		DEBUG_EXIT;
		return 0;
	}

	/* If the new value is a value, convert it and add it. */
	if (item != NULL) {
		libuser_convert_to_value(args, &value);
#ifdef DEBUG_BINDING
		fprintf(stderr, "%sSetting (`%s') to `%s'.\n", getindent(),
			attr, &value);
#endif
		lu_ent_add(self->ent, attr, &value);
		g_value_unset(&value);
		DEBUG_EXIT;
		return 0;
	}

	PyErr_SetString(PyExc_TypeError,
			"expected values or list of values");
	DEBUG_EXIT;
	return -1;
}

static PyMappingMethods libuser_entity_mapping_methods = {
	(inquiry) libuser_entity_length,
	(binaryfunc) libuser_entity_get_item,
	(objobjargproc) libuser_entity_set_item,
};

static PyMethodDef libuser_entity_methods[] = {
	{"getattrlist", (PyCFunction) libuser_entity_getattrlist,
	 METH_VARARGS,
	 "get a list of the attributes this entity has"},
	{"has_key", (PyCFunction) libuser_entity_has_key, METH_VARARGS,
	 "check if the entity has a given attribute"},
	{"get", (PyCFunction) libuser_entity_get, METH_VARARGS,
	 "get a list of the values for a given attribute"},
	{"keys", (PyCFunction) libuser_entity_getattrlist, METH_VARARGS},
	{"clear", (PyCFunction) libuser_entity_clear, METH_VARARGS,
	 "clear the list of values for a given attribute"},
	{"set", (PyCFunction) libuser_entity_set, METH_VARARGS,
	 "set the list of values for a given attribute"},
	{"add", (PyCFunction) libuser_entity_add, METH_VARARGS,
	 "add a value to the current list of values for a given attribute"},
	{"clear_all", (PyCFunction) libuser_entity_clear_all, METH_VARARGS,
	 "clear all values for all attributes"},
	{"revert", (PyCFunction) libuser_entity_revert, METH_VARARGS,
	 "revert the list of values for a given attribute to the values which "
	 "were set when the entity was looked up"},
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

	(PyNumberMethods *) NULL,
	(PySequenceMethods *) NULL,
	(PyMappingMethods *) & libuser_entity_mapping_methods,
	(hashfunc) NULL,
	(ternaryfunc) NULL,
	(reprfunc) NULL,
};
