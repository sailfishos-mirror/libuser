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

#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
#include <libuser/user.h>
#include "Python.h"

#define FIXME fprintf(stderr, "Function %s not implemented.\n", __FUNCTION__); \
return NULL;

#undef  DEBUG_BINDING
#ifdef  DEBUG
#define DEBUG_BINDING
#endif

#ifdef DEBUG_BINDING
static int indent = 0;
static char *getindent()
{
	static char buf[LINE_MAX];
	g_return_val_if_fail(indent < sizeof(buf), "");
	memset(buf, 0, sizeof(buf));
	memset(buf, ' ', indent);
	return buf;
}
#define DEBUG_ENTRY {\
	fprintf(stderr, "%sEntering `%s' at line %d.\n", \
		getindent(), __FUNCTION__, __LINE__); \
	indent++; \
	}
#define DEBUG_CALL {\
      	fprintf(stderr, "%sIn `%s' at line %d.\n", \
		getindent(), __FUNCTION__, __LINE__); \
	}
#define DEBUG_EXIT {\
	indent--; \
	fprintf(stderr, "%sLeaving `%s' at line %d.\n", \
		getindent(), __FUNCTION__, __LINE__); \
	}
#else
#define DEBUG_ENTRY
#define DEBUG_CALL
#define DEBUG_EXIT
#endif

void initlibuser(void);

struct
libuser_admin_domain {
	PyObject_HEAD
	struct libuser_admin *main;
};

struct
libuser_admin {
	PyObject_HEAD
	lu_context_t *ctx;
	struct libuser_admin_domain *user, *group;
};

struct
libuser_entity {
	PyObject_HEAD
	lu_ent_t *ent;
};

static PyMethodDef libuser_admin_user_methods[];
static PyMethodDef libuser_admin_group_methods[];
static PyMethodDef libuser_admin_methods[];
static PyMappingMethods libuser_entity_mapping_methods;
static PyMethodDef libuser_entity_methods[];
static PyMethodDef libuser_methods[];
static PyTypeObject AdminType;
static PyTypeObject EntityType;
#define Admin_Check(__x) ((__x)->ob_type == &AdminType)
#define Entity_Check(__x) ((__x)->ob_type == &EntityType)

static PyObject *
convert_glist_pystringlist(GList *strings)
{
	GList *i = NULL;
	PyObject *ret;

	DEBUG_ENTRY;

	ret = PyList_New(0);
	for(i = strings; i != NULL; i = g_list_next(i)) {
		PyList_Append(ret, PyString_FromString((char*)i->data));
#ifdef DEBUG_BINDING
		fprintf(stderr, "adding `%s' to string list\n", (char*)i->data);
#endif
	}

	DEBUG_EXIT;
	return ret;
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

/**
 * Entity methods.
 */
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

static PyObject *
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
			fprintf(stderr, "%sList has %d items.\n", getindent(),
				size);
			#endif

			for(i = 0; i < size; i++) {
				#ifdef DEBUG_BINDING
				fprintf(stderr, "%sAdding (`%s') to `%s'.\n",
					getindent(),
					PyString_AsString(PyList_GetItem(list,
									 i)),
					name);
				#endif
				lu_ent_add(self->ent, name,
					   PyString_AsString(PyList_GetItem(list, i)));
			}
			DEBUG_EXIT;
			return Py_BuildValue("");
		} else
		if(PyString_Check(list)) {
			lu_ent_set(self->ent, name, PyString_AsString(list));
			DEBUG_EXIT;
			return Py_BuildValue("");
		}
	}

	PyErr_SetString(PyExc_SystemError,
			"expected string or list of strings");
	DEBUG_EXIT;
	return NULL;
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
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "s", &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	DEBUG_EXIT;
	return convert_glist_pystringlist(lu_ent_get(self->ent, arg));
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
			fprintf(stderr, "%sAdding (`%s') to `%s'.\n",
				getindent(),
				PyString_AsString(PyList_GetItem(list, i)),
				attr);
			#endif
			lu_ent_add(self->ent, attr,
				   PyString_AsString(PyList_GetItem(list, i)));
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
	if(lu_ent_clear(self->ent, arg)) {
		DEBUG_EXIT;
		return Py_BuildValue("");
	} else {
		PyErr_SetString(PyExc_SystemError, "libuser error");
		DEBUG_EXIT;
		return NULL;
	}
}

static PyObject *
libuser_entity_revert(struct libuser_entity *self, PyObject *args)
{
	char *arg;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "s", &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
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
	if(!(attr = PyString_AsString(item))) {
		DEBUG_EXIT;
		return NULL;
	}
	DEBUG_EXIT;
	return convert_glist_pystringlist(lu_ent_get(self->ent, attr));
}

static PyObject*
libuser_entity_set_item(struct libuser_entity *self, PyObject *item,
	       		PyObject *args)
{
	char *attr = NULL;
	int i, size;
	PyObject *arg;

	DEBUG_ENTRY;

	if(!PyArg_ParseTuple(args, "O", &arg)) {
		PyErr_SetString(PyExc_TypeError, "expected a string or list");
		DEBUG_EXIT;
		return NULL;
	}

	if(!PyString_Check(item)) {
		PyErr_SetString(PyExc_TypeError, "expected a string");
		DEBUG_EXIT;
		return NULL;
	}
	attr = PyString_AsString(item);
	#ifdef DEBUG_BINDING
	fprintf(stderr, "%sSetting item (`%s')...\n", getindent(), attr);
	#endif

	if(PyString_Check(arg)) {
		#ifdef DEBUG_BINDING
		fprintf(stderr, "%sSetting (`%s') to `%s'.\n",
			getindent(),
			attr,
			PyString_AsString(args));
		#endif
		lu_ent_set(self->ent, attr, PyString_AsString(args));
		DEBUG_EXIT;
		return Py_BuildValue("");
	}

	if(PyList_Check(arg)) {
		size = PyList_Size(arg);
		#ifdef DEBUG_BINDING
		fprintf(stderr, "%sList has %d items.\n", getindent(), size);
		#endif
		lu_ent_clear(self->ent, attr);
		for(i = 0; i < size; i++) {
			if(!PyString_Check(PyList_GetItem(arg, i))) {
				PyErr_SetString(PyExc_TypeError,
						"expected strings in list");
				continue;
			}
			#ifdef DEBUG_BINDING
			fprintf(stderr, "%sAdding (`%s') to `%s'.\n",
				getindent(),
				PyString_AsString(PyList_GetItem(arg, i)),
				attr);
			#endif
			lu_ent_add(self->ent, attr,
				   PyString_AsString(PyList_GetItem(arg, i)));
		}
		DEBUG_EXIT;
		return Py_BuildValue("");
	}

	PyErr_SetString(PyExc_TypeError, "expected string or list of strings");
	DEBUG_EXIT;
	return NULL;
}

static PyMappingMethods
libuser_entity_mapping_methods = {
	(inquiry) libuser_entity_length,
	(binaryfunc) libuser_entity_get_item,
	(objobjargproc) libuser_entity_set_item,
};

static PyMethodDef
libuser_entity_methods[] = {
	{"getattrlist", (PyCFunction)libuser_entity_getattrlist, METH_VARARGS},
	{"get", (PyCFunction)libuser_entity_get, METH_VARARGS},
	{"set", (PyCFunction)libuser_entity_set, METH_VARARGS},
	{"add", (PyCFunction)libuser_entity_add, METH_VARARGS},
	{"clear", (PyCFunction)libuser_entity_clear, METH_VARARGS},
	{"revert", (PyCFunction)libuser_entity_revert, METH_VARARGS},
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

/**
 * Methods for the AdminType.
 */
static void
libuser_admin_destroy(struct libuser_admin *self)
{
	DEBUG_ENTRY;
	lu_end(self->ctx);
	PyMem_DEL(self);
	DEBUG_EXIT;
}

static void
libuser_admin_domain_destroy(struct libuser_admin_domain *self)
{
	DEBUG_ENTRY;
	PyMem_DEL(self);
	DEBUG_EXIT;
}

static PyObject *
libuser_admin_getattr(struct libuser_admin *self, char *name)
{
	DEBUG_ENTRY;
	if(strcmp(name, "user") == 0) {
		DEBUG_EXIT;
		return (PyObject*)self->user;
	}
	if(strcmp(name, "group") == 0) {
		DEBUG_EXIT;
		return (PyObject*)self->group;
	}
#ifdef DEBUG_BINDING
	fprintf(stderr, "Searching for attribute `%s'\n", name);
#endif
	DEBUG_EXIT;
	return Py_FindMethod(libuser_admin_methods, (PyObject*)self, name);
}

static PyObject *
libuser_admin_lookup_user_name(struct libuser_admin *self, PyObject *args)
{
	char *arg;
	struct lu_ent *ent;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "s", &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(ent == NULL) {
		PyErr_SetString(PyExc_SystemError, "libuser error");
		DEBUG_EXIT;
		return NULL;
	}
	if(lu_user_lookup_name(self->ctx, arg, ent)) {
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		lu_ent_free(ent);
		DEBUG_EXIT;
		return Py_BuildValue("");
	}
}

static PyObject *
libuser_admin_lookup_user_id(struct libuser_admin *self, PyObject *args)
{
	int arg;
	struct lu_ent *ent;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "i", &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(ent == NULL) {
		DEBUG_EXIT;
		return NULL;
	}
	if(lu_user_lookup_id(self->ctx, arg, ent)) {
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		lu_ent_free(ent);
		DEBUG_EXIT;
		return Py_BuildValue("");
	}
}

static PyObject *
libuser_admin_lookup_group_name(struct libuser_admin *self, PyObject *args)
{
	char *arg;
	struct lu_ent *ent;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "s", &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(ent == NULL) {
		PyErr_SetString(PyExc_SystemError, "libuser error");
		DEBUG_EXIT;
		return NULL;
	}
	if(lu_group_lookup_name(self->ctx, arg, ent)) {
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		lu_ent_free(ent);
		DEBUG_EXIT;
		return Py_BuildValue("");
	}
}

static PyObject *
libuser_admin_lookup_group_id(struct libuser_admin *self, PyObject *args)
{
	int arg;
	struct lu_ent *ent;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "i", &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(ent == NULL) {
		PyErr_SetString(PyExc_SystemError, "libuser error");
		DEBUG_EXIT;
		return NULL;
	}
	if(lu_group_lookup_id(self->ctx, arg, ent)) {
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		lu_ent_free(ent);
		DEBUG_EXIT;
		return Py_BuildValue("");
	}
}

static PyObject *
libuser_admin_init_user(struct libuser_admin *self, PyObject *args)
{
	char *arg;
	int is_system = 0;
	struct lu_ent *ent;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "s|i", &arg, &is_system)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(ent == NULL) {
		PyErr_SetString(PyExc_SystemError, "libuser error");
		DEBUG_EXIT;
		return NULL;
	}
	lu_ent_user_default(self->ctx, arg, is_system, ent);
	DEBUG_EXIT;
	return libuser_wrap_ent(ent);
}

static PyObject *
libuser_admin_init_group(struct libuser_admin *self, PyObject *args)
{
	char *arg;
	int is_system = 0;
	struct lu_ent *ent;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "s|i", &arg, &is_system)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(ent == NULL) {
		PyErr_SetString(PyExc_SystemError, "libuser error");
		DEBUG_EXIT;
		return NULL;
	}
	lu_ent_group_default(self->ctx, arg, is_system, ent);
	DEBUG_EXIT;
	return libuser_wrap_ent(ent);
}

static PyObject *
libuser_admin_generic(struct libuser_admin *self, PyObject *args,
		      gboolean (*fn)(struct lu_context *, struct lu_ent *))
{
	struct libuser_entity *ent;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "O!", &EntityType, &ent)) {
		DEBUG_EXIT;
		return NULL;
	}
	if(fn(self->ctx, ent->ent)) {
		DEBUG_EXIT;
		return Py_BuildValue("");
	} else {
		PyErr_SetString(PyExc_SystemError, "libuser error");
		DEBUG_EXIT;
		return NULL;
	}
}

static PyObject *
libuser_admin_setpass(struct libuser_admin *self, PyObject *args,
		      gboolean (*fn)(struct lu_context *, struct lu_ent *,
				     const char *))
{
	struct libuser_entity *ent;
	const char *password;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "O!z", &EntityType, &ent, &password)) {
		DEBUG_EXIT;
		return NULL;
	}
	if(fn(self->ctx, ent->ent, password)) {
		DEBUG_EXIT;
		return Py_BuildValue("");
	} else {
		PyErr_SetString(PyExc_SystemError, "libuser error");
		DEBUG_EXIT;
		return NULL;
	}
}

static PyObject *
libuser_admin_add_user(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, lu_user_add);
}

static PyObject *
libuser_admin_add_group(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, lu_group_add);
}

static PyObject *
libuser_admin_modify_user(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, lu_user_modify);
}

static PyObject *
libuser_admin_modify_group(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, lu_group_modify);
}

static PyObject *
libuser_admin_delete_user(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, lu_user_delete);
}

static PyObject *
libuser_admin_delete_group(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, lu_group_delete);
}

static PyObject *
libuser_admin_lock_user(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, lu_user_lock);
}

static PyObject *
libuser_admin_lock_group(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, lu_group_lock);
}

static PyObject *
libuser_admin_unlock_user(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, lu_user_unlock);
}

static PyObject *
libuser_admin_unlock_group(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, lu_group_unlock);
}

static PyObject *
libuser_admin_setpass_user(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_setpass(self, args, lu_user_setpass);
}

static PyObject *
libuser_admin_setpass_group(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_setpass(self, args, lu_group_setpass);
}

static PyObject *
libuser_admin_user_init(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_init_user(self, args);
}

static PyObject *
libuser_admin_user_add(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_add_user(self, args);
}

static PyObject *
libuser_admin_user_modify(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_modify_user(self, args);
}

static PyObject *
libuser_admin_user_delete(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_delete_user(self, args);
}

static PyObject *
libuser_admin_user_lock(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_lock_user(self, args);
}

static PyObject *
libuser_admin_user_unlock(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_unlock_user(self, args);
}

static PyObject *
libuser_admin_user_setpass(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_setpass_user(self, args);
}

static PyObject *
libuser_admin_group_init(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_init_group(self, args);
}

static PyObject *
libuser_admin_group_add(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_add_group(self, args);
}

static PyObject *
libuser_admin_group_modify(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_modify_group(self, args);
}

static PyObject *
libuser_admin_group_delete(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_delete_group(self, args);
}

static PyObject *
libuser_admin_group_lock(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_lock_group(self, args);
}

static PyObject *
libuser_admin_group_unlock(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_unlock_group(self, args);
}

static PyObject *
libuser_admin_group_setpass(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_setpass_group(self, args);
}

static PyObject *
libuser_admin_enumerate_users(struct libuser_admin *self, PyObject *args)
{
	GList *results;
	char *module = NULL, *pattern = NULL;
	PyObject *ret = NULL;

	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "|ss", &pattern, &module)) {
		DEBUG_EXIT;
		return NULL;
	}
	results = lu_users_enumerate(self->ctx, pattern, module);
	ret = convert_glist_pystringlist(results);
	g_list_free(results);
	DEBUG_EXIT;
	return ret;
}

static PyObject *
libuser_admin_enumerate_groups(struct libuser_admin *self, PyObject *args)
{
	GList *results;
	char *module = NULL, *pattern = NULL;
	PyObject *ret = NULL;

	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "|ss", &pattern, &module)) {
		DEBUG_EXIT;
		return NULL;
	}
	results = lu_groups_enumerate(self->ctx, pattern, module);
	ret = convert_glist_pystringlist(results);
	g_list_free(results);
	DEBUG_EXIT;
	return ret;
}

static PyMethodDef libuser_admin_user_methods[] =
{
	{"init", (PyCFunction) libuser_admin_user_init, METH_VARARGS},
	{"add", (PyCFunction) libuser_admin_user_add, METH_VARARGS},
	{"modify", (PyCFunction) libuser_admin_user_modify, METH_VARARGS},
	{"delete", (PyCFunction) libuser_admin_user_delete, METH_VARARGS},
	{"lock", (PyCFunction) libuser_admin_user_lock, METH_VARARGS},
	{"unlock", (PyCFunction) libuser_admin_user_unlock, METH_VARARGS},
	{"setpass", (PyCFunction) libuser_admin_user_setpass, METH_VARARGS},
	{NULL, NULL, 0},
};

static PyObject *
libuser_admin_user_getattr(struct libuser_admin_domain *self, char *name)
{
	DEBUG_CALL;
#ifdef DEBUG_BINDING
	fprintf(stderr, "Searching for attribute `%s'\n", name);
#endif
	return Py_FindMethod(libuser_admin_user_methods, (PyObject*)self, name);
}

static PyMethodDef libuser_admin_group_methods[] =
{
	{"init", (PyCFunction) libuser_admin_group_init, METH_VARARGS},
	{"add", (PyCFunction) libuser_admin_group_add, METH_VARARGS},
	{"modify", (PyCFunction) libuser_admin_group_modify, METH_VARARGS},
	{"delete", (PyCFunction) libuser_admin_group_delete, METH_VARARGS},
	{"lock", (PyCFunction) libuser_admin_group_lock, METH_VARARGS},
	{"unlock", (PyCFunction) libuser_admin_group_unlock, METH_VARARGS},
	{"setpass", (PyCFunction) libuser_admin_group_setpass, METH_VARARGS},
	{NULL, NULL, 0},
};

static PyObject *
libuser_admin_group_getattr(struct libuser_admin_domain *self, char *name)
{
	DEBUG_CALL;
#ifdef DEBUG_BINDING
	fprintf(stderr, "Searching for attribute `%s'\n", name);
#endif
	return Py_FindMethod(libuser_admin_group_methods, (PyObject*)self, name);
}


static PyMethodDef
libuser_admin_methods[] = {
	{"lookupUserByName", (PyCFunction)libuser_admin_lookup_user_name,
	 METH_VARARGS},
	{"lookupUserById", (PyCFunction)libuser_admin_lookup_user_id,
	 METH_VARARGS},
	{"lookupGroupByName", (PyCFunction)libuser_admin_lookup_group_name,
	 METH_VARARGS},
	{"lookupGroupById", (PyCFunction)libuser_admin_lookup_group_id,
	 METH_VARARGS},
	{"initUser", (PyCFunction)libuser_admin_init_user, METH_VARARGS},
	{"initGroup", (PyCFunction)libuser_admin_init_group, METH_VARARGS},
	{"addUser", (PyCFunction)libuser_admin_add_user, METH_VARARGS},
	{"addGroup", (PyCFunction)libuser_admin_add_group, METH_VARARGS},
	{"modifyUser", (PyCFunction)libuser_admin_modify_user, METH_VARARGS},
	{"modifyGroup", (PyCFunction)libuser_admin_modify_group, METH_VARARGS},
	{"deleteUser", (PyCFunction)libuser_admin_delete_user, METH_VARARGS},
	{"deleteGroup", (PyCFunction)libuser_admin_delete_group, METH_VARARGS},
	{"lockUser", (PyCFunction)libuser_admin_lock_user, METH_VARARGS},
	{"lockGroup", (PyCFunction)libuser_admin_lock_group, METH_VARARGS},
	{"unlockUser", (PyCFunction)libuser_admin_unlock_user, METH_VARARGS},
	{"unlockGroup", (PyCFunction)libuser_admin_unlock_group, METH_VARARGS},
	{"setpassUser", (PyCFunction)libuser_admin_setpass_user, METH_VARARGS},
	{"setpassGroup", (PyCFunction)libuser_admin_setpass_group, METH_VARARGS},
	{"enumerateUsers", (PyCFunction)libuser_admin_enumerate_users, METH_VARARGS},
	{"enumerateGroups", (PyCFunction)libuser_admin_enumerate_groups, METH_VARARGS},
	{NULL, NULL, 0},
};

static PyTypeObject AdminType = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,
	"Admin",
	sizeof(struct libuser_admin),
	0,

	(destructor) libuser_admin_destroy,
	(printfunc) NULL,
	(getattrfunc) libuser_admin_getattr,
	(setattrfunc) NULL,
	(cmpfunc) NULL,
	(reprfunc) NULL,

	(PyNumberMethods*) NULL,
	(PySequenceMethods*) NULL,
	(PyMappingMethods*) NULL,
	(hashfunc) NULL,
	(ternaryfunc) NULL,
	(reprfunc) NULL,
};

static PyTypeObject AdminUserType = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,
	"UserAdmin",
	sizeof(struct libuser_admin_domain),
	0,

	(destructor) libuser_admin_domain_destroy,
	(printfunc) NULL,
	(getattrfunc) libuser_admin_user_getattr,
	(setattrfunc) NULL,
	(cmpfunc) NULL,
	(reprfunc) NULL,

	(PyNumberMethods*) NULL,
	(PySequenceMethods*) NULL,
	(PyMappingMethods*) NULL,
	(hashfunc) NULL,
	(ternaryfunc) NULL,
	(reprfunc) NULL,
};

static PyTypeObject AdminGroupType = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,
	"GroupAdmin",
	sizeof(struct libuser_admin_domain),
	0,

	(destructor) libuser_admin_domain_destroy,
	(printfunc) NULL,
	(getattrfunc) libuser_admin_group_getattr,
	(setattrfunc) NULL,
	(cmpfunc) NULL,
	(reprfunc) NULL,

	(PyNumberMethods*) NULL,
	(PySequenceMethods*) NULL,
	(PyMappingMethods*) NULL,
	(hashfunc) NULL,
	(ternaryfunc) NULL,
	(reprfunc) NULL,
};

static PyObject*
libuser_admin_new(PyObject *self, PyObject *args, PyObject *kwargs)
{
	char *name = getlogin(), *info = "files", *auth = "shadow files";
	char *keywords[] = {"name", "type", "info", "auth", NULL};
	int type = lu_user;
	lu_context_t *context;
	struct libuser_admin *ret;

	DEBUG_ENTRY;

	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "|siss", keywords,
					&name, &type, &info, &auth)) {
		return NULL;
	}

	if((type != lu_user) && (type != lu_group)) {
		PyErr_SetString(PyExc_ValueError, "invalid type");
		return NULL;
	}

	context = lu_start(name, type, info, auth, NULL, NULL);
	if(context == NULL) {
		PyErr_SetString(PyExc_SystemError, "libuser init failed");
		return NULL;
	}

	ret = PyObject_NEW(struct libuser_admin, &AdminType);
	if(ret == NULL) {
		lu_end(context);
		return NULL;
	}
	ret->ctx = context;
	ret->user = PyObject_NEW(struct libuser_admin_domain, &AdminUserType);
	ret->user->main = ret;
	ret->group = PyObject_NEW(struct libuser_admin_domain, &AdminGroupType);
	ret->group->main = ret;

	DEBUG_EXIT;
	return (PyObject*) ret;
}

static PyMethodDef
libuser_methods[] = {
	{"Admin", (PyCFunction)libuser_admin_new, METH_VARARGS | METH_KEYWORDS},
	{NULL, NULL, 0},
};

void
initlibuser(void)
{
	PyObject *module, *dict;
	DEBUG_ENTRY;
	module = Py_InitModule("libuser", libuser_methods);
	dict = PyModule_GetDict(module);
	PyDict_SetItemString(dict, "LU_USER", PyInt_FromLong(lu_user));
	PyDict_SetItemString(dict, "LU_GROUP", PyInt_FromLong(lu_group));
	PyDict_SetItemString(dict, "LU_ADMINISTRATORUID",
			     PyString_FromString(LU_ADMINISTRATORUID));
	PyDict_SetItemString(dict, "LU_CN", PyString_FromString(LU_CN));
	PyDict_SetItemString(dict, "LU_GECOS", PyString_FromString(LU_GECOS));
	PyDict_SetItemString(dict, "LU_GID", PyString_FromString(LU_GID));
	PyDict_SetItemString(dict, "LU_GIDNUMBER",
			     PyString_FromString(LU_GIDNUMBER));
	PyDict_SetItemString(dict, "LU_GROUPNAME",
			     PyString_FromString(LU_GROUPNAME));
	PyDict_SetItemString(dict, "LU_HOMEDIRECTORY",
			     PyString_FromString(LU_HOMEDIRECTORY));
	PyDict_SetItemString(dict, "LU_LOGINSHELL",
			     PyString_FromString(LU_LOGINSHELL));
	PyDict_SetItemString(dict, "LU_MEMBERUID",
			     PyString_FromString(LU_MEMBERUID));
	PyDict_SetItemString(dict, "LU_OBJECTCLASS",
			     PyString_FromString(LU_OBJECTCLASS));
	PyDict_SetItemString(dict, "LU_SHADOWEXPIRE",
			     PyString_FromString(LU_SHADOWEXPIRE));
	PyDict_SetItemString(dict, "LU_SHADOWFLAG",
			     PyString_FromString(LU_SHADOWFLAG));
	PyDict_SetItemString(dict, "LU_SHADOWINACTIVE",
			     PyString_FromString(LU_SHADOWINACTIVE));
	PyDict_SetItemString(dict, "LU_SHADOWLASTCHANGE",
			     PyString_FromString(LU_SHADOWLASTCHANGE));
	PyDict_SetItemString(dict, "LU_SHADOWMAX",
			     PyString_FromString(LU_SHADOWMAX));
	PyDict_SetItemString(dict, "LU_SHADOWMIN",
			     PyString_FromString(LU_SHADOWMIN));
	PyDict_SetItemString(dict, "LU_SHADOWWARNING",
			     PyString_FromString(LU_SHADOWWARNING));
	PyDict_SetItemString(dict, "LU_UID", PyString_FromString(LU_UID));
	PyDict_SetItemString(dict, "LU_UIDNUMBER",
			     PyString_FromString(LU_UIDNUMBER));
	PyDict_SetItemString(dict, "LU_USERNAME",
			     PyString_FromString(LU_USERNAME));
	PyDict_SetItemString(dict, "LU_USERPASSWORD",
			     PyString_FromString(LU_USERPASSWORD));
	DEBUG_EXIT;
	return;
}
