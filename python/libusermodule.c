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
#include <libuser/user_private.h>
#include "Python.h"

#define FIXME fprintf(stderr, "Function %s not implemented.\n", __FUNCTION__); \
return NULL;

#define DEBUG_BINDING
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
	PyObject *prompter;
};

struct
libuser_entity {
	PyObject_HEAD
	lu_ent_t *ent;
};

struct
libuser_prompt {
	PyObject_HEAD
	lu_prompt_t prompt;
};

static PyMethodDef libuser_admin_user_methods[];
static PyMethodDef libuser_admin_group_methods[];
static PyMethodDef libuser_admin_methods[];
static PyMappingMethods libuser_entity_mapping_methods;
static PyMethodDef libuser_entity_methods[];
static PyMethodDef libuser_methods[];
static PyTypeObject AdminType;
static PyTypeObject EntityType;
static PyTypeObject PromptType;
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
	lu_ent_clear(self->ent, arg);
	return Py_BuildValue("");
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
		fprintf(stderr, "%sSetting (`%s') to `%s'.\n",
			getindent(),
			attr,
			PyString_AsString(args));
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
				PyErr_SetString(PyExc_TypeError,
						"expected strings in list");
				continue;
			}
			#ifdef DEBUG_BINDING
			fprintf(stderr, "%sAdding (`%s') to `%s'.\n",
				getindent(),
				PyString_AsString(PyList_GetItem(args, i)),
				attr);
			#endif
			lu_ent_add(self->ent, attr,
				   PyString_AsString(PyList_GetItem(args, i)));
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

/**
 * Methods for the AdminType.
 */
static void
libuser_admin_destroy(struct libuser_admin *self)
{
	DEBUG_ENTRY;
	Py_DECREF((PyObject*)self->ctx->prompter_data);
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
		Py_INCREF((PyObject*)self->user);
		DEBUG_EXIT;
		return (PyObject*)self->user;
	}
	if(strcmp(name, "group") == 0) {
		Py_INCREF((PyObject*)self->group);
		DEBUG_EXIT;
		return (PyObject*)self->group;
	}
	if(strcmp(name, "prompt") == 0) {
		Py_INCREF((PyObject*)self->ctx->prompter_data);
		DEBUG_EXIT;
		return self->ctx->prompter_data;
	}
#ifdef DEBUG_BINDING
	fprintf(stderr, "Searching for attribute `%s'\n", name);
#endif
	DEBUG_EXIT;
	return Py_FindMethod(libuser_admin_methods, (PyObject*)self, name);
}

static gboolean
libuser_admin_python_prompter(struct lu_prompt *prompts, int count,
			      gpointer callback_data, struct lu_error **error);

static int
libuser_admin_setattr(struct libuser_admin *self, const char *attr,
		      PyObject *args)
{
	DEBUG_ENTRY;
#ifdef DEBUG_BINDING
	fprintf(stderr, "%sSetting attribute `%s'\n", getindent(), attr);
#endif
	if(strcmp(attr, "prompt") == 0) {
		if(!PyCFunction_Check(args)) {
			PyErr_SetString(PyExc_TypeError,
					"expecting callable function");
			DEBUG_EXIT;
			return -1;
		}
		if(self->ctx->prompter_data != NULL) {
			Py_DECREF((PyObject*)self->ctx->prompter_data);
		}
		Py_INCREF(args);
#ifdef DEBUG_BINDING
		fprintf(stderr, "Setting prompter to object at <%p>.\n", args);
#endif
		lu_set_prompter(self->ctx, libuser_admin_python_prompter, args);
		DEBUG_EXIT;
		return 0;
	}
	PyErr_SetString(PyExc_AttributeError, "no such writable attribute");
	DEBUG_EXIT;
	return -1;
}

static PyObject *
libuser_admin_lookup_user_name(struct libuser_admin *self, PyObject *args)
{
	char *arg;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "s", &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(lu_user_lookup_name(self->ctx, arg, ent, &error)) {
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
	struct lu_error *error = NULL;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "i", &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(lu_user_lookup_id(self->ctx, arg, ent, &error)) {
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
	struct lu_error *error = NULL;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "s", &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(lu_group_lookup_name(self->ctx, arg, ent, &error)) {
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
	struct lu_error *error = NULL;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "i", &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(lu_group_lookup_id(self->ctx, arg, ent, &error)) {
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
		      gboolean (*fn)(struct lu_context *, struct lu_ent *,
			             struct lu_error **error))
{
	struct libuser_entity *ent;
	struct lu_error *error = NULL;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "O!", &EntityType, &ent)) {
		DEBUG_EXIT;
		return NULL;
	}
	if(fn(self->ctx, ent->ent, &error)) {
		DEBUG_EXIT;
		return Py_BuildValue("");
	} else {
		PyErr_SetString(PyExc_RuntimeError, error->string);
		lu_error_free(&error);
		DEBUG_EXIT;
		return NULL;
	}
}

static PyObject *
libuser_admin_setpass(struct libuser_admin *self, PyObject *args,
		      gboolean (*fn)(struct lu_context *, struct lu_ent *,
				     const char *, struct lu_error **))
{
	struct libuser_entity *ent;
	struct lu_error *error = NULL;
	const char *password;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "O!z", &EntityType, &ent, &password)) {
		DEBUG_EXIT;
		return NULL;
	}
	if(fn(self->ctx, ent->ent, password, &error)) {
		DEBUG_EXIT;
		return Py_BuildValue("");
	} else {
		PyErr_SetString(PyExc_SystemError, error->string);
		lu_error_free(&error);
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
	struct lu_error *error = NULL;

	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "|ss", &pattern, &module)) {
		DEBUG_EXIT;
		return NULL;
	}
	results = lu_users_enumerate(self->ctx, pattern, module, &error);
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
	struct lu_error *error = NULL;

	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "|ss", &pattern, &module)) {
		DEBUG_EXIT;
		return NULL;
	}
	results = lu_groups_enumerate(self->ctx, pattern, module, &error);
	ret = convert_glist_pystringlist(results);
	g_list_free(results);
	DEBUG_EXIT;
	return ret;
}

static struct libuser_prompt *libuser_prompt_new(void);
static PyObject *libuser_admin_prompt_console(struct libuser_admin *self,
					      PyObject *args);

static gboolean
libuser_admin_python_prompter(struct lu_prompt *prompts, int count,
			      gpointer callback_data, struct lu_error **error)
{
	PyObject *list = NULL, *tuple = NULL;
	PyObject *prompter = (PyObject*) callback_data;
	int i;

	DEBUG_ENTRY;
	if(count > 0) {
		if(!PyCallable_Check(prompter)) {
			lu_error_set(error, lu_error_generic, NULL);
			PyErr_SetString(PyExc_RuntimeError,
					"prompter is not callable");
			DEBUG_EXIT;
			return FALSE;
		}
		list = PyList_New(0);
		for(i = 0; i < count; i++) {
			struct libuser_prompt *prompt;
			prompt = libuser_prompt_new();
			prompt->prompt = prompts[i];
			PyList_Append(list, (PyObject*) prompt);
		}
		tuple = Py_BuildValue("(N)", list);
		PyObject_CallObject(prompter, tuple);
		if(PyErr_Occurred()) {
			PyErr_Print();
			Py_DECREF(list);
			DEBUG_EXIT;
			return FALSE;
		}
		for(i = 0; i < count; i++) {
			struct libuser_prompt *prompt;
			prompt = (struct libuser_prompt*) PyList_GetItem(list, i);
			prompts[i] = prompt->prompt;
		}
		Py_DECREF(list);
	}

	DEBUG_EXIT;
	return TRUE;
}

static PyObject *
libuser_admin_prompt(struct libuser_admin *self, PyObject *args,
		     lu_prompt_fn *prompter)
{
	int count, i;
	PyObject *list = NULL;
	PyObject *item = NULL;
	struct lu_prompt *prompts = NULL;
	struct lu_error *error = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail(self != NULL, NULL);

	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "O!", &PyList_Type, &list)) {
		DEBUG_EXIT;
		return NULL;
	}
	count = PyList_Size(list);
	for(i = 0; i < count; i++) {
		item = PyList_GetItem(list, i);
		if(item->ob_type != &PromptType) {
			PyErr_SetString(PyExc_TypeError,
					"expected list of Prompt objects");
			DEBUG_EXIT;
			return NULL;
		}
	}
	count = PyList_Size(list);
	prompts = g_malloc0(count * sizeof(struct lu_prompt));

	for(i = 0; i < count; i++) {
		struct libuser_prompt *obj;
		obj = (struct libuser_prompt*) PyList_GetItem(list, i);
		Py_INCREF(obj);
		prompts[i].prompt = g_strdup(obj->prompt.prompt ?: "");
		prompts[i].default_value = obj->prompt.default_value ? g_strdup(obj->prompt.default_value) : NULL;
		prompts[i].visible = obj->prompt.visible;
	}
#ifdef DEBUG_BINDING
	fprintf(stderr, "Prompter function promptConsole is at <%p>.\n",
		lu_prompt_console);
	fprintf(stderr, "Prompter function promptConsoleQuiet is at <%p>.\n",
		lu_prompt_console_quiet);
	fprintf(stderr, "Calling prompter function at <%p>.\n", prompter);
#endif
	success = prompter(prompts, count, self->prompter, &error);
	if(success) {
		for(i = 0; i < count; i++) {
			struct libuser_prompt *obj;
			obj = (struct libuser_prompt*) PyList_GetItem(list, i);
			obj->prompt.value = g_strdup(prompts[i].value ?: "");
			obj->prompt.free_value = (typeof(obj->prompt.free_value)) g_free;
			if(prompts[i].value && prompts[i].free_value) {
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
libuser_admin_prompt_console(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_prompt(self, args, lu_prompt_console);
}

static PyObject *
libuser_admin_prompt_console_quiet(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_prompt(self, args, lu_prompt_console_quiet);
}

static PyMethodDef libuser_admin_user_methods[] =
{
	{"init", (PyCFunction) libuser_admin_user_init, METH_VARARGS,
	 "initialize a user with default settings suitable for creating "
	 "a new account"},
	{"add", (PyCFunction) libuser_admin_user_add, METH_VARARGS,
	 "add a record for this user to the system user database"},
	{"modify", (PyCFunction) libuser_admin_user_modify, METH_VARARGS,
	 "modify the user's record in the system user database to match the "
	 "object's values for attributes"},
	{"delete", (PyCFunction) libuser_admin_user_delete, METH_VARARGS,
	 "remove the user's record from the system user database"},
	{"lock", (PyCFunction) libuser_admin_user_lock, METH_VARARGS,
	 "lock this user out"},
	{"unlock", (PyCFunction) libuser_admin_user_unlock, METH_VARARGS},
	{"setpass", (PyCFunction) libuser_admin_user_setpass, METH_VARARGS,
	 "set the user's password"},
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
	{"init", (PyCFunction) libuser_admin_group_init, METH_VARARGS,
	 "initialize a group with default settings suitable for creating "
	 "a new account"},
	{"add", (PyCFunction) libuser_admin_group_add, METH_VARARGS,
	 "add a record for this group to the system group database"},
	{"modify", (PyCFunction) libuser_admin_group_modify, METH_VARARGS,
	 "modify the user's record in the system user database to match the "
	 "object's values for attributes"},
	{"delete", (PyCFunction) libuser_admin_group_delete, METH_VARARGS,
	 "remove the user's record from the system user database"},
	{"lock", (PyCFunction) libuser_admin_group_lock, METH_VARARGS,
	 "lock this group out"},
	{"unlock", (PyCFunction) libuser_admin_group_unlock, METH_VARARGS},
	{"setpass", (PyCFunction) libuser_admin_group_setpass, METH_VARARGS,
	 "set the group's password"},
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
	 METH_VARARGS, "search for a user with the given name"},
	{"lookupUserById", (PyCFunction)libuser_admin_lookup_user_id,
	 METH_VARARGS, "search for a user with the given uid"},
	{"lookupGroupByName", (PyCFunction)libuser_admin_lookup_group_name,
	 METH_VARARGS, "search for a group with the given name"},
	{"lookupGroupById", (PyCFunction)libuser_admin_lookup_group_id,
	 METH_VARARGS, "search for a group with the given gid"},
	{"initUser", (PyCFunction)libuser_admin_init_user, METH_VARARGS,
	 "create an object with defaults set for creating a new user"},
	{"initGroup", (PyCFunction)libuser_admin_init_group, METH_VARARGS,
	 "create an object with defaults set for creating a new group"},
	{"addUser", (PyCFunction)libuser_admin_add_user, METH_VARARGS,
	 "add the user object to the system user database"},
	{"addGroup", (PyCFunction)libuser_admin_add_group, METH_VARARGS,
	 "add the group object to the system group database"},
	{"modifyUser", (PyCFunction)libuser_admin_modify_user, METH_VARARGS,
	 "modify an entry in the system user database to match the object"},
	{"modifyGroup", (PyCFunction)libuser_admin_modify_group, METH_VARARGS,
	 "modify an entry in the system group database to match the object"},
	{"deleteUser", (PyCFunction)libuser_admin_delete_user, METH_VARARGS,
	 "remove the entry from the system user database which matches the "
	 "object"},
	{"deleteGroup", (PyCFunction)libuser_admin_delete_group, METH_VARARGS,
	 "remove the entry from the system group database which matches the "
	 "object"},
	{"lockUser", (PyCFunction)libuser_admin_lock_user, METH_VARARGS,
	 "lock the user account associated with the object"},
	{"lockGroup", (PyCFunction)libuser_admin_lock_group, METH_VARARGS,
	 "lock the group account associated with the object"},
	{"unlockUser", (PyCFunction)libuser_admin_unlock_user, METH_VARARGS,
	 "unlock the user account associated with the object"},
	{"unlockGroup", (PyCFunction)libuser_admin_unlock_group, METH_VARARGS,
	 "unlock the group account associated with the object"},
	{"setpassUser", (PyCFunction)libuser_admin_setpass_user, METH_VARARGS,
	 "set the password for the user account associated with the object"},
	{"setpassGroup", (PyCFunction)libuser_admin_setpass_group, METH_VARARGS,
	 "set the password for the group account associated with the object"},
	{"enumerateUsers", (PyCFunction)libuser_admin_enumerate_users,
	 METH_VARARGS,
	 "get a list of users matching a pattern, in listed databases"},
	{"enumerateGroups", (PyCFunction)libuser_admin_enumerate_groups,
	 METH_VARARGS,
	 "get a list of groups matching a pattern, in listed databases"},
	{"promptConsole", (PyCFunction)libuser_admin_prompt_console,
	 METH_VARARGS},
	{"promptConsoleQuiet", (PyCFunction)libuser_admin_prompt_console_quiet,
	 METH_VARARGS},
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
	(setattrfunc) libuser_admin_setattr,
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
	char *name = getlogin(), *info = NULL, *auth = NULL;
	char *keywords[] = {"name", "type", "info", "auth", NULL};
	int type = lu_user;
	lu_context_t *context;
	struct lu_error *error = NULL;
	struct libuser_admin *ret;

	DEBUG_ENTRY;

	ret = PyObject_NEW(struct libuser_admin, &AdminType);
	if(ret == NULL) {
		return NULL;
	}
	self = (PyObject*) ret;

	ret->prompter = Py_FindMethod(libuser_admin_methods, self,
				      "promptConsole");

	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "|siss", keywords,
					&name, &type, &info, &auth)) {
		Py_DECREF(ret->prompter);
		Py_DECREF(self);
		return NULL;
	}

	if((type != lu_user) && (type != lu_group)) {
		PyErr_SetString(PyExc_ValueError, "invalid type");
		Py_DECREF(ret->prompter);
		Py_DECREF(self);
		return NULL;
	}

#ifdef DEBUG_BINDING
	fprintf(stderr, "%sprompter at <%p>, self = <%p>, "
		"info = <%p>, auth = <%p>\n",
		getindent(), ret->prompter, self, info, auth);
#endif
	context = lu_start(name, type, info, auth,
			   libuser_admin_python_prompter, ret->prompter,
			   &error);

	if(context == NULL) {
		PyErr_SetString(PyExc_SystemError, error->string);
		lu_error_free(&error);
		Py_DECREF(ret->prompter);
		Py_DECREF(self);
		return NULL;
	}

	ret->ctx = context;
	ret->user = PyObject_NEW(struct libuser_admin_domain, &AdminUserType);
	ret->user->main = ret;
	ret->group = PyObject_NEW(struct libuser_admin_domain, &AdminGroupType);
	ret->group->main = ret;

	DEBUG_EXIT;
	return self;
}

/**
 * Methods for the PromptType
 */
static void
libuser_prompt_destroy(struct libuser_prompt *self)
{
	DEBUG_ENTRY;
	if(self->prompt.value && self->prompt.free_value)
		self->prompt.free_value(self->prompt.value);
	if(self->prompt.prompt)
		g_free((char*)self->prompt.prompt);
	if(self->prompt.default_value)
		g_free((char*)self->prompt.default_value);
	memset(&self->prompt, 0, sizeof(self->prompt));
	PyMem_DEL(self);
	DEBUG_EXIT;
}

static PyObject *
libuser_prompt_getattr(struct libuser_prompt *self, char *attr)
{
	DEBUG_ENTRY;
	if(strcmp(attr, "prompt") == 0) {
		DEBUG_EXIT;
		return PyString_FromString(self->prompt.prompt);
	}
	if(strcmp(attr, "visible") == 0) {
		DEBUG_EXIT;
		return PyInt_FromLong(self->prompt.visible);
	}
	if((strcmp(attr, "default_value") == 0) ||
	   (strcmp(attr, "defaultValue") == 0)) {
		DEBUG_EXIT;
		return self->prompt.default_value ?
		       Py_BuildValue("") :
		       PyString_FromString(self->prompt.default_value);
	}
	if(strcmp(attr, "value") == 0) {
		DEBUG_EXIT;
		return self->prompt.value ?
		       PyString_FromString(self->prompt.value) :
		       Py_BuildValue("");
	}
	DEBUG_EXIT;
	return Py_FindMethod(NULL, (PyObject*) self, attr);
}

static int
libuser_prompt_setattr(struct libuser_prompt *self, const char *attr,
		       PyObject *args)
{
	DEBUG_ENTRY;
	if(strcmp(attr, "prompt") == 0) {
		if(!PyString_Check(args)) {
			PyErr_SetString(PyExc_TypeError,
					"prompt must be a string");
			DEBUG_EXIT;
			return -1;
		}
		if(self->prompt.prompt)
			g_free((char*)self->prompt.prompt);
		self->prompt.prompt = g_strdup(PyString_AsString(args));
		DEBUG_EXIT;
		return 0;
	}
	if(strcmp(attr, "visible") == 0) {
		self->prompt.visible = PyObject_IsTrue(args);
		DEBUG_EXIT;
		return 0;
	}
	if((strcmp(attr, "default_value") == 0) ||
	   (strcmp(attr, "defaultValue") == 0)) {
		if(!PyString_Check(args)) {
			PyErr_SetString(PyExc_TypeError,
					"default value must be a string");
			DEBUG_EXIT;
			return -1;
		}
		if(self->prompt.default_value)
			g_free((char*)self->prompt.default_value);
		self->prompt.default_value = (args == Py_None) ?
					     NULL :
					     g_strdup(PyString_AsString(args));
		DEBUG_EXIT;
		return 0;
	}
	if(strcmp(attr, "value") == 0) {
		if(!PyString_Check(args)) {
			PyErr_SetString(PyExc_TypeError,
					"value must be a string");
			DEBUG_EXIT;
			return -1;
		}
		if(self->prompt.value && self->prompt.free_value)
			self->prompt.free_value(self->prompt.value);
		self->prompt.value = g_strdup(PyString_AsString(args));
		self->prompt.free_value = (typeof(self->prompt.free_value))g_free;
		DEBUG_EXIT;
		return 0;
	}
	DEBUG_EXIT;
	PyErr_SetString(PyExc_AttributeError, "invalid attribute");
	return -1;
}

static int
libuser_prompt_print(struct libuser_prompt *self, FILE *fp, int flags)
{
	fprintf(fp,
		"{prompt = \"%s\", visible = %s, default_value = \"%s\", "
		"value = \"%s\"}",
		self->prompt.prompt ?: "",
		self->prompt.visible ? "true" : "false",
		self->prompt.default_value ?: "",
		self->prompt.value ?: "");
	return 0;
}

static struct libuser_prompt *
libuser_prompt_new(void)
{
	struct libuser_prompt *ret = NULL;
	DEBUG_ENTRY;
	ret = PyObject_NEW(struct libuser_prompt, &PromptType);
	if(ret != NULL) {
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

	(PyNumberMethods*) NULL,
	(PySequenceMethods*) NULL,
	(PyMappingMethods*) NULL,
	(hashfunc) NULL,
	(ternaryfunc) NULL,
	(reprfunc) NULL,
};

static PyObject*
libuser_get_user_shells(PyObject *self, PyObject *args)
{
	GList *results = NULL;
	PyObject *ret = NULL;
	const char *shell;

	DEBUG_ENTRY;

	setusershell();
	while((shell = getusershell()) != NULL) {
		results = g_list_append(results, g_strdup(shell));
	}
	endusershell();

	ret = convert_glist_pystringlist(results);
	g_list_foreach(results, (GFunc)g_free, NULL);
	g_list_free(results);

	DEBUG_EXIT;
	return ret;
}

static PyMethodDef
libuser_methods[] = {
	{"admin", (PyCFunction)libuser_admin_new, METH_VARARGS | METH_KEYWORDS,
	 "create and return a new administration context"},
	{"prompt", (PyCFunction)libuser_prompt_new, 0,
	 "create and return a new prompt record"},
	{"getUserShells", (PyCFunction)libuser_get_user_shells, 0,
	 "return a list of valid shells"},
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
}
