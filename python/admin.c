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
#include <Python.h>
#include "common.h"

static PyMethodDef libuser_admin_user_methods[];
static PyMethodDef libuser_admin_group_methods[];
static PyMethodDef libuser_admin_methods[];
static PyTypeObject AdminType;
#define Admin_Check(__x) ((__x)->ob_type == &AdminType)

static struct libuser_admin *libuser_admin_new(PyObject *self, PyObject *args, PyObject *kwargs);

static void
libuser_admin_destroy(struct libuser_admin *self)
{
	DEBUG_ENTRY;
	Py_DECREF((PyObject*)self->ctx->prompter_data);
	lu_end(self->ctx);
	PyMem_DEL(self);
	DEBUG_EXIT;
}

static PyObject *
libuser_admin_getattr(struct libuser_admin *self, char *name)
{
	DEBUG_ENTRY;
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
	lu_user_default(self->ctx, arg, is_system, ent);
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
	lu_group_default(self->ctx, arg, is_system, ent);
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
libuser_admin_wrap(struct libuser_admin *self, PyObject *args,
		   gboolean (*fn)(struct lu_context *, struct lu_ent *,
			          struct lu_error **error))
{
	struct libuser_entity *ent;
	struct lu_error *error = NULL;
	DEBUG_ENTRY;
	if(!PyArg_ParseTuple(args, "O!", &EntityType, &ent)) {
		DEBUG_EXIT;
	}
	if(fn(self->ctx, ent->ent, &error)) {
		DEBUG_EXIT;
		return Py_BuildValue("%d", 1);
	} else {
		DEBUG_EXIT;
		return Py_BuildValue("%d", 0);
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
libuser_admin_user_islocked(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, lu_user_islocked);
}

static PyObject *
libuser_admin_group_islocked(struct libuser_admin *self, PyObject *args)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, lu_group_islocked);
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
	{"userIsLocked", (PyCFunction)libuser_admin_user_islocked, METH_VARARGS,
	 "check if the user account associated with the object is locked"},
	{"groupIsLocked", (PyCFunction)libuser_admin_group_islocked, METH_VARARGS,
	 "check if the group account associated with the object is locked"},

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

	{"getUserShells", (PyCFunction)libuser_get_user_shells, 0,
	 "return a list of valid shells"},
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

static struct libuser_admin *
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

	DEBUG_EXIT;
	return ret;
}
