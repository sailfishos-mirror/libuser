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
#include <Python.h>
#include "common.h"
#include "../include/libuser/user.h"
#include "../include/libuser/user_private.h"
#include "../apps/apputil.h"

static PyMethodDef libuser_admin_user_methods[];
static PyMethodDef libuser_admin_group_methods[];
static PyMethodDef libuser_admin_methods[];
static PyTypeObject AdminType;
#define Admin_Check(__x) ((__x)->ob_type == &AdminType)

static struct libuser_admin *libuser_admin_new(PyObject *self, PyObject *args, PyObject *kwargs);

static void
libuser_admin_destroy(PyObject *self)
{
	struct libuser_admin *me = (struct libuser_admin *)self;
	int i;
	DEBUG_ENTRY;
	if(me->ctx != NULL) {
		lu_end(me->ctx);
	}
	for(i = 0; i < sizeof(me->prompt_data) / sizeof(me->prompt_data[0]); i++) {
		if(me->prompt_data[i]) {
			Py_DECREF(me->prompt_data[i]);
		}
		me->prompt_data[i] = NULL;
	}
	PyMem_DEL(self);
	DEBUG_EXIT;
}

static PyObject *
libuser_admin_getattr(PyObject *self, char *name)
{
	struct libuser_admin *me = (struct libuser_admin *)self;
	DEBUG_ENTRY;
	if(strcmp(name, "prompt") == 0) {
		Py_INCREF(me->prompt_data[0]);
		DEBUG_EXIT;
		return me->prompt_data[0];
	}
	if(strcmp(name, "prompt_args") == 0) {
		Py_INCREF(me->prompt_data[1]);
		DEBUG_EXIT;
		return me->prompt_data[1];
	}
#ifdef DEBUG_BINDING
	fprintf(stderr, "Searching for attribute `%s'\n", name);
#endif
	DEBUG_EXIT;
	return Py_FindMethod(libuser_admin_methods, (PyObject*)self, name);
}

static int
libuser_admin_setattr(PyObject *self, const char *attr, PyObject *args)
{
	struct libuser_admin *me = (struct libuser_admin *)self;

	DEBUG_ENTRY;
#ifdef DEBUG_BINDING
	fprintf(stderr, "%sSetting attribute `%s'\n", getindent(), attr);
#endif
	if(strcmp(attr, "prompt") == 0) {
		if(PyCFunction_Check(args)) {
			Py_DECREF(me->prompt_data[0]);
			Py_DECREF(me->prompt_data[1]);
			me->prompt_data[0] = args;
			me->prompt_data[1] = Py_BuildValue("");
		}
		if(PyTuple_Check(args)) {
			Py_DECREF(me->prompt_data[0]);
			Py_DECREF(me->prompt_data[1]);

			me->prompt_data[0] = PyTuple_GetItem(args, 0);
			Py_INCREF(me->prompt_data[0]);

			me->prompt_data[1] = PyTuple_GetSlice(args, 1, PyTuple_Size(args));
			Py_INCREF(me->prompt_data[1]);
		}
		DEBUG_EXIT;
		return 0;
	}
	if(strcmp(attr, "prompt_args") == 0) {
			Py_DECREF(me->prompt_data[1]);
			me->prompt_data[1] = args;
			Py_INCREF(me->prompt_data[1]);
	}
	PyErr_SetString(PyExc_AttributeError, "no such writable attribute");
	DEBUG_EXIT;
	return -1;
}

static PyObject *
libuser_admin_lookup_user_name(PyObject *self, PyObject *args, PyObject *kwargs)
{
	char *arg;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	char *keywords[] = {"name", NULL};
	struct libuser_admin *me = (struct libuser_admin *)self;

	DEBUG_ENTRY;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "s", keywords, &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(lu_user_lookup_name(me->ctx, arg, ent, &error)) {
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		lu_ent_free(ent);
		DEBUG_EXIT;
		return Py_BuildValue("");
	}
}

static PyObject *
libuser_admin_lookup_user_id(PyObject *self, PyObject *args, PyObject *kwargs)
{
	int arg;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	char *keywords[] = {"id", NULL};
	struct libuser_admin *me = (struct libuser_admin *)self;
	
	DEBUG_ENTRY;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "i", keywords, &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(lu_user_lookup_id(me->ctx, arg, ent, &error)) {
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		lu_ent_free(ent);
		DEBUG_EXIT;
		return Py_BuildValue("");
	}
}

static PyObject *
libuser_admin_lookup_group_name(PyObject *self, PyObject *args, PyObject *kwargs)
{
	char *arg;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	char *keywords[] = {"name", NULL};
	struct libuser_admin *me = (struct libuser_admin *)self;
	
	DEBUG_ENTRY;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "s", keywords, &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(lu_group_lookup_name(me->ctx, arg, ent, &error)) {
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		lu_ent_free(ent);
		DEBUG_EXIT;
		return Py_BuildValue("");
	}
}

static PyObject *
libuser_admin_lookup_group_id(PyObject *self, PyObject *args, PyObject *kwargs)
{
	int arg;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	char *keywords[] = {"id", NULL};
	struct libuser_admin *me = (struct libuser_admin *)self;
	
	DEBUG_ENTRY;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "i", keywords, &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(lu_group_lookup_id(me->ctx, arg, ent, &error)) {
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		lu_ent_free(ent);
		DEBUG_EXIT;
		return Py_BuildValue("");
	}
}

static PyObject *
libuser_admin_init_user(PyObject *self, PyObject *args, PyObject *kwargs)
{
	char *arg;
	int is_system = 0;
	struct lu_ent *ent;
	char *keywords[] = {"name", "id", NULL};
	struct libuser_admin *me = (struct libuser_admin *)self;
	
	DEBUG_ENTRY;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "s|i", keywords, &arg, &is_system)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(ent == NULL) {
		PyErr_SetString(PyExc_SystemError, PACKAGE " error");
		DEBUG_EXIT;
		return NULL;
	}
	lu_user_default(me->ctx, arg, is_system, ent);
	DEBUG_EXIT;
	return libuser_wrap_ent(ent);
}

static PyObject *
libuser_admin_init_group(PyObject *self, PyObject *args, PyObject *kwargs)
{
	char *arg;
	int is_system = 0;
	struct lu_ent *ent;
	char *keywords[] = {"name", "id", NULL};
	struct libuser_admin *me = (struct libuser_admin *)self;
	
	DEBUG_ENTRY;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "s|i", keywords, &arg, &is_system)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if(ent == NULL) {
		PyErr_SetString(PyExc_SystemError, PACKAGE " error");
		DEBUG_EXIT;
		return NULL;
	}
	lu_group_default(me->ctx, arg, is_system, ent);
	DEBUG_EXIT;
	return libuser_wrap_ent(ent);
}

static PyObject *
libuser_admin_generic(PyObject *self, PyObject *args, PyObject *kwargs,
		      gboolean (*fn)(struct lu_context *, struct lu_ent *,
			             struct lu_error **error))
{
	struct libuser_entity *ent;
	struct lu_error *error = NULL;
	char *keywords[] = {"entity", NULL};
	struct libuser_admin *me = (struct libuser_admin *)self;
	PyObject *garbage = NULL;
	
	DEBUG_ENTRY;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|O", keywords, &EntityType, &ent, &garbage)) {
		DEBUG_EXIT;
		return NULL;
	}
	if(fn(me->ctx, ent->ent, &error)) {
		DEBUG_EXIT;
		return Py_BuildValue("");
	} else {
		PyErr_SetString(PyExc_RuntimeError, error ? error->string : _("unknown error"));
		if(error) {
			lu_error_free(&error);
		}
		DEBUG_EXIT;
		return NULL;
	}
}

static PyObject *
libuser_admin_wrap(PyObject *self, PyObject *args, PyObject *kwargs,
		   gboolean (*fn)(struct lu_context *, struct lu_ent *, struct lu_error **error))
{
	struct libuser_entity *ent;
	struct lu_error *error = NULL;
	char *keywords[] = {"entity", NULL};
	struct libuser_admin *me = (struct libuser_admin *)self;
	
	DEBUG_ENTRY;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", keywords, &EntityType, &ent)) {
		DEBUG_EXIT;
	}
	if(fn(me->ctx, ent->ent, &error)) {
		DEBUG_EXIT;
		return Py_BuildValue("%d", 1);
	} else {
		DEBUG_EXIT;
		return Py_BuildValue("%d", 0);
	}
}

static PyObject *
libuser_admin_setpass(PyObject *self, PyObject *args, PyObject *kwargs,
		      gboolean (*fn)(struct lu_context *, struct lu_ent *, const char *, struct lu_error **))
{
	struct libuser_entity *ent;
	struct lu_error *error = NULL;
	const char *password;
	char *keywords[] = {"entity", "password", NULL};
	struct libuser_admin *me = (struct libuser_admin *)self;
	
	DEBUG_ENTRY;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O!z", keywords, &EntityType, &ent, &password)) {
		DEBUG_EXIT;
		return NULL;
	}
	if(fn(me->ctx, ent->ent, password, &error)) {
		DEBUG_EXIT;
		return Py_BuildValue("");
	} else {
		PyErr_SetString(PyExc_SystemError, error ? error->string : _("unknown error"));
		if(error) {
			lu_error_free(&error);
		}
		DEBUG_EXIT;
		return NULL;
	}
}

static PyObject *
libuser_admin_create_home(PyObject *self, PyObject *args, PyObject *kwargs)
{
	struct libuser_entity *ent = NULL;
	char *dir = "/var/tmp/libuser-newhome", *skeleton = "/etc/skel";
	GList *values;
	char *keywords[] = {"home", "skeleton", NULL};
	long uidNumber = 0, gidNumber = 0;
	struct lu_error *error = NULL;

	DEBUG_ENTRY;

	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|s", keywords, &EntityType, &ent, &skeleton)) {
		DEBUG_EXIT;
		return NULL;
	}

	values = lu_ent_get(ent->ent, LU_HOMEDIRECTORY);
	if((values == NULL) || (values->data == NULL)) {
		PyErr_SetString(PyExc_KeyError, "user does not have a `" LU_HOMEDIRECTORY "' attribute");
		return NULL;
	}
	dir = (char*) values->data;

	values = lu_ent_get(ent->ent, LU_UIDNUMBER);
	if((values == NULL) || (values->data == NULL)) {
		PyErr_SetString(PyExc_KeyError, "user does not have a `" LU_UIDNUMBER "' attribute");
		return NULL;
	}
	uidNumber = atol((char*)values->data);

	values = lu_ent_get(ent->ent, LU_GIDNUMBER);
	if((values == NULL) || (values->data == NULL)) {
		PyErr_SetString(PyExc_KeyError, "user does not have a `" LU_GIDNUMBER "' attribute");
		return NULL;
	}
	gidNumber = atol((char*)values->data);

	if(lu_homedir_populate(skeleton, dir, uidNumber, gidNumber, 0700, &error)) {
		DEBUG_EXIT;
		return Py_BuildValue("");
	} else {
		PyErr_SetString(PyExc_RuntimeError, error ? error->string : _("error creating home directory for user"));
		if(error) {
			lu_error_free(&error);
		}
		DEBUG_EXIT;
		return NULL;
	}
}

static PyObject *
libuser_admin_remove_home(PyObject *self, PyObject *args, PyObject *kwargs)
{
	struct libuser_entity *ent = NULL;
	char *dir = "/var/tmp/libuser-oldhome";
	GList *values;
	char *keywords[] = {"home", NULL};
	struct lu_error *error = NULL;

	DEBUG_ENTRY;

	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", keywords, &EntityType, &ent)) {
		DEBUG_EXIT;
		return NULL;
	}

	values = lu_ent_get(ent->ent, LU_HOMEDIRECTORY);
	if((values == NULL) || (values->data == NULL)) {
		PyErr_SetString(PyExc_KeyError, "user does not have a `" LU_HOMEDIRECTORY "' attribute");
		return NULL;
	}

	dir = (char*) values->data;

	if(lu_homedir_remove(dir, &error)) {
		DEBUG_EXIT;
		return Py_BuildValue("");
	} else {
		PyErr_SetString(PyExc_RuntimeError, error ? error->string : _("error removing home directory for user"));
		if(error) {
			lu_error_free(&error);
		}
		DEBUG_EXIT;
		return NULL;
	}
}

static PyObject *
libuser_admin_move_home(PyObject *self, PyObject *args, PyObject *kwargs)
{
	struct libuser_entity *ent = NULL;
	char *olddir = NULL, *newdir = NULL;
	GList *values;
	char *keywords[] = {"entity", "newhome", NULL};
	struct lu_error *error = NULL;

	DEBUG_ENTRY;

	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O|s", keywords, &EntityType, &ent, &newdir)) {
		DEBUG_EXIT;
		return NULL;
	}

	if(newdir != NULL) {
		values = lu_ent_get(ent->ent, LU_HOMEDIRECTORY);
		if((values == NULL) || (values->data == NULL)) {
			PyErr_SetString(PyExc_KeyError, "user does not have a current `" LU_HOMEDIRECTORY "' attribute");
			return NULL;
		}
		olddir = (char*) values->data;
	} else {
		values = lu_ent_get_original(ent->ent, LU_HOMEDIRECTORY);
		if((values == NULL) || (values->data == NULL)) {
			PyErr_SetString(PyExc_KeyError, "user does not have an original `" LU_HOMEDIRECTORY "' attribute");
			return NULL;
		}
		olddir = (char*) values->data;

		values = lu_ent_get(ent->ent, LU_HOMEDIRECTORY);
		if((values == NULL) || (values->data == NULL)) {
			PyErr_SetString(PyExc_KeyError, "user does not have a `" LU_HOMEDIRECTORY "' attribute");
			return NULL;
		}
		newdir = (char*) values->data;
	}

	if(lu_homedir_move(olddir, newdir, &error)) {
		DEBUG_EXIT;
		return Py_BuildValue("");
	} else {
		PyErr_SetString(PyExc_RuntimeError, error ? error->string : _("error moving home directory for user"));
		if(error) {
			lu_error_free(&error);
		}
		DEBUG_EXIT;
		return NULL;
	}
}

static PyObject *
libuser_admin_add_user(PyObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *ent = NULL;
	PyObject *ret = NULL;
	PyObject *mkhomedir = self;
	PyObject *subargs, *subkwargs;
	char *keywords[] = {"entity", "mkhomedir", NULL};

	DEBUG_ENTRY;

	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O|O", keywords, &ent, &mkhomedir)) {
		return NULL;
	}

	ret = libuser_admin_generic(self, args, kwargs, lu_user_add);
	if(ret != NULL) {
		if((mkhomedir != NULL) && (PyObject_IsTrue(mkhomedir))) {
			Py_DECREF(ret);
			subargs = PyTuple_New(1);
			PyTuple_SetItem(subargs, 0, ent);
			subkwargs = PyDict_New();
			ret = libuser_admin_create_home(self, subargs, subkwargs);
		}
	}

	DEBUG_EXIT;

	return ret;
}

static PyObject *
libuser_admin_add_group(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, kwargs, lu_group_add);
}

static PyObject *
libuser_admin_modify_user(PyObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *ent = NULL;
	PyObject *ret = NULL;
	PyObject *mvhomedir = NULL;
	PyObject *subargs, *subkwargs;
	char *keywords[] = {"entity", "mvhomedir", NULL};

	DEBUG_ENTRY;

	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O|O", keywords, &ent, &mvhomedir)) {
		return NULL;
	}

	ret = libuser_admin_generic(self, args, kwargs, lu_user_modify);
	if(ret != NULL) {
		if((mvhomedir != NULL) && (PyObject_IsTrue(mvhomedir))) {
			Py_DECREF(ret);
			subargs = PyTuple_New(1);
			PyTuple_SetItem(subargs, 0, ent);
			subkwargs = PyDict_New();
			ret = libuser_admin_move_home(self, subargs, subkwargs);
		}
	}

	DEBUG_EXIT;

	return ret;
}

static PyObject *
libuser_admin_modify_group(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, kwargs, lu_group_modify);
}

static PyObject *
libuser_admin_delete_user(PyObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *ent = NULL;
	PyObject *ret = NULL;
	PyObject *rmhomedir = NULL;
	PyObject *subargs, *subkwargs;
	char *keywords[] = {"entity", "rmhomedir", NULL};

	DEBUG_ENTRY;

	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O|O", keywords, &ent, &rmhomedir)) {
		return NULL;
	}

	ret = libuser_admin_generic(self, args, kwargs, lu_user_delete);
	if(ret != NULL) {
		if((rmhomedir != NULL) && (PyObject_IsTrue(rmhomedir))) {
			Py_DECREF(ret);
			subargs = PyTuple_New(1);
			PyTuple_SetItem(subargs, 0, ent);
			subkwargs = PyDict_New();
			ret = libuser_admin_remove_home(self, subargs, subkwargs);
		}
	}

	DEBUG_EXIT;

	return ret;
}

static PyObject *
libuser_admin_delete_group(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, kwargs, lu_group_delete);
}

static PyObject *
libuser_admin_lock_user(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, kwargs, lu_user_lock);
}

static PyObject *
libuser_admin_lock_group(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, kwargs, lu_group_lock);
}

static PyObject *
libuser_admin_unlock_user(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, kwargs, lu_user_unlock);
}

static PyObject *
libuser_admin_unlock_group(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_generic(self, args, kwargs, lu_group_unlock);
}

static PyObject *
libuser_admin_user_islocked(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_user_islocked);
}

static PyObject *
libuser_admin_group_islocked(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_group_islocked);
}

static PyObject *
libuser_admin_setpass_user(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_setpass(self, args, kwargs, lu_user_setpass);
}

static PyObject *
libuser_admin_setpass_group(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_setpass(self, args, kwargs, lu_group_setpass);
}

static PyObject *
libuser_admin_enumerate_users(PyObject *self, PyObject *args, PyObject *kwargs)
{
	GList *results;
	char *module = NULL, *pattern = NULL;
	PyObject *ret = NULL;
	struct lu_error *error = NULL;
	char *keywords[] = {"pattern", "module", NULL};
	struct libuser_admin *me = (struct libuser_admin *)self;

	DEBUG_ENTRY;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "|ss", keywords, &pattern, &module)) {
		DEBUG_EXIT;
		return NULL;
	}
	results = lu_users_enumerate(me->ctx, pattern, module, &error);
	ret = convert_glist_pystringlist(results);
	g_list_free(results);
	DEBUG_EXIT;
	return ret;
}

static PyObject *
libuser_admin_enumerate_groups(PyObject *self, PyObject *args, PyObject *kwargs)
{
	GList *results;
	char *module = NULL, *pattern = NULL;
	PyObject *ret = NULL;
	struct lu_error *error = NULL;
	char *keywords[] = {"pattern", "module", NULL};
	struct libuser_admin *me = (struct libuser_admin *)self;

	DEBUG_ENTRY;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "|ss", keywords, &pattern, &module)) {
		DEBUG_EXIT;
		return NULL;
	}
	results = lu_groups_enumerate(me->ctx, pattern, module, &error);
	ret = convert_glist_pystringlist(results);
	g_list_free(results);
	DEBUG_EXIT;
	return ret;
}

static PyObject *
libuser_admin_enumerate_users_by_group(PyObject *self, PyObject *args, PyObject *kwargs)
{
	GList *results;
	char *module = NULL, *group = NULL;
	PyObject *ret = NULL;
	struct lu_error *error = NULL;
	char *keywords[] = {"group", "module", NULL};
	struct libuser_admin *me = (struct libuser_admin *)self;

	DEBUG_ENTRY;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "s|s", keywords, &group, &module)) {
		DEBUG_EXIT;
		return NULL;
	}
	results = lu_users_enumerate_by_group(me->ctx, group, module, &error);
	ret = convert_glist_pystringlist(results);
	g_list_free(results);
	DEBUG_EXIT;
	return ret;
}

static PyObject *
libuser_admin_enumerate_groups_by_user(PyObject *self, PyObject *args, PyObject *kwargs)
{
	GList *results;
	char *module = NULL, *user = NULL;
	PyObject *ret = NULL;
	struct lu_error *error = NULL;
	char *keywords[] = {"user", "module", NULL};
	struct libuser_admin *me = (struct libuser_admin *)self;

	DEBUG_ENTRY;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "s|s", keywords, &user, &module)) {
		DEBUG_EXIT;
		return NULL;
	}
	results = lu_groups_enumerate_by_user(me->ctx, user, module, &error);
	ret = convert_glist_pystringlist(results);
	g_list_free(results);
	DEBUG_EXIT;
	return ret;
}

static struct PyMethodDef libuser_admin_methods[] = {
	{"lookupUserByName", (PyCFunction)libuser_admin_lookup_user_name, METH_VARARGS | METH_KEYWORDS,
	 "search for a user with the given name"},
	{"lookupUserById", (PyCFunction)libuser_admin_lookup_user_id, METH_VARARGS | METH_KEYWORDS,
	 "search for a user with the given uid"},
	{"lookupGroupByName", (PyCFunction)libuser_admin_lookup_group_name, METH_VARARGS | METH_KEYWORDS,
	 "search for a group with the given name"},
	{"lookupGroupById", (PyCFunction)libuser_admin_lookup_group_id, METH_VARARGS | METH_KEYWORDS,
	 "search for a group with the given gid"},

	{"initUser", (PyCFunction)libuser_admin_init_user, METH_VARARGS | METH_KEYWORDS,
	 "create an object with defaults set for creating a new user"},
	{"initGroup", (PyCFunction)libuser_admin_init_group, METH_VARARGS | METH_KEYWORDS,
	 "create an object with defaults set for creating a new group"},

	{"addUser", (PyCFunction)libuser_admin_add_user, METH_VARARGS | METH_KEYWORDS,
	 "add the user object to the system user database"},
	{"addGroup", (PyCFunction)libuser_admin_add_group, METH_VARARGS | METH_KEYWORDS,
	 "add the group object to the system group database"},

	{"modifyUser", (PyCFunction)libuser_admin_modify_user, METH_VARARGS | METH_KEYWORDS,
	 "modify an entry in the system user database to match the object"},
	{"modifyGroup", (PyCFunction)libuser_admin_modify_group, METH_VARARGS | METH_KEYWORDS,
	 "modify an entry in the system group database to match the object"},

	{"deleteUser", (PyCFunction)libuser_admin_delete_user, METH_VARARGS | METH_KEYWORDS,
	 "remove the entry from the system user database which matches the object"},
	{"deleteGroup", (PyCFunction)libuser_admin_delete_group, METH_VARARGS | METH_KEYWORDS,
	 "remove the entry from the system group database which matches the object"},

	{"lockUser", (PyCFunction)libuser_admin_lock_user, METH_VARARGS | METH_KEYWORDS,
	 "lock the user account associated with the object"},
	{"lockGroup", (PyCFunction)libuser_admin_lock_group, METH_VARARGS | METH_KEYWORDS,
	 "lock the group account associated with the object"},
	{"unlockUser", (PyCFunction)libuser_admin_unlock_user, METH_VARARGS | METH_KEYWORDS,
	 "unlock the user account associated with the object"},
	{"unlockGroup", (PyCFunction)libuser_admin_unlock_group, METH_VARARGS | METH_KEYWORDS,
	 "unlock the group account associated with the object"},
	{"userIsLocked", (PyCFunction)libuser_admin_user_islocked, METH_VARARGS | METH_KEYWORDS,
	 "check if the user account associated with the object is locked"},
	{"groupIsLocked", (PyCFunction)libuser_admin_group_islocked, METH_VARARGS | METH_KEYWORDS,
	 "check if the group account associated with the object is locked"},

	{"setpassUser", (PyCFunction)libuser_admin_setpass_user, METH_VARARGS | METH_KEYWORDS,
	 "set the password for the user account associated with the object"},
	{"setpassGroup", (PyCFunction)libuser_admin_setpass_group, METH_VARARGS | METH_KEYWORDS,
	 "set the password for the group account associated with the object"},

	{"enumerateUsers", (PyCFunction)libuser_admin_enumerate_users, METH_VARARGS | METH_KEYWORDS,
	 "get a list of users matching a pattern, in listed databases"},
	{"enumerateGroups", (PyCFunction)libuser_admin_enumerate_groups, METH_VARARGS | METH_KEYWORDS,
	 "get a list of groups matching a pattern, in listed databases"},
	{"enumerateUsersByGroup", (PyCFunction)libuser_admin_enumerate_users_by_group, METH_VARARGS | METH_KEYWORDS,
	 "get a list of users in a group"},
	{"enumerateGroupsByUser", (PyCFunction)libuser_admin_enumerate_groups_by_user, METH_VARARGS | METH_KEYWORDS,
	 "get a list of groups to which a user belongs"},

	{"promptConsole", (PyCFunction)libuser_admin_prompt_console, METH_VARARGS | METH_KEYWORDS,
	 "prompt the user for information using the console, and confirming defaults"},
	{"promptConsoleQuiet", (PyCFunction)libuser_admin_prompt_console_quiet, METH_VARARGS | METH_KEYWORDS,
	 "prompt the user for information using the console, silently accepting defaults"},

	{"createHome", (PyCFunction)libuser_admin_create_home, METH_VARARGS | METH_KEYWORDS,
	 "create a home directory for a user"},
	{"moveHome", (PyCFunction)libuser_admin_move_home, METH_VARARGS | METH_KEYWORDS,
	 "move a user's home directory"},
	{"removeHome", (PyCFunction)libuser_admin_remove_home, METH_VARARGS | METH_KEYWORDS,
	 "remove a user's home directory"},

	{"getUserShells", (PyCFunction)libuser_get_user_shells, 0, "return a list of valid shells"},

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
	char *name = getlogin(), *info = NULL, *auth = NULL, *p, *q;
	PyObject *prompt = NULL, *prompt_data = NULL;
	char *keywords[] = {"name", "type", "info", "auth", "prompt", "prompt_data", NULL};
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
	p = ((char*)ret) + sizeof(PyObject);
	q = ((char*)ret) + sizeof(struct libuser_admin);
	memset(p, '\0', q - p);

	ret->ctx = NULL;

	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "|sissOO", keywords, &name, &type, &info, &auth, &prompt, &prompt_data)) {
		Py_DECREF(ret);
		return NULL;
	}

	if((type != lu_user) && (type != lu_group)) {
		PyErr_SetString(PyExc_ValueError, "invalid type");
		Py_DECREF(ret);
		return NULL;
	}

	if(PyCallable_Check(prompt)) {
		ret->prompt_data[0] = prompt;
		Py_INCREF(ret->prompt_data[0]);
	} else {
		ret->prompt_data[0] = Py_FindMethod(libuser_admin_methods, self, "promptConsole");
	}

	if(prompt_data != NULL) {
		ret->prompt_data[1] = prompt_data;
		Py_INCREF(ret->prompt_data[1]);
	} else {
		ret->prompt_data[1] = Py_BuildValue("");
	}

#ifdef DEBUG_BINDING
	fprintf(stderr, "%sprompt at <%p>, self = <%p>, info = <%p>, auth = <%p>\n",
		getindent(), prompt, ret, info, auth);
#endif
	context = lu_start(name, type, info, auth, libuser_admin_python_prompter, ret->prompt_data, &error);

	if(context == NULL) {
		PyErr_SetString(PyExc_SystemError, error ? error->string : "error initializing " PACKAGE);
		if(error) {
			lu_error_free(&error);
		}
		Py_DECREF(ret);
		return NULL;
	}

	ret->ctx = context;

	DEBUG_EXIT;
	return ret;
}
