/* Copyright (C) 2001, 2002, 2004 Red Hat, Inc.
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

#include <Python.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
#include "common.h"
#include "../lib/user.h"
#include "../lib/user_private.h"
#include "../apps/apputil.h"

/* Boilerplate for the admin object, which wraps a libuser context. */
static PyMethodDef libuser_admin_user_methods[];
static PyMethodDef libuser_admin_group_methods[];
static PyMethodDef libuser_admin_methods[];
static PyTypeObject AdminType;
#define Admin_Check(__x) ((__x)->ob_type == &AdminType)

static struct libuser_admin *libuser_admin_new(PyObject *self,
					       PyObject *args,
					       PyObject *kwargs);

/* Destroy the object. */
static void
libuser_admin_destroy(PyObject *self)
{
	struct libuser_admin *me = (struct libuser_admin *) self;
	size_t i;
	DEBUG_ENTRY;
	/* Free the context. */
	if (me->ctx != NULL) {
		lu_end(me->ctx);
		me->ctx = NULL;
	}
	/* Free the prompt data. */
	for (i = 0;
	     i < sizeof(me->prompt_data) / sizeof(me->prompt_data[0]);
	     i++) {
		if (me->prompt_data[i]) {
			Py_DECREF(me->prompt_data[i]);
		}
		me->prompt_data[i] = NULL;
	}
	/* Delete the python object. */
	PyMem_DEL(self);
	DEBUG_EXIT;
}

/* Get an attribute of the admin object. */
static PyObject *
libuser_admin_getattr(PyObject *self, char *name)
{
	struct libuser_admin *me = (struct libuser_admin *) self;
	DEBUG_ENTRY;
	/* The prompting function. */
	if (strcmp(name, "prompt") == 0) {
		Py_INCREF(me->prompt_data[0]);
		DEBUG_EXIT;
		return me->prompt_data[0];
	}
	/* The prompting function's arguments. */
	if (strcmp(name, "prompt_args") == 0) {
		Py_INCREF(me->prompt_data[1]);
		DEBUG_EXIT;
		return me->prompt_data[1];
	}
	/* Random other methods or members. */
#ifdef DEBUG_BINDING
	fprintf(stderr, "Searching for attribute `%s'\n", name);
#endif
	DEBUG_EXIT;
	return Py_FindMethod(libuser_admin_methods, (PyObject *) self, name);
}

/* Set an attribute in the admin object. */
static int
libuser_admin_setattr(PyObject *self, const char *attr, PyObject *args)
{
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
#ifdef DEBUG_BINDING
	fprintf(stderr, "%sSetting attribute `%s'\n", getindent(), attr);
#endif
	/* The prompting function. */
	if (strcmp(attr, "prompt") == 0) {
		/* If it's a wrapped up function, set the first prompt data
		 * to the function, and the second to an empty tuple. */
		if (PyCFunction_Check(args)) {
			Py_DECREF(me->prompt_data[0]);
			Py_DECREF(me->prompt_data[1]);
			me->prompt_data[0] = args;
			Py_INCREF(me->prompt_data[0]);
			me->prompt_data[1] = Py_BuildValue("");
		}
		/* If it's a tuple, the first item is the function, and the
		 * rest are arguments to pass to it. */
		if (PyTuple_Check(args)) {
			Py_DECREF(me->prompt_data[0]);
			Py_DECREF(me->prompt_data[1]);

			me->prompt_data[0] = PyTuple_GetItem(args, 0);
			Py_INCREF(me->prompt_data[0]);

			me->prompt_data[1] = PyTuple_GetSlice(args, 1,
							      PyTuple_Size(args));
		}
		DEBUG_EXIT;
		return 0;
	}
	/* If it's just prompting arguments, save them as the second chunk of
	 * prompting data. */
	if (strcmp(attr, "prompt_args") == 0) {
		Py_DECREF(me->prompt_data[1]);
		me->prompt_data[1] = args;
		Py_INCREF(me->prompt_data[1]);
		DEBUG_EXIT;
		return 0;
	}
	PyErr_SetString(PyExc_AttributeError,
			"no such writable attribute");
	DEBUG_EXIT;
	return -1;
}

/* Look up a user by name. */
static PyObject *
libuser_admin_lookup_user_name(PyObject *self, PyObject *args,
			       PyObject *kwargs)
{
	char *arg;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	char *keywords[] = { "name", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* We expect a single string (no mapping shenanigans here). */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", keywords, &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Create the entity to return, and look it up. */
	ent = lu_ent_new();
	if (lu_user_lookup_name(me->ctx, arg, ent, &error)) {
		/* Wrap it up, and return it. */
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		/* No such user.  Clean up and bug out. */
		lu_ent_free(ent);
		DEBUG_EXIT;
		return Py_BuildValue("");
	}
}

/* Look up a user give the UID. */
static PyObject *
libuser_admin_lookup_user_id(PyObject *self, PyObject *args,
			     PyObject *kwargs)
{
	int arg;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	char *keywords[] = { "id", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* We expect a single string (no mapping shenanigans here). */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "i", keywords, &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	ent = lu_ent_new();
	if (lu_user_lookup_id(me->ctx, arg, ent, &error)) {
		/* Wrap it up, and return it. */
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		/* No such user.  Clean up and bug out. */
		lu_ent_free(ent);
		DEBUG_EXIT;
		return Py_BuildValue("");
	}
}

/* Look up a group by name. */
static PyObject *
libuser_admin_lookup_group_name(PyObject *self, PyObject *args,
				PyObject *kwargs)
{
	char *arg;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	char *keywords[] = { "name", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect a string. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", keywords, &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Try to look up this user. */
	ent = lu_ent_new();
	if (lu_group_lookup_name(me->ctx, arg, ent, &error)) {
		/* Got you!  Wrap and return. */
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		/* We've got nothing.  Return nothing. */
		lu_ent_free(ent);
		DEBUG_EXIT;
		return Py_BuildValue("");
	}
}

/* Look up a group by ID. */
static PyObject *
libuser_admin_lookup_group_id(PyObject *self, PyObject *args,
			      PyObject *kwargs)
{
	int arg;
	struct lu_ent *ent;
	struct lu_error *error = NULL;
	char *keywords[] = { "id", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect a number. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "i", keywords, &arg)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Try to look up the group. */
	ent = lu_ent_new();
	if (lu_group_lookup_id(me->ctx, arg, ent, &error)) {
		/* Wrap the answer up. */
		DEBUG_EXIT;
		return libuser_wrap_ent(ent);
	} else {
		/* Clean up and exit, we have nothing to return. */
		lu_ent_free(ent);
		DEBUG_EXIT;
		return Py_BuildValue("");
	}
}

/* Create a template user object. */
static PyObject *
libuser_admin_init_user(PyObject *self, PyObject *args,
			PyObject *kwargs)
{
	char *arg;
	int is_system = 0;
	struct lu_ent *ent;
	char *keywords[] = { "name", "is_system", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* We expect a string and an optional flag indicating that the
	 * user will be a system user. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|i", keywords,
					 &arg, &is_system)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Create a new user object for the user name, and return it. */
	ent = lu_ent_new();
	lu_user_default(me->ctx, arg, is_system, ent);
	DEBUG_EXIT;
	return libuser_wrap_ent(ent);
}

/* Create a group object. */
static PyObject *
libuser_admin_init_group(PyObject *self, PyObject *args,
			 PyObject *kwargs)
{
	char *arg;
	int is_system = 0;
	struct lu_ent *ent;
	char *keywords[] = { "name", "is_system", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect a string and a flag indicating that the group is to be a
	 * system group. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|i", keywords,
					 &arg, &is_system)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Create a defaulted group by this name, and wrap it up. */
	ent = lu_ent_new();
	lu_group_default(me->ctx, arg, is_system, ent);
	DEBUG_EXIT;
	return libuser_wrap_ent(ent);
}

/* Run the given function. If the function fails, raise an error. */
static PyObject *
libuser_admin_do_wrap(PyObject *self, struct libuser_entity *ent,
		      gboolean (*fn) (struct lu_context *, struct lu_ent *,
				      struct lu_error ** error))
{
	struct lu_error *error = NULL;
	struct libuser_admin *me = (struct libuser_admin *)self;

	DEBUG_ENTRY;
	/* Try running the function. */
	if (fn(me->ctx, ent->ent, &error)) {
		/* It succeeded!  Return truth. */
		DEBUG_EXIT;
		return Py_BuildValue("i", 1);
	} else {
		/* It failed.  Build an exception and return an error. */
		PyErr_SetString(PyExc_RuntimeError, lu_strerror(error));
		if (error)
			lu_error_free(&error);
		DEBUG_EXIT;
		return NULL;
	}
}

/* Run the given function, using a Python entity passed in as the first
 * argument to the function.  If the function fails, raise an error. */
static PyObject *
libuser_admin_wrap(PyObject *self, PyObject *args, PyObject *kwargs,
		   gboolean(*fn) (struct lu_context *, struct lu_ent *,
				  struct lu_error ** error))
{
	PyObject *ent;
	char *keywords[] = { "entity", NULL };
	PyObject *ret;

	DEBUG_ENTRY;
	/* Expect a Python Entity object and maybe some other stuff we
	 * don't really care about. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", keywords,
					 &EntityType, &ent)) {
		DEBUG_EXIT;
		return NULL;
	}
	ret = libuser_admin_do_wrap(self, (struct libuser_entity *)ent, fn);
	DEBUG_EXIT;
	return ret;
}

/* Run the given function, using a Python entity passed in as the first
 * argument to the function.  Return a 1 or 0 depending on the boolean
 * returned by the function. */
static PyObject *
libuser_admin_wrap_boolean(PyObject *self, PyObject *args, PyObject *kwargs,
			   gboolean(*fn) (struct lu_context *, struct lu_ent *,
				  	  struct lu_error ** error))
{
	struct libuser_entity *ent;
	struct lu_error *error = NULL;
	char *keywords[] = { "entity", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect a Python Entity object and maybe some other stuff we
	 * don't really care about. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", keywords,
					 &EntityType, &ent)) {
		DEBUG_EXIT;
	}
	/* Run the function. */
	DEBUG_EXIT;
	return Py_BuildValue("i", (fn(me->ctx, ent->ent, &error)) ? 1 : 0);
}

/* Wrap the setpass function for either type of entity. */
static PyObject *
libuser_admin_setpass(PyObject *self, PyObject *args, PyObject *kwargs,
		      gboolean(*fn) (struct lu_context *, struct lu_ent *,
				     const char *, gboolean,
				     struct lu_error **))
{
	struct libuser_entity *ent;
	struct lu_error *error = NULL;
	PyObject *is_crypted = NULL;
	const char *password = NULL;
	char *keywords[] = { "entity", "password", "is_crypted", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* We expect an entity object and a string. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!sO", keywords,
					 &EntityType, &ent, &password,
					 &is_crypted)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Call the appropriate setpass function for this entity. */
	if (fn(me->ctx, ent->ent, password,
	       ((is_crypted != NULL) && (PyObject_IsTrue(is_crypted))),
	       &error)) {
		/* The change succeeded.  Return a truth. */
		DEBUG_EXIT;
		return Py_BuildValue("i", 1);
	} else {
		/* The change failed.  Return an error. */
		PyErr_SetString(PyExc_SystemError, lu_strerror(error));
		if (error) {
			lu_error_free(&error);
		}
		DEBUG_EXIT;
		return NULL;
	}
}

/* Create a home directory for a user. */
static PyObject *
libuser_admin_create_home(PyObject *self, PyObject *args,
			  PyObject *kwargs)
{
	struct libuser_entity *ent = NULL;
	const char *dir = NULL, *skeleton = "/etc/skel";
	GValueArray *values;
	GValue *value;
	char *keywords[] = { "home", "skeleton", NULL };
	long uidNumber = 0, gidNumber = 0;
	struct lu_error *error = NULL;

	(void)self;
	DEBUG_ENTRY;

	/* Expect an object and a string. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|s", keywords,
					 &EntityType, &ent, &skeleton)) {
		DEBUG_EXIT;
		return NULL;
	}

	/* Get the user's home directory value. */
	values = lu_ent_get(ent->ent, LU_HOMEDIRECTORY);
	if (values == NULL) {
		PyErr_SetString(PyExc_KeyError,
				"user does not have a `" LU_HOMEDIRECTORY
				"' attribute");
		return NULL;
	}
	value = g_value_array_get_nth(values, 0);
	dir = g_value_get_string(value);

	/* Get the user's UID. */
	values = lu_ent_get(ent->ent, LU_UIDNUMBER);
	if (values == NULL) {
		PyErr_SetString(PyExc_KeyError,
				"user does not have a `" LU_UIDNUMBER
				"' attribute");
		return NULL;
	}
	value = g_value_array_get_nth(values, 0);
	uidNumber = g_value_get_long(value);

	/* Get the user's GID. */
	values = lu_ent_get(ent->ent, LU_GIDNUMBER);
	if (values == NULL) {
		PyErr_SetString(PyExc_KeyError,
				"user does not have a `" LU_GIDNUMBER
				"' attribute");
		return NULL;
	}
	value = g_value_array_get_nth(values, 0);
	gidNumber = g_value_get_long(value);

	/* Attempt to populate the directory. */
	if (lu_homedir_populate(skeleton, dir, uidNumber, gidNumber,
				0700, &error)) {
		/* Success -- return an empty tuple. */
		DEBUG_EXIT;
		return Py_BuildValue("i", 1);
	} else {
		/* Failure.  Mark the error. */
		PyErr_SetString(PyExc_RuntimeError,
				error ?
				error->string :
				_("error creating home directory for user"));
		if (error) {
			lu_error_free(&error);
		}
		DEBUG_EXIT;
		return NULL;
	}
}

/* Remove a user's home directory. */
static PyObject *
libuser_admin_remove_home(PyObject *self, PyObject *args,
			  PyObject *kwargs)
{
	struct libuser_entity *ent = NULL;
	const char *dir = NULL;
	GValueArray *values;
	GValue *value;
	char *keywords[] = { "home", NULL };
	struct lu_error *error = NULL;

	(void)self;
	DEBUG_ENTRY;

	/* We expect an object. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", keywords,
					 &EntityType, &ent)) {
		DEBUG_EXIT;
		return NULL;
	}

	/* Get the user's home directory. */
	values = lu_ent_get(ent->ent, LU_HOMEDIRECTORY);
	if (values == NULL) {
		PyErr_SetString(PyExc_KeyError,
				"user does not have a `" LU_HOMEDIRECTORY
				"' attribute");
		return NULL;
	}
	value = g_value_array_get_nth(values, 0);
	dir = g_value_get_string(value);

	/* Remove the directory. */
	if (lu_homedir_remove(dir, &error)) {
		/* Successfully removed. */
		DEBUG_EXIT;
		return Py_BuildValue("i", 1);
	} else {
		/* Removal failed.  You'll have to come back for repeated
		 * treatments. */
		PyErr_SetString(PyExc_RuntimeError,
				error ?
				error->string :
				_("error removing home directory for user"));
		if (error) {
			lu_error_free(&error);
		}
		DEBUG_EXIT;
		return NULL;
	}
}

/* Move a user's home directory somewhere else. */
static PyObject *
libuser_admin_move_home(PyObject *self, PyObject *args,
			PyObject *kwargs)
{
	struct libuser_entity *ent = NULL;
	const char *olddir = NULL, *newdir = NULL;
	GValueArray *values;
	GValue *value;
	char *keywords[] = { "entity", "newhome", NULL };
	struct lu_error *error = NULL;

	(void)self;
	DEBUG_ENTRY;

	/* We expect an object and an optional string. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|s", keywords,
					 &EntityType, &ent, &newdir)) {
		DEBUG_EXIT;
		return NULL;
	}

	if (newdir != NULL) {
		/* We were given a string, so move the user's home directory
		 * to the new location. */
		values = lu_ent_get(ent->ent, LU_HOMEDIRECTORY);
		if (values == NULL) {
			PyErr_SetString(PyExc_KeyError,
					"user does not have a current `"
					LU_HOMEDIRECTORY "' attribute");
			return NULL;
		}
		value = g_value_array_get_nth(values, 0);
		olddir = g_value_get_string(value);
	} else {
		/* We weren't given a string, so use the current and pending
		 * values, and move from one to the other. */
		values = lu_ent_get_current(ent->ent, LU_HOMEDIRECTORY);
		if (values == NULL) {
			PyErr_SetString(PyExc_KeyError,
					"user does not have a current `"
					LU_HOMEDIRECTORY "' attribute");
			return NULL;
		}
		value = g_value_array_get_nth(values, 0);
		olddir = g_value_get_string(value);

		/* Now read the pending directory. */
		values = lu_ent_get(ent->ent, LU_HOMEDIRECTORY);
		if (values == NULL) {
			PyErr_SetString(PyExc_KeyError,
					"user does not have a pending `"
					LU_HOMEDIRECTORY "' attribute");
			return NULL;
		}
		value = g_value_array_get_nth(values, 0);
		newdir = g_value_get_string(value);
	}

	/* Attempt the move. */
	if (lu_homedir_move(olddir, newdir, &error)) {
		/* Success! */
		DEBUG_EXIT;
		return Py_BuildValue("i", 1);
	} else {
		/* Failure.  Set an error. */
		PyErr_SetString(PyExc_RuntimeError,
				error ?
				error->string :
				_("error moving home directory for user"));
		if (error) {
			lu_error_free(&error);
		}
		DEBUG_EXIT;
		return NULL;
	}
}

/* Create a user's mail spool. */
static PyObject *
libuser_admin_create_remove_mail(PyObject *self, PyObject *args,
				 PyObject *kwargs, gboolean action)
{
	struct libuser_entity *ent = NULL;

	char *keywords[] = { "entity", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;

	/* We expect an Entity object. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", keywords,
					 &EntityType, &ent)) {
		DEBUG_EXIT;
		return NULL;
	}

	/* Now just pass it to the internal function. */
	if (lu_mailspool_create_remove(me->ctx, ent->ent, action)) {
		return Py_BuildValue("i", 1);
	} else {
		PyErr_SetString(PyExc_RuntimeError,
				_("error creating mail spool for user"));
		return NULL;
	}
}

/* Create a user's mail spool. */
static PyObject *
libuser_admin_create_mail(PyObject *self, PyObject *args, PyObject *kwargs)
{
	return libuser_admin_create_remove_mail(self, args, kwargs, TRUE);
}

/* Destroy a user's mail spool. */
static PyObject *
libuser_admin_remove_mail(PyObject *self, PyObject *args, PyObject *kwargs)
{
	return libuser_admin_create_remove_mail(self, args, kwargs, FALSE);
}

/* Add a user. */
static PyObject *
libuser_admin_add_user(PyObject *self, PyObject *args, PyObject *kwargs)
{
	PyObject *ret = NULL;
	PyObject *mkhomedir = self;
	PyObject *mkmailspool = self;
	struct libuser_entity *ent = NULL;
	struct lu_context *context = NULL;
	char *keywords[] = { "entity", "mkhomedir", "mkmailspool", NULL };

	DEBUG_ENTRY;

	context = ((struct libuser_admin *)self)->ctx;

	/* Expect an entity and a flag to tell us if we need to create the
	 * user's home directory. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|OO", keywords,
					 &EntityType, &ent,
					 &mkhomedir, &mkmailspool)) {
		DEBUG_EXIT;
		return NULL;
	}

	/* Pass the entity object to lu_user_add(). */
	ret = libuser_admin_do_wrap(self, ent, lu_user_add);
	if (ret != NULL) {
		/* If we got a non-NULL response, then it was okay. */
		if ((mkhomedir != NULL) && (PyObject_IsTrue(mkhomedir))) {
			PyObject *subargs, *subkwargs;

			/* Free the result we got. */
			if (ret != NULL) {
				Py_DECREF(ret);
			}
			/* Create the user's home directory we need to pass
			 * the entity structure in a tuple, so create a tuple
			 * and add just that object to it. */
			subargs = PyTuple_New(1);
			Py_INCREF(ent);
			PyTuple_SetItem(subargs, 0, (PyObject*) ent);
			/* Create an empty dictionary for keyword args. */
			subkwargs = PyDict_New();
			/* We'll return the result of the creation call. */
			ret = libuser_admin_create_home(self, subargs,
							subkwargs);
			Py_DECREF(subargs);
			Py_DECREF(subkwargs);
		}
		/* If we got a non-NULL response, then it was okay. */
		if ((mkmailspool != NULL) && (PyObject_IsTrue(mkmailspool))) {
			if (ret != NULL) {
				Py_DECREF(ret);
			}
			if (lu_mailspool_create_remove(context, ent->ent, TRUE) ) {
				ret = Py_BuildValue("i", 1);
			} else {
				/* An exception has been thrown. */
				ret = NULL;
			}
		}
	}

	DEBUG_EXIT;

	return ret;
}

/* Add a group.  Simple wrapper. */
static PyObject *
libuser_admin_add_group(PyObject *self, PyObject *args,
			PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_group_add);
}

static PyObject *
libuser_admin_modify_user(PyObject *self, PyObject *args,
			  PyObject *kwargs)
{
	PyObject *ent = NULL;
	PyObject *ret = NULL;
	PyObject *mvhomedir = NULL;
	struct lu_ent *copy = NULL;
	char *keywords[] = { "entity", "mvhomedir", NULL };

	DEBUG_ENTRY;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|O", keywords,
					 &EntityType, &ent, &mvhomedir))
		return NULL;

	if (mvhomedir != NULL) {
		if (!PyObject_IsTrue(mvhomedir))
			/* Cache the PyObject_IsTrue() result */
			mvhomedir = NULL;
		else {
			copy = lu_ent_new();
			lu_ent_copy(((struct libuser_entity *)ent)->ent, copy);
		}
	}
	ret = libuser_admin_do_wrap(self, (struct libuser_entity *)ent,
				    lu_user_modify);
	if (ret != NULL && mvhomedir != NULL) {
		PyObject *subargs, *subkwargs, *wrapped;

		Py_DECREF(ret);
		subargs = PyTuple_New(1);
		wrapped = libuser_wrap_ent(copy);
		copy = NULL; /* Will be freed along with `wrapped' */
		PyTuple_SetItem(subargs, 0, wrapped);
		subkwargs = PyDict_New();
		ret = libuser_admin_move_home(self, subargs, subkwargs);
		Py_DECREF(subargs);
		Py_DECREF(subkwargs);
	}
	if (copy != NULL)
		lu_ent_free(copy);

	DEBUG_EXIT;

	return ret;
}

/* Modify a group.  Trivial wrapper. */
static PyObject *
libuser_admin_modify_group(PyObject *self, PyObject *args,
			   PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_group_modify);
}

static PyObject *
libuser_admin_delete_user(PyObject *self, PyObject *args,
			  PyObject *kwargs)
{
	PyObject *ent = NULL;
	PyObject *ret = NULL;
	PyObject *rmhomedir = NULL, *rmmailspool = NULL;
	struct lu_context *context;
	char *keywords[] = { "entity", "rmhomedir", "rmmailspool", NULL };

	DEBUG_ENTRY;

	context = ((struct libuser_admin *)self)->ctx;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!|OO", keywords,
					 &EntityType, &ent,
					 &rmhomedir, &rmmailspool)) {
		return NULL;
	}

	ret = libuser_admin_do_wrap(self, (struct libuser_entity *)ent,
				    lu_user_delete);
	if (ret != NULL) {
		if ((rmhomedir != NULL) && (PyObject_IsTrue(rmhomedir))) {
			PyObject *subargs, *subkwargs;

			Py_DECREF(ret);
			subargs = PyTuple_New(1);
			Py_INCREF(ent);
			PyTuple_SetItem(subargs, 0, ent);
			subkwargs = PyDict_New();
			ret = libuser_admin_remove_home(self, subargs,
						        subkwargs);
			Py_DECREF(subargs);
			Py_DECREF(subkwargs);
		}
	}
	if (ret != NULL) {
		if ((rmmailspool!= NULL) && (PyObject_IsTrue(rmmailspool))) {
			struct libuser_entity *entity;
			Py_DECREF(ret);
			entity = (struct libuser_entity *)ent;
			ret = lu_mailspool_create_remove(context, entity->ent, TRUE) ?
			      Py_BuildValue("i", 1) :
			      NULL;
		}
	}

	DEBUG_EXIT;

	return ret;
}

/* Delete a group.  Trivial wrapper. */
static PyObject *
libuser_admin_delete_group(PyObject *self, PyObject *args,
			   PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_group_delete);
}

/* Lock a user account.  Trivial wrapper. */
static PyObject *
libuser_admin_lock_user(PyObject *self, PyObject *args,
			PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_user_lock);
}

/* Lock a group account.  Trivial wrapper. */
static PyObject *
libuser_admin_lock_group(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_group_lock);
}

/* Unlock a user account.  Trivial wrapper. */
static PyObject *
libuser_admin_unlock_user(PyObject *self, PyObject *args,
			  PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_user_unlock);
}

/* Unlock a group account.  Trivial wrapper. */
static PyObject *
libuser_admin_unlock_group(PyObject *self, PyObject *args,
			   PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_group_unlock);
}

/* Check if a user account is locked.  Trivial wrapper. */
static PyObject *
libuser_admin_user_islocked(PyObject *self, PyObject *args,
			    PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap_boolean(self, args, kwargs, lu_user_islocked);
}

/* Check if a group account is locked.  Trivial wrapper. */
static PyObject *
libuser_admin_group_islocked(PyObject *self, PyObject *args,
			     PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap_boolean(self, args, kwargs,
					  lu_group_islocked);
}

/* Remove a user's password.  Trivial wrapper to make sure the right function
 * gets called. */
static PyObject *
libuser_admin_removepass_user(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_user_removepass);
}

/* Remove a group's password.  Trivial wrapper to make sure the right function
 * gets called. */
static PyObject *
libuser_admin_removepass_group(PyObject *self, PyObject *args, PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_wrap(self, args, kwargs, lu_group_removepass);
}

/* Set a user's password.  Trivial wrapper to make sure the right setpass
 * function gets called. */
static PyObject *
libuser_admin_setpass_user(PyObject *self, PyObject *args,
			   PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_setpass(self, args, kwargs, lu_user_setpass);
}

/* Set a group's password.  Trivial wrapper to make sure the right setpass
 * function gets called. */
static PyObject *
libuser_admin_setpass_group(PyObject *self, PyObject *args,
			    PyObject *kwargs)
{
	DEBUG_CALL;
	return libuser_admin_setpass(self, args, kwargs, lu_group_setpass);
}

/* Get a list of all users who match a particular pattern. */
static PyObject *
libuser_admin_enumerate_users(PyObject *self, PyObject *args,
			      PyObject *kwargs)
{
	GValueArray *results;
	const char *pattern = NULL;
	PyObject *ret = NULL;
	struct lu_error *error = NULL;
	char *keywords[] = { "pattern", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect a possible pattern. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", keywords,
					 &pattern)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Read the list of all users. */
	results = lu_users_enumerate(me->ctx, pattern, &error);
	/* Convert the list to a PyList. */
	ret = convert_value_array_pylist(results);
	g_value_array_free(results);
	DEBUG_EXIT;
	return ret;
}

/* Get a list of all groups. */
static PyObject *
libuser_admin_enumerate_groups(PyObject *self, PyObject *args,
			       PyObject *kwargs)
{
	GValueArray *results;
	const char *pattern = NULL;
	PyObject *ret = NULL;
	struct lu_error *error = NULL;
	char *keywords[] = { "pattern", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Possibly expect a pattern. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", keywords,
					 &pattern)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Get the list of groups. */
	results = lu_groups_enumerate(me->ctx, pattern, &error);
	/* Convert the list to a PyList. */
	ret = convert_value_array_pylist(results);
	g_value_array_free(results);
	DEBUG_EXIT;
	return ret;
}

/* Get the list of users who belong to a group. */
static PyObject *
libuser_admin_enumerate_users_by_group(PyObject *self, PyObject *args,
				       PyObject *kwargs)
{
	GValueArray *results;
	char *group = NULL;
	PyObject *ret = NULL;
	struct lu_error *error = NULL;
	char *keywords[] = { "group", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect the group's name. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", keywords, &group)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Get a list of the users in this group. */
	results = lu_users_enumerate_by_group(me->ctx, group, &error);
	ret = convert_value_array_pylist(results);
	g_value_array_free(results);
	DEBUG_EXIT;
	return ret;
}

/* Get a list of groups a user belongs to. */
static PyObject *
libuser_admin_enumerate_groups_by_user(PyObject *self, PyObject *args,
				       PyObject *kwargs)
{
	GValueArray *results;
	char *user = NULL;
	PyObject *ret = NULL;
	struct lu_error *error = NULL;
	char *keywords[] = { "user", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	DEBUG_ENTRY;
	/* Expect the user's name. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", keywords, &user)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Get the list. */
	results = lu_groups_enumerate_by_user(me->ctx, user, &error);
	ret = convert_value_array_pylist(results);
	g_value_array_free(results);
	DEBUG_EXIT;
	return ret;
}

/* Get a list of all users who match a particular pattern. */
static PyObject *
libuser_admin_enumerate_users_full(PyObject *self, PyObject *args,
				   PyObject *kwargs)
{
	GPtrArray *results;
	const char *pattern = NULL;
	PyObject *ret = NULL;
	struct lu_error *error = NULL;
	char *keywords[] = { "pattern", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;
	size_t i;

	DEBUG_ENTRY;
	/* Expect a possible pattern. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", keywords,
					 &pattern)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Read the list of all users. */
	results = lu_users_enumerate_full(me->ctx, pattern, &error);
	/* Convert the list to a PyList. */
	ret = PyList_New(0);
	for (i = 0; i < results->len; i++) {
		PyObject *ent;

		ent = libuser_wrap_ent(g_ptr_array_index(results, i));
		PyList_Append(ret, ent);
		Py_DECREF(ent);
	}
	g_ptr_array_free(results, TRUE);
	DEBUG_EXIT;
	return ret;
}

/* Get a list of all groups. */
static PyObject *
libuser_admin_enumerate_groups_full(PyObject *self, PyObject *args,
				    PyObject *kwargs)
{
	GPtrArray *results;
	const char *pattern = NULL;
	PyObject *ret = NULL;
	struct lu_error *error = NULL;
	char *keywords[] = { "pattern", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;
	size_t i;

	DEBUG_ENTRY;
	/* Possibly expect a pattern. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", keywords,
					 &pattern)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Get the list of groups. */
	results = lu_groups_enumerate_full(me->ctx, pattern, &error);
	/* Convert the list to a PyList. */
	ret = PyList_New(0);
	for (i = 0; i < results->len; i++) {
		PyObject *ent;

		ent = libuser_wrap_ent(g_ptr_array_index(results, i));
		PyList_Append(ret, ent);
		Py_DECREF(ent);
	}
	g_ptr_array_free(results, TRUE);
	DEBUG_EXIT;
	return ret;
}

#ifdef PLACEHOLDERS
/* Get the list of users who belong to a group. */
static PyObject *
libuser_admin_enumerate_users_by_group_full(PyObject *self, PyObject *args,
					    PyObject *kwargs)
{
	GPtrArray *results;
	char *group = NULL;
	PyObject *ret = NULL;
	char *keywords[] = { "group", NULL };
	int i;

	DEBUG_ENTRY;
	/* Expect the group's name. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", keywords, &group)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Get a list of the users in this group. */
	ret = PyList_New(0);
	for (i = 0; i < results->len; i++) {
		PyObject *ent;

		ent = libuser_wrap_ent(g_ptr_array_index(results, i));
		PyList_Append(ret, ent);
		Py_DECREF(ent);
	}
	g_ptr_array_free(results, TRUE);
	DEBUG_EXIT;
	return ret;
}

/* Get a list of groups a user belongs to. */
static PyObject *
libuser_admin_enumerate_groups_by_user_full(PyObject *self, PyObject *args,
					    PyObject *kwargs)
{
	GPtrArray *results;
	char *user = NULL;
	PyObject *ret = NULL;
	struct lu_error *error = NULL;
	char *keywords[] = { "user", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;
	int i;

	DEBUG_ENTRY;
	/* Expect the user's name. */
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", keywords, &user)) {
		DEBUG_EXIT;
		return NULL;
	}
	/* Get the list. */
	ret = PyList_New(0);
	for (i = 0; i < results->len; i++) {
		PyObject *ent;

		ent = libuser_wrap_ent(g_ptr_array_index(results, i));
		PyList_Append(ret, ent);
		Py_DECREF(ent);
	}
	g_ptr_array_free(results, TRUE);
	results = lu_groups_enumerate_by_user_full(me->ctx, user, &error);
	DEBUG_EXIT;
	return ret;
}
#endif

static PyObject *
libuser_admin_get_first_unused_id_type(struct libuser_admin *self,
				       PyObject * args, PyObject * kwargs,
				       enum lu_entity_type enttype)
{
	char *keywords[] = { "start", NULL };
	struct libuser_admin *me = (struct libuser_admin *) self;

	glong start = 500;

	g_return_val_if_fail(self != NULL, NULL);

	DEBUG_ENTRY;
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|l", keywords,
					 &start)) {
		DEBUG_EXIT;
		return NULL;
	}

	return Py_BuildValue("l", lu_get_first_unused_id(me->ctx,
							 enttype,
							 start));
}

static PyObject *
libuser_admin_get_first_unused_uid(struct libuser_admin *self, PyObject * args,
			           PyObject * kwargs)
{
	return libuser_admin_get_first_unused_id_type(self,
						      args,
						      kwargs,
						      lu_user);
}

static PyObject *
libuser_admin_get_first_unused_gid(struct libuser_admin *self, PyObject * args,
			           PyObject * kwargs)
{
	return libuser_admin_get_first_unused_id_type(self,
						      args,
						      kwargs,
						      lu_group);
}

static struct PyMethodDef libuser_admin_methods[] = {
	{"lookupUserByName", (PyCFunction) libuser_admin_lookup_user_name,
	 METH_VARARGS | METH_KEYWORDS,
	 "search for a user with the given name"},
	{"lookupUserById", (PyCFunction) libuser_admin_lookup_user_id,
	 METH_VARARGS | METH_KEYWORDS,
	 "search for a user with the given uid"},
	{"lookupGroupByName",
	 (PyCFunction) libuser_admin_lookup_group_name,
	 METH_VARARGS | METH_KEYWORDS,
	 "search for a group with the given name"},
	{"lookupGroupById", (PyCFunction) libuser_admin_lookup_group_id,
	 METH_VARARGS | METH_KEYWORDS,
	 "search for a group with the given gid"},

	{"initUser", (PyCFunction) libuser_admin_init_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "create an object with defaults set for creating a new user"},
	{"initGroup", (PyCFunction) libuser_admin_init_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "create an object with defaults set for creating a new group"},

	{"addUser", (PyCFunction) libuser_admin_add_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "add the user object to the system user database"},
	{"addGroup", (PyCFunction) libuser_admin_add_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "add the group object to the system group database"},

	{"modifyUser", (PyCFunction) libuser_admin_modify_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "modify an entry in the system user database to match the object"},
	{"modifyGroup", (PyCFunction) libuser_admin_modify_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "modify an entry in the system group database to match the object"},

	{"deleteUser", (PyCFunction) libuser_admin_delete_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "remove the entry from the system user database which matches the object"},
	{"deleteGroup", (PyCFunction) libuser_admin_delete_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "remove the entry from the system group database which matches the object"},

	{"lockUser", (PyCFunction) libuser_admin_lock_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "lock the user account associated with the object"},
	{"lockGroup", (PyCFunction) libuser_admin_lock_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "lock the group account associated with the object"},
	{"unlockUser", (PyCFunction) libuser_admin_unlock_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "unlock the user account associated with the object"},
	{"unlockGroup", (PyCFunction) libuser_admin_unlock_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "unlock the group account associated with the object"},
	{"userIsLocked", (PyCFunction) libuser_admin_user_islocked,
	 METH_VARARGS | METH_KEYWORDS,
	 "check if the user account associated with the object is locked"},
	{"groupIsLocked", (PyCFunction) libuser_admin_group_islocked,
	 METH_VARARGS | METH_KEYWORDS,
	 "check if the group account associated with the object is locked"},

	{"setpassUser", (PyCFunction) libuser_admin_setpass_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "set the password for the user account associated with the object"},
	{"setpassGroup", (PyCFunction) libuser_admin_setpass_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "set the password for the group account associated with the object"},

	{"removepassUser", (PyCFunction) libuser_admin_removepass_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "remove the password for the user account associated with the object"},
	{"removepassGroup", (PyCFunction) libuser_admin_removepass_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "remove the password for the group account associated with the object"},

	{"enumerateUsers", (PyCFunction) libuser_admin_enumerate_users,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of users matching a pattern, in listed databases"},
	{"enumerateGroups", (PyCFunction) libuser_admin_enumerate_groups,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of groups matching a pattern, in listed databases"},
	{"enumerateUsersByGroup",
	 (PyCFunction) libuser_admin_enumerate_users_by_group,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of users in a group"},
	{"enumerateGroupsByUser",
	 (PyCFunction) libuser_admin_enumerate_groups_by_user,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of groups to which a user belongs"},

	{"enumerateUsersFull", (PyCFunction) libuser_admin_enumerate_users_full,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of users matching a pattern, in listed databases"},
	{"enumerateGroupsFull", (PyCFunction) libuser_admin_enumerate_groups_full,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of groups matching a pattern, in listed databases"},
#ifdef PLACEHOLDERS
	{"enumerateUsersByGroupFull",
	 (PyCFunction) libuser_admin_enumerate_users_by_group_full,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of users in a group"},
	{"enumerateGroupsByUserFull",
	 (PyCFunction) libuser_admin_enumerate_groups_by_user_full,
	 METH_VARARGS | METH_KEYWORDS,
	 "get a list of groups to which a user belongs"},
#endif

	{"promptConsole", (PyCFunction) libuser_admin_prompt_console,
	 METH_VARARGS | METH_KEYWORDS,
	 "prompt the user for information using the console, and confirming defaults"},
	{"promptConsoleQuiet",
	 (PyCFunction) libuser_admin_prompt_console_quiet,
	 METH_VARARGS | METH_KEYWORDS,
	 "prompt the user for information using the console, silently accepting defaults"},

	{"createHome", (PyCFunction) libuser_admin_create_home,
	 METH_VARARGS | METH_KEYWORDS,
	 "create a home directory for a user"},
	{"moveHome", (PyCFunction) libuser_admin_move_home,
	 METH_VARARGS | METH_KEYWORDS,
	 "move a user's home directory"},
	{"removeHome", (PyCFunction) libuser_admin_remove_home,
	 METH_VARARGS | METH_KEYWORDS,
	 "remove a user's home directory"},

	{"createMail", (PyCFunction) libuser_admin_create_mail,
	 METH_VARARGS | METH_KEYWORDS,
	 "create a mail spool for a user"},
	{"removeMail", (PyCFunction) libuser_admin_remove_mail,
	 METH_VARARGS | METH_KEYWORDS,
	 "remove a mail spool for a user"},

	{"getUserShells", (PyCFunction) libuser_get_user_shells, 0,
	 "return a list of valid shells"},


	{"getFirstUnusedUid",
	 (PyCFunction) libuser_admin_get_first_unused_uid,
	 METH_VARARGS | METH_KEYWORDS,
	 "return the first available uid"},

	{"getFirstUnusedGid",
	 (PyCFunction) libuser_admin_get_first_unused_gid,
	 METH_VARARGS | METH_KEYWORDS,
	 "return the first available gid"},

	{NULL, NULL, 0, NULL},
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

	(PyNumberMethods *) NULL,
	(PySequenceMethods *) NULL,
	(PyMappingMethods *) NULL,
	(hashfunc) NULL,
	(ternaryfunc) NULL,
	(reprfunc) NULL,
};

static struct libuser_admin *
libuser_admin_new(PyObject *self, PyObject *args, PyObject *kwargs)
{
	char *name = getlogin(), *modules = NULL, *create = NULL, *p, *q;
	PyObject *prompt = NULL, *prompt_data = NULL;
	char *keywords[] = {
		"name",
		"type",
		"modules",
		"create_modules",
		"prompt",
		"prompt_data",
		NULL,
	};
	int type = lu_user;
	struct lu_context *context;
	struct lu_error *error = NULL;
	struct libuser_admin *ret;

	DEBUG_ENTRY;

	ret = PyObject_NEW(struct libuser_admin, &AdminType);
	if (ret == NULL) {
		return NULL;
	}
	self = (PyObject *) ret;
	p = ((char *) ret) + sizeof(PyObject);
	q = ((char *) ret) + sizeof(struct libuser_admin);
	memset(p, '\0', q - p);

	ret->ctx = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|sissOO", keywords,
					 &name, &type, &modules, &create,
					 &prompt, &prompt_data)) {
		Py_DECREF(ret);
		return NULL;
	}

	if ((type != lu_user) && (type != lu_group)) {
		PyErr_SetString(PyExc_ValueError, "invalid type");
		Py_DECREF(ret);
		return NULL;
	}

	if (PyCallable_Check(prompt)) {
		ret->prompt_data[0] = prompt;
		Py_INCREF(ret->prompt_data[0]);
	} else {
		ret->prompt_data[0] =
		    Py_FindMethod(libuser_admin_methods, self,
				  "promptConsole");
	}

	if (prompt_data != NULL) {
		ret->prompt_data[1] = prompt_data;
		Py_INCREF(ret->prompt_data[1]);
	} else {
		ret->prompt_data[1] = Py_BuildValue("");
	}

#ifdef DEBUG_BINDING
	fprintf(stderr,
		"%sprompt at <%p>, self = <%p>, modules = <%p>, create = <%p>\n",
		getindent(), prompt, ret, modules, create);
#endif
	context =
	    lu_start(name, type, modules, create, libuser_admin_python_prompter,
		     ret->prompt_data, &error);

	if (context == NULL) {
		PyErr_SetString(PyExc_SystemError,
				error ? error->
				string : "error initializing " PACKAGE);
		if (error) {
			lu_error_free(&error);
		}
		Py_DECREF(ret);
		return NULL;
	}

	ret->ctx = context;

	DEBUG_EXIT;
	return ret;
}
