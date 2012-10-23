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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <Python.h>
#include <config.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>
#include <utmp.h>
#include <glib.h>
#include "../lib/user.h"
#include "../lib/user_private.h"
#include "common.h"

#include "admin.c"
#include "ent.c"
#include "misc.c"

/* Return a list of the valid shells in the system, picked up from
 * getusershells(). */
static PyObject *
libuser_get_user_shells(PyObject *self, PyObject *ignored)
{
	PyObject *ret;
	const char *shell;

	(void)self;
	(void)ignored;
	DEBUG_ENTRY;

	ret = PyList_New(0);
	setusershell();
	while ((shell = getusershell()) != NULL) {
		PyObject *str;

		str = PyString_FromString(shell);
		PyList_Append(ret, str);
		Py_DECREF(str);
	}
	endusershell();

	DEBUG_EXIT;
	return ret;
}

static PyObject *
libuser_validate_id_value(PyObject *self, PyObject *value)
{
	PY_LONG_LONG ll;

	DEBUG_ENTRY;
	ll = PyLong_AsLongLong(value);
	if (PyErr_Occurred())
		goto error;

	if ((id_t)ll != ll) {
		PyErr_SetString(PyExc_OverflowError, _("Value out of range"));
		goto error;
	}
	if (ll < 0) {
		PyErr_SetString(PyExc_ValueError, _("ID must not be negative"));
		goto error;
	}
	if (ll == LU_VALUE_INVALID_ID) {
		PyErr_SetString(PyExc_ValueError, _("Invalid ID value"));
		goto error;
	}
	DEBUG_EXIT;
	Py_RETURN_NONE;

error:
	DEBUG_EXIT;
	return NULL;
}

static PyMethodDef libuser_methods[] = {
	{"admin", (PyCFunction) libuser_admin_new, METH_VARARGS | METH_KEYWORDS,
	 "create a new administration context"},
	{"prompt", libuser_prompt_new, METH_NOARGS,
	 "create and return a new prompt record"},
	{"get_user_shells", libuser_get_user_shells, METH_NOARGS,
	 "return a list of valid shells"},
	{"ADMIN", (PyCFunction) libuser_admin_new, METH_VARARGS | METH_KEYWORDS,
	 "create a new administration context"},
	{"PROMPT", libuser_prompt_new, METH_NOARGS,
	 "create and return a new prompt record"},
	{"getUserShells", libuser_get_user_shells, METH_NOARGS,
	 "return a list of valid shells"},
	{"validateIdValue", libuser_validate_id_value, METH_O,
	 "validate an id_t value"},
	{NULL, NULL, 0, NULL},
};

/* Add KEY=VALUE to DICT, stealing the refrence to VALUE. */
static void
dict_add_stolen_object(PyObject *dict, const char *key, PyObject *value)
{
	PyDict_SetItemString(dict, key, value);
	Py_DECREF(value);
}

/* Add KEY=VALUE to DICT */
static void
dict_add_string(PyObject *dict, const char *key, const char *value)
{
	dict_add_stolen_object(dict, key, PyString_FromString(value));
}

void
initlibuser(void)
{
	PyObject *module, *dict;
	DEBUG_ENTRY;
	module = Py_InitModule("libuser", libuser_methods);
	dict = PyModule_GetDict(module);
	dict_add_stolen_object(dict, "USER", PyInt_FromLong(lu_user));
	dict_add_stolen_object(dict, "GROUP", PyInt_FromLong(lu_group));

	/* User attributes. */
	dict_add_string(dict, "USERNAME", LU_USERNAME);
	dict_add_string(dict, "USERPASSWORD", LU_USERPASSWORD);
	dict_add_string(dict, "UIDNUMBER", LU_UIDNUMBER);
	dict_add_string(dict, "GIDNUMBER", LU_GIDNUMBER);
	dict_add_string(dict, "GECOS", LU_GECOS);
	dict_add_string(dict, "HOMEDIRECTORY", LU_HOMEDIRECTORY);
	dict_add_string(dict, "LOGINSHELL", LU_LOGINSHELL);

	/* Group attributes. */
	dict_add_string(dict, "GROUPNAME", LU_GROUPNAME);
	dict_add_string(dict, "GROUPPASSWORD", LU_GROUPPASSWORD);
	dict_add_string(dict, "ADMINISTRATORNAME", LU_ADMINISTRATORNAME);
	dict_add_string(dict, "MEMBERNAME", LU_MEMBERNAME);

	/* Shadow attributes. */
	dict_add_string(dict, "SHADOWNAME", LU_SHADOWNAME);
	dict_add_string(dict, "SHADOWPASSWORD", LU_SHADOWPASSWORD);
	dict_add_string(dict, "SHADOWLASTCHANGE", LU_SHADOWLASTCHANGE);
	dict_add_string(dict, "SHADOWMIN", LU_SHADOWMIN);
	dict_add_string(dict, "SHADOWMAX", LU_SHADOWMAX);
	dict_add_string(dict, "SHADOWWARNING", LU_SHADOWWARNING);
	dict_add_string(dict, "SHADOWINACTIVE", LU_SHADOWINACTIVE);
	dict_add_string(dict, "SHADOWEXPIRE", LU_SHADOWEXPIRE);
	dict_add_string(dict, "SHADOWFLAG", LU_SHADOWFLAG);

	/* Additional fields. */
	dict_add_string(dict, "COMMONNAME", LU_COMMONNAME);
	dict_add_string(dict, "GIVENNAME", LU_GIVENNAME);
	dict_add_string(dict, "SN", LU_SN);
	dict_add_string(dict, "ROOMNUMBER", LU_ROOMNUMBER);
	dict_add_string(dict, "TELEPHONENUMBER", LU_TELEPHONENUMBER);
	dict_add_string(dict, "HOMEPHONE", LU_HOMEPHONE);
	dict_add_string(dict, "EMAIL", LU_EMAIL);

	/* Miscellaneous. */
	dict_add_stolen_object(dict, "UT_NAMESIZE",
			       PyInt_FromLong(UT_NAMESIZE));
	dict_add_stolen_object(dict, "VALUE_INVALID_ID",
			       PyLong_FromLongLong(LU_VALUE_INVALID_ID));

	DEBUG_EXIT;
}
