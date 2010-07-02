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
	{NULL, NULL, 0, NULL},
};

void
initlibuser(void)
{
	PyObject *module, *dict;
	DEBUG_ENTRY;
	module = Py_InitModule("libuser", libuser_methods);
	dict = PyModule_GetDict(module);
	PyDict_SetItemString(dict, "USER", PyInt_FromLong(lu_user));
	PyDict_SetItemString(dict, "GROUP", PyInt_FromLong(lu_group));

	/* User attributes. */
	PyDict_SetItemString(dict, "USERNAME",
			     PyString_FromString(LU_USERNAME));
	PyDict_SetItemString(dict, "USERPASSWORD",
			     PyString_FromString(LU_USERPASSWORD));
	PyDict_SetItemString(dict, "UIDNUMBER",
			     PyString_FromString(LU_UIDNUMBER));
	PyDict_SetItemString(dict, "GIDNUMBER",
			     PyString_FromString(LU_GIDNUMBER));
	PyDict_SetItemString(dict, "GECOS", PyString_FromString(LU_GECOS));
	PyDict_SetItemString(dict, "HOMEDIRECTORY",
			     PyString_FromString(LU_HOMEDIRECTORY));
	PyDict_SetItemString(dict, "LOGINSHELL",
			     PyString_FromString(LU_LOGINSHELL));

	/* Group attributes. */
	PyDict_SetItemString(dict, "GROUPNAME",
			     PyString_FromString(LU_GROUPNAME));
	PyDict_SetItemString(dict, "GROUPPASSWORD",
			     PyString_FromString(LU_GROUPPASSWORD));
	PyDict_SetItemString(dict, "ADMINISTRATORNAME",
			     PyString_FromString(LU_ADMINISTRATORNAME));
	PyDict_SetItemString(dict, "MEMBERNAME",
			     PyString_FromString(LU_MEMBERNAME));

	/* Shadow attributes. */
	PyDict_SetItemString(dict, "SHADOWNAME",
			     PyString_FromString(LU_SHADOWNAME));
	PyDict_SetItemString(dict, "SHADOWPASSWORD",
			     PyString_FromString(LU_SHADOWPASSWORD));
	PyDict_SetItemString(dict, "SHADOWLASTCHANGE",
			     PyString_FromString(LU_SHADOWLASTCHANGE));
	PyDict_SetItemString(dict, "SHADOWMIN",
			     PyString_FromString(LU_SHADOWMIN));
	PyDict_SetItemString(dict, "SHADOWMAX",
			     PyString_FromString(LU_SHADOWMAX));
	PyDict_SetItemString(dict, "SHADOWWARNING",
			     PyString_FromString(LU_SHADOWWARNING));
	PyDict_SetItemString(dict, "SHADOWINACTIVE",
			     PyString_FromString(LU_SHADOWINACTIVE));
	PyDict_SetItemString(dict, "SHADOWEXPIRE",
			     PyString_FromString(LU_SHADOWEXPIRE));
	PyDict_SetItemString(dict, "SHADOWFLAG",
			     PyString_FromString(LU_SHADOWFLAG));

	/* Additional fields. */
	PyDict_SetItemString(dict, "COMMONNAME",
			     PyString_FromString(LU_COMMONNAME));
	PyDict_SetItemString(dict, "GIVENNAME",
			     PyString_FromString(LU_GIVENNAME));
	PyDict_SetItemString(dict, "SN", PyString_FromString(LU_SN));
	PyDict_SetItemString(dict, "ROOMNUMBER",
			     PyString_FromString(LU_ROOMNUMBER));
	PyDict_SetItemString(dict, "TELEPHONENUMBER",
			     PyString_FromString(LU_TELEPHONENUMBER));
	PyDict_SetItemString(dict, "HOMEPHONE",
			     PyString_FromString(LU_HOMEPHONE));
	PyDict_SetItemString(dict, "EMAIL", PyString_FromString(LU_EMAIL));

	/* Miscellaneous. */
	PyDict_SetItemString(dict, "UT_NAMESIZE", PyInt_FromLong(UT_NAMESIZE));
	PyDict_SetItemString(dict, "VALUE_INVALID_ID",
			     PyLong_FromLongLong(LU_VALUE_INVALID_ID));

	DEBUG_EXIT;
}
